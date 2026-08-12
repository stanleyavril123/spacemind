use spacemind_core::{
    AnalysisPhase, CancellationToken, DuplicateReport, FileIdentity, Finding, ItemKind, ProgressEvent,
    Relationship, RelationshipKind, RelationshipReport, ScanResult, ScannedItem,
};
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

const PROGRESS_INTERVAL_ITEMS: u64 = 128;

#[derive(Debug, thiserror::Error)]
pub enum RelationshipError {
    #[error("relationship detection cancelled after analyzing {items_analyzed} items")]
    Cancelled { items_analyzed: u64 },
}

pub fn detect_relationships(
    scan: &ScanResult,
    duplicates: &DuplicateReport,
) -> RelationshipReport {
    let cancellation = CancellationToken::new();
    detect_relationships_with_progress(scan, duplicates, &cancellation, |_| {})
        .expect("a fresh cancellation token cannot be cancelled")
}

pub fn detect_relationships_with_progress<F>(
    scan: &ScanResult,
    duplicates: &DuplicateReport,
    cancellation: &CancellationToken,
    mut on_progress: F,
) -> Result<RelationshipReport, RelationshipError>
where
    F: FnMut(&ProgressEvent),
{
    let index = ItemIndex::new(scan);
    let total_items = scan.items.len() as u64 + duplicates.groups.len() as u64;
    let mut items_analyzed = 0_u64;
    let mut relationships = Vec::new();

    report_progress(&mut on_progress, items_analyzed, total_items, None, false);
    check_cancelled(cancellation, items_analyzed)?;

    for item in &scan.items {
        check_cancelled(cancellation, items_analyzed)?;
        match item.kind {
            ItemKind::File => {
                detect_archive_relationship(item, &index, &mut relationships);
                detect_installer_relationship(item, &index, &mut relationships);
                detect_virtual_machine_relationship(item, &index, &mut relationships);
            }
            ItemKind::Directory => {
                detect_build_relationship(item, &index, &mut relationships);
                detect_android_emulator_relationship(item, &index, &mut relationships);
            }
            ItemKind::Symlink | ItemKind::Other => {}
        }
        items_analyzed = items_analyzed.saturating_add(1);
        report_progress(
            &mut on_progress,
            items_analyzed,
            total_items,
            Some(item.path.clone()),
            false,
        );
    }

    for group in &duplicates.groups {
        check_cancelled(cancellation, items_analyzed)?;
        detect_duplicate_relationships(group, &mut relationships);
        items_analyzed = items_analyzed.saturating_add(1);
        report_progress(
            &mut on_progress,
            items_analyzed,
            total_items,
            group.entries.first().map(|entry| entry.path.clone()),
            false,
        );
    }

    relationships.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.source_path.cmp(&right.source_path))
            .then_with(|| left.target_path.cmp(&right.target_path))
    });
    relationships.dedup_by(|left, right| {
        left.kind == right.kind
            && left.source_path == right.source_path
            && left.target_path == right.target_path
    });

    check_cancelled(cancellation, items_analyzed)?;
    report_progress(&mut on_progress, items_analyzed, total_items, None, true);
    Ok(RelationshipReport {
        relationships,
        items_analyzed,
    })
}

pub fn enrich_findings_with_relationships(
    findings: &mut [Finding],
    report: &RelationshipReport,
) {
    for finding in findings {
        for relationship in &report.relationships {
            let related_path = if relationship.source_path == finding.path {
                Some(&relationship.target_path)
            } else if relationship.target_path == finding.path {
                Some(&relationship.source_path)
            } else {
                None
            };
            if let Some(path) = related_path {
                let evidence = format!(
                    "{}: {}",
                    relationship_evidence_label(relationship.kind),
                    path.display()
                );
                if !finding.evidence.contains(&evidence) {
                    finding.evidence.push(evidence);
                }
            }
        }
    }
}

fn relationship_evidence_label(kind: RelationshipKind) -> &'static str {
    match kind {
        RelationshipKind::ArchiveExtractedDirectory => "Related extracted directory",
        RelationshipKind::InstallerApplicationDirectory => "Related application directory",
        RelationshipKind::BuildDirectoryProject => "Source project",
        RelationshipKind::VirtualMachineComponent => "Related VM component",
        RelationshipKind::AndroidEmulatorConfiguration => "AVD configuration",
        RelationshipKind::ExactDuplicate => "Exact duplicate",
    }
}

struct ItemIndex<'a> {
    children: BTreeMap<PathBuf, Vec<&'a ScannedItem>>,
    named_children: BTreeMap<(PathBuf, String), Vec<&'a ScannedItem>>,
}

impl<'a> ItemIndex<'a> {
    fn new(scan: &'a ScanResult) -> Self {
        let mut children: BTreeMap<PathBuf, Vec<&ScannedItem>> = BTreeMap::new();
        let mut named_children: BTreeMap<(PathBuf, String), Vec<&ScannedItem>> =
            BTreeMap::new();
        for item in &scan.items {
            if let Some(parent) = item.path.parent() {
                if let Some(name) = item.path.file_name() {
                    named_children
                        .entry((
                            parent.to_path_buf(),
                            name.to_string_lossy().to_ascii_lowercase(),
                        ))
                        .or_default()
                        .push(item);
                }
                children
                    .entry(parent.to_path_buf())
                    .or_default()
                    .push(item);
            }
        }
        for items in children.values_mut() {
            items.sort_by(|left, right| left.path.cmp(&right.path));
        }
        Self {
            children,
            named_children,
        }
    }

    fn children_of(&self, parent: &Path) -> &[&'a ScannedItem] {
        self.children
            .get(parent)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    fn child_named(
        &self,
        parent: &Path,
        name: &str,
        kind: ItemKind,
    ) -> Option<&'a ScannedItem> {
        self.named_children
            .get(&(parent.to_path_buf(), name.to_ascii_lowercase()))
            .and_then(|items| items.iter().copied().find(|item| item.kind == kind))
    }

    fn first_child_with_suffixes(
        &self,
        parent: &Path,
        suffixes: &[&str],
    ) -> Option<&'a ScannedItem> {
        self.children_of(parent)
            .iter()
            .copied()
            .find(|item| item.kind == ItemKind::File && has_any_suffix(&item.path, suffixes))
    }
}

fn detect_archive_relationship(
    archive: &ScannedItem,
    index: &ItemIndex<'_>,
    relationships: &mut Vec<Relationship>,
) {
    let Some(base_name) = archive_base_name(&archive.path) else {
        return;
    };
    let Some(parent) = archive.path.parent() else {
        return;
    };
    let Some(directory) = index.child_named(parent, &base_name, ItemKind::Directory) else {
        return;
    };

    relationships.push(Relationship {
        kind: RelationshipKind::ArchiveExtractedDirectory,
        source_path: archive.path.clone(),
        target_path: directory.path.clone(),
        confidence: 0.96,
        evidence: vec![format!(
            "Archive name matches sibling directory {:?}",
            directory.path.file_name().unwrap_or_default()
        )],
    });
}

fn detect_installer_relationship(
    installer: &ScannedItem,
    index: &ItemIndex<'_>,
    relationships: &mut Vec<Relationship>,
) {
    let Some(base_name) = installer_base_name(&installer.path) else {
        return;
    };
    let product_name = normalized_product_name(&base_name);
    if product_name.is_empty() {
        return;
    }
    let Some(parent) = installer.path.parent() else {
        return;
    };
    let related_directory = index.children_of(parent).iter().copied().find(|item| {
        item.kind == ItemKind::Directory
            && normalized_product_name(&lowercase_name(&item.path)) == product_name
    });
    let Some(directory) = related_directory else {
        return;
    };

    relationships.push(Relationship {
        kind: RelationshipKind::InstallerApplicationDirectory,
        source_path: installer.path.clone(),
        target_path: directory.path.clone(),
        confidence: 0.78,
        evidence: vec![
            "Installer and sibling application directory share a normalized product name"
                .to_owned(),
            "This does not prove that the application is installed".to_owned(),
        ],
    });
}

fn detect_build_relationship(
    build_directory: &ScannedItem,
    index: &ItemIndex<'_>,
    relationships: &mut Vec<Relationship>,
) {
    let name = lowercase_name(&build_directory.path);
    let manifests: &[&str] = match name.as_str() {
        "node_modules" => &["package.json"],
        "target" => &["Cargo.toml"],
        "build" | "dist" => &[
            "Cargo.toml",
            "package.json",
            "build.gradle",
            "build.gradle.kts",
            "settings.gradle",
            "settings.gradle.kts",
            "CMakeLists.txt",
            "pyproject.toml",
        ],
        _ => return,
    };
    let Some(project_root) = build_directory.path.parent() else {
        return;
    };
    let manifest = manifests
        .iter()
        .find_map(|name| index.child_named(project_root, name, ItemKind::File));
    let Some(manifest) = manifest else {
        return;
    };

    relationships.push(Relationship {
        kind: RelationshipKind::BuildDirectoryProject,
        source_path: build_directory.path.clone(),
        target_path: project_root.to_path_buf(),
        confidence: 0.99,
        evidence: vec![format!(
            "Build directory is linked to project manifest {}",
            manifest.path.display()
        )],
    });
}

fn detect_virtual_machine_relationship(
    item: &ScannedItem,
    index: &ItemIndex<'_>,
    relationships: &mut Vec<Relationship>,
) {
    if is_virtual_disk(&item.path) {
        let Some(parent) = item.path.parent() else {
            return;
        };
        if let Some(configuration) =
            index.first_child_with_suffixes(parent, &[".vbox", ".vmx", ".ovf"])
        {
            if configuration.path != item.path {
                relationships.push(Relationship {
                    kind: RelationshipKind::VirtualMachineComponent,
                    source_path: item.path.clone(),
                    target_path: configuration.path.clone(),
                    confidence: 0.99,
                    evidence: vec![
                        "Virtual disk and virtual-machine configuration share a directory"
                            .to_owned(),
                    ],
                });
            }
        }
        return;
    }

    if !has_any_suffix(&item.path, &[".ova"]) {
        return;
    }
    let Some(parent) = item.path.parent() else {
        return;
    };
    let Some(package_name) = item
        .path
        .file_stem()
        .map(|value| normalized_product_name(&value.to_string_lossy()))
    else {
        return;
    };
    let imported_directory = index.children_of(parent).iter().copied().find(|candidate| {
        candidate.kind == ItemKind::Directory
            && normalized_product_name(&lowercase_name(&candidate.path)) == package_name
            && index
                .first_child_with_suffixes(&candidate.path, &[".vbox", ".vmx", ".ovf"])
                .is_some()
    });
    let Some(directory) = imported_directory else {
        return;
    };

    relationships.push(Relationship {
        kind: RelationshipKind::VirtualMachineComponent,
        source_path: item.path.clone(),
        target_path: directory.path.clone(),
        confidence: 0.90,
        evidence: vec![
            "VM package name matches a sibling directory containing VM configuration".to_owned(),
        ],
    });
}

fn detect_android_emulator_relationship(
    directory: &ScannedItem,
    index: &ItemIndex<'_>,
    relationships: &mut Vec<Relationship>,
) {
    let name = lowercase_name(&directory.path);
    if !name.ends_with(".avd") {
        return;
    }
    let Some(parent) = directory.path.parent() else {
        return;
    };
    let config_name = format!("{}.ini", name.trim_end_matches(".avd"));
    let Some(configuration) = index.child_named(parent, &config_name, ItemKind::File) else {
        return;
    };

    relationships.push(Relationship {
        kind: RelationshipKind::AndroidEmulatorConfiguration,
        source_path: directory.path.clone(),
        target_path: configuration.path.clone(),
        confidence: 0.99,
        evidence: vec!["Android Virtual Device directory matches its AVD .ini file".to_owned()],
    });
}

fn detect_duplicate_relationships(
    group: &spacemind_core::DuplicateGroup,
    relationships: &mut Vec<Relationship>,
) {
    let mut seen_identities = HashSet::new();
    let mut physical_entries = Vec::new();
    for entry in &group.entries {
        let is_new_physical_file = match entry.file_identity {
            Some(identity) => seen_identities.insert(PhysicalIdentity::Known(identity)),
            None => seen_identities.insert(PhysicalIdentity::Unknown(entry.path.clone())),
        };
        if is_new_physical_file {
            physical_entries.push(entry);
        }
    }
    let Some((source, copies)) = physical_entries.split_first() else {
        return;
    };
    for copy in copies {
        relationships.push(Relationship {
            kind: RelationshipKind::ExactDuplicate,
            source_path: source.path.clone(),
            target_path: copy.path.clone(),
            confidence: 1.0,
            evidence: vec![format!(
                "Files have the same size and BLAKE3 fingerprint {}",
                group.blake3_hash
            )],
        });
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum PhysicalIdentity {
    Known(FileIdentity),
    Unknown(PathBuf),
}

fn archive_base_name(path: &Path) -> Option<String> {
    strip_known_suffix(
        path,
        &[
            ".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst", ".tbz2", ".tgz", ".txz",
            ".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz", ".zst",
        ],
    )
}

fn installer_base_name(path: &Path) -> Option<String> {
    strip_known_suffix(
        path,
        &[
            ".msixbundle", ".appimage", ".msix", ".deb", ".rpm", ".exe", ".msi", ".dmg",
            ".pkg", ".apk", ".run",
        ],
    )
}

fn strip_known_suffix(path: &Path, suffixes: &[&str]) -> Option<String> {
    let name = lowercase_name(path);
    suffixes
        .iter()
        .find_map(|suffix| name.strip_suffix(suffix).map(str::to_owned))
        .filter(|name| !name.is_empty())
}

fn normalized_product_name(name: &str) -> String {
    let name = name.to_ascii_lowercase();
    let ignored_tokens = [
        "amd64", "x86", "x64", "x86_64", "arm64", "aarch64", "linux", "windows", "win",
        "macos", "setup", "installer",
    ];
    name.split(|character: char| character == '-' || character == '_' || character == ' ')
        .take_while(|token| !token.chars().next().is_some_and(|value| value.is_ascii_digit()))
        .filter(|token| !token.is_empty() && !ignored_tokens.contains(token))
        .collect::<Vec<_>>()
        .join("-")
}

fn is_virtual_disk(path: &Path) -> bool {
    has_any_suffix(
        path,
        &[".vdi", ".vmdk", ".vhd", ".vhdx", ".qcow", ".qcow2"],
    )
}

fn has_any_suffix(path: &Path, suffixes: &[&str]) -> bool {
    let name = lowercase_name(path);
    suffixes.iter().any(|suffix| name.ends_with(suffix))
}

fn lowercase_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default()
}

fn check_cancelled(
    cancellation: &CancellationToken,
    items_analyzed: u64,
) -> Result<(), RelationshipError> {
    if cancellation.is_cancelled() {
        Err(RelationshipError::Cancelled { items_analyzed })
    } else {
        Ok(())
    }
}

fn report_progress<F>(
    on_progress: &mut F,
    items_analyzed: u64,
    total_items: u64,
    current_path: Option<PathBuf>,
    complete: bool,
) where
    F: FnMut(&ProgressEvent),
{
    if complete || items_analyzed == 0 || items_analyzed % PROGRESS_INTERVAL_ITEMS == 0 {
        on_progress(&ProgressEvent {
            phase: AnalysisPhase::DetectingRelationships,
            items_processed: items_analyzed,
            bytes_processed: 0,
            total_items: Some(total_items),
            total_bytes: None,
            current_path,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spacemind_core::{DuplicateEntry, DuplicateGroup, DuplicateWarning, ScanWarning};

    fn item(path: &str, kind: ItemKind) -> ScannedItem {
        ScannedItem {
            path: PathBuf::from(path),
            kind,
            size_bytes: 100,
            allocated_size_bytes: None,
            file_identity: None,
            hard_link_count: None,
            created_at_epoch_seconds: None,
            modified_at_epoch_seconds: None,
            modified_at_epoch_nanoseconds: None,
            accessed_at_epoch_seconds: None,
            extension: Path::new(path)
                .extension()
                .and_then(|extension| extension.to_str())
                .map(str::to_owned),
        }
    }

    fn scan(items: Vec<ScannedItem>) -> ScanResult {
        ScanResult {
            root: PathBuf::from("/test"),
            started_at_epoch_seconds: 0,
            completed_at_epoch_seconds: 0,
            total_size_bytes: items.iter().map(|item| item.size_bytes).sum(),
            total_allocated_size_bytes: None,
            file_count: items.iter().filter(|item| item.kind == ItemKind::File).count() as u64,
            directory_count: items
                .iter()
                .filter(|item| item.kind == ItemKind::Directory)
                .count() as u64,
            items,
            ignored_paths: Vec::new(),
            warnings: Vec::<ScanWarning>::new(),
        }
    }

    fn no_duplicates() -> DuplicateReport {
        DuplicateReport {
            groups: Vec::new(),
            warnings: Vec::<DuplicateWarning>::new(),
            files_hashed: 0,
            bytes_hashed: 0,
            logical_duplicate_bytes: 0,
            potential_recovery_allocated_bytes: Some(0),
        }
    }

    #[test]
    fn links_archives_to_extracted_sibling_directories() {
        let scan = scan(vec![
            item("/test/project.tar.gz", ItemKind::File),
            item("/test/project", ItemKind::Directory),
        ]);

        let report = detect_relationships(&scan, &no_duplicates());

        assert_eq!(report.relationships.len(), 1);
        assert_eq!(
            report.relationships[0].kind,
            RelationshipKind::ArchiveExtractedDirectory
        );
    }

    #[test]
    fn links_versioned_installers_to_matching_application_directories() {
        let scan = scan(vec![
            item("/test/android-studio-2025.1-linux.run", ItemKind::File),
            item("/test/android-studio", ItemKind::Directory),
        ]);

        let report = detect_relationships(&scan, &no_duplicates());

        assert_eq!(report.relationships.len(), 1);
        assert_eq!(
            report.relationships[0].kind,
            RelationshipKind::InstallerApplicationDirectory
        );
        assert!(report.relationships[0].confidence < 0.80);
    }

    #[test]
    fn links_build_directories_to_projects_with_manifests() {
        let scan = scan(vec![
            item("/test/project/Cargo.toml", ItemKind::File),
            item("/test/project/target", ItemKind::Directory),
        ]);

        let report = detect_relationships(&scan, &no_duplicates());

        assert_eq!(report.relationships.len(), 1);
        assert_eq!(
            report.relationships[0].kind,
            RelationshipKind::BuildDirectoryProject
        );
        assert_eq!(
            report.relationships[0].target_path,
            PathBuf::from("/test/project")
        );
    }

    #[test]
    fn links_virtual_disks_to_vm_configuration() {
        let scan = scan(vec![
            item("/test/Kali/Kali.vbox", ItemKind::File),
            item("/test/Kali/Kali.vdi", ItemKind::File),
        ]);

        let report = detect_relationships(&scan, &no_duplicates());

        assert_eq!(report.relationships.len(), 1);
        assert_eq!(
            report.relationships[0].kind,
            RelationshipKind::VirtualMachineComponent
        );
    }

    #[test]
    fn links_downloaded_vm_packages_to_imported_vm_directories() {
        let scan = scan(vec![
            item("/test/Kali-2025.1.ova", ItemKind::File),
            item("/test/Kali", ItemKind::Directory),
            item("/test/Kali/Kali.vbox", ItemKind::File),
        ]);

        let report = detect_relationships(&scan, &no_duplicates());

        assert_eq!(report.relationships.len(), 1);
        assert_eq!(
            report.relationships[0].kind,
            RelationshipKind::VirtualMachineComponent
        );
        assert_eq!(
            report.relationships[0].target_path,
            PathBuf::from("/test/Kali")
        );
    }

    #[test]
    fn links_android_emulator_directory_to_ini_configuration() {
        let scan = scan(vec![
            item("/test/.android/avd/pixel.ini", ItemKind::File),
            item("/test/.android/avd/pixel.avd", ItemKind::Directory),
        ]);

        let report = detect_relationships(&scan, &no_duplicates());

        assert_eq!(report.relationships.len(), 1);
        assert_eq!(
            report.relationships[0].kind,
            RelationshipKind::AndroidEmulatorConfiguration
        );
    }

    #[test]
    fn turns_duplicate_groups_into_evidence_relationships() {
        let duplicates = DuplicateReport {
            groups: vec![DuplicateGroup {
                blake3_hash: "abc123".to_owned(),
                size_bytes_per_file: 100,
                entries: vec![
                    DuplicateEntry {
                        path: PathBuf::from("/test/a.bin"),
                        file_identity: Some(FileIdentity {
                            volume_id: 1,
                            file_id: 1,
                        }),
                        allocated_size_bytes: Some(100),
                        hard_link_count: Some(1),
                        protected: false,
                    },
                    DuplicateEntry {
                        path: PathBuf::from("/test/b.bin"),
                        file_identity: Some(FileIdentity {
                            volume_id: 1,
                            file_id: 2,
                        }),
                        allocated_size_bytes: Some(100),
                        hard_link_count: Some(1),
                        protected: false,
                    },
                ],
                unique_file_count: 2,
                protected_file_count: 0,
                logical_duplicate_bytes: 100,
                potential_recovery_allocated_bytes: Some(100),
            }],
            warnings: Vec::new(),
            files_hashed: 2,
            bytes_hashed: 200,
            logical_duplicate_bytes: 100,
            potential_recovery_allocated_bytes: Some(100),
        };

        let report = detect_relationships(&scan(Vec::new()), &duplicates);

        assert_eq!(report.relationships.len(), 1);
        assert_eq!(
            report.relationships[0].kind,
            RelationshipKind::ExactDuplicate
        );
        assert_eq!(report.relationships[0].confidence, 1.0);
    }

    #[test]
    fn relationship_evidence_enriches_matching_findings() {
        let report = RelationshipReport {
            relationships: vec![Relationship {
                kind: RelationshipKind::ArchiveExtractedDirectory,
                source_path: PathBuf::from("/test/project.zip"),
                target_path: PathBuf::from("/test/project"),
                confidence: 0.96,
                evidence: Vec::new(),
            }],
            items_analyzed: 2,
        };
        let mut findings = vec![Finding {
            category: spacemind_core::FindingCategory::OldArchive,
            path: PathBuf::from("/test/project.zip"),
            potential_recovery_bytes: 100,
            confidence: 0.82,
            risk: spacemind_core::RiskLevel::Medium,
            evidence: Vec::new(),
            suggested_action: spacemind_core::SuggestedAction::ReviewForDeletion,
        }];

        enrich_findings_with_relationships(&mut findings, &report);

        assert_eq!(
            findings[0].evidence,
            vec!["Related extracted directory: /test/project"]
        );
    }

    #[test]
    fn hard_link_aliases_do_not_create_duplicate_relationships() {
        let identity = FileIdentity {
            volume_id: 1,
            file_id: 1,
        };
        let duplicates = DuplicateReport {
            groups: vec![DuplicateGroup {
                blake3_hash: "abc123".to_owned(),
                size_bytes_per_file: 100,
                entries: vec![
                    DuplicateEntry {
                        path: PathBuf::from("/test/a.bin"),
                        file_identity: Some(identity),
                        allocated_size_bytes: Some(100),
                        hard_link_count: Some(2),
                        protected: false,
                    },
                    DuplicateEntry {
                        path: PathBuf::from("/test/a-link.bin"),
                        file_identity: Some(identity),
                        allocated_size_bytes: Some(100),
                        hard_link_count: Some(2),
                        protected: false,
                    },
                    DuplicateEntry {
                        path: PathBuf::from("/test/copy.bin"),
                        file_identity: Some(FileIdentity {
                            volume_id: 1,
                            file_id: 2,
                        }),
                        allocated_size_bytes: Some(100),
                        hard_link_count: Some(1),
                        protected: false,
                    },
                ],
                unique_file_count: 2,
                protected_file_count: 0,
                logical_duplicate_bytes: 100,
                potential_recovery_allocated_bytes: Some(100),
            }],
            warnings: Vec::new(),
            files_hashed: 2,
            bytes_hashed: 200,
            logical_duplicate_bytes: 100,
            potential_recovery_allocated_bytes: Some(100),
        };

        let report = detect_relationships(&scan(Vec::new()), &duplicates);

        assert_eq!(report.relationships.len(), 1);
    }

    #[test]
    fn reports_relationship_progress_with_final_totals() {
        let scan = scan(vec![
            item("/test/project.zip", ItemKind::File),
            item("/test/project", ItemKind::Directory),
        ]);
        let cancellation = CancellationToken::new();
        let mut events = Vec::new();

        let report = detect_relationships_with_progress(
            &scan,
            &no_duplicates(),
            &cancellation,
            |event| events.push(event.clone()),
        )
        .unwrap();

        assert_eq!(events.first().unwrap().phase, AnalysisPhase::DetectingRelationships);
        assert_eq!(events.first().unwrap().items_processed, 0);
        assert_eq!(events.last().unwrap().items_processed, report.items_analyzed);
        assert_eq!(events.last().unwrap().total_items, Some(report.items_analyzed));
    }

    #[test]
    fn cancellation_stops_relationship_detection() {
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        let result = detect_relationships_with_progress(
            &scan(vec![item("/test/archive.zip", ItemKind::File)]),
            &no_duplicates(),
            &cancellation,
            |_| {},
        );

        assert!(matches!(
            result,
            Err(RelationshipError::Cancelled { items_analyzed: 0 })
        ));
    }
}
