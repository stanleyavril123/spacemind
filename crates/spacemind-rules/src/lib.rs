use spacemind_core::{
    AnalysisPhase, CancellationToken, Finding, FindingCategory, ItemKind, PathMatcher, PathRule,
    PathRuleError, ProgressEvent, RiskLevel, ScanResult, ScannedItem, SuggestedAction,
};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const DAY_SECONDS: u64 = 24 * 60 * 60;
const PROGRESS_INTERVAL_ITEMS: u64 = 128;

#[derive(Debug, thiserror::Error)]
pub enum RuleError {
    #[error("invalid protected-path rule: {0}")]
    InvalidProtectedRule(#[from] PathRuleError),
    #[error("recommendation building cancelled after processing {items_processed} items")]
    Cancelled { items_processed: u64 },
}

#[derive(Debug, Clone)]
pub struct RuleOptions {
    pub large_item_threshold_bytes: u64,
    pub old_item_threshold_days: u64,
    pub now_epoch_seconds: u64,
    pub protected_rules: Vec<PathRule>,
}

impl Default for RuleOptions {
    fn default() -> Self {
        Self {
            large_item_threshold_bytes: 1024 * 1024 * 1024,
            old_item_threshold_days: 180,
            now_epoch_seconds: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_secs())
                .unwrap_or(0),
            protected_rules: Vec::new(),
        }
    }
}

pub fn evaluate(scan: &ScanResult, options: &RuleOptions) -> Vec<Finding> {
    let cancellation = CancellationToken::new();
    evaluate_with_progress(scan, options, &cancellation, |_| {})
        .expect("a fresh cancellation token and valid rules cannot fail")
}

#[derive(Debug, Clone, PartialEq)]
pub struct RuleEvaluation {
    pub findings: Vec<Finding>,
    pub protected_items: u64,
    pub suppressed_findings: u64,
}

pub fn evaluate_with_progress<F>(
    scan: &ScanResult,
    options: &RuleOptions,
    cancellation: &CancellationToken,
    on_progress: F,
) -> Result<Vec<Finding>, RuleError>
where
    F: FnMut(&ProgressEvent),
{
    Ok(evaluate_with_policy_progress(
        scan,
        options,
        cancellation,
        on_progress,
    )?
    .findings)
}

pub fn evaluate_with_policy_progress<F>(
    scan: &ScanResult,
    options: &RuleOptions,
    cancellation: &CancellationToken,
    mut on_progress: F,
) -> Result<RuleEvaluation, RuleError>
where
    F: FnMut(&ProgressEvent),
{
    let protected_matcher = PathMatcher::new(&scan.root, &options.protected_rules)?;
    let context = RuleContext::new(scan);
    let mut findings = Vec::new();
    let mut protected_items = 0_u64;
    let mut suppressed_findings = 0_u64;
    let total_items = scan.items.len() as u64;
    let mut items_processed = 0_u64;
    report_rule_progress(&mut on_progress, items_processed, total_items, false);

    for item in &scan.items {
        if cancellation.is_cancelled() {
            return Err(RuleError::Cancelled { items_processed });
        }
        items_processed = items_processed.saturating_add(1);
        if item.path == scan.root || matches!(item.kind, ItemKind::Symlink | ItemKind::Other) {
            report_rule_progress(&mut on_progress, items_processed, total_items, false);
            continue;
        }

        let protected = protected_matcher.is_match(&item.path);
        let findings_before_item = findings.len();
        if item.size_bytes >= options.large_item_threshold_bytes {
            findings.push(large_item_finding(item, options.large_item_threshold_bytes));
        }

        if let Some(finding) = classify_item(item, &context, options) {
            findings.push(finding);
        }

        if protected {
            protected_items = protected_items.saturating_add(1);
            suppressed_findings = suppressed_findings
                .saturating_add((findings.len() - findings_before_item) as u64);
            findings.truncate(findings_before_item);
        }
        report_rule_progress(&mut on_progress, items_processed, total_items, false);
    }

    findings.sort_by(|left, right| {
        right
            .potential_recovery_bytes
            .cmp(&left.potential_recovery_bytes)
            .then_with(|| left.path.cmp(&right.path))
            .then_with(|| category_rank(left.category).cmp(&category_rank(right.category)))
    });
    if cancellation.is_cancelled() {
        return Err(RuleError::Cancelled { items_processed });
    }
    report_rule_progress(&mut on_progress, items_processed, total_items, true);
    Ok(RuleEvaluation {
        findings,
        protected_items,
        suppressed_findings,
    })
}

fn report_rule_progress<F>(
    on_progress: &mut F,
    items_processed: u64,
    total_items: u64,
    complete: bool,
) where
    F: FnMut(&ProgressEvent),
{
    if complete || items_processed == 0 || items_processed % PROGRESS_INTERVAL_ITEMS == 0 {
        on_progress(&ProgressEvent {
            phase: AnalysisPhase::BuildingRecommendations,
            items_processed,
            bytes_processed: 0,
            total_items: Some(total_items),
            total_bytes: None,
            current_path: None,
        });
    }
}

#[derive(Debug, Default)]
struct RuleContext {
    rust_project_roots: HashSet<PathBuf>,
    virtual_machine_directories: HashSet<PathBuf>,
    android_emulator_directories: HashSet<PathBuf>,
}

impl RuleContext {
    fn new(scan: &ScanResult) -> Self {
        let mut context = Self::default();
        for item in &scan.items {
            match item.kind {
                ItemKind::Directory => {
                    if is_virtual_machine_bundle(&item.path) {
                        context.virtual_machine_directories.insert(item.path.clone());
                    }
                    if is_android_emulator_directory(&item.path) {
                        context.android_emulator_directories.insert(item.path.clone());
                    }
                }
                ItemKind::File => {
                    if lowercase_name(&item.path) == "cargo.toml" {
                        if let Some(parent) = item.path.parent() {
                            context.rust_project_roots.insert(parent.to_path_buf());
                        }
                    }
                    if has_any_suffix(&item.path, &[".vbox", ".vmx"]) {
                        if let Some(parent) = item.path.parent() {
                            context.virtual_machine_directories.insert(parent.to_path_buf());
                        }
                    }
                }
                ItemKind::Symlink | ItemKind::Other => {}
            }
        }
        context
    }

    fn contains_virtual_machine(&self, path: &Path) -> bool {
        self.virtual_machine_directories.contains(path)
    }

    fn contains_android_emulator(&self, path: &Path) -> bool {
        self.android_emulator_directories.contains(path)
    }

    fn has_classified_container(&self, path: &Path) -> bool {
        path.ancestors().any(|ancestor| {
            self.virtual_machine_directories.contains(ancestor)
                || self.android_emulator_directories.contains(ancestor)
        })
    }
}

fn classify_item(
    item: &ScannedItem,
    context: &RuleContext,
    options: &RuleOptions,
) -> Option<Finding> {
    match item.kind {
        ItemKind::Directory => classify_directory(item, context),
        ItemKind::File => classify_file(item, context, options),
        ItemKind::Symlink | ItemKind::Other => None,
    }
}

struct FindingClassification {
    category: FindingCategory,
    risk: RiskLevel,
    confidence: f32,
    evidence: &'static str,
    suggested_action: SuggestedAction,
}

fn classify_directory(item: &ScannedItem, context: &RuleContext) -> Option<Finding> {
    let path = &item.path;
    let classification = if context.contains_android_emulator(path) {
        FindingClassification {
            category: FindingCategory::AndroidEmulator,
            risk: RiskLevel::High,
            confidence: 0.98,
            evidence: "Recognized as an Android Virtual Device; it may contain unique emulator state",
            suggested_action: SuggestedAction::ReviewForArchive,
        }
    } else if context.contains_virtual_machine(path) {
        FindingClassification {
            category: FindingCategory::VirtualMachine,
            risk: RiskLevel::High,
            confidence: 0.98,
            evidence: "Recognized as a virtual-machine bundle; it may contain unique guest data",
            suggested_action: SuggestedAction::ReviewForArchive,
        }
    } else if lowercase_name(path) == "node_modules" {
        FindingClassification {
            category: FindingCategory::NodeModules,
            risk: RiskLevel::Medium,
            confidence: 0.99,
            evidence: "Directory is a Node.js dependency installation that can usually be recreated",
            suggested_action: SuggestedAction::ReviewForDeletion,
        }
    } else if lowercase_name(path) == "target"
        && path
            .parent()
            .is_some_and(|parent| context.rust_project_roots.contains(parent))
    {
        FindingClassification {
            category: FindingCategory::RustBuildArtifacts,
            risk: RiskLevel::Low,
            confidence: 0.98,
            evidence: "Directory is a Rust target folder beside a Cargo.toml project manifest",
            suggested_action: SuggestedAction::ReviewForDeletion,
        }
    } else if is_gradle_cache_directory(path) {
        FindingClassification {
            category: FindingCategory::GradleCache,
            risk: RiskLevel::Low,
            confidence: 0.97,
            evidence: "Path matches a known Gradle cache location",
            suggested_action: SuggestedAction::ReviewForDeletion,
        }
    } else if is_operating_system_cache(path) {
        FindingClassification {
            category: FindingCategory::OperatingSystemCache,
            risk: RiskLevel::Medium,
            confidence: 0.95,
            evidence: "Path matches a cache managed by the operating system",
            suggested_action: SuggestedAction::ReviewForDeletion,
        }
    } else if is_cache_directory(path) {
        FindingClassification {
            category: FindingCategory::CacheDirectory,
            risk: RiskLevel::Low,
            confidence: 0.90,
            evidence: "Recognized as a common user cache directory",
            suggested_action: SuggestedAction::ReviewForDeletion,
        }
    } else if is_generated_directory(path) {
        FindingClassification {
            category: FindingCategory::GeneratedDirectory,
            risk: RiskLevel::Medium,
            confidence: 0.88,
            evidence: "Recognized as a generated build directory",
            suggested_action: SuggestedAction::ReviewForDeletion,
        }
    } else {
        return None;
    };

    Some(directory_finding(
        item,
        classification.category,
        classification.risk,
        classification.confidence,
        classification.evidence,
        classification.suggested_action,
    ))
}

fn classify_file(
    item: &ScannedItem,
    context: &RuleContext,
    options: &RuleOptions,
) -> Option<Finding> {
    if is_virtual_machine_image(&item.path) && !context.has_classified_container(&item.path) {
        return Some(file_finding(
            item,
            FindingCategory::VirtualMachine,
            RiskLevel::High,
            0.98,
            "File extension is commonly used for a virtual-machine disk or package; it may contain unique guest data",
            SuggestedAction::ReviewForArchive,
        ));
    }
    if !is_old(item, options) {
        return None;
    }
    if is_iso_image(&item.path) {
        Some(old_file_finding(
            item,
            options,
            FindingCategory::IsoImage,
            "Recognized as an ISO disk image",
        ))
    } else if is_installer(&item.path) {
        Some(old_file_finding(
            item,
            options,
            FindingCategory::OldInstaller,
            "Recognized as an application installer",
        ))
    } else if is_archive(&item.path) {
        Some(old_file_finding(
            item,
            options,
            FindingCategory::OldArchive,
            "Recognized as an archive",
        ))
    } else {
        None
    }
}

fn large_item_finding(item: &ScannedItem, threshold: u64) -> Finding {
    Finding {
        category: FindingCategory::LargeItem,
        path: item.path.clone(),
        potential_recovery_bytes: item.size_bytes,
        confidence: 1.0,
        risk: RiskLevel::High,
        evidence: vec![format!(
            "Item is at least {threshold} bytes, the configured large-item threshold"
        )],
        suggested_action: SuggestedAction::ReviewForArchive,
    }
}

fn old_file_finding(
    item: &ScannedItem,
    options: &RuleOptions,
    category: FindingCategory,
    type_evidence: &str,
) -> Finding {
    let age_days = age_days(item, options).unwrap_or(options.old_item_threshold_days);
    Finding {
        category,
        path: item.path.clone(),
        potential_recovery_bytes: item.size_bytes,
        confidence: 0.82,
        risk: RiskLevel::Medium,
        evidence: vec![
            type_evidence.to_owned(),
            format!("Not modified in {age_days} days"),
        ],
        suggested_action: SuggestedAction::ReviewForDeletion,
    }
}

fn file_finding(
    item: &ScannedItem,
    category: FindingCategory,
    risk: RiskLevel,
    confidence: f32,
    evidence: &str,
    suggested_action: SuggestedAction,
) -> Finding {
    Finding {
        category,
        path: item.path.clone(),
        potential_recovery_bytes: item.size_bytes,
        confidence,
        risk,
        evidence: vec![evidence.to_owned()],
        suggested_action,
    }
}

fn directory_finding(
    item: &ScannedItem,
    category: FindingCategory,
    risk: RiskLevel,
    confidence: f32,
    evidence: &str,
    suggested_action: SuggestedAction,
) -> Finding {
    Finding {
        category,
        path: item.path.clone(),
        potential_recovery_bytes: item.size_bytes,
        confidence,
        risk,
        evidence: vec![
            evidence.to_owned(),
            format!("Directory occupies {} bytes", item.size_bytes),
        ],
        suggested_action,
    }
}

fn is_old(item: &ScannedItem, options: &RuleOptions) -> bool {
    age_days(item, options)
        .map(|days| days >= options.old_item_threshold_days)
        .unwrap_or(false)
}

fn age_days(item: &ScannedItem, options: &RuleOptions) -> Option<u64> {
    item.modified_at_epoch_seconds.map(|modified| {
        options.now_epoch_seconds.saturating_sub(modified) / DAY_SECONDS
    })
}

fn lowercase_name(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
}

fn has_any_suffix(path: &Path, suffixes: &[&str]) -> bool {
    let name = lowercase_name(path);
    suffixes.iter().any(|suffix| name.ends_with(suffix))
}

fn is_iso_image(path: &Path) -> bool {
    has_any_suffix(path, &[".iso"])
}

fn is_installer(path: &Path) -> bool {
    has_any_suffix(
        path,
        &[
            ".deb", ".rpm", ".exe", ".msi", ".msix", ".msixbundle", ".dmg", ".pkg",
            ".appimage", ".apk", ".run",
        ],
    )
}

fn is_archive(path: &Path) -> bool {
    has_any_suffix(
        path,
        &[
            ".zip", ".7z", ".rar", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2",
            ".tar.xz", ".txz", ".tar.zst", ".gz", ".bz2", ".xz", ".zst",
        ],
    )
}

fn is_virtual_machine_image(path: &Path) -> bool {
    has_any_suffix(
        path,
        &[
            ".vdi", ".vmdk", ".vhd", ".vhdx", ".qcow", ".qcow2", ".img", ".ova", ".ovf",
        ],
    )
}

fn is_virtual_machine_bundle(path: &Path) -> bool {
    lowercase_name(path).ends_with(".vmwarevm")
}

fn is_android_emulator_directory(path: &Path) -> bool {
    lowercase_name(path).ends_with(".avd")
        && path.parent().is_some_and(|parent| lowercase_name(parent) == "avd")
        && path
            .parent()
            .and_then(Path::parent)
            .is_some_and(|parent| lowercase_name(parent) == ".android")
}

fn is_gradle_cache_directory(path: &Path) -> bool {
    let name = lowercase_name(path);
    let parent_name = path.parent().map(lowercase_name).unwrap_or_default();
    if parent_name == ".gradle"
        && matches!(
            name.as_str(),
            "caches" | "daemon" | "jdks" | "native" | "notifications"
        )
    {
        return true;
    }
    name == "dists"
        && parent_name == "wrapper"
        && path
            .parent()
            .and_then(Path::parent)
            .is_some_and(|parent| lowercase_name(parent) == ".gradle")
}

fn is_operating_system_cache(path: &Path) -> bool {
    #[cfg(target_os = "linux")]
    if path == Path::new("/var/cache") {
        return true;
    }

    #[cfg(windows)]
    if path_has_suffix(path, &["windows", "softwaredistribution", "download"])
        || path_has_suffix(path, &["appdata", "local", "temp"])
        || path_has_suffix(path, &["microsoft", "windows", "inetcache"])
        || (lowercase_name(path) == "localcache"
            && path.ancestors().any(|ancestor| lowercase_name(ancestor) == "packages"))
    {
        return true;
    }

    false
}

#[cfg(windows)]
fn path_has_suffix(path: &Path, suffix: &[&str]) -> bool {
    let components = path
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(value) => {
                Some(value.to_string_lossy().to_ascii_lowercase())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    components.len() >= suffix.len()
        && components[components.len() - suffix.len()..]
            .iter()
            .zip(suffix)
            .all(|(component, expected)| component.as_str() == *expected)
}

fn is_cache_directory(path: &Path) -> bool {
    lowercase_name(path) == ".cache"
}

fn is_generated_directory(path: &Path) -> bool {
    matches!(lowercase_name(path).as_str(), "target" | "build" | "dist")
}

fn category_rank(category: FindingCategory) -> u8 {
    match category {
        FindingCategory::LargeItem => 0,
        FindingCategory::VirtualMachine => 1,
        FindingCategory::AndroidEmulator => 2,
        FindingCategory::IsoImage => 3,
        FindingCategory::OldArchive => 4,
        FindingCategory::OldInstaller => 5,
        FindingCategory::NodeModules => 6,
        FindingCategory::RustBuildArtifacts => 7,
        FindingCategory::GradleCache => 8,
        FindingCategory::OperatingSystemCache => 9,
        FindingCategory::GeneratedDirectory => 10,
        FindingCategory::CacheDirectory => 11,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spacemind_core::ScanWarning;
    use std::path::PathBuf;

    fn scan_with(item: ScannedItem) -> ScanResult {
        ScanResult {
            root: PathBuf::from("/test"),
            started_at_epoch_seconds: 0,
            completed_at_epoch_seconds: 0,
            total_size_bytes: item.size_bytes,
            total_allocated_size_bytes: None,
            file_count: u64::from(item.kind == ItemKind::File),
            directory_count: u64::from(item.kind == ItemKind::Directory),
            items: vec![item],
            ignored_paths: Vec::new(),
            warnings: Vec::<ScanWarning>::new(),
        }
    }

    fn test_item(path: &str, kind: ItemKind, size_bytes: u64) -> ScannedItem {
        ScannedItem {
            path: PathBuf::from(path),
            kind,
            size_bytes,
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

    fn scan_with_items(root: &str, items: Vec<ScannedItem>) -> ScanResult {
        ScanResult {
            root: PathBuf::from(root),
            started_at_epoch_seconds: 0,
            completed_at_epoch_seconds: 0,
            total_size_bytes: items.iter().map(|item| item.size_bytes).sum(),
            total_allocated_size_bytes: None,
            file_count: items
                .iter()
                .filter(|item| item.kind == ItemKind::File)
                .count() as u64,
            directory_count: items
                .iter()
                .filter(|item| item.kind == ItemKind::Directory)
                .count() as u64,
            items,
            ignored_paths: Vec::new(),
            warnings: Vec::new(),
        }
    }

    #[test]
    fn recognizes_an_old_installer() {
        let item = ScannedItem {
            path: PathBuf::from("/test/android-studio.deb"),
            kind: ItemKind::File,
            size_bytes: 500,
            allocated_size_bytes: None,
            file_identity: None,
            hard_link_count: None,
            created_at_epoch_seconds: None,
            modified_at_epoch_seconds: Some(100 * DAY_SECONDS),
            modified_at_epoch_nanoseconds: None,
            accessed_at_epoch_seconds: None,
            extension: Some("deb".into()),
        };
        let options = RuleOptions {
            large_item_threshold_bytes: 1_000,
            old_item_threshold_days: 180,
            now_epoch_seconds: 300 * DAY_SECONDS,
            ..RuleOptions::default()
        };

        let findings = evaluate(&scan_with(item), &options);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, FindingCategory::OldInstaller);
    }

    #[test]
    fn recognizes_node_modules_directories() {
        let item = ScannedItem {
            path: PathBuf::from("/test/node_modules"),
            kind: ItemKind::Directory,
            size_bytes: 500,
            allocated_size_bytes: None,
            file_identity: None,
            hard_link_count: None,
            created_at_epoch_seconds: None,
            modified_at_epoch_seconds: None,
            modified_at_epoch_nanoseconds: None,
            accessed_at_epoch_seconds: None,
            extension: None,
        };
        let options = RuleOptions {
            large_item_threshold_bytes: 1_000,
            ..RuleOptions::default()
        };

        let findings = evaluate(&scan_with(item), &options);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, FindingCategory::NodeModules);
    }

    #[test]
    fn recognizes_rust_target_beside_a_cargo_manifest() {
        let manifest = test_item("/test/project/Cargo.toml", ItemKind::File, 50);
        let target = test_item("/test/project/target", ItemKind::Directory, 500);
        let scan = scan_with_items("/test", vec![manifest, target]);
        let options = RuleOptions {
            large_item_threshold_bytes: 1_000,
            ..RuleOptions::default()
        };

        let findings = evaluate(&scan, &options);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, FindingCategory::RustBuildArtifacts);
        assert_eq!(findings[0].risk, RiskLevel::Low);
    }

    #[test]
    fn recognizes_gradle_cache_locations() {
        let cache = test_item("/test/.gradle/caches", ItemKind::Directory, 500);
        let findings = evaluate(
            &scan_with(cache),
            &RuleOptions {
                large_item_threshold_bytes: 1_000,
                ..RuleOptions::default()
            },
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, FindingCategory::GradleCache);
        assert_eq!(findings[0].risk, RiskLevel::Low);
    }

    #[test]
    fn treats_android_emulators_as_high_risk_state() {
        let emulator = test_item(
            "/test/.android/avd/pixel_8.avd",
            ItemKind::Directory,
            500,
        );
        let findings = evaluate(
            &scan_with(emulator),
            &RuleOptions {
                large_item_threshold_bytes: 1_000,
                ..RuleOptions::default()
            },
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, FindingCategory::AndroidEmulator);
        assert_eq!(findings[0].risk, RiskLevel::High);
        assert_eq!(findings[0].suggested_action, SuggestedAction::ReviewForArchive);
    }

    #[test]
    fn reports_one_high_risk_finding_for_a_virtual_machine_bundle() {
        let directory = test_item("/test/Kali", ItemKind::Directory, 1_000);
        let config = test_item("/test/Kali/Kali.vbox", ItemKind::File, 50);
        let disk = test_item("/test/Kali/Kali.vdi", ItemKind::File, 900);
        let scan = scan_with_items("/test", vec![directory, config, disk]);
        let findings = evaluate(
            &scan,
            &RuleOptions {
                large_item_threshold_bytes: 2_000,
                ..RuleOptions::default()
            },
        );
        let virtual_machines = findings
            .iter()
            .filter(|finding| finding.category == FindingCategory::VirtualMachine)
            .collect::<Vec<_>>();

        assert_eq!(virtual_machines.len(), 1);
        assert_eq!(virtual_machines[0].path, PathBuf::from("/test/Kali"));
        assert_eq!(virtual_machines[0].risk, RiskLevel::High);
        assert_eq!(
            virtual_machines[0].suggested_action,
            SuggestedAction::ReviewForArchive
        );
    }

    #[test]
    fn recognizes_old_iso_images_separately_from_installers() {
        let mut iso = test_item("/test/linux.iso", ItemKind::File, 500);
        iso.modified_at_epoch_seconds = Some(100 * DAY_SECONDS);
        let options = RuleOptions {
            large_item_threshold_bytes: 1_000,
            old_item_threshold_days: 180,
            now_epoch_seconds: 300 * DAY_SECONDS,
            ..RuleOptions::default()
        };

        let findings = evaluate(&scan_with(iso), &options);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, FindingCategory::IsoImage);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn recognizes_linux_system_cache() {
        let cache = test_item("/var/cache", ItemKind::Directory, 500);
        let scan = scan_with_items("/", vec![cache]);
        let findings = evaluate(
            &scan,
            &RuleOptions {
                large_item_threshold_bytes: 1_000,
                ..RuleOptions::default()
            },
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].category,
            FindingCategory::OperatingSystemCache
        );
        assert_eq!(findings[0].risk, RiskLevel::Medium);
    }

    #[test]
    fn target_without_cargo_context_stays_generic() {
        let target = test_item("/test/download/target", ItemKind::Directory, 500);
        let findings = evaluate(
            &scan_with(target),
            &RuleOptions {
                large_item_threshold_bytes: 1_000,
                ..RuleOptions::default()
            },
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, FindingCategory::GeneratedDirectory);
    }

    #[test]
    fn recognizes_standalone_virtual_disk_images() {
        let disk = test_item("/test/machine.qcow2", ItemKind::File, 500);
        let findings = evaluate(
            &scan_with(disk),
            &RuleOptions {
                large_item_threshold_bytes: 1_000,
                ..RuleOptions::default()
            },
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, FindingCategory::VirtualMachine);
        assert_eq!(findings[0].risk, RiskLevel::High);
    }

    #[test]
    fn installers_and_archives_support_additional_common_formats() {
        let mut installer = test_item("/test/application.msixbundle", ItemKind::File, 500);
        let mut archive = test_item("/test/backup.tar.zst", ItemKind::File, 500);
        installer.modified_at_epoch_seconds = Some(100 * DAY_SECONDS);
        archive.modified_at_epoch_seconds = Some(100 * DAY_SECONDS);
        let findings = evaluate(
            &scan_with_items("/test", vec![installer, archive]),
            &RuleOptions {
                large_item_threshold_bytes: 1_000,
                old_item_threshold_days: 180,
                now_epoch_seconds: 300 * DAY_SECONDS,
                ..RuleOptions::default()
            },
        );
        let categories = findings
            .iter()
            .map(|finding| finding.category)
            .collect::<Vec<_>>();

        assert!(categories.contains(&FindingCategory::OldInstaller));
        assert!(categories.contains(&FindingCategory::OldArchive));
    }

    #[test]
    fn recent_iso_images_are_not_cleanup_candidates() {
        let mut iso = test_item("/test/recent.iso", ItemKind::File, 500);
        iso.modified_at_epoch_seconds = Some(290 * DAY_SECONDS);
        let findings = evaluate(
            &scan_with(iso),
            &RuleOptions {
                large_item_threshold_bytes: 1_000,
                old_item_threshold_days: 180,
                now_epoch_seconds: 300 * DAY_SECONDS,
                ..RuleOptions::default()
            },
        );

        assert!(findings.is_empty());
    }

    #[test]
    fn reports_recommendation_progress() {
        let item = ScannedItem {
            path: PathBuf::from("/test/archive.zip"),
            kind: ItemKind::File,
            size_bytes: 500,
            allocated_size_bytes: None,
            file_identity: None,
            hard_link_count: None,
            created_at_epoch_seconds: None,
            modified_at_epoch_seconds: None,
            modified_at_epoch_nanoseconds: None,
            accessed_at_epoch_seconds: None,
            extension: Some("zip".into()),
        };
        let scan = scan_with(item);
        let cancellation = CancellationToken::new();
        let mut events = Vec::new();

        evaluate_with_progress(&scan, &RuleOptions::default(), &cancellation, |event| {
            events.push(event.clone())
        })
        .unwrap();

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].items_processed, 0);
        assert_eq!(events[0].total_items, Some(1));
        assert_eq!(events[1].items_processed, 1);
        assert_eq!(events[1].phase, AnalysisPhase::BuildingRecommendations);
    }

    #[test]
    fn protected_items_are_counted_but_never_recommended() {
        let item = ScannedItem {
            path: PathBuf::from("/test/Documents/archive.zip"),
            kind: ItemKind::File,
            size_bytes: 500,
            allocated_size_bytes: None,
            file_identity: None,
            hard_link_count: None,
            created_at_epoch_seconds: None,
            modified_at_epoch_seconds: Some(100 * DAY_SECONDS),
            modified_at_epoch_nanoseconds: None,
            accessed_at_epoch_seconds: None,
            extension: Some("zip".into()),
        };
        let scan = scan_with(item);
        let options = RuleOptions {
            large_item_threshold_bytes: 100,
            old_item_threshold_days: 180,
            now_epoch_seconds: 300 * DAY_SECONDS,
            protected_rules: vec![PathRule::Exact(PathBuf::from("/test/Documents"))],
        };
        let cancellation = CancellationToken::new();

        let evaluation =
            evaluate_with_policy_progress(&scan, &options, &cancellation, |_| {}).unwrap();

        assert!(evaluation.findings.is_empty());
        assert_eq!(evaluation.protected_items, 1);
        assert_eq!(evaluation.suppressed_findings, 2);
    }

    #[test]
    fn cancellation_stops_recommendation_building() {
        let item = ScannedItem {
            path: PathBuf::from("/test/archive.zip"),
            kind: ItemKind::File,
            size_bytes: 500,
            allocated_size_bytes: None,
            file_identity: None,
            hard_link_count: None,
            created_at_epoch_seconds: None,
            modified_at_epoch_seconds: None,
            modified_at_epoch_nanoseconds: None,
            accessed_at_epoch_seconds: None,
            extension: Some("zip".into()),
        };
        let scan = scan_with(item);
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        assert!(matches!(
            evaluate_with_progress(&scan, &RuleOptions::default(), &cancellation, |_| {}),
            Err(RuleError::Cancelled { items_processed: 0 })
        ));
    }
}
