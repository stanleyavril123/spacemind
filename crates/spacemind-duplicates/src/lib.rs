use blake3::Hasher;
use spacemind_core::{
    DuplicateEntry, DuplicateGroup, DuplicateReport, DuplicateWarning, DuplicateWarningKind,
    FileIdentity, ItemKind, ScanResult, ScannedItem,
};
use std::collections::BTreeMap;
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const HASH_BUFFER_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct DuplicateOptions {
    pub minimum_size_bytes: u64,
}

impl Default for DuplicateOptions {
    fn default() -> Self {
        Self {
            minimum_size_bytes: 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum PhysicalKey {
    Known(FileIdentity),
    Unknown(PathBuf),
}

struct PhysicalCandidate<'a> {
    representative: &'a ScannedItem,
    entries: Vec<&'a ScannedItem>,
}

pub fn detect_duplicates(scan: &ScanResult, options: &DuplicateOptions) -> DuplicateReport {
    detect_duplicates_with_hook(scan, options, |_| {})
}

fn detect_duplicates_with_hook<F>(
    scan: &ScanResult,
    options: &DuplicateOptions,
    mut before_hash: F,
) -> DuplicateReport
where
    F: FnMut(&Path),
{
    let mut candidates_by_size: BTreeMap<u64, Vec<&ScannedItem>> = BTreeMap::new();
    for item in &scan.items {
        if item.kind == ItemKind::File
            && item.size_bytes > 0
            && item.size_bytes >= options.minimum_size_bytes
        {
            candidates_by_size
                .entry(item.size_bytes)
                .or_default()
                .push(item);
        }
    }

    let mut groups = Vec::new();
    let mut warnings = Vec::new();
    let mut files_hashed = 0_u64;
    let mut bytes_hashed = 0_u64;

    for (size_bytes, same_size_items) in candidates_by_size {
        let physical_candidates = collapse_hard_links(same_size_items);
        if physical_candidates.len() < 2 {
            continue;
        }

        let mut candidates_by_hash: BTreeMap<String, Vec<PhysicalCandidate<'_>>> =
            BTreeMap::new();
        for candidate in physical_candidates.into_values() {
            before_hash(&candidate.representative.path);
            match hash_scanned_file(candidate.representative) {
                Ok(hash) => {
                    files_hashed = files_hashed.saturating_add(1);
                    bytes_hashed = bytes_hashed.saturating_add(size_bytes);
                    candidates_by_hash.entry(hash).or_default().push(candidate);
                }
                Err(warning) => warnings.push(warning),
            }
        }

        for (hash, matching_candidates) in candidates_by_hash {
            if matching_candidates.len() >= 2 {
                groups.push(build_group(hash, size_bytes, matching_candidates));
            }
        }
    }

    groups.sort_by(|left, right| {
        right
            .potential_recovery_bytes
            .cmp(&left.potential_recovery_bytes)
            .then_with(|| right.size_bytes_per_file.cmp(&left.size_bytes_per_file))
            .then_with(|| first_path(left).cmp(first_path(right)))
    });
    warnings.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.message.cmp(&right.message))
    });
    let potential_recovery_bytes = groups.iter().fold(0_u64, |total, group| {
        total.saturating_add(group.potential_recovery_bytes)
    });

    DuplicateReport {
        groups,
        warnings,
        files_hashed,
        bytes_hashed,
        potential_recovery_bytes,
    }
}

fn collapse_hard_links(
    items: Vec<&ScannedItem>,
) -> BTreeMap<PhysicalKey, PhysicalCandidate<'_>> {
    let mut physical = BTreeMap::new();
    for item in items {
        let key = item
            .file_identity
            .map(PhysicalKey::Known)
            .unwrap_or_else(|| PhysicalKey::Unknown(item.path.clone()));
        physical
            .entry(key)
            .and_modify(|candidate: &mut PhysicalCandidate<'_>| candidate.entries.push(item))
            .or_insert_with(|| PhysicalCandidate {
                representative: item,
                entries: vec![item],
            });
    }
    physical
}

fn build_group(
    hash: String,
    size_bytes: u64,
    candidates: Vec<PhysicalCandidate<'_>>,
) -> DuplicateGroup {
    let unique_file_count = candidates.len() as u64;
    let mut physical_allocations = Vec::with_capacity(candidates.len());
    let mut entries = Vec::new();

    for candidate in candidates {
        physical_allocations.push(
            candidate
                .representative
                .allocated_size_bytes
                .unwrap_or(size_bytes),
        );
        entries.extend(candidate.entries.into_iter().map(|item| DuplicateEntry {
            path: item.path.clone(),
            file_identity: item.file_identity,
            allocated_size_bytes: item.allocated_size_bytes,
            hard_link_count: item.hard_link_count,
        }));
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));

    let total_allocated = physical_allocations
        .iter()
        .fold(0_u64, |total, size| total.saturating_add(*size));
    let retained_copy = physical_allocations.into_iter().max().unwrap_or(0);

    DuplicateGroup {
        blake3_hash: hash,
        size_bytes_per_file: size_bytes,
        entries,
        unique_file_count,
        potential_recovery_bytes: total_allocated.saturating_sub(retained_copy),
    }
}

fn hash_scanned_file(item: &ScannedItem) -> Result<String, DuplicateWarning> {
    let path = &item.path;
    let path_before = fs::symlink_metadata(path).map_err(|error| DuplicateWarning {
        path: path.clone(),
        kind: DuplicateWarningKind::MetadataUnavailable,
        message: format!("cannot read metadata before hashing: {error}"),
    })?;

    if !path_before.file_type().is_file() {
        return Err(DuplicateWarning {
            path: path.clone(),
            kind: DuplicateWarningKind::NotRegularFile,
            message: "item is no longer a regular file".to_owned(),
        });
    }
    validate_scan_snapshot(item, &path_before)?;

    let mut file = File::open(path).map_err(|error| DuplicateWarning {
        path: path.clone(),
        kind: DuplicateWarningKind::Unreadable,
        message: format!("cannot open file for hashing: {error}"),
    })?;
    let opened_before = file.metadata().map_err(|error| DuplicateWarning {
        path: path.clone(),
        kind: DuplicateWarningKind::MetadataUnavailable,
        message: format!("cannot read opened-file metadata: {error}"),
    })?;
    if !same_snapshot(&path_before, &opened_before) {
        return Err(changed_warning(
            path,
            "file changed between metadata inspection and opening",
        ));
    }

    let mut hasher = Hasher::new();
    let mut buffer = [0_u8; HASH_BUFFER_BYTES];
    let mut bytes_read = 0_u64;
    loop {
        let count = file.read(&mut buffer).map_err(|error| DuplicateWarning {
            path: path.clone(),
            kind: DuplicateWarningKind::Unreadable,
            message: format!("failed while hashing file: {error}"),
        })?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        bytes_read = bytes_read.saturating_add(count as u64);
    }

    let opened_after = file.metadata().map_err(|error| DuplicateWarning {
        path: path.clone(),
        kind: DuplicateWarningKind::MetadataUnavailable,
        message: format!("cannot verify opened file after hashing: {error}"),
    })?;
    let path_after = fs::symlink_metadata(path).map_err(|error| {
        changed_warning(path, &format!("file path disappeared after hashing: {error}"))
    })?;

    if bytes_read != path_before.len()
        || !same_snapshot(&path_before, &opened_after)
        || !same_snapshot(&opened_after, &path_after)
    {
        return Err(changed_warning(path, "file changed while it was being hashed"));
    }

    Ok(hasher.finalize().to_hex().to_string())
}

fn validate_scan_snapshot(item: &ScannedItem, metadata: &Metadata) -> Result<(), DuplicateWarning> {
    let current_identity = file_identity(metadata);
    let current_modified = metadata.modified().ok().and_then(epoch_nanoseconds);
    let identity_changed = item
        .file_identity
        .map(|expected| current_identity != Some(expected))
        .unwrap_or(false);
    let modified_changed = item
        .modified_at_epoch_nanoseconds
        .map(|expected| current_modified != Some(expected))
        .unwrap_or(false);

    if metadata.len() != item.size_bytes || identity_changed || modified_changed {
        return Err(changed_warning(
            &item.path,
            "file changed after scanning and before duplicate detection",
        ));
    }
    Ok(())
}

fn same_snapshot(left: &Metadata, right: &Metadata) -> bool {
    left.len() == right.len()
        && left.modified().ok() == right.modified().ok()
        && match (file_identity(left), file_identity(right)) {
            (Some(left), Some(right)) => left == right,
            _ => true,
        }
}

fn changed_warning(path: &Path, message: &str) -> DuplicateWarning {
    DuplicateWarning {
        path: path.to_path_buf(),
        kind: DuplicateWarningKind::ChangedDuringDetection,
        message: message.to_owned(),
    }
}

fn first_path(group: &DuplicateGroup) -> &Path {
    group
        .entries
        .first()
        .map(|entry| entry.path.as_path())
        .unwrap_or_else(|| Path::new(""))
}

fn epoch_nanoseconds(time: SystemTime) -> Option<u64> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|value| u64::try_from(value.as_nanos()).ok())
}

#[cfg(unix)]
fn file_identity(metadata: &Metadata) -> Option<FileIdentity> {
    use std::os::unix::fs::MetadataExt;

    Some(FileIdentity {
        volume_id: metadata.dev(),
        file_id: metadata.ino(),
    })
}

#[cfg(windows)]
fn file_identity(metadata: &Metadata) -> Option<FileIdentity> {
    use std::os::windows::fs::MetadataExt;

    Some(FileIdentity {
        volume_id: u64::from(metadata.volume_serial_number()?),
        file_id: metadata.file_index()?,
    })
}

#[cfg(not(any(unix, windows)))]
fn file_identity(_metadata: &Metadata) -> Option<FileIdentity> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use spacemind_scanner::{scan, ScanOptions};
    use std::time::Duration;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(name: &str) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "spacemind-duplicates-{name}-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn scan(&self) -> ScanResult {
            scan(&ScanOptions::new(&self.0)).unwrap()
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn finds_identical_files_and_reports_recovery() {
        let directory = TestDirectory::new("identical");
        let content = vec![3_u8; 8192];
        fs::write(directory.0.join("a.bin"), &content).unwrap();
        fs::write(directory.0.join("b.bin"), &content).unwrap();

        let report = detect_duplicates(&directory.scan(), &DuplicateOptions::default());

        assert_eq!(report.groups.len(), 1);
        assert_eq!(report.groups[0].entries.len(), 2);
        assert_eq!(report.groups[0].unique_file_count, 2);
        assert!(report.groups[0].potential_recovery_bytes > 0);
        assert_eq!(
            report.potential_recovery_bytes,
            report.groups[0].potential_recovery_bytes
        );
    }

    #[test]
    fn rejects_same_sized_files_with_different_content() {
        let directory = TestDirectory::new("different-content");
        fs::write(directory.0.join("a.bin"), [1_u8; 64]).unwrap();
        fs::write(directory.0.join("b.bin"), [2_u8; 64]).unwrap();

        let report = detect_duplicates(&directory.scan(), &DuplicateOptions::default());

        assert!(report.groups.is_empty());
        assert_eq!(report.files_hashed, 2);
    }

    #[test]
    fn skips_different_sizes_before_hashing() {
        let directory = TestDirectory::new("different-sizes");
        fs::write(directory.0.join("a.bin"), [1_u8; 63]).unwrap();
        fs::write(directory.0.join("b.bin"), [1_u8; 64]).unwrap();

        let report = detect_duplicates(&directory.scan(), &DuplicateOptions::default());

        assert!(report.groups.is_empty());
        assert_eq!(report.files_hashed, 0);
    }

    #[test]
    fn calculates_recovery_for_three_copies() {
        let directory = TestDirectory::new("three-copies");
        for name in ["a.bin", "b.bin", "c.bin"] {
            fs::write(directory.0.join(name), vec![9_u8; 4096]).unwrap();
        }

        let report = detect_duplicates(&directory.scan(), &DuplicateOptions::default());
        let group = &report.groups[0];
        let one_allocation = group.entries[0]
            .allocated_size_bytes
            .unwrap_or(group.size_bytes_per_file);

        assert_eq!(group.unique_file_count, 3);
        assert_eq!(group.potential_recovery_bytes, one_allocation * 2);
    }

    #[test]
    fn ignores_empty_files() {
        let directory = TestDirectory::new("empty");
        fs::write(directory.0.join("a.bin"), []).unwrap();
        fs::write(directory.0.join("b.bin"), []).unwrap();

        let report = detect_duplicates(&directory.scan(), &DuplicateOptions::default());

        assert!(report.groups.is_empty());
        assert_eq!(report.files_hashed, 0);
    }

    #[cfg(unix)]
    #[test]
    fn hard_links_alone_are_not_reported_as_recoverable_duplicates() {
        let directory = TestDirectory::new("hard-links-only");
        let original = directory.0.join("original.bin");
        let alias = directory.0.join("alias.bin");
        fs::write(&original, vec![4_u8; 4096]).unwrap();
        fs::hard_link(&original, &alias).unwrap();

        let report = detect_duplicates(&directory.scan(), &DuplicateOptions::default());

        assert!(report.groups.is_empty());
        assert_eq!(report.files_hashed, 0);
        assert_eq!(report.potential_recovery_bytes, 0);
    }

    #[cfg(unix)]
    #[test]
    fn hard_link_aliases_do_not_inflate_recovery() {
        let directory = TestDirectory::new("hard-links");
        let original = directory.0.join("original.bin");
        let alias = directory.0.join("alias.bin");
        let copy = directory.0.join("copy.bin");
        fs::write(&original, vec![4_u8; 4096]).unwrap();
        fs::hard_link(&original, &alias).unwrap();
        fs::copy(&original, &copy).unwrap();

        let report = detect_duplicates(&directory.scan(), &DuplicateOptions::default());
        let group = &report.groups[0];
        let one_allocation = group.entries[0]
            .allocated_size_bytes
            .unwrap_or(group.size_bytes_per_file);

        assert_eq!(group.entries.len(), 3);
        assert_eq!(group.unique_file_count, 2);
        assert_eq!(group.potential_recovery_bytes, one_allocation);
        assert_eq!(report.files_hashed, 2);
    }

    #[test]
    fn warns_when_file_changes_after_scan() {
        let directory = TestDirectory::new("changed");
        let changed = directory.0.join("a.bin");
        fs::write(&changed, [1_u8; 64]).unwrap();
        fs::write(directory.0.join("b.bin"), [1_u8; 64]).unwrap();
        let scan = directory.scan();

        let report = detect_duplicates_with_hook(
            &scan,
            &DuplicateOptions::default(),
            |path| {
                if path == changed {
                    fs::write(path, [2_u8; 65]).unwrap();
                }
            },
        );

        assert!(report.groups.is_empty());
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.kind == DuplicateWarningKind::ChangedDuringDetection));
    }

    #[cfg(unix)]
    #[test]
    fn warns_when_candidate_is_unreadable() {
        use std::os::unix::fs::PermissionsExt;

        let directory = TestDirectory::new("unreadable");
        let unreadable = directory.0.join("a.bin");
        fs::write(&unreadable, [1_u8; 64]).unwrap();
        fs::write(directory.0.join("b.bin"), [1_u8; 64]).unwrap();
        let scan = directory.scan();
        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o000)).unwrap();

        if File::open(&unreadable).is_ok() {
            fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o600)).unwrap();
            return;
        }
        let report = detect_duplicates(&scan, &DuplicateOptions::default());
        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o600)).unwrap();

        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.kind == DuplicateWarningKind::Unreadable));
    }
}
