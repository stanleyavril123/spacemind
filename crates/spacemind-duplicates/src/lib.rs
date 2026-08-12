use blake3::Hasher;
use spacemind_core::{
    AnalysisPhase, CancellationToken, DuplicateEntry, DuplicateGroup, DuplicateReport,
    DuplicateWarning, DuplicateWarningKind, FileIdentity, ItemKind, ProgressEvent, ScanResult,
    ScannedItem,
};
use std::collections::BTreeMap;
use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const HASH_BUFFER_BYTES: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum DuplicateError {
    #[error(
        "duplicate detection cancelled after processing {items_processed} files and {bytes_processed} bytes"
    )]
    Cancelled {
        items_processed: u64,
        bytes_processed: u64,
    },
}

enum HashFileError {
    Warning(DuplicateWarning),
    Cancelled,
}

impl From<DuplicateWarning> for HashFileError {
    fn from(warning: DuplicateWarning) -> Self {
        Self::Warning(warning)
    }
}

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
    let cancellation = CancellationToken::new();
    detect_duplicates_with_progress(scan, options, &cancellation, |_| {})
        .expect("a fresh cancellation token cannot be cancelled")
}

pub fn detect_duplicates_with_progress<F>(
    scan: &ScanResult,
    options: &DuplicateOptions,
    cancellation: &CancellationToken,
    mut on_progress: F,
) -> Result<DuplicateReport, DuplicateError>
where
    F: FnMut(&ProgressEvent),
{
    detect_duplicates_internal(
        scan,
        options,
        cancellation,
        &mut on_progress,
        &mut |_| {},
        &mut |_| {},
    )
}

#[cfg(test)]
fn detect_duplicates_with_hook<F>(
    scan: &ScanResult,
    options: &DuplicateOptions,
    before_validation: F,
) -> DuplicateReport
where
    F: FnMut(&Path),
{
    detect_duplicates_with_hooks(scan, options, before_validation, |_| {})
}

#[cfg(test)]
fn detect_duplicates_with_hooks<F, G>(
    scan: &ScanResult,
    options: &DuplicateOptions,
    mut before_validation: F,
    mut after_hash: G,
) -> DuplicateReport
where
    F: FnMut(&Path),
    G: FnMut(&Path),
{
    let cancellation = CancellationToken::new();
    detect_duplicates_internal(
        scan,
        options,
        &cancellation,
        &mut |_| {},
        &mut before_validation,
        &mut after_hash,
    )
    .expect("test hook did not cancel duplicate detection")
}

fn detect_duplicates_internal<F, B, A>(
    scan: &ScanResult,
    options: &DuplicateOptions,
    cancellation: &CancellationToken,
    on_progress: &mut F,
    before_validation: &mut B,
    after_hash: &mut A,
) -> Result<DuplicateReport, DuplicateError>
where
    F: FnMut(&ProgressEvent),
    B: FnMut(&Path),
    A: FnMut(&Path),
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

    let mut candidate_groups = Vec::new();
    let mut total_items = 0_u64;
    let mut total_bytes = 0_u64;
    for (size_bytes, same_size_items) in candidates_by_size {
        let physical_candidates = collapse_hard_links(same_size_items);
        if physical_candidates.len() < 2 {
            continue;
        }
        let candidate_count = physical_candidates.len() as u64;
        total_items = total_items.saturating_add(candidate_count);
        total_bytes = total_bytes.saturating_add(size_bytes.saturating_mul(candidate_count));
        candidate_groups.push((size_bytes, physical_candidates));
    }

    let mut groups = Vec::new();
    let mut warnings = Vec::new();
    let mut files_hashed = 0_u64;
    let mut bytes_hashed = 0_u64;
    let mut items_processed = 0_u64;
    let mut bytes_processed = 0_u64;

    on_progress(&ProgressEvent {
        phase: AnalysisPhase::HashingDuplicates,
        items_processed,
        bytes_processed,
        total_items: Some(total_items),
        total_bytes: Some(total_bytes),
        current_path: None,
    });
    check_cancelled(cancellation, items_processed, bytes_processed)?;

    for (size_bytes, physical_candidates) in candidate_groups {
        let mut candidates_by_hash: BTreeMap<String, Vec<PhysicalCandidate<'_>>> =
            BTreeMap::new();
        for candidate in physical_candidates.into_values() {
            check_cancelled(cancellation, items_processed, bytes_processed)?;
            let candidate_path = candidate.representative.path.clone();
            for entry in &candidate.entries {
                before_validation(&entry.path);
            }
            let Some(candidate) = revalidate_candidate(candidate, &mut warnings) else {
                items_processed = items_processed.saturating_add(1);
                report_duplicate_progress(
                    on_progress,
                    items_processed,
                    bytes_processed,
                    total_items,
                    total_bytes,
                    Some(candidate_path),
                );
                continue;
            };
            let hash_result = hash_scanned_file_with_progress(
                candidate.representative,
                cancellation,
                |bytes| {
                    bytes_processed = bytes_processed.saturating_add(bytes);
                    report_duplicate_progress(
                        on_progress,
                        items_processed,
                        bytes_processed,
                        total_items,
                        total_bytes,
                        Some(candidate_path.clone()),
                    );
                },
            );
            match hash_result {
                Ok(hash) => {
                    files_hashed = files_hashed.saturating_add(1);
                    bytes_hashed = bytes_hashed.saturating_add(size_bytes);
                    after_hash(&candidate.representative.path);
                    let Some(candidate) = revalidate_candidate(candidate, &mut warnings) else {
                        items_processed = items_processed.saturating_add(1);
                        report_duplicate_progress(
                            on_progress,
                            items_processed,
                            bytes_processed,
                            total_items,
                            total_bytes,
                            Some(candidate_path),
                        );
                        continue;
                    };
                    candidates_by_hash.entry(hash).or_default().push(candidate);
                }
                Err(HashFileError::Warning(warning)) => warnings.push(warning),
                Err(HashFileError::Cancelled) => {
                    return Err(DuplicateError::Cancelled {
                        items_processed,
                        bytes_processed,
                    });
                }
            }
            items_processed = items_processed.saturating_add(1);
            report_duplicate_progress(
                on_progress,
                items_processed,
                bytes_processed,
                total_items,
                total_bytes,
                Some(candidate_path),
            );
        }

        for (hash, matching_candidates) in candidates_by_hash {
            if matching_candidates.len() >= 2 {
                groups.push(build_group(hash, size_bytes, matching_candidates));
            }
        }
    }

    groups.sort_by(|left, right| {
        right
            .logical_duplicate_bytes
            .cmp(&left.logical_duplicate_bytes)
            .then_with(|| right.size_bytes_per_file.cmp(&left.size_bytes_per_file))
            .then_with(|| first_path(left).cmp(first_path(right)))
    });
    warnings.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.message.cmp(&right.message))
    });
    let logical_duplicate_bytes = groups.iter().fold(0_u64, |total, group| {
        total.saturating_add(group.logical_duplicate_bytes)
    });
    let potential_recovery_allocated_bytes = groups.iter().try_fold(0_u64, |total, group| {
        group
            .potential_recovery_allocated_bytes
            .map(|recovery| total.saturating_add(recovery))
    });

    let report = DuplicateReport {
        groups,
        warnings,
        files_hashed,
        bytes_hashed,
        logical_duplicate_bytes,
        potential_recovery_allocated_bytes,
    };

    report_duplicate_progress(
        on_progress,
        items_processed,
        bytes_processed,
        total_items,
        total_bytes,
        None,
    );
    Ok(report)
}

fn check_cancelled(
    cancellation: &CancellationToken,
    items_processed: u64,
    bytes_processed: u64,
) -> Result<(), DuplicateError> {
    if cancellation.is_cancelled() {
        Err(DuplicateError::Cancelled {
            items_processed,
            bytes_processed,
        })
    } else {
        Ok(())
    }
}

fn report_duplicate_progress<F>(
    on_progress: &mut F,
    items_processed: u64,
    bytes_processed: u64,
    total_items: u64,
    total_bytes: u64,
    current_path: Option<PathBuf>,
) where
    F: FnMut(&ProgressEvent),
{
    on_progress(&ProgressEvent {
        phase: AnalysisPhase::HashingDuplicates,
        items_processed,
        bytes_processed,
        total_items: Some(total_items),
        total_bytes: Some(total_bytes),
        current_path,
    });
}

fn revalidate_candidate<'a>(
    candidate: PhysicalCandidate<'a>,
    warnings: &mut Vec<DuplicateWarning>,
) -> Option<PhysicalCandidate<'a>> {
    let mut valid_entries = Vec::with_capacity(candidate.entries.len());
    for entry in candidate.entries {
        match validate_path_snapshot(entry) {
            Ok(()) => valid_entries.push(entry),
            Err(warning) => warnings.push(warning),
        }
    }

    let representative = valid_entries.first().copied()?;
    Some(PhysicalCandidate {
        representative,
        entries: valid_entries,
    })
}

fn validate_path_snapshot(item: &ScannedItem) -> Result<(), DuplicateWarning> {
    let metadata = fs::symlink_metadata(&item.path).map_err(|error| DuplicateWarning {
        path: item.path.clone(),
        kind: DuplicateWarningKind::MetadataUnavailable,
        message: format!("cannot revalidate duplicate candidate: {error}"),
    })?;
    if !metadata.file_type().is_file() {
        return Err(DuplicateWarning {
            path: item.path.clone(),
            kind: DuplicateWarningKind::NotRegularFile,
            message: "item is no longer a regular file".to_owned(),
        });
    }
    validate_scan_snapshot(item, &metadata)
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
    let physical_allocations: Option<Vec<u64>> = candidates
        .iter()
        .map(|candidate| candidate.representative.allocated_size_bytes)
        .collect();
    let mut entries = Vec::new();

    for candidate in candidates {
        entries.extend(candidate.entries.into_iter().map(|item| DuplicateEntry {
            path: item.path.clone(),
            file_identity: item.file_identity,
            allocated_size_bytes: item.allocated_size_bytes,
            hard_link_count: item.hard_link_count,
        }));
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));

    let logical_duplicate_bytes = size_bytes.saturating_mul(unique_file_count.saturating_sub(1));
    let potential_recovery_allocated_bytes = physical_allocations.map(|allocations| {
        let total_allocated = allocations
            .iter()
            .fold(0_u64, |total, size| total.saturating_add(*size));
        let retained_copy = allocations.into_iter().max().unwrap_or(0);
        total_allocated.saturating_sub(retained_copy)
    });

    DuplicateGroup {
        blake3_hash: hash,
        size_bytes_per_file: size_bytes,
        entries,
        unique_file_count,
        logical_duplicate_bytes,
        potential_recovery_allocated_bytes,
    }
}

#[cfg(test)]
fn hash_scanned_file_with_opener<F>(
    item: &ScannedItem,
    open_file: F,
) -> Result<String, DuplicateWarning>
where
    F: FnOnce(&Path) -> io::Result<File>,
{
    let cancellation = CancellationToken::new();
    match hash_scanned_file_internal(item, open_file, &cancellation, |_| {}) {
        Ok(hash) => Ok(hash),
        Err(HashFileError::Warning(warning)) => Err(warning),
        Err(HashFileError::Cancelled) => unreachable!("a fresh token cannot be cancelled"),
    }
}

fn hash_scanned_file_with_progress<F>(
    item: &ScannedItem,
    cancellation: &CancellationToken,
    on_bytes: F,
) -> Result<String, HashFileError>
where
    F: FnMut(u64),
{
    hash_scanned_file_internal(item, |path| File::open(path), cancellation, on_bytes)
}

fn hash_scanned_file_internal<O, P>(
    item: &ScannedItem,
    open_file: O,
    cancellation: &CancellationToken,
    mut on_bytes: P,
) -> Result<String, HashFileError>
where
    O: FnOnce(&Path) -> io::Result<File>,
    P: FnMut(u64),
{
    if cancellation.is_cancelled() {
        return Err(HashFileError::Cancelled);
    }
    let path = &item.path;
    let path_before = fs::symlink_metadata(path).map_err(|error| DuplicateWarning {
        path: path.clone(),
        kind: DuplicateWarningKind::MetadataUnavailable,
        message: format!("cannot read metadata before hashing: {error}"),
    })?;

    if !path_before.file_type().is_file() {
        return Err(HashFileError::Warning(DuplicateWarning {
            path: path.clone(),
            kind: DuplicateWarningKind::NotRegularFile,
            message: "item is no longer a regular file".to_owned(),
        }));
    }
    validate_scan_snapshot(item, &path_before)?;

    let mut file = open_file(path).map_err(|error| DuplicateWarning {
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
        return Err(HashFileError::Warning(changed_warning(
            path,
            "file changed between metadata inspection and opening",
        )));
    }

    let mut hasher = Hasher::new();
    let mut buffer = [0_u8; HASH_BUFFER_BYTES];
    let mut bytes_read = 0_u64;
    loop {
        if cancellation.is_cancelled() {
            return Err(HashFileError::Cancelled);
        }
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
        on_bytes(count as u64);
    }

    let opened_after = file.metadata().map_err(|error| DuplicateWarning {
        path: path.clone(),
        kind: DuplicateWarningKind::MetadataUnavailable,
        message: format!("cannot verify opened file after hashing: {error}"),
    })?;
    let path_after = fs::symlink_metadata(path).map_err(|error| {
        changed_warning(path, &format!("file path disappeared after hashing: {error}"))
    })?;
    validate_scan_snapshot(item, &path_after)?;

    if bytes_read != path_before.len()
        || !same_snapshot(&path_before, &opened_after)
        || !same_snapshot(&opened_after, &path_after)
    {
        return Err(HashFileError::Warning(changed_warning(
            path,
            "file changed while it was being hashed",
        )));
    }

    Ok(hasher.finalize().to_hex().to_string())
}

fn validate_scan_snapshot(item: &ScannedItem, metadata: &Metadata) -> Result<(), DuplicateWarning> {
    let current_identity = path_file_identity(&item.path, metadata);
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
        && match (metadata_file_identity(left), metadata_file_identity(right)) {
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
fn metadata_file_identity(metadata: &Metadata) -> Option<FileIdentity> {
    use std::os::unix::fs::MetadataExt;

    Some(FileIdentity {
        volume_id: metadata.dev(),
        file_id: metadata.ino(),
    })
}

#[cfg(unix)]
fn path_file_identity(_path: &Path, metadata: &Metadata) -> Option<FileIdentity> {
    metadata_file_identity(metadata)
}

#[cfg(windows)]
fn metadata_file_identity(_metadata: &Metadata) -> Option<FileIdentity> {
    None
}

#[cfg(windows)]
fn path_file_identity(path: &Path, _metadata: &Metadata) -> Option<FileIdentity> {
    use std::mem::MaybeUninit;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };

    let file = File::open(path).ok()?;
    let mut information = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
    let succeeded = unsafe {
        GetFileInformationByHandle(file.as_raw_handle() as isize, information.as_mut_ptr())
    };
    if succeeded == 0 {
        return None;
    }
    let information = unsafe { information.assume_init() };
    Some(FileIdentity {
        volume_id: u64::from(information.dwVolumeSerialNumber),
        file_id: (u64::from(information.nFileIndexHigh) << 32)
            | u64::from(information.nFileIndexLow),
    })
}

#[cfg(not(any(unix, windows)))]
fn metadata_file_identity(_metadata: &Metadata) -> Option<FileIdentity> {
    None
}

#[cfg(not(any(unix, windows)))]
fn path_file_identity(_path: &Path, _metadata: &Metadata) -> Option<FileIdentity> {
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
        assert!(report.groups[0].potential_recovery_allocated_bytes.is_some_and(|bytes| bytes > 0));
        assert_eq!(
            report.potential_recovery_allocated_bytes,
            report.groups[0].potential_recovery_allocated_bytes
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
        let one_allocation = group.entries[0].allocated_size_bytes.unwrap();

        assert_eq!(group.unique_file_count, 3);
        assert_eq!(group.potential_recovery_allocated_bytes, Some(one_allocation * 2));
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
        assert_eq!(report.potential_recovery_allocated_bytes, Some(0));
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
        let one_allocation = group.entries[0].allocated_size_bytes.unwrap();

        assert_eq!(group.entries.len(), 3);
        assert_eq!(group.unique_file_count, 2);
        assert_eq!(group.potential_recovery_allocated_bytes, Some(one_allocation));
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

    #[test]
    fn reports_logical_duplicates_when_allocated_size_is_unavailable() {
        let directory = TestDirectory::new("logical-only");
        fs::write(directory.0.join("a.bin"), [1_u8; 64]).unwrap();
        fs::write(directory.0.join("b.bin"), [1_u8; 64]).unwrap();
        let mut scan = directory.scan();
        for item in &mut scan.items {
            if item.kind == ItemKind::File {
                item.allocated_size_bytes = None;
            }
        }

        let report = detect_duplicates(&scan, &DuplicateOptions::default());

        assert_eq!(report.logical_duplicate_bytes, 64);
        assert_eq!(report.potential_recovery_allocated_bytes, None);
        assert_eq!(report.groups[0].logical_duplicate_bytes, 64);
        assert_eq!(report.groups[0].potential_recovery_allocated_bytes, None);
    }

    #[cfg(unix)]
    #[test]
    fn excludes_replaced_hard_link_alias() {
        let directory = TestDirectory::new("replaced-alias");
        let original = directory.0.join("original.bin");
        let alias = directory.0.join("alias.bin");
        let copy = directory.0.join("copy.bin");
        let content = vec![4_u8; 4096];
        fs::write(&original, &content).unwrap();
        fs::hard_link(&original, &alias).unwrap();
        fs::write(&copy, &content).unwrap();
        let scan = directory.scan();
        let mut replaced = false;

        let report = detect_duplicates_with_hook(
            &scan,
            &DuplicateOptions::default(),
            |path| {
                if path == alias && !replaced {
                    fs::remove_file(path).unwrap();
                    fs::write(path, &content).unwrap();
                    replaced = true;
                }
            },
        );

        assert_eq!(report.groups.len(), 1);
        assert!(!report.groups[0].entries.iter().any(|entry| entry.path == alias));
        assert!(report.warnings.iter().any(|warning| {
            warning.path == alias && warning.kind == DuplicateWarningKind::ChangedDuringDetection
        }));
    }

    #[cfg(unix)]
    #[test]
    fn excludes_disappeared_hard_link_alias() {
        let directory = TestDirectory::new("disappeared-alias");
        let original = directory.0.join("original.bin");
        let alias = directory.0.join("alias.bin");
        let copy = directory.0.join("copy.bin");
        let content = vec![4_u8; 4096];
        fs::write(&original, &content).unwrap();
        fs::hard_link(&original, &alias).unwrap();
        fs::write(&copy, &content).unwrap();
        let scan = directory.scan();
        let mut removed = false;

        let report = detect_duplicates_with_hook(
            &scan,
            &DuplicateOptions::default(),
            |path| {
                if path == alias && !removed {
                    fs::remove_file(path).unwrap();
                    removed = true;
                }
            },
        );

        assert_eq!(report.groups.len(), 1);
        assert!(!report.groups[0].entries.iter().any(|entry| entry.path == alias));
        assert!(report.warnings.iter().any(|warning| {
            warning.path == alias && warning.kind == DuplicateWarningKind::MetadataUnavailable
        }));
    }

    #[cfg(unix)]
    #[test]
    fn excludes_alias_replaced_after_representative_hashing() {
        let directory = TestDirectory::new("post-hash-replaced-alias");
        let representative = directory.0.join("alias.bin");
        let changed_alias = directory.0.join("original.bin");
        let copy = directory.0.join("copy.bin");
        let content = vec![4_u8; 4096];
        fs::write(&representative, &content).unwrap();
        fs::hard_link(&representative, &changed_alias).unwrap();
        fs::write(&copy, &content).unwrap();
        let scan = directory.scan();
        let expected_allocation = scan
            .items
            .iter()
            .find(|item| item.path == representative)
            .and_then(|item| item.allocated_size_bytes)
            .unwrap();
        let mut replaced = false;

        let report = detect_duplicates_with_hooks(
            &scan,
            &DuplicateOptions::default(),
            |_| {},
            |hashed_path| {
                if hashed_path == representative && !replaced {
                    fs::remove_file(&changed_alias).unwrap();
                    fs::write(&changed_alias, &content).unwrap();
                    replaced = true;
                }
            },
        );

        assert_eq!(report.groups.len(), 1);
        let group = &report.groups[0];
        assert_eq!(group.unique_file_count, 2);
        assert_eq!(group.entries.len(), 2);
        assert_eq!(group.logical_duplicate_bytes, 4096);
        assert_eq!(
            group.potential_recovery_allocated_bytes,
            Some(expected_allocation)
        );
        assert!(!group.entries.iter().any(|entry| entry.path == changed_alias));
        assert!(report.warnings.iter().any(|warning| {
            warning.path == changed_alias
                && warning.kind == DuplicateWarningKind::ChangedDuringDetection
        }));
    }

    #[cfg(unix)]
    #[test]
    fn drops_physical_candidate_when_all_aliases_disappear_after_hashing() {
        let directory = TestDirectory::new("post-hash-all-aliases-gone");
        let representative = directory.0.join("alias.bin");
        let other_alias = directory.0.join("original.bin");
        let copy = directory.0.join("copy.bin");
        let content = vec![4_u8; 4096];
        fs::write(&representative, &content).unwrap();
        fs::hard_link(&representative, &other_alias).unwrap();
        fs::write(&copy, &content).unwrap();
        let scan = directory.scan();
        let mut removed = false;

        let report = detect_duplicates_with_hooks(
            &scan,
            &DuplicateOptions::default(),
            |_| {},
            |hashed_path| {
                if hashed_path == representative && !removed {
                    fs::remove_file(&representative).unwrap();
                    fs::remove_file(&other_alias).unwrap();
                    removed = true;
                }
            },
        );

        assert!(report.groups.is_empty());
        assert_eq!(report.logical_duplicate_bytes, 0);
        assert_eq!(report.potential_recovery_allocated_bytes, Some(0));
        assert_eq!(
            report
                .warnings
                .iter()
                .filter(|warning| warning.kind == DuplicateWarningKind::MetadataUnavailable)
                .count(),
            2
        );
    }

    #[test]
    fn maps_file_open_failures_to_unreadable_warnings() {
        let directory = TestDirectory::new("unreadable");
        let path = directory.0.join("a.bin");
        fs::write(&path, [1_u8; 64]).unwrap();
        let scan = directory.scan();
        let item = scan.items.iter().find(|item| item.path == path).unwrap();

        let warning = hash_scanned_file_with_opener(item, |_| {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "injected permission denial",
            ))
        })
        .unwrap_err();

        assert_eq!(warning.kind, DuplicateWarningKind::Unreadable);
        assert_eq!(warning.path, path);
    }

    #[test]
    fn reports_duplicate_hashing_progress_with_totals() {
        let directory = TestDirectory::new("progress");
        let content = vec![7_u8; HASH_BUFFER_BYTES * 2];
        fs::write(directory.0.join("a.bin"), &content).unwrap();
        fs::write(directory.0.join("b.bin"), &content).unwrap();
        let scan = directory.scan();
        let cancellation = CancellationToken::new();
        let mut events = Vec::new();

        let report = detect_duplicates_with_progress(
            &scan,
            &DuplicateOptions::default(),
            &cancellation,
            |event| events.push(event.clone()),
        )
        .unwrap();

        assert_eq!(report.groups.len(), 1);
        assert_eq!(events.first().unwrap().phase, AnalysisPhase::HashingDuplicates);
        assert_eq!(events.first().unwrap().total_items, Some(2));
        assert_eq!(
            events.first().unwrap().total_bytes,
            Some((content.len() * 2) as u64)
        );
        let final_event = events.last().unwrap();
        assert_eq!(final_event.items_processed, 2);
        assert_eq!(final_event.bytes_processed, (content.len() * 2) as u64);
        assert_eq!(final_event.current_path, None);
    }

    #[test]
    fn cancellation_stops_duplicate_hashing_between_chunks() {
        let directory = TestDirectory::new("cancel-progress");
        let content = vec![8_u8; HASH_BUFFER_BYTES * 3];
        fs::write(directory.0.join("a.bin"), &content).unwrap();
        fs::write(directory.0.join("b.bin"), &content).unwrap();
        let scan = directory.scan();
        let cancellation = CancellationToken::new();
        let signal = cancellation.clone();

        let error = detect_duplicates_with_progress(
            &scan,
            &DuplicateOptions::default(),
            &cancellation,
            move |event| {
                if event.bytes_processed > 0 {
                    signal.cancel();
                }
            },
        )
        .unwrap_err();

        assert!(matches!(
            error,
            DuplicateError::Cancelled {
                items_processed: 0,
                bytes_processed
            } if bytes_processed > 0
        ));
    }
}
