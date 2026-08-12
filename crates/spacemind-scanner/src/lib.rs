use spacemind_core::{
    AnalysisPhase, CancellationToken, FileIdentity, ItemKind, ProgressEvent, ScanResult,
    ScanWarning, ScannedItem,
};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use walkdir::WalkDir;

const PROGRESS_INTERVAL_ITEMS: u64 = 128;

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub root: PathBuf,
    pub cross_filesystems: bool,
}

impl ScanOptions {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            cross_filesystems: false,
        }
    }
}

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("cannot access scan root {path}: {source}")]
    RootAccess { path: PathBuf, source: io::Error },
    #[error("scan root is not a directory: {0}")]
    RootNotDirectory(PathBuf),
    #[error("scan cancelled after processing {items_processed} items and {bytes_processed} bytes")]
    Cancelled {
        items_processed: u64,
        bytes_processed: u64,
    },
}

pub fn scan(options: &ScanOptions) -> Result<ScanResult, ScanError> {
    let cancellation = CancellationToken::new();
    scan_with_progress(options, &cancellation, |_| {})
}

pub fn scan_with_progress<F>(
    options: &ScanOptions,
    cancellation: &CancellationToken,
    mut on_progress: F,
) -> Result<ScanResult, ScanError>
where
    F: FnMut(&ProgressEvent),
{
    scan_internal(
        options,
        cancellation,
        &mut on_progress,
        &mut |_| {},
    )
}

fn scan_internal<F, H>(
    options: &ScanOptions,
    cancellation: &CancellationToken,
    on_progress: &mut F,
    before_metadata: &mut H,
) -> Result<ScanResult, ScanError>
where
    F: FnMut(&ProgressEvent),
    H: FnMut(&Path),
{
    let mut items_processed = 0_u64;
    let mut bytes_processed = 0_u64;
    on_progress(&ProgressEvent::starting(AnalysisPhase::Scanning));
    check_cancelled(cancellation, items_processed, bytes_processed)?;

    let started_at_epoch_seconds = now_epoch_seconds();
    let root = fs::canonicalize(&options.root).map_err(|source| ScanError::RootAccess {
        path: options.root.clone(),
        source,
    })?;

    let root_metadata = fs::metadata(&root).map_err(|source| ScanError::RootAccess {
        path: root.clone(),
        source,
    })?;
    if !root_metadata.is_dir() {
        return Err(ScanError::RootNotDirectory(root));
    }

    let mut walker = WalkDir::new(&root).follow_links(false);
    if !options.cross_filesystems {
        walker = walker.same_file_system(true);
    }

    let mut items = Vec::new();
    let mut warnings = Vec::new();
    let mut directory_sizes: HashMap<PathBuf, u64> = HashMap::new();
    let mut directory_allocated_sizes: HashMap<PathBuf, u64> = HashMap::new();
    let mut hard_link_allocations: HashMap<FileIdentity, (u64, Vec<PathBuf>)> = HashMap::new();
    let mut allocated_sizes_available = true;
    let mut file_count = 0_u64;
    let mut directory_count = 0_u64;

    for result in walker {
        check_cancelled(cancellation, items_processed, bytes_processed)?;
        items_processed = items_processed.saturating_add(1);

        let entry = match result {
            Ok(entry) => entry,
            Err(error) => {
                let current_path = error.path().map(Path::to_path_buf);
                warnings.push(ScanWarning {
                    path: current_path.clone(),
                    message: error.to_string(),
                });
                report_scan_progress(
                    on_progress,
                    items_processed,
                    bytes_processed,
                    current_path,
                    false,
                );
                continue;
            }
        };

        let path = entry.path().to_path_buf();
        before_metadata(&path);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) => {
                warnings.push(ScanWarning {
                    path: Some(path.clone()),
                    message: error.to_string(),
                });
                report_scan_progress(
                    on_progress,
                    items_processed,
                    bytes_processed,
                    Some(path),
                    false,
                );
                continue;
            }
        };

        let file_type = metadata.file_type();
        let kind = if file_type.is_file() {
            ItemKind::File
        } else if file_type.is_dir() {
            ItemKind::Directory
        } else if file_type.is_symlink() {
            ItemKind::Symlink
        } else {
            ItemKind::Other
        };

        let size_bytes = if kind == ItemKind::File {
            metadata.len()
        } else {
            0
        };
        bytes_processed = bytes_processed.saturating_add(size_bytes);
        let identity = (kind == ItemKind::File)
            .then(|| file_identity(&path, &metadata))
            .flatten();
        let allocated_size_bytes = (kind == ItemKind::File)
            .then(|| allocated_size(&metadata))
            .flatten();
        let links = (kind == ItemKind::File)
            .then(|| hard_link_count(&path, &metadata))
            .flatten();

        match kind {
            ItemKind::File => {
                file_count += 1;
                add_size_to_ancestors(&root, &path, size_bytes, &mut directory_sizes);
                match allocated_size_bytes {
                    Some(allocated) => match (identity, links) {
                        (Some(identity), Some(link_count)) if link_count > 1 => {
                            let occurrence = hard_link_allocations
                                .entry(identity)
                                .or_insert_with(|| (allocated, Vec::new()));
                            occurrence.1.push(path.clone());
                        }
                        _ => add_allocated_size_to_ancestors(
                            &root,
                            &path,
                            allocated,
                            &mut directory_allocated_sizes,
                        ),
                    },
                    None => allocated_sizes_available = false,
                }
            }
            ItemKind::Directory => {
                directory_count += 1;
                directory_sizes.entry(path.clone()).or_default();
                directory_allocated_sizes.entry(path.clone()).or_default();
            }
            ItemKind::Symlink | ItemKind::Other => {}
        }

        let modified = metadata.modified().ok();
        items.push(ScannedItem {
            extension: normalized_extension(&path, kind),
            path: path.clone(),
            kind,
            size_bytes,
            allocated_size_bytes,
            file_identity: identity,
            hard_link_count: links,
            created_at_epoch_seconds: metadata.created().ok().and_then(epoch_seconds),
            modified_at_epoch_seconds: modified.and_then(epoch_seconds),
            modified_at_epoch_nanoseconds: modified.and_then(epoch_nanoseconds),
            accessed_at_epoch_seconds: metadata.accessed().ok().and_then(epoch_seconds),
        });
        report_scan_progress(
            on_progress,
            items_processed,
            bytes_processed,
            Some(path),
            false,
        );
    }

    check_cancelled(cancellation, items_processed, bytes_processed)?;
    for (_, (allocated, paths)) in hard_link_allocations {
        let mut seen_ancestors = HashSet::new();
        for path in paths {
            check_cancelled(cancellation, items_processed, bytes_processed)?;
            add_allocated_size_to_unique_ancestors(
                &root,
                &path,
                allocated,
                &mut directory_allocated_sizes,
                &mut seen_ancestors,
            );
        }
    }

    for (index, item) in items.iter_mut().enumerate() {
        if index % 1024 == 0 {
            check_cancelled(cancellation, items_processed, bytes_processed)?;
        }
        if item.kind == ItemKind::Directory {
            item.size_bytes = directory_sizes.get(&item.path).copied().unwrap_or(0);
            item.allocated_size_bytes = allocated_sizes_available.then(|| {
                directory_allocated_sizes
                    .get(&item.path)
                    .copied()
                    .unwrap_or(0)
            });
        }
    }

    items.sort_by(|left, right| left.path.cmp(&right.path));
    warnings.sort_by(|left, right| left.path.cmp(&right.path));
    let total_size_bytes = directory_sizes.get(&root).copied().unwrap_or(0);
    let total_allocated_size_bytes = allocated_sizes_available.then(|| {
        directory_allocated_sizes
            .get(&root)
            .copied()
            .unwrap_or(0)
    });

    report_scan_progress(
        on_progress,
        items_processed,
        bytes_processed,
        None,
        true,
    );

    Ok(ScanResult {
        root,
        started_at_epoch_seconds,
        completed_at_epoch_seconds: now_epoch_seconds(),
        total_size_bytes,
        total_allocated_size_bytes,
        file_count,
        directory_count,
        items,
        warnings,
    })
}

fn check_cancelled(
    cancellation: &CancellationToken,
    items_processed: u64,
    bytes_processed: u64,
) -> Result<(), ScanError> {
    if cancellation.is_cancelled() {
        Err(ScanError::Cancelled {
            items_processed,
            bytes_processed,
        })
    } else {
        Ok(())
    }
}

fn report_scan_progress<F>(
    on_progress: &mut F,
    items_processed: u64,
    bytes_processed: u64,
    current_path: Option<PathBuf>,
    complete: bool,
) where
    F: FnMut(&ProgressEvent),
{
    if complete || items_processed == 1 || items_processed % PROGRESS_INTERVAL_ITEMS == 0 {
        on_progress(&ProgressEvent {
            phase: AnalysisPhase::Scanning,
            items_processed,
            bytes_processed,
            total_items: complete.then_some(items_processed),
            total_bytes: complete.then_some(bytes_processed),
            current_path,
        });
    }
}

fn add_size_to_ancestors(
    root: &Path,
    path: &Path,
    size_bytes: u64,
    directory_sizes: &mut HashMap<PathBuf, u64>,
) {
    let Some(parent) = path.parent() else {
        return;
    };

    for ancestor in parent.ancestors() {
        if !ancestor.starts_with(root) {
            break;
        }
        let total = directory_sizes.entry(ancestor.to_path_buf()).or_default();
        *total = total.saturating_add(size_bytes);
        if ancestor == root {
            break;
        }
    }
}

fn add_allocated_size_to_ancestors(
    root: &Path,
    path: &Path,
    allocated_size_bytes: u64,
    directory_sizes: &mut HashMap<PathBuf, u64>,
) {
    let Some(parent) = path.parent() else {
        return;
    };

    for ancestor in parent.ancestors() {
        if !ancestor.starts_with(root) {
            break;
        }
        let total = directory_sizes.entry(ancestor.to_path_buf()).or_default();
        *total = total.saturating_add(allocated_size_bytes);
        if ancestor == root {
            break;
        }
    }
}

fn add_allocated_size_to_unique_ancestors(
    root: &Path,
    path: &Path,
    allocated_size_bytes: u64,
    directory_sizes: &mut HashMap<PathBuf, u64>,
    seen_ancestors: &mut HashSet<PathBuf>,
) {
    let Some(parent) = path.parent() else {
        return;
    };

    for ancestor in parent.ancestors() {
        if !ancestor.starts_with(root) {
            break;
        }
        let ancestor = ancestor.to_path_buf();
        if seen_ancestors.insert(ancestor.clone()) {
            let total = directory_sizes.entry(ancestor.clone()).or_default();
            *total = total.saturating_add(allocated_size_bytes);
        }
        if ancestor == root {
            break;
        }
    }
}

fn normalized_extension(path: &Path, kind: ItemKind) -> Option<String> {
    if kind != ItemKind::File {
        return None;
    }
    path.extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
}

fn epoch_seconds(time: SystemTime) -> Option<u64> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .map(|value| value.as_secs())
}

fn epoch_nanoseconds(time: SystemTime) -> Option<u64> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|value| u64::try_from(value.as_nanos()).ok())
}

fn now_epoch_seconds() -> u64 {
    epoch_seconds(SystemTime::now()).unwrap_or(0)
}

#[cfg(unix)]
fn file_identity(_path: &Path, metadata: &fs::Metadata) -> Option<FileIdentity> {
    use std::os::unix::fs::MetadataExt;

    Some(FileIdentity {
        volume_id: metadata.dev(),
        file_id: metadata.ino(),
    })
}

#[cfg(windows)]
fn file_identity(path: &Path, _metadata: &fs::Metadata) -> Option<FileIdentity> {
    windows_file_information(path).map(|information| FileIdentity {
        volume_id: u64::from(information.dwVolumeSerialNumber),
        file_id: (u64::from(information.nFileIndexHigh) << 32)
            | u64::from(information.nFileIndexLow),
    })
}

#[cfg(not(any(unix, windows)))]
fn file_identity(_path: &Path, _metadata: &fs::Metadata) -> Option<FileIdentity> {
    None
}

#[cfg(unix)]
fn allocated_size(metadata: &fs::Metadata) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;

    Some(metadata.blocks().saturating_mul(512))
}

#[cfg(not(unix))]
fn allocated_size(_metadata: &fs::Metadata) -> Option<u64> {
    None
}

#[cfg(unix)]
fn hard_link_count(_path: &Path, metadata: &fs::Metadata) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;

    Some(metadata.nlink())
}

#[cfg(windows)]
fn hard_link_count(path: &Path, _metadata: &fs::Metadata) -> Option<u64> {
    windows_file_information(path).map(|information| u64::from(information.nNumberOfLinks))
}

#[cfg(not(any(unix, windows)))]
fn hard_link_count(_path: &Path, _metadata: &fs::Metadata) -> Option<u64> {
    None
}

#[cfg(windows)]
fn windows_file_information(
    path: &Path,
) -> Option<windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION> {
    use std::mem::MaybeUninit;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };

    let file = fs::File::open(path).ok()?;
    let mut information = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
    let succeeded = unsafe {
        GetFileInformationByHandle(file.as_raw_handle() as isize, information.as_mut_ptr())
    };
    (succeeded != 0).then(|| unsafe { information.assume_init() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(name: &str) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "spacemind-scanner-{name}-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("create test directory");
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn aggregates_nested_directory_sizes() {
        let test_dir = TestDirectory::new("nested-sizes");
        let nested = test_dir.0.join("nested");
        fs::create_dir(&nested).unwrap();
        fs::write(test_dir.0.join("one.bin"), [0_u8; 3]).unwrap();
        fs::write(nested.join("two.bin"), [0_u8; 5]).unwrap();

        let result = scan(&ScanOptions::new(&test_dir.0)).unwrap();

        assert_eq!(result.file_count, 2);
        assert_eq!(result.total_size_bytes, 8);
        let nested_item = result
            .items
            .iter()
            .find(|item| item.path == nested)
            .unwrap();
        assert_eq!(nested_item.size_bytes, 5);
    }

    #[test]
    fn reports_progress_with_final_totals() {
        let test_dir = TestDirectory::new("progress");
        fs::write(test_dir.0.join("one.bin"), [0_u8; 3]).unwrap();
        fs::write(test_dir.0.join("two.bin"), [0_u8; 5]).unwrap();
        let cancellation = CancellationToken::new();
        let mut events = Vec::new();

        let result = scan_with_progress(
            &ScanOptions::new(&test_dir.0),
            &cancellation,
            |event| events.push(event.clone()),
        )
        .unwrap();

        assert!(events.len() >= 2);
        assert_eq!(events[0], ProgressEvent::starting(AnalysisPhase::Scanning));
        let final_event = events.last().unwrap();
        assert_eq!(final_event.total_items, Some(result.items.len() as u64));
        assert_eq!(final_event.total_bytes, Some(result.total_size_bytes));
    }

    #[test]
    fn cancellation_stops_scan_cooperatively() {
        let test_dir = TestDirectory::new("cancel");
        fs::write(test_dir.0.join("one.bin"), [0_u8; 3]).unwrap();
        let cancellation = CancellationToken::new();
        let cancellation_from_callback = cancellation.clone();

        let result = scan_with_progress(
            &ScanOptions::new(&test_dir.0),
            &cancellation,
            move |event| {
                if event.items_processed >= 1 {
                    cancellation_from_callback.cancel();
                }
            },
        );

        assert!(matches!(result, Err(ScanError::Cancelled { .. })));
    }

    #[test]
    fn disappearing_file_becomes_a_warning() {
        let test_dir = TestDirectory::new("disappearing");
        let disappearing = test_dir.0.join("disappearing.bin");
        fs::write(&disappearing, [0_u8; 3]).unwrap();
        let cancellation = CancellationToken::new();
        let mut removed = false;

        let result = scan_internal(
            &ScanOptions::new(&test_dir.0),
            &cancellation,
            &mut |_| {},
            &mut |path| {
                if path == disappearing && !removed {
                    fs::remove_file(path).unwrap();
                    removed = true;
                }
            },
        )
        .unwrap();

        assert_eq!(result.file_count, 0);
        assert!(result
            .warnings
            .iter()
            .any(|warning| warning.path.as_ref() == Some(&disappearing)));
    }

    #[cfg(unix)]
    #[test]
    fn permission_denied_directory_becomes_a_warning() {
        use std::os::unix::fs::PermissionsExt;

        let test_dir = TestDirectory::new("permission-denied");
        let locked = test_dir.0.join("locked");
        fs::create_dir(&locked).unwrap();
        fs::write(locked.join("hidden.bin"), [0_u8; 3]).unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();

        if fs::read_dir(&locked).is_ok() {
            fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).unwrap();
            return;
        }
        let result = scan(&ScanOptions::new(&test_dir.0)).unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).unwrap();

        assert!(result
            .warnings
            .iter()
            .any(|warning| warning.path.as_ref().is_some_and(|path| path.starts_with(&locked))));
    }

    #[test]
    fn reports_empty_directories() {
        let test_dir = TestDirectory::new("empty-directory");
        let empty = test_dir.0.join("empty");
        fs::create_dir(&empty).unwrap();

        let result = scan(&ScanOptions::new(&test_dir.0)).unwrap();
        let empty_item = result
            .items
            .iter()
            .find(|item| item.path == empty)
            .unwrap();

        assert_eq!(empty_item.kind, ItemKind::Directory);
        assert_eq!(empty_item.size_bytes, 0);
    }

    #[cfg(unix)]
    #[test]
    fn does_not_follow_symbolic_links() {
        use std::os::unix::fs::symlink;

        let test_dir = TestDirectory::new("symlink");
        let outside = TestDirectory::new("outside");
        fs::write(outside.0.join("large.bin"), [0_u8; 32]).unwrap();
        symlink(&outside.0, test_dir.0.join("outside-link")).unwrap();

        let result = scan(&ScanOptions::new(&test_dir.0)).unwrap();

        assert_eq!(result.file_count, 0);
        assert_eq!(result.total_size_bytes, 0);
        assert!(result
            .items
            .iter()
            .any(|item| item.kind == ItemKind::Symlink));
    }

    #[cfg(unix)]
    #[test]
    fn records_hard_links_without_double_counting_allocated_total() {
        let test_dir = TestDirectory::new("hard-link");
        let original = test_dir.0.join("original.bin");
        let alias = test_dir.0.join("alias.bin");
        fs::write(&original, vec![7_u8; 4096]).unwrap();
        fs::hard_link(&original, &alias).unwrap();

        let result = scan(&ScanOptions::new(&test_dir.0)).unwrap();
        let original_item = result
            .items
            .iter()
            .find(|item| item.path == original)
            .unwrap();
        let alias_item = result
            .items
            .iter()
            .find(|item| item.path == alias)
            .unwrap();

        assert_eq!(result.total_size_bytes, 8192);
        assert_eq!(original_item.file_identity, alias_item.file_identity);
        assert_eq!(original_item.hard_link_count, Some(2));
        assert_eq!(
            result.total_allocated_size_bytes,
            original_item.allocated_size_bytes
        );
    }

    #[cfg(unix)]
    #[test]
    fn distinguishes_logical_and_allocated_size() {
        let test_dir = TestDirectory::new("allocated-size");
        let sparse = test_dir.0.join("sparse.bin");
        fs::File::create(&sparse)
            .unwrap()
            .set_len(1024 * 1024)
            .unwrap();

        let result = scan(&ScanOptions::new(&test_dir.0)).unwrap();
        let item = result
            .items
            .iter()
            .find(|item| item.path == sparse)
            .unwrap();

        assert_eq!(item.size_bytes, 1024 * 1024);
        assert!(item.allocated_size_bytes.is_some());
        assert!(item.allocated_size_bytes.unwrap() <= item.size_bytes);
    }
}
