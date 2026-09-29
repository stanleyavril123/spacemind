use spacemind_core::{FileIdentity, ItemKind, ScannedItem};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::UNIX_EPOCH;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PlatformError {
    #[error("cannot inspect {path}: {source}")]
    Inspect { path: PathBuf, source: io::Error },
    #[error("cannot resolve {path}: {source}")]
    Canonicalize { path: PathBuf, source: io::Error },
    #[error("refusing to move the scan root to Trash: {0}")]
    ScanRoot(PathBuf),
    #[error("refusing to act on a path outside the scan root: {0}")]
    OutsideScanRoot(PathBuf),
    #[error("refusing to move a symbolic link from a recommendation to Trash: {0}")]
    SymbolicLink(PathBuf),
    #[error("{path} is no longer the same kind of item recorded by the scan")]
    KindChanged { path: PathBuf },
    #[error("{path} changed size after the scan (was {expected} bytes, now {actual} bytes)")]
    SizeChanged {
        path: PathBuf,
        expected: u64,
        actual: u64,
    },
    #[error("{0} changed after the scan; scan it again before moving it to Trash")]
    ChangedAfterScan(PathBuf),
    #[error("cannot move {path} to the operating system Trash/Recycle Bin: {source}")]
    Trash {
        path: PathBuf,
        source: trash::Error,
    },
    #[error("opening file locations is not supported on this operating system")]
    OpenUnsupported,
    #[error("cannot open the location for {path}: {source}")]
    Open { path: PathBuf, source: io::Error },
}

pub type Result<T> = std::result::Result<T, PlatformError>;

/// Opens the item's containing folder using the operating system file manager.
pub fn open_item_location(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|source| PlatformError::Inspect {
        path: path.to_path_buf(),
        source,
    })?;
    open_item_location_impl(path, metadata.is_dir())
}

/// Revalidates an item against its scan snapshot, then moves it to the system Trash.
///
/// This function does not ask for confirmation. Callers must obtain explicit user
/// confirmation immediately before invoking it.
pub fn move_item_to_trash(root: &Path, snapshot: &ScannedItem) -> Result<()> {
    validate_trash_target(root, snapshot)?;
    trash::delete(&snapshot.path).map_err(|source| PlatformError::Trash {
        path: snapshot.path.clone(),
        source,
    })
}

fn validate_trash_target(root: &Path, snapshot: &ScannedItem) -> Result<()> {
    let path = &snapshot.path;
    if path == root {
        return Err(PlatformError::ScanRoot(path.clone()));
    }

    let metadata = fs::symlink_metadata(path).map_err(|source| PlatformError::Inspect {
        path: path.clone(),
        source,
    })?;
    if metadata.file_type().is_symlink() {
        return Err(PlatformError::SymbolicLink(path.clone()));
    }

    let canonical_root = fs::canonicalize(root).map_err(|source| PlatformError::Canonicalize {
        path: root.to_path_buf(),
        source,
    })?;
    let canonical_path = fs::canonicalize(path).map_err(|source| PlatformError::Canonicalize {
        path: path.clone(),
        source,
    })?;
    if canonical_path == canonical_root {
        return Err(PlatformError::ScanRoot(path.clone()));
    }
    if !canonical_path.starts_with(&canonical_root) {
        return Err(PlatformError::OutsideScanRoot(path.clone()));
    }

    let current_kind = if metadata.is_file() {
        ItemKind::File
    } else if metadata.is_dir() {
        ItemKind::Directory
    } else {
        ItemKind::Other
    };
    if current_kind != snapshot.kind {
        return Err(PlatformError::KindChanged { path: path.clone() });
    }
    if current_kind == ItemKind::File && metadata.len() != snapshot.size_bytes {
        return Err(PlatformError::SizeChanged {
            path: path.clone(),
            expected: snapshot.size_bytes,
            actual: metadata.len(),
        });
    }
    if current_kind == ItemKind::File {
        if let Some(expected) = snapshot.allocated_size_bytes {
            if allocated_size(&metadata) != Some(expected) {
                return Err(PlatformError::ChangedAfterScan(path.clone()));
            }
        }
    }
    if let Some(expected) = snapshot.file_identity {
        if file_identity(path, &metadata) != Some(expected) {
            return Err(PlatformError::ChangedAfterScan(path.clone()));
        }
    }
    if let Some(expected) = snapshot.hard_link_count {
        if hard_link_count(path, &metadata) != Some(expected) {
            return Err(PlatformError::ChangedAfterScan(path.clone()));
        }
    }
    if snapshot.modified_at_epoch_seconds.is_some()
        || snapshot.modified_at_epoch_nanoseconds.is_some()
    {
        let modified = metadata
            .modified()
            .ok()
            .and_then(|value| value.duration_since(UNIX_EPOCH).ok());
        let unchanged = modified.is_some_and(|actual| {
            snapshot
                .modified_at_epoch_seconds
                .map_or(true, |expected| actual.as_secs() == expected)
                && snapshot.modified_at_epoch_nanoseconds.map_or(true, |expected| {
                    u64::try_from(actual.as_nanos()) == Ok(expected)
                })
        });
        if !unchanged {
            return Err(PlatformError::ChangedAfterScan(path.clone()));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_item_location_impl(path: &Path, is_directory: bool) -> Result<()> {
    let directory = if is_directory {
        path
    } else {
        path.parent().unwrap_or(path)
    };
    Command::new("xdg-open")
        .arg(directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(|_| ())
        .map_err(|source| PlatformError::Open {
            path: path.to_path_buf(),
            source,
        })
}

#[cfg(windows)]
fn open_item_location_impl(path: &Path, _is_directory: bool) -> Result<()> {
    Command::new("explorer")
        .arg(format!("/select,{}", path.display()))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(|_| ())
        .map_err(|source| PlatformError::Open {
            path: path.to_path_buf(),
            source,
        })
}

#[cfg(not(any(target_os = "linux", windows)))]
fn open_item_location_impl(_path: &Path, _is_directory: bool) -> Result<()> {
    Err(PlatformError::OpenUnsupported)
}

#[cfg(unix)]
fn file_identity(_path: &Path, metadata: &fs::Metadata) -> Option<FileIdentity> {
    use std::os::unix::fs::MetadataExt;
    Some(FileIdentity {
        volume_id: metadata.dev(),
        file_id: metadata.ino(),
    })
}

#[cfg(unix)]
fn hard_link_count(_path: &Path, metadata: &fs::Metadata) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    Some(metadata.nlink())
}

#[cfg(unix)]
fn allocated_size(metadata: &fs::Metadata) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    Some(metadata.blocks().saturating_mul(512))
}

#[cfg(windows)]
fn file_identity(path: &Path, _metadata: &fs::Metadata) -> Option<FileIdentity> {
    windows_file_information(path).map(|information| FileIdentity {
        volume_id: u64::from(information.dwVolumeSerialNumber),
        file_id: (u64::from(information.nFileIndexHigh) << 32)
            | u64::from(information.nFileIndexLow),
    })
}

#[cfg(windows)]
fn hard_link_count(path: &Path, _metadata: &fs::Metadata) -> Option<u64> {
    windows_file_information(path).map(|information| u64::from(information.nNumberOfLinks))
}

#[cfg(not(unix))]
fn allocated_size(_metadata: &fs::Metadata) -> Option<u64> {
    None
}

#[cfg(not(any(unix, windows)))]
fn file_identity(_path: &Path, _metadata: &fs::Metadata) -> Option<FileIdentity> {
    None
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
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(name: &str) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "spacemind-platform-{}-{name}-{unique}",
                std::process::id()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn snapshot(path: PathBuf, kind: ItemKind, size_bytes: u64) -> ScannedItem {
        ScannedItem {
            path,
            kind,
            size_bytes,
            allocated_size_bytes: None,
            file_identity: None,
            hard_link_count: None,
            created_at_epoch_seconds: None,
            modified_at_epoch_seconds: None,
            modified_at_epoch_nanoseconds: None,
            accessed_at_epoch_seconds: None,
            extension: None,
        }
    }

    #[test]
    fn refuses_the_scan_root() {
        let directory = TestDirectory::new("root");
        let item = snapshot(directory.0.clone(), ItemKind::Directory, 0);

        assert!(matches!(
            validate_trash_target(&directory.0, &item),
            Err(PlatformError::ScanRoot(_))
        ));
    }

    #[test]
    fn refuses_paths_outside_the_scan_root() {
        let root = TestDirectory::new("inside");
        let outside = TestDirectory::new("outside");
        let path = outside.0.join("file.bin");
        fs::write(&path, [0_u8; 4]).unwrap();
        let item = snapshot(path, ItemKind::File, 4);

        assert!(matches!(
            validate_trash_target(&root.0, &item),
            Err(PlatformError::OutsideScanRoot(_))
        ));
    }

    #[test]
    fn detects_a_file_that_changed_size() {
        let directory = TestDirectory::new("changed");
        let path = directory.0.join("file.bin");
        fs::write(&path, [0_u8; 8]).unwrap();
        let item = snapshot(path, ItemKind::File, 4);

        assert!(matches!(
            validate_trash_target(&directory.0, &item),
            Err(PlatformError::SizeChanged { .. })
        ));
    }

    #[test]
    fn detects_changed_allocation_or_modification_metadata() {
        let directory = TestDirectory::new("metadata");
        let path = directory.0.join("file.bin");
        fs::write(&path, [0_u8; 4]).unwrap();
        let mut changed_allocation = snapshot(path.clone(), ItemKind::File, 4);
        changed_allocation.allocated_size_bytes = Some(u64::MAX);
        assert!(matches!(
            validate_trash_target(&directory.0, &changed_allocation),
            Err(PlatformError::ChangedAfterScan(_))
        ));

        let mut changed_modification = snapshot(path, ItemKind::File, 4);
        changed_modification.modified_at_epoch_nanoseconds = Some(0);
        assert!(matches!(
            validate_trash_target(&directory.0, &changed_modification),
            Err(PlatformError::ChangedAfterScan(_))
        ));
    }

    #[test]
    fn accepts_an_unchanged_regular_file_inside_the_scan_root() {
        let directory = TestDirectory::new("unchanged");
        let path = directory.0.join("file.bin");
        fs::write(&path, [0_u8; 4]).unwrap();
        let metadata = fs::metadata(&path).unwrap();
        let modified = metadata
            .modified()
            .unwrap()
            .duration_since(UNIX_EPOCH)
            .unwrap();
        let mut item = snapshot(path.clone(), ItemKind::File, 4);
        item.allocated_size_bytes = allocated_size(&metadata);
        item.file_identity = file_identity(&path, &metadata);
        item.hard_link_count = hard_link_count(&path, &metadata);
        item.modified_at_epoch_seconds = Some(modified.as_secs());
        item.modified_at_epoch_nanoseconds = u64::try_from(modified.as_nanos()).ok();

        validate_trash_target(&directory.0, &item).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn detects_a_replaced_file_identity() {
        let directory = TestDirectory::new("identity");
        let path = directory.0.join("file.bin");
        fs::write(&path, [0_u8; 4]).unwrap();
        let mut item = snapshot(path, ItemKind::File, 4);
        item.file_identity = Some(FileIdentity {
            volume_id: u64::MAX,
            file_id: u64::MAX,
        });

        assert!(matches!(
            validate_trash_target(&directory.0, &item),
            Err(PlatformError::ChangedAfterScan(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symbolic_links() {
        use std::os::unix::fs::symlink;
        let directory = TestDirectory::new("symlink");
        let target = directory.0.join("target.bin");
        let link = directory.0.join("link.bin");
        fs::write(&target, [0_u8; 4]).unwrap();
        symlink(&target, &link).unwrap();
        let item = snapshot(link, ItemKind::File, 4);

        assert!(matches!(
            validate_trash_target(&directory.0, &item),
            Err(PlatformError::SymbolicLink(_))
        ));
    }
}
