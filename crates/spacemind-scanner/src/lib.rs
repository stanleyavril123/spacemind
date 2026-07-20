use spacemind_core::{ItemKind, ScanResult, ScanWarning, ScannedItem};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use walkdir::WalkDir;

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
}

pub fn scan(options: &ScanOptions) -> Result<ScanResult, ScanError> {
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
    let mut file_count = 0_u64;
    let mut directory_count = 0_u64;

    // start walking trough the root
    for result in walker {
        let entry = match result {
            Ok(entry) => entry,
            Err(error) => {
                warnings.push(ScanWarning {
                    path: error.path().map(Path::to_path_buf),
                    message: error.to_string(),
                });
                continue;
            }
        };

        let path = entry.path().to_path_buf();
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) => {
                warnings.push(ScanWarning {
                    path: Some(path),
                    message: error.to_string(),
                });
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

        match kind {
            ItemKind::File => {
                file_count += 1;
                add_size_to_ancestors(&root, &path, size_bytes, &mut directory_sizes);
            }
            ItemKind::Directory => {
                directory_count += 1;
                directory_sizes.entry(path.clone()).or_default();
            }
            ItemKind::Symlink | ItemKind::Other => {}
        }

        items.push(ScannedItem {
            extension: normalized_extension(&path, kind),
            path,
            kind,
            size_bytes,
            created_at_epoch_seconds: metadata.created().ok().and_then(epoch_seconds),
            modified_at_epoch_seconds: metadata.modified().ok().and_then(epoch_seconds),
            accessed_at_epoch_seconds: metadata.accessed().ok().and_then(epoch_seconds),
        });
    }

    for item in &mut items {
        if item.kind == ItemKind::Directory {
            item.size_bytes = directory_sizes.get(&item.path).copied().unwrap_or(0);
        }
    }

    items.sort_by(|left, right| left.path.cmp(&right.path));
    warnings.sort_by(|left, right| left.path.cmp(&right.path));
    let total_size_bytes = directory_sizes.get(&root).copied().unwrap_or(0);

    Ok(ScanResult {
        root,
        started_at_epoch_seconds,
        completed_at_epoch_seconds: now_epoch_seconds(),
        total_size_bytes,
        file_count,
        directory_count,
        items,
        warnings,
    })
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

fn normalized_extension(path: &Path, kind: ItemKind) -> Option<String> {
    if kind != ItemKind::File {
        return None;
    }
    path.extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
}

fn epoch_seconds(time: SystemTime) -> Option<u64> {
    time.duration_since(UNIX_EPOCH).ok().map(|value| value.as_secs())
}

fn now_epoch_seconds() -> u64 {
    epoch_seconds(SystemTime::now()).unwrap_or(0)
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
        let nested_item = result.items.iter().find(|item| item.path == nested).unwrap();
        assert_eq!(nested_item.size_bytes, 5);
    }

    #[test]
    fn reports_empty_directories() {
        let test_dir = TestDirectory::new("empty-directory");
        let empty = test_dir.0.join("empty");
        fs::create_dir(&empty).unwrap();

        let result = scan(&ScanOptions::new(&test_dir.0)).unwrap();
        let empty_item = result.items.iter().find(|item| item.path == empty).unwrap();

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
        assert!(result.items.iter().any(|item| item.kind == ItemKind::Symlink));
    }
}
