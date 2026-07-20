use spacemind_core::{
    Finding, FindingCategory, ItemKind, RiskLevel, ScanResult, ScannedItem, SuggestedAction,
};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const DAY_SECONDS: u64 = 24 * 60 * 60;

#[derive(Debug, Clone)]
pub struct RuleOptions {
    pub large_item_threshold_bytes: u64,
    pub old_item_threshold_days: u64,
    pub now_epoch_seconds: u64,
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
        }
    }
}

pub fn evaluate(scan: &ScanResult, options: &RuleOptions) -> Vec<Finding> {
    let mut findings = Vec::new();

    for item in &scan.items {
        if item.path == scan.root || matches!(item.kind, ItemKind::Symlink | ItemKind::Other) {
            continue;
        }

        if item.size_bytes >= options.large_item_threshold_bytes {
            findings.push(large_item_finding(item, options.large_item_threshold_bytes));
        }

        if item.kind == ItemKind::File && is_old(item, options) {
            if is_installer(&item.path) {
                findings.push(old_file_finding(
                    item,
                    options,
                    FindingCategory::OldInstaller,
                    "Recognized as an installer or disk image",
                ));
            } else if is_archive(&item.path) {
                findings.push(old_file_finding(
                    item,
                    options,
                    FindingCategory::OldArchive,
                    "Recognized as an archive",
                ));
            }
        }

        if item.kind == ItemKind::Directory {
            if is_cache_directory(&item.path) {
                findings.push(directory_finding(
                    item,
                    FindingCategory::CacheDirectory,
                    RiskLevel::Low,
                    0.90,
                    "Recognized as a common cache directory",
                ));
            } else if is_generated_directory(&item.path) {
                findings.push(directory_finding(
                    item,
                    FindingCategory::GeneratedDirectory,
                    RiskLevel::Medium,
                    0.88,
                    "Recognized as a generated dependency or build directory",
                ));
            }
        }
    }

    findings.sort_by(|left, right| {
        right
            .potential_recovery_bytes
            .cmp(&left.potential_recovery_bytes)
            .then_with(|| left.path.cmp(&right.path))
            .then_with(|| category_rank(left.category).cmp(&category_rank(right.category)))
    });
    findings
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

fn directory_finding(
    item: &ScannedItem,
    category: FindingCategory,
    risk: RiskLevel,
    confidence: f32,
    evidence: &str,
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
        suggested_action: SuggestedAction::ReviewForDeletion,
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

fn is_installer(path: &Path) -> bool {
    let name = lowercase_name(path);
    [".iso", ".deb", ".rpm", ".exe", ".msi", ".dmg", ".appimage", ".apk"]
        .iter()
        .any(|suffix| name.ends_with(suffix))
}

fn is_archive(path: &Path) -> bool {
    let name = lowercase_name(path);
    [
        ".zip", ".7z", ".rar", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2",
        ".tar.xz", ".txz", ".gz",
    ]
    .iter()
    .any(|suffix| name.ends_with(suffix))
}

fn is_cache_directory(path: &Path) -> bool {
    let name = lowercase_name(path);
    if name == ".cache" {
        return true;
    }

    name == "caches"
        && path
            .parent()
            .map(lowercase_name)
            .map(|parent| parent == ".gradle")
            .unwrap_or(false)
}

fn is_generated_directory(path: &Path) -> bool {
    matches!(
        lowercase_name(path).as_str(),
        "node_modules" | "target" | "build" | "dist"
    )
}

fn category_rank(category: FindingCategory) -> u8 {
    match category {
        FindingCategory::LargeItem => 0,
        FindingCategory::OldArchive => 1,
        FindingCategory::OldInstaller => 2,
        FindingCategory::GeneratedDirectory => 3,
        FindingCategory::CacheDirectory => 4,
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
            file_count: u64::from(item.kind == ItemKind::File),
            directory_count: u64::from(item.kind == ItemKind::Directory),
            items: vec![item],
            warnings: Vec::<ScanWarning>::new(),
        }
    }

    #[test]
    fn recognizes_an_old_installer() {
        let item = ScannedItem {
            path: PathBuf::from("/test/android-studio.deb"),
            kind: ItemKind::File,
            size_bytes: 500,
            created_at_epoch_seconds: None,
            modified_at_epoch_seconds: Some(100 * DAY_SECONDS),
            accessed_at_epoch_seconds: None,
            extension: Some("deb".into()),
        };
        let options = RuleOptions {
            large_item_threshold_bytes: 1_000,
            old_item_threshold_days: 180,
            now_epoch_seconds: 300 * DAY_SECONDS,
        };

        let findings = evaluate(&scan_with(item), &options);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, FindingCategory::OldInstaller);
    }

    #[test]
    fn recognizes_generated_directories() {
        let item = ScannedItem {
            path: PathBuf::from("/test/node_modules"),
            kind: ItemKind::Directory,
            size_bytes: 500,
            created_at_epoch_seconds: None,
            modified_at_epoch_seconds: None,
            accessed_at_epoch_seconds: None,
            extension: None,
        };
        let options = RuleOptions {
            large_item_threshold_bytes: 1_000,
            ..RuleOptions::default()
        };

        let findings = evaluate(&scan_with(item), &options);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, FindingCategory::GeneratedDirectory);
    }
}
