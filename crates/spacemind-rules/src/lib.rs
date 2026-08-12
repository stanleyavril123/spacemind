use spacemind_core::{
    AnalysisPhase, CancellationToken, Finding, FindingCategory, ItemKind, PathMatcher, PathRule,
    PathRuleError, ProgressEvent, RiskLevel, ScanResult, ScannedItem, SuggestedAction,
};
use std::path::Path;
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
            total_allocated_size_bytes: None,
            file_count: u64::from(item.kind == ItemKind::File),
            directory_count: u64::from(item.kind == ItemKind::Directory),
            items: vec![item],
            ignored_paths: Vec::new(),
            warnings: Vec::<ScanWarning>::new(),
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
    fn recognizes_generated_directories() {
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
        assert_eq!(findings[0].category, FindingCategory::GeneratedDirectory);
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
