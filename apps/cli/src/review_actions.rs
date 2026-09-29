use crate::format_bytes;
use crossterm::event::KeyCode;
use spacemind_core::{Finding, ItemKind, ScannedItem};
use spacemind_db::{Database, DecisionKind, StoredAnalysis, UserDecision};
use spacemind_platform::{move_item_to_trash, open_item_location};
use std::io;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub(crate) struct ReviewNotice {
    pub(crate) message: String,
    pub(crate) is_error: bool,
}

impl ReviewNotice {
    fn success(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            is_error: false,
        }
    }

    fn error(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            is_error: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReviewAction {
    OpenLocation,
    Ignore,
    Protect,
    MoveToTrash,
}

impl ReviewAction {
    pub(crate) fn from_key(code: &KeyCode) -> Option<Self> {
        match code {
            KeyCode::Char('o') => Some(Self::OpenLocation),
            KeyCode::Char('i') => Some(Self::Ignore),
            KeyCode::Char('p') => Some(Self::Protect),
            KeyCode::Char('t') => Some(Self::MoveToTrash),
            _ => None,
        }
    }

    pub(crate) fn confirmation_title(self) -> &'static str {
        match self {
            Self::OpenLocation => "OPEN LOCATION",
            Self::Ignore => "IGNORE FUTURE SCANS",
            Self::Protect => "PROTECT PATH",
            Self::MoveToTrash => "MOVE TO TRASH",
        }
    }

    pub(crate) fn confirmation_explanation(self) -> &'static str {
        match self {
            Self::OpenLocation => "Open this item's containing folder.",
            Self::Ignore => "SpaceMind will skip this exact path in future scans.",
            Self::Protect => {
                "SpaceMind may scan it for totals, but will never recommend it."
            }
            Self::MoveToTrash => {
                "The item will be revalidated, then moved to the system Trash/Recycle Bin."
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PolicyAction {
    Ignore,
    Protect,
}

impl PolicyAction {
    fn review_action(self) -> ReviewAction {
        match self {
            Self::Ignore => ReviewAction::Ignore,
            Self::Protect => ReviewAction::Protect,
        }
    }

    fn decision(self) -> DecisionKind {
        match self {
            Self::Ignore => DecisionKind::Ignored,
            Self::Protect => DecisionKind::Protected,
        }
    }

    fn already_message(self) -> &'static str {
        match self {
            Self::Ignore => "This item is already ignored for future scans.",
            Self::Protect => "This path is already protected.",
        }
    }

    fn success_message(self) -> &'static str {
        match self {
            Self::Ignore => "Ignored. Future scans will skip this exact path.",
            Self::Protect => "Protected. Future scans will not recommend this path.",
        }
    }

    fn error_prefix(self) -> &'static str {
        match self {
            Self::Ignore => "Could not save ignore choice",
            Self::Protect => "Could not save protection",
        }
    }
}

pub(crate) fn handle_review_action<C>(
    database: &mut Database,
    analysis: &mut StoredAnalysis,
    selected: usize,
    action: ReviewAction,
    mut confirm: C,
) -> io::Result<Option<ReviewNotice>>
where
    C: FnMut(ReviewAction, &Finding) -> io::Result<bool>,
{
    let Some(finding) = analysis.findings.get(selected).cloned() else {
        return Ok(Some(ReviewNotice::error(
            "The selected recommendation is no longer available.",
        )));
    };
    let notice = match action {
        ReviewAction::OpenLocation => Ok(Some(match open_item_location(&finding.path) {
            Ok(()) => ReviewNotice::success("Opened the item location in your file manager."),
            Err(error) => ReviewNotice::error(error.to_string()),
        })),
        ReviewAction::Ignore => handle_policy_action(
            database,
            analysis,
            &finding,
            PolicyAction::Ignore,
            &mut confirm,
        ),
        ReviewAction::Protect => handle_policy_action(
            database,
            analysis,
            &finding,
            PolicyAction::Protect,
            &mut confirm,
        ),
        ReviewAction::MoveToTrash => {
            handle_trash_action(database, analysis, &finding, &mut confirm)
        }
    }?;
    prune_resolved_findings(analysis);
    Ok(notice)
}

pub(crate) fn prune_resolved_findings(analysis: &mut StoredAnalysis) {
    analysis.findings.retain(|finding| {
        !analysis
            .decisions
            .iter()
            .any(|decision| finding.path.starts_with(&decision.path))
    });
}

fn handle_policy_action<C>(
    database: &mut Database,
    analysis: &mut StoredAnalysis,
    finding: &Finding,
    action: PolicyAction,
    confirm: &mut C,
) -> io::Result<Option<ReviewNotice>>
where
    C: FnMut(ReviewAction, &Finding) -> io::Result<bool>,
{
    let decision = action.decision();
    if has_decision(analysis, &finding.path, decision) {
        return Ok(Some(ReviewNotice::success(action.already_message())));
    }
    if !confirm(action.review_action(), finding)? {
        return Ok(None);
    }

    let result = match action {
        PolicyAction::Ignore => database.ignore_item(analysis.summary.id, &finding.path),
        PolicyAction::Protect => database.protect_item(analysis.summary.id, &finding.path),
    };
    Ok(Some(match result {
        Ok(()) => {
            add_local_decision(analysis, &finding.path, decision, 0);
            ReviewNotice::success(action.success_message())
        }
        Err(error) => ReviewNotice::error(format!("{}: {error}", action.error_prefix())),
    }))
}

fn handle_trash_action<C>(
    database: &mut Database,
    analysis: &mut StoredAnalysis,
    finding: &Finding,
    confirm: &mut C,
) -> io::Result<Option<ReviewNotice>>
where
    C: FnMut(ReviewAction, &Finding) -> io::Result<bool>,
{
    if has_decision(analysis, &finding.path, DecisionKind::Trashed) {
        return Ok(Some(ReviewNotice::success(
            "This item was already moved to Trash from this scan.",
        )));
    }
    if has_decision(analysis, &finding.path, DecisionKind::Protected) {
        return Ok(Some(ReviewNotice::error(
            "Protected paths cannot be moved to Trash.",
        )));
    }
    if !confirm(ReviewAction::MoveToTrash, finding)? {
        return Ok(None);
    }

    let snapshot = match database.scanned_item(analysis.summary.id, &finding.path) {
        Ok(Some(snapshot)) => snapshot,
        Ok(None) => {
            return Ok(Some(ReviewNotice::error(
                "The saved scan snapshot is missing; scan again before acting.",
            )))
        }
        Err(error) => {
            return Ok(Some(ReviewNotice::error(format!(
                "Could not load the saved scan snapshot: {error}"
            ))))
        }
    };
    if let Err(error) = move_item_to_trash(&analysis.summary.root, &snapshot) {
        return Ok(Some(ReviewNotice::error(error.to_string())));
    }

    let recovered = estimated_recovery_bytes(finding, &snapshot);
    add_local_decision(
        analysis,
        &finding.path,
        DecisionKind::Trashed,
        recovered,
    );
    analysis.summary.recovered_space_bytes = analysis
        .summary
        .recovered_space_bytes
        .saturating_add(recovered);
    let notice = match database.record_trashed_item(
        analysis.summary.id,
        &finding.path,
        recovered,
    ) {
        Ok(()) => ReviewNotice::success(format!(
            "Moved to Trash ({}). Space may not be freed until Trash is emptied.",
            format_bytes(recovered)
        )),
        Err(error) => ReviewNotice::error(format!(
            "Moved to Trash, but history could not be updated: {error}"
        )),
    };
    Ok(Some(notice))
}

fn has_decision(analysis: &StoredAnalysis, path: &Path, decision: DecisionKind) -> bool {
    analysis
        .decisions
        .iter()
        .any(|entry| entry.path == path && entry.decision == decision)
}

fn add_local_decision(
    analysis: &mut StoredAnalysis,
    path: &Path,
    decision: DecisionKind,
    recovered_space_bytes: u64,
) {
    if has_decision(analysis, path, decision) {
        return;
    }
    let decided_at_epoch_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    analysis.decisions.push(UserDecision {
        scan_id: Some(analysis.summary.id),
        path: path.to_path_buf(),
        decision,
        recovered_space_bytes,
        decided_at_epoch_seconds,
    });
}

fn estimated_recovery_bytes(finding: &Finding, snapshot: &ScannedItem) -> u64 {
    if snapshot.kind == ItemKind::File && snapshot.hard_link_count.unwrap_or(1) > 1 {
        0
    } else {
        snapshot
            .allocated_size_bytes
            .unwrap_or(finding.potential_recovery_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spacemind_core::{
        AiReport, DuplicateReport, FindingCategory, RelationshipReport, RiskLevel, ScanResult,
        SuggestedAction,
    };
    use spacemind_db::Analysis;
    use std::path::PathBuf;

    fn finding() -> Finding {
        Finding {
            category: FindingCategory::LargeItem,
            path: PathBuf::from("/tmp/large.bin"),
            potential_recovery_bytes: 8192,
            confidence: 1.0,
            risk: RiskLevel::Low,
            evidence: Vec::new(),
            suggested_action: SuggestedAction::ReviewForDeletion,
        }
    }

    fn snapshot(finding: &Finding) -> ScannedItem {
        ScannedItem {
            path: finding.path.clone(),
            kind: ItemKind::File,
            size_bytes: finding.potential_recovery_bytes,
            allocated_size_bytes: Some(4096),
            file_identity: None,
            hard_link_count: Some(1),
            created_at_epoch_seconds: None,
            modified_at_epoch_seconds: None,
            modified_at_epoch_nanoseconds: None,
            accessed_at_epoch_seconds: None,
            extension: None,
        }
    }

    #[test]
    fn action_keys_are_explicit_and_do_not_overlap_navigation() {
        assert_eq!(
            ReviewAction::from_key(&KeyCode::Char('o')),
            Some(ReviewAction::OpenLocation)
        );
        assert_eq!(
            ReviewAction::from_key(&KeyCode::Char('i')),
            Some(ReviewAction::Ignore)
        );
        assert_eq!(
            ReviewAction::from_key(&KeyCode::Char('p')),
            Some(ReviewAction::Protect)
        );
        assert_eq!(
            ReviewAction::from_key(&KeyCode::Char('t')),
            Some(ReviewAction::MoveToTrash)
        );
        assert_eq!(ReviewAction::from_key(&KeyCode::Char('j')), None);
    }

    #[test]
    fn recovered_space_uses_allocated_bytes_and_does_not_count_hard_link_aliases() {
        let finding = finding();
        let mut snapshot = snapshot(&finding);

        assert_eq!(estimated_recovery_bytes(&finding, &snapshot), 4096);
        snapshot.hard_link_count = Some(2);
        assert_eq!(estimated_recovery_bytes(&finding, &snapshot), 0);
    }

    #[test]
    fn consecutive_choices_advance_the_queue_and_stay_resolved_in_history() {
        let mut database = Database::open_in_memory().unwrap();
        let first = finding();
        let mut second = first.clone();
        second.path = PathBuf::from("/tmp/next.bin");
        let scan = ScanResult {
            root: PathBuf::from("/tmp"),
            started_at_epoch_seconds: 1,
            completed_at_epoch_seconds: 2,
            total_size_bytes: 0,
            total_allocated_size_bytes: Some(0),
            file_count: 0,
            directory_count: 0,
            items: Vec::new(),
            ignored_paths: Vec::new(),
            warnings: Vec::new(),
        };
        let duplicates = DuplicateReport {
            groups: Vec::new(),
            warnings: Vec::new(),
            files_hashed: 0,
            bytes_hashed: 0,
            logical_duplicate_bytes: 0,
            potential_recovery_allocated_bytes: Some(0),
        };
        let relationships = RelationshipReport {
            relationships: Vec::new(),
            items_analyzed: 0,
        };
        let ai = AiReport::disabled();
        let scan_id = database
            .save_analysis(Analysis {
                scan: &scan,
                findings: &[first.clone(), second.clone()],
                duplicates: &duplicates,
                relationships: &relationships,
                ai: &ai,
            })
            .unwrap();
        let mut review = database.analysis(scan_id).unwrap().unwrap();

        handle_review_action(&mut database, &mut review, 0, ReviewAction::Ignore, |_, _| {
            Ok(true)
        })
        .unwrap();
        assert_eq!(review.findings.len(), 1);
        assert_eq!(review.findings[0].path, second.path);

        handle_review_action(&mut database, &mut review, 0, ReviewAction::Protect, |_, _| {
            Ok(true)
        })
        .unwrap();
        assert!(review.findings.is_empty());

        let mut reopened = database.analysis(scan_id).unwrap().unwrap();
        prune_resolved_findings(&mut reopened);
        assert!(reopened.findings.is_empty());
    }
}
