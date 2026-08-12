use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisPhase {
    Scanning,
    HashingDuplicates,
    BuildingRecommendations,
    Complete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgressEvent {
    pub phase: AnalysisPhase,
    pub items_processed: u64,
    pub bytes_processed: u64,
    pub total_items: Option<u64>,
    pub total_bytes: Option<u64>,
    pub current_path: Option<PathBuf>,
}

impl ProgressEvent {
    pub fn starting(phase: AnalysisPhase) -> Self {
        Self {
            phase,
            items_processed: 0,
            bytes_processed: 0,
            total_items: None,
            total_bytes: None,
            current_path: None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_is_shared_between_clones() {
        let first = CancellationToken::new();
        let second = first.clone();

        second.cancel();

        assert!(first.is_cancelled());
    }
}
