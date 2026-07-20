use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    File,
    Directory,
    Symlink,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScannedItem {
    pub path: PathBuf,
    pub kind: ItemKind,
    pub size_bytes: u64,
    pub created_at_epoch_seconds: Option<u64>,
    pub modified_at_epoch_seconds: Option<u64>,
    pub accessed_at_epoch_seconds: Option<u64>,
    pub extension: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanWarning {
    pub path: Option<PathBuf>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanResult {
    pub root: PathBuf,
    pub started_at_epoch_seconds: u64,
    pub completed_at_epoch_seconds: u64,
    pub total_size_bytes: u64,
    pub file_count: u64,
    pub directory_count: u64,
    pub items: Vec<ScannedItem>,
    pub warnings: Vec<ScanWarning>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingCategory {
    LargeItem,
    OldArchive,
    OldInstaller,
    GeneratedDirectory,
    CacheDirectory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuggestedAction {
    ReviewForDeletion,
    ReviewForArchive,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub category: FindingCategory,
    pub path: PathBuf,
    pub potential_recovery_bytes: u64,
    pub confidence: f32,
    pub risk: RiskLevel,
    pub evidence: Vec<String>,
    pub suggested_action: SuggestedAction,
}
