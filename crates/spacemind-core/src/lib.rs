use serde::{Deserialize, Serialize};
use std::path::PathBuf;

mod path_policy;
mod progress;
pub use path_policy::{PathMatcher, PathRule, PathRuleError};
pub use progress::{AnalysisPhase, CancellationToken, ProgressEvent};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FileIdentity {
    /// Identifies the filesystem or volume containing the file.
    pub volume_id: u64,
    /// Identifies the physical file within that filesystem or volume.
    pub file_id: u64,
}

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
    /// Logical file length, or the sum of descendant logical lengths for a directory.
    pub size_bytes: u64,
    /// Disk blocks used, when the platform exposes this information.
    pub allocated_size_bytes: Option<u64>,
    pub file_identity: Option<FileIdentity>,
    pub hard_link_count: Option<u64>,
    pub created_at_epoch_seconds: Option<u64>,
    pub modified_at_epoch_seconds: Option<u64>,
    pub modified_at_epoch_nanoseconds: Option<u64>,
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
    pub total_allocated_size_bytes: Option<u64>,
    pub file_count: u64,
    pub directory_count: u64,
    pub items: Vec<ScannedItem>,
    /// Paths omitted from the scan because they matched an ignore rule.
    pub ignored_paths: Vec<PathBuf>,
    pub warnings: Vec<ScanWarning>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DuplicateWarningKind {
    MetadataUnavailable,
    Unreadable,
    ChangedDuringDetection,
    NotRegularFile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DuplicateWarning {
    pub path: PathBuf,
    pub kind: DuplicateWarningKind,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DuplicateEntry {
    pub path: PathBuf,
    pub file_identity: Option<FileIdentity>,
    pub allocated_size_bytes: Option<u64>,
    pub hard_link_count: Option<u64>,
    /// Protected entries are evidence only and are never counted as recoverable.
    pub protected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DuplicateGroup {
    pub blake3_hash: String,
    pub size_bytes_per_file: u64,
    pub entries: Vec<DuplicateEntry>,
    /// Number of separately allocated files after hard-linked names are collapsed.
    pub unique_file_count: u64,
    /// Number of separately allocated copies covered by a protection rule.
    pub protected_file_count: u64,
    /// Logical bytes represented by all but one separately allocated copy.
    pub logical_duplicate_bytes: u64,
    /// Conservative allocated-space estimate that retains one physical copy.
    /// `None` means allocated size was unavailable for at least one physical copy.
    pub potential_recovery_allocated_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DuplicateReport {
    pub groups: Vec<DuplicateGroup>,
    pub warnings: Vec<DuplicateWarning>,
    pub files_hashed: u64,
    pub bytes_hashed: u64,
    pub logical_duplicate_bytes: u64,
    /// Total conservative allocated-space estimate, when every group has one.
    pub potential_recovery_allocated_bytes: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingCategory {
    LargeItem,
    OldArchive,
    OldInstaller,
    NodeModules,
    RustBuildArtifacts,
    GradleCache,
    AndroidEmulator,
    VirtualMachine,
    IsoImage,
    OperatingSystemCache,
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

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum RelationshipKind {
    ArchiveExtractedDirectory,
    InstallerApplicationDirectory,
    BuildDirectoryProject,
    VirtualMachineComponent,
    AndroidEmulatorConfiguration,
    ExactDuplicate,
}

/// A deterministic connection between two scanned items.
///
/// Relationships are evidence for explanations. They never authorize deletion.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Relationship {
    pub kind: RelationshipKind,
    pub source_path: PathBuf,
    pub target_path: PathBuf,
    pub confidence: f32,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RelationshipReport {
    pub relationships: Vec<Relationship>,
    pub items_analyzed: u64,
}
