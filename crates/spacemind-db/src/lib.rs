use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use spacemind_core::{
    AiExplanation, AiReport, AiStatus, CancellationToken, DuplicateEntry, DuplicateGroup,
    DuplicateReport, FileIdentity, Finding, Relationship, RelationshipReport, ScanResult,
    ScannedItem,
};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;

const SCHEMA_VERSION: i64 = 3;

const SCHEMA_V1: &str = r#"
BEGIN IMMEDIATE;

CREATE TABLE scans (
    id INTEGER PRIMARY KEY,
    root_path BLOB NOT NULL,
    started_at INTEGER NOT NULL,
    completed_at INTEGER NOT NULL,
    total_size_bytes INTEGER NOT NULL,
    total_allocated_size_bytes INTEGER,
    file_count INTEGER NOT NULL,
    directory_count INTEGER NOT NULL,
    scan_warning_count INTEGER NOT NULL,
    duplicate_warning_count INTEGER NOT NULL,
    recommendation_count INTEGER NOT NULL,
    duplicate_group_count INTEGER NOT NULL,
    relationship_count INTEGER NOT NULL,
    duplicate_recovery_bytes INTEGER,
    recovered_space_bytes INTEGER NOT NULL DEFAULT 0,
    recorded_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX scans_completed_at_idx ON scans(completed_at DESC);

CREATE TABLE scan_items (
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    path BLOB NOT NULL,
    kind TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    allocated_size_bytes INTEGER,
    volume_id INTEGER,
    file_id INTEGER,
    hard_link_count INTEGER,
    created_at INTEGER,
    modified_at INTEGER,
    modified_at_nanoseconds INTEGER,
    accessed_at INTEGER,
    extension TEXT,
    PRIMARY KEY (scan_id, path)
);

CREATE INDEX scan_items_size_idx ON scan_items(scan_id, size_bytes DESC);

CREATE TABLE recommendations (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    path BLOB NOT NULL,
    category TEXT NOT NULL,
    potential_recovery_bytes INTEGER NOT NULL,
    confidence REAL NOT NULL,
    risk TEXT NOT NULL,
    suggested_action TEXT NOT NULL,
    evidence_json TEXT NOT NULL
);

CREATE INDEX recommendations_scan_idx ON recommendations(scan_id);

CREATE TABLE duplicate_groups (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    blake3_hash TEXT NOT NULL,
    size_bytes_per_file INTEGER NOT NULL,
    unique_file_count INTEGER NOT NULL,
    protected_file_count INTEGER NOT NULL,
    logical_duplicate_bytes INTEGER NOT NULL,
    potential_recovery_bytes INTEGER
);

CREATE TABLE duplicate_entries (
    group_id INTEGER NOT NULL REFERENCES duplicate_groups(id) ON DELETE CASCADE,
    path BLOB NOT NULL,
    volume_id INTEGER,
    file_id INTEGER,
    allocated_size_bytes INTEGER,
    hard_link_count INTEGER,
    protected INTEGER NOT NULL,
    PRIMARY KEY (group_id, path)
);

CREATE TABLE relationships (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    source_path BLOB NOT NULL,
    target_path BLOB NOT NULL,
    confidence REAL NOT NULL,
    evidence_json TEXT NOT NULL
);

CREATE INDEX relationships_scan_idx ON relationships(scan_id);

CREATE TABLE ignored_paths (
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    path BLOB NOT NULL,
    PRIMARY KEY (scan_id, path)
);

CREATE TABLE user_decisions (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id) ON DELETE SET NULL,
    path BLOB NOT NULL,
    decision TEXT NOT NULL,
    recovered_space_bytes INTEGER NOT NULL DEFAULT 0,
    decided_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE protected_paths (
    id INTEGER PRIMARY KEY,
    rule_kind TEXT NOT NULL,
    value TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE(rule_kind, value)
);

CREATE TABLE ignored_items (
    id INTEGER PRIMARY KEY,
    rule_kind TEXT NOT NULL,
    value TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE(rule_kind, value)
);

CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

PRAGMA user_version = 1;
COMMIT;
"#;

const SCHEMA_V2: &str = r#"
BEGIN IMMEDIATE;

ALTER TABLE scans ADD COLUMN ai_status TEXT NOT NULL DEFAULT 'disabled';
ALTER TABLE scans ADD COLUMN ai_model TEXT;
ALTER TABLE scans ADD COLUMN ai_status_detail TEXT;
ALTER TABLE scans ADD COLUMN ai_candidate_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE scans ADD COLUMN ai_warning_count INTEGER NOT NULL DEFAULT 0;

CREATE TABLE ai_explanations (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    path BLOB NOT NULL,
    category TEXT NOT NULL,
    risk TEXT NOT NULL,
    confidence REAL NOT NULL,
    reason TEXT NOT NULL,
    suggested_action TEXT NOT NULL
);

CREATE INDEX ai_explanations_scan_idx ON ai_explanations(scan_id);

PRAGMA user_version = 2;
COMMIT;
"#;

const SCHEMA_V3: &str = r#"
BEGIN IMMEDIATE;

CREATE TABLE analysis_warnings (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    path BLOB,
    kind TEXT,
    message TEXT NOT NULL
);

CREATE INDEX analysis_warnings_scan_idx ON analysis_warnings(scan_id);

PRAGMA user_version = 3;
COMMIT;
"#;

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("cannot create database directory {path}: {source}")]
    CreateDirectory { path: PathBuf, source: std::io::Error },
    #[error("cannot determine a local data directory; set SPACEMIND_DATABASE")]
    DataDirectoryUnavailable,
    #[error("database schema version {found} is not supported; expected {supported}")]
    UnsupportedSchemaVersion { found: i64, supported: i64 },
    #[error("{field} is too large to store in SQLite: {value}")]
    IntegerOutOfRange { field: &'static str, value: u64 },
    #[error("invalid negative value in database column {field}: {value}")]
    InvalidStoredInteger { field: &'static str, value: i64 },
    #[error("database write cancelled; no scan history was saved")]
    Cancelled,
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, DatabaseError>;

#[derive(Debug)]
pub struct Database {
    connection: Connection,
}

#[derive(Debug, Clone, Copy)]
pub struct Analysis<'a> {
    pub scan: &'a ScanResult,
    pub findings: &'a [Finding],
    pub duplicates: &'a DuplicateReport,
    pub relationships: &'a RelationshipReport,
    pub ai: &'a AiReport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanHistoryEntry {
    pub id: i64,
    #[serde(serialize_with = "serialize_path", deserialize_with = "deserialize_path")]
    pub root: PathBuf,
    pub started_at_epoch_seconds: u64,
    pub completed_at_epoch_seconds: u64,
    pub total_size_bytes: u64,
    pub total_allocated_size_bytes: Option<u64>,
    pub file_count: u64,
    pub directory_count: u64,
    pub recommendation_count: u64,
    pub duplicate_group_count: u64,
    pub relationship_count: u64,
    pub warning_count: u64,
    pub duplicate_recovery_bytes: Option<u64>,
    pub recovered_space_bytes: u64,
    pub ai_status: String,
    pub ai_model: Option<String>,
    pub ai_candidate_count: u64,
    pub ai_explanation_count: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredAnalysis {
    pub summary: ScanHistoryEntry,
    pub findings: Vec<Finding>,
    pub duplicate_groups: Vec<DuplicateGroup>,
    pub relationships: Vec<Relationship>,
    pub ai_explanations: Vec<AiExplanation>,
    pub warnings: Vec<StoredWarning>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredWarning {
    pub source: String,
    pub path: Option<PathBuf>,
    pub kind: Option<String>,
    pub message: String,
}

impl Database {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
            fs::create_dir_all(parent).map_err(|source| DatabaseError::CreateDirectory {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let connection = Connection::open(path)?;
        Self::initialize(connection)
    }

    pub fn open_in_memory() -> Result<Self> {
        Self::initialize(Connection::open_in_memory()?)
    }

    fn initialize(connection: Connection) -> Result<Self> {
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch("PRAGMA foreign_keys = ON;")?;
        let mut database = Self { connection };
        database.migrate()?;
        Ok(database)
    }

    fn migrate(&mut self) -> Result<()> {
        let version: i64 = self
            .connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))?;
        match version {
            0 => {
                self.connection.execute_batch(SCHEMA_V1)?;
                self.connection.execute_batch(SCHEMA_V2)?;
                self.connection.execute_batch(SCHEMA_V3)?;
            }
            1 => {
                self.connection.execute_batch(SCHEMA_V2)?;
                self.connection.execute_batch(SCHEMA_V3)?;
            }
            2 => self.connection.execute_batch(SCHEMA_V3)?,
            SCHEMA_VERSION => {}
            found => {
                return Err(DatabaseError::UnsupportedSchemaVersion {
                    found,
                    supported: SCHEMA_VERSION,
                })
            }
        }
        Ok(())
    }

    pub fn save_analysis(&mut self, analysis: Analysis<'_>) -> Result<i64> {
        self.save_analysis_with_cancellation(analysis, &CancellationToken::new())
    }

    pub fn save_analysis_with_cancellation(
        &mut self,
        analysis: Analysis<'_>,
        cancellation: &CancellationToken,
    ) -> Result<i64> {
        check_cancelled(cancellation)?;
        validate_analysis_numbers(analysis)?;
        let transaction = self.connection.transaction()?;
        let scan_id = insert_scan(&transaction, analysis)?;
        insert_items(&transaction, scan_id, analysis.scan, cancellation)?;
        insert_findings(&transaction, scan_id, analysis.findings, cancellation)?;
        insert_duplicates(
            &transaction,
            scan_id,
            analysis.duplicates,
            cancellation,
        )?;
        insert_relationships(
            &transaction,
            scan_id,
            analysis.relationships,
            cancellation,
        )?;
        insert_ai_explanations(&transaction, scan_id, analysis.ai, cancellation)?;
        insert_warnings(&transaction, scan_id, analysis, cancellation)?;
        insert_ignored_paths(&transaction, scan_id, analysis.scan, cancellation)?;
        check_cancelled(cancellation)?;
        transaction.commit()?;
        Ok(scan_id)
    }

    pub fn scan_history(&self, limit: usize) -> Result<Vec<ScanHistoryEntry>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut statement = self.connection.prepare(
            "SELECT id, root_path, started_at, completed_at, total_size_bytes, \
                    total_allocated_size_bytes, file_count, directory_count, \
                    recommendation_count, duplicate_group_count, relationship_count, \
                    scan_warning_count + duplicate_warning_count, duplicate_recovery_bytes, \
                    recovered_space_bytes, ai_status, ai_model, ai_candidate_count, \
                    (SELECT COUNT(*) FROM ai_explanations WHERE scan_id = scans.id) \
             FROM scans ORDER BY completed_at DESC, id DESC LIMIT ?1",
        )?;
        let rows = statement.query_map([limit], read_history_row)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub fn scan(&self, scan_id: i64) -> Result<Option<ScanHistoryEntry>> {
        self.connection
            .query_row(
                "SELECT id, root_path, started_at, completed_at, total_size_bytes, \
                        total_allocated_size_bytes, file_count, directory_count, \
                        recommendation_count, duplicate_group_count, relationship_count, \
                        scan_warning_count + duplicate_warning_count, duplicate_recovery_bytes, \
                        recovered_space_bytes, ai_status, ai_model, ai_candidate_count, \
                        (SELECT COUNT(*) FROM ai_explanations WHERE scan_id = scans.id) \
                 FROM scans WHERE id = ?1",
                [scan_id],
                read_history_row,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn analysis(&self, scan_id: i64) -> Result<Option<StoredAnalysis>> {
        let Some(summary) = self.scan(scan_id)? else {
            return Ok(None);
        };
        Ok(Some(StoredAnalysis {
            summary,
            findings: self.findings(scan_id)?,
            duplicate_groups: self.duplicate_groups(scan_id)?,
            relationships: self.relationships(scan_id)?,
            ai_explanations: self.ai_explanations(scan_id)?,
            warnings: self.warnings(scan_id)?,
        }))
    }

    fn findings(&self, scan_id: i64) -> Result<Vec<Finding>> {
        let mut statement = self.connection.prepare(
            "SELECT path, category, potential_recovery_bytes, confidence, risk, \
             evidence_json, suggested_action FROM recommendations \
             WHERE scan_id = ?1 ORDER BY potential_recovery_bytes DESC, path",
        )?;
        let mut rows = statement.query([scan_id])?;
        let mut findings = Vec::new();
        while let Some(row) = rows.next()? {
            findings.push(Finding {
                path: stored_path(row.get(0)?)?,
                category: deserialized_name(&row.get::<_, String>(1)?)?,
                potential_recovery_bytes: stored_integer(
                    row.get(2)?,
                    "finding.potential_recovery_bytes",
                )?,
                confidence: row.get::<_, f64>(3)? as f32,
                risk: deserialized_name(&row.get::<_, String>(4)?)?,
                evidence: serde_json::from_str(&row.get::<_, String>(5)?)?,
                suggested_action: deserialized_name(&row.get::<_, String>(6)?)?,
            });
        }
        findings.sort_by(|left, right| {
            stored_action_rank(left.suggested_action)
                .cmp(&stored_action_rank(right.suggested_action))
                .then_with(|| stored_risk_rank(left.risk).cmp(&stored_risk_rank(right.risk)))
                .then_with(|| right.confidence.total_cmp(&left.confidence))
                .then_with(|| {
                    right
                        .potential_recovery_bytes
                        .cmp(&left.potential_recovery_bytes)
                })
                .then_with(|| left.path.cmp(&right.path))
        });
        Ok(findings)
    }

    fn duplicate_groups(&self, scan_id: i64) -> Result<Vec<DuplicateGroup>> {
        let mut group_statement = self.connection.prepare(
            "SELECT id, blake3_hash, size_bytes_per_file, unique_file_count, \
             protected_file_count, logical_duplicate_bytes, potential_recovery_bytes \
             FROM duplicate_groups WHERE scan_id = ?1 ORDER BY logical_duplicate_bytes DESC, id",
        )?;
        let mut entry_statement = self.connection.prepare(
            "SELECT path, volume_id, file_id, allocated_size_bytes, hard_link_count, protected \
             FROM duplicate_entries WHERE group_id = ?1 ORDER BY path",
        )?;
        let mut rows = group_statement.query([scan_id])?;
        let mut groups = Vec::new();
        while let Some(row) = rows.next()? {
            let group_id: i64 = row.get(0)?;
            let mut entry_rows = entry_statement.query([group_id])?;
            let mut entries = Vec::new();
            while let Some(entry) = entry_rows.next()? {
                let volume_id = stored_optional_integer(entry.get(1)?, "duplicate.volume_id")?;
                let file_id = stored_optional_integer(entry.get(2)?, "duplicate.file_id")?;
                entries.push(DuplicateEntry {
                    path: stored_path(entry.get(0)?)?,
                    file_identity: match (volume_id, file_id) {
                        (Some(volume_id), Some(file_id)) => Some(FileIdentity {
                            volume_id,
                            file_id,
                        }),
                        _ => None,
                    },
                    allocated_size_bytes: stored_optional_integer(
                        entry.get(3)?,
                        "duplicate.allocated_size_bytes",
                    )?,
                    hard_link_count: stored_optional_integer(
                        entry.get(4)?,
                        "duplicate.hard_link_count",
                    )?,
                    protected: entry.get(5)?,
                });
            }
            groups.push(DuplicateGroup {
                blake3_hash: row.get(1)?,
                size_bytes_per_file: stored_integer(row.get(2)?, "duplicate.size_bytes_per_file")?,
                unique_file_count: stored_integer(row.get(3)?, "duplicate.unique_file_count")?,
                protected_file_count: stored_integer(
                    row.get(4)?,
                    "duplicate.protected_file_count",
                )?,
                logical_duplicate_bytes: stored_integer(
                    row.get(5)?,
                    "duplicate.logical_duplicate_bytes",
                )?,
                potential_recovery_allocated_bytes: stored_optional_integer(
                    row.get(6)?,
                    "duplicate.potential_recovery_allocated_bytes",
                )?,
                entries,
            });
        }
        Ok(groups)
    }

    fn relationships(&self, scan_id: i64) -> Result<Vec<Relationship>> {
        let mut statement = self.connection.prepare(
            "SELECT kind, source_path, target_path, confidence, evidence_json \
             FROM relationships WHERE scan_id = ?1 ORDER BY kind, source_path, target_path",
        )?;
        let mut rows = statement.query([scan_id])?;
        let mut relationships = Vec::new();
        while let Some(row) = rows.next()? {
            relationships.push(Relationship {
                kind: deserialized_name(&row.get::<_, String>(0)?)?,
                source_path: stored_path(row.get(1)?)?,
                target_path: stored_path(row.get(2)?)?,
                confidence: row.get::<_, f64>(3)? as f32,
                evidence: serde_json::from_str(&row.get::<_, String>(4)?)?,
            });
        }
        Ok(relationships)
    }

    fn ai_explanations(&self, scan_id: i64) -> Result<Vec<AiExplanation>> {
        let mut statement = self.connection.prepare(
            "SELECT path, category, risk, confidence, reason, suggested_action \
             FROM ai_explanations WHERE scan_id = ?1 ORDER BY path",
        )?;
        let mut rows = statement.query([scan_id])?;
        let mut explanations = Vec::new();
        while let Some(row) = rows.next()? {
            explanations.push(AiExplanation {
                path: stored_path(row.get(0)?)?,
                category: deserialized_name(&row.get::<_, String>(1)?)?,
                risk: deserialized_name(&row.get::<_, String>(2)?)?,
                confidence: row.get::<_, f64>(3)? as f32,
                reason: row.get(4)?,
                suggested_action: deserialized_name(&row.get::<_, String>(5)?)?,
            });
        }
        Ok(explanations)
    }

    fn warnings(&self, scan_id: i64) -> Result<Vec<StoredWarning>> {
        let mut statement = self.connection.prepare(
            "SELECT source, path, kind, message FROM analysis_warnings \
             WHERE scan_id = ?1 ORDER BY id",
        )?;
        let mut rows = statement.query([scan_id])?;
        let mut warnings = Vec::new();
        while let Some(row) = rows.next()? {
            let path = row
                .get::<_, Option<Vec<u8>>>(1)?
                .map(stored_path)
                .transpose()?;
            warnings.push(StoredWarning {
                source: row.get(0)?,
                path,
                kind: row.get(2)?,
                message: row.get(3)?,
            });
        }
        Ok(warnings)
    }

    #[cfg(test)]
    fn row_count(&self, table: &str) -> i64 {
        self.connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row.get(0))
            .unwrap()
    }
}

pub fn default_database_path() -> Result<PathBuf> {
    if let Some(path) = env::var_os("SPACEMIND_DATABASE").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(path));
    }

    #[cfg(windows)]
    if let Some(path) = env::var_os("LOCALAPPDATA").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(path).join("SpaceMind").join("spacemind.db"));
    }

    #[cfg(not(windows))]
    {
        if let Some(path) = env::var_os("XDG_DATA_HOME").filter(|value| !value.is_empty()) {
            return Ok(PathBuf::from(path).join("spacemind").join("spacemind.db"));
        }
        if let Some(home) = env::var_os("HOME") {
            return Ok(PathBuf::from(home)
                .join(".local")
                .join("share")
                .join("spacemind")
                .join("spacemind.db"));
        }
    }

    Err(DatabaseError::DataDirectoryUnavailable)
}

fn insert_scan(transaction: &Transaction<'_>, analysis: Analysis<'_>) -> Result<i64> {
    let scan = analysis.scan;
    let (ai_status, ai_model, ai_status_detail) = ai_status_parts(&analysis.ai.status);
    transaction.execute(
        "INSERT INTO scans (root_path, started_at, completed_at, total_size_bytes, \
         total_allocated_size_bytes, file_count, directory_count, scan_warning_count, \
         duplicate_warning_count, recommendation_count, duplicate_group_count, \
         relationship_count, duplicate_recovery_bytes, ai_status, ai_model, ai_status_detail, \
         ai_candidate_count, ai_warning_count) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
        params![
            path_bytes(&scan.root),
            integer(scan.started_at_epoch_seconds, "scan.started_at")?,
            integer(scan.completed_at_epoch_seconds, "scan.completed_at")?,
            integer(scan.total_size_bytes, "scan.total_size_bytes")?,
            optional_integer(scan.total_allocated_size_bytes, "scan.total_allocated_size_bytes")?,
            integer(scan.file_count, "scan.file_count")?,
            integer(scan.directory_count, "scan.directory_count")?,
            integer(scan.warnings.len() as u64, "scan.warning_count")?,
            integer(analysis.duplicates.warnings.len() as u64, "duplicate.warning_count")?,
            integer(analysis.findings.len() as u64, "recommendation.count")?,
            integer(analysis.duplicates.groups.len() as u64, "duplicate.group_count")?,
            integer(analysis.relationships.relationships.len() as u64, "relationship.count")?,
            optional_integer(
                analysis.duplicates.potential_recovery_allocated_bytes,
                "duplicate.potential_recovery_allocated_bytes"
            )?,
            ai_status,
            ai_model,
            ai_status_detail,
            integer(analysis.ai.candidates_considered, "ai.candidate_count")?,
            integer(analysis.ai.warnings.len() as u64, "ai.warning_count")?,
        ],
    )?;
    Ok(transaction.last_insert_rowid())
}

fn insert_items(
    transaction: &Transaction<'_>,
    scan_id: i64,
    scan: &ScanResult,
    cancellation: &CancellationToken,
) -> Result<()> {
    let mut statement = transaction.prepare_cached(
        "INSERT INTO scan_items (scan_id, path, kind, size_bytes, allocated_size_bytes, \
         volume_id, file_id, hard_link_count, created_at, modified_at, \
         modified_at_nanoseconds, accessed_at, extension) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
    )?;
    for item in &scan.items {
        check_cancelled(cancellation)?;
        insert_item(&mut statement, scan_id, item)?;
    }
    Ok(())
}

fn insert_item(
    statement: &mut rusqlite::CachedStatement<'_>,
    scan_id: i64,
    item: &ScannedItem,
) -> Result<()> {
    let (volume_id, file_id) = match item.file_identity {
        Some(identity) => (
            Some(integer(identity.volume_id, "item.volume_id")?),
            Some(integer(identity.file_id, "item.file_id")?),
        ),
        None => (None, None),
    };
    statement.execute(params![
        scan_id,
        path_bytes(&item.path),
        serialized_name(&item.kind)?,
        integer(item.size_bytes, "item.size_bytes")?,
        optional_integer(item.allocated_size_bytes, "item.allocated_size_bytes")?,
        volume_id,
        file_id,
        optional_integer(item.hard_link_count, "item.hard_link_count")?,
        optional_integer(item.created_at_epoch_seconds, "item.created_at")?,
        optional_integer(item.modified_at_epoch_seconds, "item.modified_at")?,
        optional_integer(
            item.modified_at_epoch_nanoseconds,
            "item.modified_at_nanoseconds"
        )?,
        optional_integer(item.accessed_at_epoch_seconds, "item.accessed_at")?,
        item.extension,
    ])?;
    Ok(())
}

fn insert_findings(
    transaction: &Transaction<'_>,
    scan_id: i64,
    findings: &[Finding],
    cancellation: &CancellationToken,
) -> Result<()> {
    let mut statement = transaction.prepare_cached(
        "INSERT INTO recommendations (scan_id, path, category, potential_recovery_bytes, \
         confidence, risk, suggested_action, evidence_json) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )?;
    for finding in findings {
        check_cancelled(cancellation)?;
        statement.execute(params![
            scan_id,
            path_bytes(&finding.path),
            serialized_name(&finding.category)?,
            integer(
                finding.potential_recovery_bytes,
                "finding.potential_recovery_bytes"
            )?,
            f64::from(finding.confidence),
            serialized_name(&finding.risk)?,
            serialized_name(&finding.suggested_action)?,
            serde_json::to_string(&finding.evidence)?,
        ])?;
    }
    Ok(())
}

fn insert_duplicates(
    transaction: &Transaction<'_>,
    scan_id: i64,
    duplicates: &DuplicateReport,
    cancellation: &CancellationToken,
) -> Result<()> {
    let mut group_statement = transaction.prepare_cached(
        "INSERT INTO duplicate_groups (scan_id, blake3_hash, size_bytes_per_file, \
         unique_file_count, protected_file_count, logical_duplicate_bytes, \
         potential_recovery_bytes) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )?;
    let mut entry_statement = transaction.prepare_cached(
        "INSERT INTO duplicate_entries (group_id, path, volume_id, file_id, \
         allocated_size_bytes, hard_link_count, protected) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )?;
    for group in &duplicates.groups {
        check_cancelled(cancellation)?;
        group_statement.execute(params![
            scan_id,
            group.blake3_hash,
            integer(group.size_bytes_per_file, "duplicate.size_bytes_per_file")?,
            integer(group.unique_file_count, "duplicate.unique_file_count")?,
            integer(group.protected_file_count, "duplicate.protected_file_count")?,
            integer(group.logical_duplicate_bytes, "duplicate.logical_duplicate_bytes")?,
            optional_integer(
                group.potential_recovery_allocated_bytes,
                "duplicate.potential_recovery_allocated_bytes"
            )?,
        ])?;
        let group_id = transaction.last_insert_rowid();
        for entry in &group.entries {
            check_cancelled(cancellation)?;
            let (volume_id, file_id) = match entry.file_identity {
                Some(identity) => (
                    Some(integer(identity.volume_id, "duplicate.volume_id")?),
                    Some(integer(identity.file_id, "duplicate.file_id")?),
                ),
                None => (None, None),
            };
            entry_statement.execute(params![
                group_id,
                path_bytes(&entry.path),
                volume_id,
                file_id,
                optional_integer(
                    entry.allocated_size_bytes,
                    "duplicate.allocated_size_bytes"
                )?,
                optional_integer(entry.hard_link_count, "duplicate.hard_link_count")?,
                entry.protected,
            ])?;
        }
    }
    Ok(())
}

fn insert_relationships(
    transaction: &Transaction<'_>,
    scan_id: i64,
    relationships: &RelationshipReport,
    cancellation: &CancellationToken,
) -> Result<()> {
    let mut statement = transaction.prepare_cached(
        "INSERT INTO relationships (scan_id, kind, source_path, target_path, confidence, \
         evidence_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )?;
    for relationship in &relationships.relationships {
        check_cancelled(cancellation)?;
        statement.execute(params![
            scan_id,
            serialized_name(&relationship.kind)?,
            path_bytes(&relationship.source_path),
            path_bytes(&relationship.target_path),
            f64::from(relationship.confidence),
            serde_json::to_string(&relationship.evidence)?,
        ])?;
    }
    Ok(())
}

fn insert_ignored_paths(
    transaction: &Transaction<'_>,
    scan_id: i64,
    scan: &ScanResult,
    cancellation: &CancellationToken,
) -> Result<()> {
    let mut statement = transaction.prepare_cached(
        "INSERT INTO ignored_paths (scan_id, path) VALUES (?1, ?2)",
    )?;
    for path in &scan.ignored_paths {
        check_cancelled(cancellation)?;
        statement.execute(params![scan_id, path_bytes(path)])?;
    }
    Ok(())
}

fn insert_ai_explanations(
    transaction: &Transaction<'_>,
    scan_id: i64,
    ai: &AiReport,
    cancellation: &CancellationToken,
) -> Result<()> {
    let mut statement = transaction.prepare_cached(
        "INSERT INTO ai_explanations (scan_id, path, category, risk, confidence, reason, \
         suggested_action) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )?;
    for explanation in &ai.explanations {
        check_cancelled(cancellation)?;
        statement.execute(params![
            scan_id,
            path_bytes(&explanation.path),
            serialized_name(&explanation.category)?,
            serialized_name(&explanation.risk)?,
            f64::from(explanation.confidence),
            explanation.reason,
            serialized_name(&explanation.suggested_action)?,
        ])?;
    }
    Ok(())
}

fn insert_warnings(
    transaction: &Transaction<'_>,
    scan_id: i64,
    analysis: Analysis<'_>,
    cancellation: &CancellationToken,
) -> Result<()> {
    let mut statement = transaction.prepare_cached(
        "INSERT INTO analysis_warnings (scan_id, source, path, kind, message) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )?;
    for warning in &analysis.scan.warnings {
        check_cancelled(cancellation)?;
        statement.execute(params![
            scan_id,
            "scan",
            warning.path.as_deref().map(path_bytes),
            Option::<String>::None,
            warning.message,
        ])?;
    }
    for warning in &analysis.duplicates.warnings {
        check_cancelled(cancellation)?;
        statement.execute(params![
            scan_id,
            "duplicate",
            path_bytes(&warning.path),
            serialized_name(&warning.kind)?,
            warning.message,
        ])?;
    }
    Ok(())
}

fn ai_status_parts(status: &AiStatus) -> (&'static str, Option<&str>, Option<&str>) {
    match status {
        AiStatus::Disabled => ("disabled", None, None),
        AiStatus::NoCandidates => ("no_candidates", None, None),
        AiStatus::Unavailable { reason } => ("unavailable", None, Some(reason)),
        AiStatus::Complete { model } => ("complete", Some(model), None),
        AiStatus::Partial { model } => ("partial", Some(model), None),
    }
}

fn validate_analysis_numbers(analysis: Analysis<'_>) -> Result<()> {
    integer(analysis.scan.started_at_epoch_seconds, "scan.started_at")?;
    integer(analysis.scan.completed_at_epoch_seconds, "scan.completed_at")?;
    integer(analysis.scan.total_size_bytes, "scan.total_size_bytes")?;
    optional_integer(
        analysis.scan.total_allocated_size_bytes,
        "scan.total_allocated_size_bytes",
    )?;
    Ok(())
}

fn check_cancelled(cancellation: &CancellationToken) -> Result<()> {
    if cancellation.is_cancelled() {
        Err(DatabaseError::Cancelled)
    } else {
        Ok(())
    }
}

fn integer(value: u64, field: &'static str) -> Result<i64> {
    i64::try_from(value).map_err(|_| DatabaseError::IntegerOutOfRange { field, value })
}

fn optional_integer(value: Option<u64>, field: &'static str) -> Result<Option<i64>> {
    value.map(|value| integer(value, field)).transpose()
}

fn stored_integer(value: i64, field: &'static str) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Integer,
            Box::new(DatabaseError::InvalidStoredInteger { field, value }),
        )
    })
}

fn stored_optional_integer(
    value: Option<i64>,
    field: &'static str,
) -> rusqlite::Result<Option<u64>> {
    value.map(|value| stored_integer(value, field)).transpose()
}

fn read_history_row(row: &Row<'_>) -> rusqlite::Result<ScanHistoryEntry> {
    Ok(ScanHistoryEntry {
        id: row.get(0)?,
        root: stored_path(row.get(1)?)?,
        started_at_epoch_seconds: stored_integer(row.get(2)?, "started_at")?,
        completed_at_epoch_seconds: stored_integer(row.get(3)?, "completed_at")?,
        total_size_bytes: stored_integer(row.get(4)?, "total_size_bytes")?,
        total_allocated_size_bytes: stored_optional_integer(
            row.get(5)?,
            "total_allocated_size_bytes",
        )?,
        file_count: stored_integer(row.get(6)?, "file_count")?,
        directory_count: stored_integer(row.get(7)?, "directory_count")?,
        recommendation_count: stored_integer(row.get(8)?, "recommendation_count")?,
        duplicate_group_count: stored_integer(row.get(9)?, "duplicate_group_count")?,
        relationship_count: stored_integer(row.get(10)?, "relationship_count")?,
        warning_count: stored_integer(row.get(11)?, "warning_count")?,
        duplicate_recovery_bytes: stored_optional_integer(
            row.get(12)?,
            "duplicate_recovery_bytes",
        )?,
        recovered_space_bytes: stored_integer(row.get(13)?, "recovered_space_bytes")?,
        ai_status: row.get(14)?,
        ai_model: row.get(15)?,
        ai_candidate_count: stored_integer(row.get(16)?, "ai_candidate_count")?,
        ai_explanation_count: stored_integer(row.get(17)?, "ai_explanation_count")?,
    })
}

fn serialized_name<T: Serialize>(value: &T) -> Result<String> {
    match serde_json::to_value(value)? {
        serde_json::Value::String(value) => Ok(value),
        value => Ok(value.to_string()),
    }
}

fn deserialized_name<T: for<'de> Deserialize<'de>>(value: &str) -> Result<T> {
    serde_json::from_value(serde_json::Value::String(value.to_owned())).map_err(Into::into)
}

fn stored_action_rank(action: spacemind_core::SuggestedAction) -> u8 {
    match action {
        spacemind_core::SuggestedAction::ReviewForDeletion => 0,
        spacemind_core::SuggestedAction::ReviewForArchive => 1,
    }
}

fn stored_risk_rank(risk: spacemind_core::RiskLevel) -> u8 {
    match risk {
        spacemind_core::RiskLevel::Low => 0,
        spacemind_core::RiskLevel::Medium => 1,
        spacemind_core::RiskLevel::High => 2,
    }
}

fn serialize_path<S>(path: &Path, serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&path.to_string_lossy())
}

fn deserialize_path<'de, D>(deserializer: D) -> std::result::Result<PathBuf, D::Error>
where
    D: Deserializer<'de>,
{
    String::deserialize(deserializer).map(PathBuf::from)
}

#[cfg(unix)]
fn path_bytes(path: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    path.as_os_str().as_bytes().to_vec()
}

#[cfg(windows)]
fn path_bytes(path: &Path) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;
    path.as_os_str()
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect()
}

#[cfg(unix)]
fn stored_path(bytes: Vec<u8>) -> rusqlite::Result<PathBuf> {
    use std::os::unix::ffi::OsStringExt;
    Ok(PathBuf::from(OsString::from_vec(bytes)))
}

#[cfg(windows)]
fn stored_path(bytes: Vec<u8>) -> rusqlite::Result<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    if bytes.len() % 2 != 0 {
        return Err(invalid_path_blob(bytes));
    }
    let wide = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    Ok(PathBuf::from(OsString::from_wide(&wide)))
}

#[cfg(windows)]
fn invalid_path_blob(bytes: Vec<u8>) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        1,
        rusqlite::types::Type::Blob,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("stored path contains an odd number of bytes: {}", bytes.len()),
        )),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use spacemind_core::{
        AiCategory, AiExplanation, AiSuggestedAction, DuplicateEntry, DuplicateGroup, FileIdentity,
        DuplicateWarning, DuplicateWarningKind, FindingCategory, ItemKind, Relationship,
        RelationshipKind, RiskLevel, ScanWarning, SuggestedAction,
    };

    fn sample_scan() -> ScanResult {
        ScanResult {
            root: PathBuf::from("/home/example/Downloads"),
            started_at_epoch_seconds: 100,
            completed_at_epoch_seconds: 110,
            total_size_bytes: 24,
            total_allocated_size_bytes: Some(32),
            file_count: 2,
            directory_count: 1,
            items: vec![ScannedItem {
                path: PathBuf::from("/home/example/Downloads/archive.zip"),
                kind: ItemKind::File,
                size_bytes: 12,
                allocated_size_bytes: Some(16),
                file_identity: Some(FileIdentity {
                    volume_id: 1,
                    file_id: 2,
                }),
                hard_link_count: Some(1),
                created_at_epoch_seconds: Some(50),
                modified_at_epoch_seconds: Some(60),
                modified_at_epoch_nanoseconds: Some(60_000_000_000),
                accessed_at_epoch_seconds: Some(70),
                extension: Some("zip".to_owned()),
            }],
            ignored_paths: vec![PathBuf::from("/home/example/Downloads/node_modules")],
            warnings: vec![ScanWarning {
                path: Some(PathBuf::from("/home/example/Downloads/unreadable")),
                message: "Permission denied".to_owned(),
            }],
        }
    }

    fn sample_finding() -> Finding {
        Finding {
            category: FindingCategory::OldArchive,
            path: PathBuf::from("/home/example/Downloads/archive.zip"),
            potential_recovery_bytes: 12,
            confidence: 0.9,
            risk: RiskLevel::Low,
            evidence: vec!["Old archive".to_owned()],
            suggested_action: SuggestedAction::ReviewForDeletion,
        }
    }

    fn sample_duplicates() -> DuplicateReport {
        DuplicateReport {
            groups: vec![DuplicateGroup {
                blake3_hash: "abc123".to_owned(),
                size_bytes_per_file: 12,
                entries: vec![DuplicateEntry {
                    path: PathBuf::from("/home/example/Downloads/archive.zip"),
                    file_identity: None,
                    allocated_size_bytes: Some(16),
                    hard_link_count: Some(1),
                    protected: false,
                }],
                unique_file_count: 2,
                protected_file_count: 0,
                logical_duplicate_bytes: 12,
                potential_recovery_allocated_bytes: Some(16),
            }],
            warnings: vec![DuplicateWarning {
                path: PathBuf::from("/home/example/Downloads/changing.zip"),
                kind: DuplicateWarningKind::ChangedDuringDetection,
                message: "File changed while hashing".to_owned(),
            }],
            files_hashed: 2,
            bytes_hashed: 24,
            logical_duplicate_bytes: 12,
            potential_recovery_allocated_bytes: Some(16),
        }
    }

    fn sample_relationships() -> RelationshipReport {
        RelationshipReport {
            relationships: vec![Relationship {
                kind: RelationshipKind::ArchiveExtractedDirectory,
                source_path: PathBuf::from("/home/example/Downloads/archive.zip"),
                target_path: PathBuf::from("/home/example/Downloads/archive"),
                confidence: 0.95,
                evidence: vec!["Matching name".to_owned()],
            }],
            items_analyzed: 1,
        }
    }

    fn sample_ai() -> AiReport {
        AiReport {
            status: AiStatus::Complete {
                model: "qwen3:4b".to_owned(),
            },
            candidates_considered: 1,
            explanations: vec![AiExplanation {
                path: PathBuf::from("/home/example/Downloads/archive.zip"),
                category: AiCategory::ArchiveWithExtractedCopy,
                risk: RiskLevel::Low,
                confidence: 0.91,
                reason: "An extracted sibling was found; inspect both before deciding.".to_owned(),
                suggested_action: AiSuggestedAction::ReviewForDeletion,
            }],
            warnings: Vec::new(),
        }
    }

    #[test]
    fn migrates_an_empty_database_and_persists_a_complete_analysis() {
        let mut database = Database::open_in_memory().unwrap();
        let scan = sample_scan();
        let findings = vec![sample_finding()];
        let duplicates = sample_duplicates();
        let relationships = sample_relationships();
        let ai = sample_ai();

        let id = database
            .save_analysis(Analysis {
                scan: &scan,
                findings: &findings,
                duplicates: &duplicates,
                relationships: &relationships,
                ai: &ai,
            })
            .unwrap();

        assert_eq!(id, 1);
        assert_eq!(database.row_count("scans"), 1);
        assert_eq!(database.row_count("scan_items"), 1);
        assert_eq!(database.row_count("recommendations"), 1);
        assert_eq!(database.row_count("duplicate_groups"), 1);
        assert_eq!(database.row_count("duplicate_entries"), 1);
        assert_eq!(database.row_count("relationships"), 1);
        assert_eq!(database.row_count("ai_explanations"), 1);
        assert_eq!(database.row_count("analysis_warnings"), 2);
        assert_eq!(database.row_count("ignored_paths"), 1);

        let history = database.scan_history(10).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].root, scan.root);
        assert_eq!(history[0].duplicate_recovery_bytes, Some(16));
        assert_eq!(history[0].ai_model.as_deref(), Some("qwen3:4b"));
        assert_eq!(history[0].ai_explanation_count, 1);
        assert_eq!(database.scan(id).unwrap(), Some(history[0].clone()));
        let stored = database.analysis(id).unwrap().unwrap();
        assert_eq!(stored.summary, history[0]);
        assert_eq!(stored.findings, findings);
        assert_eq!(stored.duplicate_groups, duplicates.groups);
        assert_eq!(stored.relationships, relationships.relationships);
        assert_eq!(stored.ai_explanations, ai.explanations);
        assert_eq!(stored.warnings.len(), 2);
        assert_eq!(stored.warnings[0].source, "scan");
        assert_eq!(stored.warnings[1].kind.as_deref(), Some("changed_during_detection"));
    }

    #[test]
    fn history_is_newest_first_and_honors_the_limit() {
        let mut database = Database::open_in_memory().unwrap();
        let mut first = sample_scan();
        first.completed_at_epoch_seconds = 200;
        let mut second = sample_scan();
        second.root = PathBuf::from("/newer");
        second.completed_at_epoch_seconds = 300;
        let duplicates = sample_duplicates();
        let relationships = sample_relationships();
        let ai = sample_ai();

        for scan in [&first, &second] {
            database
                .save_analysis(Analysis {
                    scan,
                    findings: &[],
                    duplicates: &duplicates,
                    relationships: &relationships,
                    ai: &ai,
                })
                .unwrap();
        }

        let history = database.scan_history(1).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].root, PathBuf::from("/newer"));
        assert!(database.scan_history(0).unwrap().is_empty());
    }

    #[test]
    fn detailed_review_orders_actionable_low_risk_findings_first() {
        let mut database = Database::open_in_memory().unwrap();
        let scan = sample_scan();
        let mut high_risk = sample_finding();
        high_risk.path = PathBuf::from("/home/example/Downloads/huge-vm");
        high_risk.potential_recovery_bytes = 10_000;
        high_risk.risk = RiskLevel::High;
        high_risk.suggested_action = SuggestedAction::ReviewForArchive;
        let mut low_risk = sample_finding();
        low_risk.path = PathBuf::from("/home/example/Downloads/cache");
        low_risk.potential_recovery_bytes = 100;
        low_risk.risk = RiskLevel::Low;
        low_risk.suggested_action = SuggestedAction::ReviewForDeletion;
        let duplicates = sample_duplicates();
        let relationships = sample_relationships();
        let ai = sample_ai();

        let id = database
            .save_analysis(Analysis {
                scan: &scan,
                findings: &[high_risk, low_risk.clone()],
                duplicates: &duplicates,
                relationships: &relationships,
                ai: &ai,
            })
            .unwrap();
        let stored = database.analysis(id).unwrap().unwrap();

        assert_eq!(stored.findings[0].path, low_risk.path);
    }

    #[test]
    fn rejects_values_that_sqlite_cannot_represent_before_writing() {
        let mut database = Database::open_in_memory().unwrap();
        let mut scan = sample_scan();
        scan.total_size_bytes = u64::MAX;
        let duplicates = sample_duplicates();
        let relationships = sample_relationships();
        let ai = sample_ai();

        let error = database
            .save_analysis(Analysis {
                scan: &scan,
                findings: &[],
                duplicates: &duplicates,
                relationships: &relationships,
                ai: &ai,
            })
            .unwrap_err();

        assert!(matches!(error, DatabaseError::IntegerOutOfRange { .. }));
        assert_eq!(database.row_count("scans"), 0);
    }

    #[test]
    fn cancellation_leaves_no_partial_scan() {
        let mut database = Database::open_in_memory().unwrap();
        let scan = sample_scan();
        let duplicates = sample_duplicates();
        let relationships = sample_relationships();
        let ai = sample_ai();
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        let error = database
            .save_analysis_with_cancellation(
                Analysis {
                    scan: &scan,
                    findings: &[],
                    duplicates: &duplicates,
                    relationships: &relationships,
                    ai: &ai,
                },
                &cancellation,
            )
            .unwrap_err();

        assert!(matches!(error, DatabaseError::Cancelled));
        assert_eq!(database.row_count("scans"), 0);
    }

    #[test]
    fn rejects_a_newer_or_unknown_schema() {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch("PRAGMA user_version = 4;").unwrap();

        let error = Database::initialize(connection).unwrap_err();

        assert!(matches!(
            error,
            DatabaseError::UnsupportedSchemaVersion {
                found: 4,
                supported: SCHEMA_VERSION
            }
        ));
    }

    #[test]
    fn migrates_a_version_one_database_without_losing_scans() {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(SCHEMA_V1).unwrap();
        connection
            .execute(
                "INSERT INTO scans (root_path, started_at, completed_at, total_size_bytes, \
                 file_count, directory_count, scan_warning_count, duplicate_warning_count, \
                 recommendation_count, duplicate_group_count, relationship_count, \
                 recovered_space_bytes) VALUES (?1, 1, 2, 3, 1, 1, 0, 0, 0, 0, 0, 0)",
                [path_bytes(Path::new("/tmp"))],
            )
            .unwrap();

        let database = Database::initialize(connection).unwrap();
        let history = database.scan_history(1).unwrap();

        assert_eq!(history.len(), 1);
        assert_eq!(history[0].ai_status, "disabled");
        assert_eq!(history[0].ai_explanation_count, 0);
    }

    #[test]
    fn migrates_a_version_two_database_for_detailed_warnings() {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(SCHEMA_V1).unwrap();
        connection.execute_batch(SCHEMA_V2).unwrap();

        let database = Database::initialize(connection).unwrap();

        assert_eq!(database.row_count("analysis_warnings"), 0);
    }

    #[cfg(unix)]
    #[test]
    fn preserves_distinct_non_utf8_paths() {
        use std::os::unix::ffi::OsStringExt;

        let mut database = Database::open_in_memory().unwrap();
        let mut scan = sample_scan();
        scan.root = PathBuf::from(OsString::from_vec(b"/tmp/\x82".to_vec()));
        let mut first = scan.items[0].clone();
        first.path = PathBuf::from(OsString::from_vec(b"/tmp/\x80".to_vec()));
        let mut second = first.clone();
        second.path = PathBuf::from(OsString::from_vec(b"/tmp/\x81".to_vec()));
        scan.items = vec![first, second];
        let duplicates = sample_duplicates();
        let relationships = sample_relationships();
        let ai = sample_ai();

        database
            .save_analysis(Analysis {
                scan: &scan,
                findings: &[],
                duplicates: &duplicates,
                relationships: &relationships,
                ai: &ai,
            })
            .unwrap();

        assert_eq!(database.row_count("scan_items"), 2);
        let history = database.scan_history(1).unwrap();
        assert_eq!(history[0].root, scan.root);
        assert!(serde_json::to_string(&history).is_ok());
    }
}
