use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use spacemind_core::{
    AiCategory, AiExplanation, AiReport, AiStatus, AiSuggestedAction, AnalysisPhase,
    CancellationToken, DuplicateReport, Finding, FindingCategory, ProgressEvent,
    RelationshipKind, RelationshipReport, RiskLevel, ScanResult,
};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use thiserror::Error;

const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:11434";
const DEFAULT_MODEL: &str = "qwen3:4b";
const MAX_CANDIDATES_PER_REQUEST: usize = 32;
const MAX_HTTP_RESPONSE_BYTES: u64 = 1024 * 1024;
const SYSTEM_PROMPT: &str = "You are SpaceMind's local explanation layer. Be concise, \
    conservative, and explicit about uncertainty. Never claim a file is safe to delete. \
    Never request or infer file contents.";

#[derive(Debug, Clone)]
pub struct OllamaOptions {
    pub endpoint: String,
    pub model: String,
    pub maximum_candidates: usize,
    pub timeout: Duration,
}

impl Default for OllamaOptions {
    fn default() -> Self {
        Self {
            endpoint: DEFAULT_ENDPOINT.to_owned(),
            model: DEFAULT_MODEL.to_owned(),
            maximum_candidates: 8,
            timeout: Duration::from_secs(90),
        }
    }
}

#[derive(Debug, Error)]
pub enum AiError {
    #[error("local AI analysis cancelled")]
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AiCandidateContext {
    pub candidate_id: u64,
    #[serde(serialize_with = "serialize_lossy_path")]
    pub path: PathBuf,
    pub size_bytes: u64,
    pub allocated_size_bytes: Option<u64>,
    pub modified_days_ago: Option<u64>,
    pub deterministic_categories: Vec<FindingCategory>,
    pub deterministic_risk: RiskLevel,
    pub deterministic_confidence_percent: u8,
    pub deterministic_evidence: Vec<String>,
    pub related_items: Vec<RelatedItemContext>,
    pub exact_duplicate_count: u64,
    pub protected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RelatedItemContext {
    pub kind: RelationshipKind,
    #[serde(serialize_with = "serialize_lossy_path")]
    pub path: PathBuf,
    pub confidence_percent: u8,
}

#[derive(Debug, Deserialize)]
struct TagsResponse {
    #[serde(default)]
    models: Vec<ModelSummary>,
}

#[derive(Debug, Deserialize)]
struct ModelSummary {
    name: String,
    #[serde(default)]
    model: String,
    #[serde(default)]
    remote_model: Option<String>,
    #[serde(default)]
    remote_host: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GenerateResponse {
    response: String,
    #[serde(default)]
    done: bool,
}

#[derive(Debug, Deserialize)]
struct ModelOutput {
    explanations: Vec<ModelExplanation>,
}

#[derive(Debug, Deserialize)]
struct ModelExplanation {
    candidate_id: u64,
    category: AiCategory,
    risk: RiskLevel,
    confidence: f32,
    reason: String,
    suggested_action: AiSuggestedAction,
}

pub fn analyze_with_ollama<F>(
    scan: &ScanResult,
    findings: &[Finding],
    duplicates: &DuplicateReport,
    relationships: &RelationshipReport,
    options: &OllamaOptions,
    cancellation: &CancellationToken,
    mut on_progress: F,
) -> Result<AiReport, AiError>
where
    F: FnMut(&ProgressEvent),
{
    check_cancelled(cancellation)?;
    let candidates = shortlist_candidates(
        scan,
        findings,
        duplicates,
        relationships,
        options.maximum_candidates.min(MAX_CANDIDATES_PER_REQUEST),
    );
    if candidates.is_empty() {
        return Ok(AiReport {
            status: AiStatus::NoCandidates,
            candidates_considered: 0,
            explanations: Vec::new(),
            warnings: Vec::new(),
        });
    }

    report_progress(&mut on_progress, 0, candidates.len() as u64);
    let endpoint = match validate_local_endpoint(&options.endpoint) {
        Ok(endpoint) => endpoint,
        Err(reason) => return Ok(unavailable(candidates.len(), reason)),
    };
    let api = HttpOllamaApi::new(endpoint, options.timeout);
    analyze_candidates_with_api(candidates, options, cancellation, &mut on_progress, &api)
}

trait OllamaApi {
    fn list_models(&self) -> Result<TagsResponse, String>;
    fn generate(
        &self,
        request: Value,
        cancellation: &CancellationToken,
    ) -> Result<Result<GenerateResponse, String>, AiError>;
}

struct HttpOllamaApi {
    endpoint: String,
    tags_agent: ureq::Agent,
    generation_agent: ureq::Agent,
}

impl HttpOllamaApi {
    fn new(endpoint: String, generation_timeout: Duration) -> Self {
        Self {
            endpoint,
            tags_agent: ureq::AgentBuilder::new()
                .timeout_connect(Duration::from_secs(1))
                .timeout_read(Duration::from_secs(2))
                .timeout_write(Duration::from_secs(5))
                .redirects(0)
                .build(),
            generation_agent: ureq::AgentBuilder::new()
                .timeout_connect(Duration::from_secs(1))
                .timeout_read(generation_timeout)
                .timeout_write(Duration::from_secs(5))
                .redirects(0)
                .build(),
        }
    }
}

impl OllamaApi for HttpOllamaApi {
    fn list_models(&self) -> Result<TagsResponse, String> {
        get_json(&self.tags_agent, &format!("{}/api/tags", self.endpoint))
            .map_err(|reason| format!("Ollama is not available at {}: {reason}", self.endpoint))
    }

    fn generate(
        &self,
        request: Value,
        cancellation: &CancellationToken,
    ) -> Result<Result<GenerateResponse, String>, AiError> {
        post_generate_cancellable(
            self.generation_agent.clone(),
            format!("{}/api/generate", self.endpoint),
            request,
            cancellation,
        )
    }
}

fn analyze_candidates_with_api<F, A>(
    candidates: Vec<AiCandidateContext>,
    options: &OllamaOptions,
    cancellation: &CancellationToken,
    on_progress: &mut F,
    api: &A,
) -> Result<AiReport, AiError>
where
    F: FnMut(&ProgressEvent),
    A: OllamaApi,
{
    let tags = match api.list_models() {
        Ok(tags) => tags,
        Err(reason) => return Ok(unavailable(candidates.len(), reason)),
    };
    let configured_model = tags
        .models
        .iter()
        .find(|model| model.name == options.model || model.model == options.model);
    let Some(configured_model) = configured_model else {
        return Ok(unavailable(
            candidates.len(),
            format!(
                "model {:?} is not installed; run `ollama pull {}`",
                options.model, options.model
            ),
        ));
    };
    if configured_model
        .remote_model
        .as_deref()
        .is_some_and(|value| !value.is_empty())
        || configured_model
            .remote_host
            .as_deref()
            .is_some_and(|value| !value.is_empty())
    {
        return Ok(unavailable(
            candidates.len(),
            format!(
                "model {:?} is backed by a remote Ollama service; SpaceMind only allows local models",
                options.model
            ),
        ));
    }

    check_cancelled(cancellation)?;
    let request = generate_request(&options.model, &candidates);
    let response = match api.generate(request, cancellation)? {
        Ok(response) => response,
        Err(reason) => {
            return Ok(unavailable(
                candidates.len(),
                format!("Ollama could not explain the candidates: {reason}"),
            ))
        }
    };
    check_cancelled(cancellation)?;

    let (explanations, warnings) = validate_output(&response, &candidates);
    report_progress(
        on_progress,
        candidates.len() as u64,
        candidates.len() as u64,
    );
    let status = if warnings.is_empty() {
        AiStatus::Complete {
            model: options.model.clone(),
        }
    } else if explanations.is_empty() {
        AiStatus::Unavailable {
            reason: "the local model returned no valid explanations".to_owned(),
        }
    } else {
        AiStatus::Partial {
            model: options.model.clone(),
        }
    };
    Ok(AiReport {
        status,
        candidates_considered: candidates.len() as u64,
        explanations,
        warnings,
    })
}

pub fn shortlist_candidates(
    scan: &ScanResult,
    findings: &[Finding],
    duplicates: &DuplicateReport,
    relationships: &RelationshipReport,
    maximum_candidates: usize,
) -> Vec<AiCandidateContext> {
    if maximum_candidates == 0 {
        return Vec::new();
    }
    let items: BTreeMap<&Path, _> = scan
        .items
        .iter()
        .map(|item| (item.path.as_path(), item))
        .collect();
    let mut by_path: BTreeMap<&Path, Vec<&Finding>> = BTreeMap::new();
    for finding in findings {
        by_path.entry(&finding.path).or_default().push(finding);
    }

    let mut ranked = Vec::new();
    for (path, path_findings) in by_path {
        let has_generic_large = path_findings
            .iter()
            .any(|finding| finding.category == FindingCategory::LargeItem);
        let lowest_confidence = path_findings
            .iter()
            .map(|finding| finding.confidence)
            .fold(1.0_f32, f32::min);
        let has_relationship = relationships.relationships.iter().any(|relationship| {
            relationship.source_path == path || relationship.target_path == path
        });
        if !has_generic_large && lowest_confidence >= 0.95 && !has_relationship {
            continue;
        }
        let Some(item) = items.get(path).copied() else {
            continue;
        };
        let highest_risk = path_findings
            .iter()
            .map(|finding| finding.risk)
            .max_by_key(|risk| risk_rank(*risk))
            .unwrap_or(RiskLevel::High);
        let confidence = path_findings
            .iter()
            .map(|finding| finding.confidence)
            .fold(1.0_f32, f32::min);
        let mut categories: Vec<_> = path_findings.iter().map(|finding| finding.category).collect();
        categories.sort_by_key(|category| finding_category_rank(*category));
        categories.dedup();
        let evidence: BTreeSet<_> = path_findings
            .iter()
            .flat_map(|finding| finding.evidence.iter().cloned())
            .collect();
        let related_items = relationships
            .relationships
            .iter()
            .filter_map(|relationship| {
                if relationship.source_path == path {
                    Some((&relationship.target_path, relationship))
                } else if relationship.target_path == path {
                    Some((&relationship.source_path, relationship))
                } else {
                    None
                }
            })
            .map(|(related_path, relationship)| RelatedItemContext {
                kind: relationship.kind,
                path: related_path.clone(),
                confidence_percent: percent(relationship.confidence),
            })
            .collect();
        let exact_duplicate_count = duplicates
            .groups
            .iter()
            .find(|group| group.entries.iter().any(|entry| entry.path == path))
            .map(|group| group.unique_file_count.saturating_sub(1))
            .unwrap_or(0);
        ranked.push((
            path_findings
                .iter()
                .map(|finding| finding.potential_recovery_bytes)
                .max()
                .unwrap_or(0),
            AiCandidateContext {
                candidate_id: 0,
                path: path.to_path_buf(),
                size_bytes: item.size_bytes,
                allocated_size_bytes: item.allocated_size_bytes,
                modified_days_ago: item.modified_at_epoch_seconds.map(|modified| {
                    scan.completed_at_epoch_seconds.saturating_sub(modified) / 86_400
                }),
                deterministic_categories: categories,
                deterministic_risk: highest_risk,
                deterministic_confidence_percent: percent(confidence),
                deterministic_evidence: evidence.into_iter().collect(),
                related_items,
                exact_duplicate_count,
                protected: false,
            },
        ));
    }
    ranked.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.path.cmp(&right.1.path)));
    ranked
        .into_iter()
        .take(maximum_candidates)
        .enumerate()
        .map(|(index, (_, mut candidate))| {
            candidate.candidate_id = index as u64 + 1;
            candidate
        })
        .collect()
}

fn generate_request(model: &str, candidates: &[AiCandidateContext]) -> Value {
    let schema = output_schema();
    let prompt = format!(
        "Explain why each shortlisted filesystem item may exist and whether it is replaceable. \
         Use only the supplied metadata and relationships. Do not infer file contents. \
         Do not authorize deletion. Return exactly one explanation for every candidate_id.\n\n\
         JSON schema:\n{}\n\nCandidate context:\n{}",
        schema,
        serde_json::to_string_pretty(candidates).expect("candidate context is serializable")
    );
    json!({
        "model": model,
        "system": SYSTEM_PROMPT,
        "prompt": prompt,
        "stream": false,
        "think": false,
        "format": schema,
        "options": { "temperature": 0, "num_predict": 1400 },
        "keep_alive": "5m"
    })
}

fn output_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "explanations": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "candidate_id": { "type": "integer", "minimum": 1 },
                        "category": { "type": "string", "enum": [
                            "replaceable_installer", "archive_with_extracted_copy",
                            "cache_or_generated", "duplicate_copy", "user_data_or_state", "unknown"
                        ] },
                        "risk": { "type": "string", "enum": ["low", "medium", "high"] },
                        "confidence": { "type": "number", "minimum": 0, "maximum": 1 },
                        "reason": { "type": "string", "minLength": 1, "maxLength": 600 },
                        "suggested_action": { "type": "string", "enum": [
                            "review_for_deletion", "review_for_archive", "keep_or_review"
                        ] }
                    },
                    "required": [
                        "candidate_id", "category", "risk", "confidence", "reason",
                        "suggested_action"
                    ]
                }
            }
        },
        "required": ["explanations"]
    })
}

fn validate_output(
    response: &GenerateResponse,
    candidates: &[AiCandidateContext],
) -> (Vec<AiExplanation>, Vec<String>) {
    let mut warnings = Vec::new();
    if !response.done {
        warnings.push("Ollama did not mark the response as complete".to_owned());
    }
    let output: ModelOutput = match serde_json::from_str(&response.response) {
        Ok(output) => output,
        Err(error) => {
            warnings.push(format!("invalid structured response: {error}"));
            return (Vec::new(), warnings);
        }
    };
    let paths: BTreeMap<u64, &PathBuf> = candidates
        .iter()
        .map(|candidate| (candidate.candidate_id, &candidate.path))
        .collect();
    let mut seen = BTreeSet::new();
    let mut explanations = Vec::new();
    for explanation in output.explanations {
        let Some(path) = paths.get(&explanation.candidate_id) else {
            warnings.push(format!(
                "model returned unknown candidate_id {}",
                explanation.candidate_id
            ));
            continue;
        };
        if !seen.insert(explanation.candidate_id) {
            warnings.push(format!(
                "model returned candidate_id {} more than once",
                explanation.candidate_id
            ));
            continue;
        }
        let reason = explanation.reason.trim();
        if reason.is_empty()
            || reason.chars().count() > 600
            || reason.chars().any(char::is_control)
            || !explanation.confidence.is_finite()
            || !(0.0..=1.0).contains(&explanation.confidence)
        {
            warnings.push(format!(
                "model returned invalid fields for candidate_id {}",
                explanation.candidate_id
            ));
            continue;
        }
        explanations.push(AiExplanation {
            path: (*path).clone(),
            category: explanation.category,
            risk: explanation.risk,
            confidence: explanation.confidence,
            reason: reason.to_owned(),
            suggested_action: explanation.suggested_action,
        });
    }
    for candidate in candidates {
        if !seen.contains(&candidate.candidate_id) {
            warnings.push(format!(
                "model omitted candidate_id {}",
                candidate.candidate_id
            ));
        }
    }
    explanations.sort_by(|left, right| left.path.cmp(&right.path));
    (explanations, warnings)
}

fn validate_local_endpoint(endpoint: &str) -> Result<String, String> {
    let endpoint = endpoint.trim().trim_end_matches('/');
    let authority = endpoint
        .strip_prefix("http://")
        .ok_or_else(|| "the Ollama endpoint must use local HTTP".to_owned())?;
    if authority.is_empty() || authority.contains('/') || authority.contains('@') {
        return Err("the Ollama endpoint must contain only a loopback host and port".to_owned());
    }
    let valid = if let Some(rest) = authority.strip_prefix("[::1]") {
        valid_optional_port(rest)
    } else {
        let (host, port) = authority
            .split_once(':')
            .map(|(host, port)| (host, Some(port)))
            .unwrap_or((authority, None));
        matches!(host, "localhost" | "127.0.0.1")
            && port.map(valid_port).unwrap_or(true)
    };
    if !valid {
        return Err(
            "remote Ollama endpoints are not allowed; use localhost or a loopback address"
                .to_owned(),
        );
    }
    Ok(endpoint.to_owned())
}

fn valid_optional_port(rest: &str) -> bool {
    rest.is_empty() || rest.strip_prefix(':').is_some_and(valid_port)
}

fn valid_port(port: &str) -> bool {
    port.parse::<u16>().is_ok_and(|port| port != 0)
}

fn get_json<T: for<'de> Deserialize<'de>>(agent: &ureq::Agent, url: &str) -> Result<T, String> {
    let response = agent.get(url).call().map_err(http_error)?;
    parse_limited_json(response)
}

fn post_json<T: for<'de> Deserialize<'de>>(
    agent: &ureq::Agent,
    url: &str,
    body: &Value,
) -> Result<T, String> {
    let response = agent
        .post(url)
        .set("Content-Type", "application/json")
        .send_string(&body.to_string())
        .map_err(http_error)?;
    parse_limited_json(response)
}

fn post_generate_cancellable(
    agent: ureq::Agent,
    url: String,
    body: Value,
    cancellation: &CancellationToken,
) -> Result<Result<GenerateResponse, String>, AiError> {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let _ = sender.send(post_json(&agent, &url, &body));
    });
    loop {
        check_cancelled(cancellation)?;
        match receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(result) => return Ok(result),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Ok(Err("the Ollama request ended unexpectedly".to_owned()))
            }
        }
    }
}

fn parse_limited_json<T: for<'de> Deserialize<'de>>(response: ureq::Response) -> Result<T, String> {
    let mut body = Vec::new();
    response
        .into_reader()
        .take(MAX_HTTP_RESPONSE_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(|error| error.to_string())?;
    if body.len() as u64 > MAX_HTTP_RESPONSE_BYTES {
        return Err("Ollama response exceeded the 1 MiB safety limit".to_owned());
    }
    serde_json::from_slice(&body).map_err(|error| error.to_string())
}

fn http_error(error: ureq::Error) -> String {
    match error {
        ureq::Error::Status(status, _) => format!("HTTP status {status}"),
        ureq::Error::Transport(error) => error.to_string(),
    }
}

fn unavailable(candidate_count: usize, reason: String) -> AiReport {
    AiReport {
        status: AiStatus::Unavailable { reason },
        candidates_considered: candidate_count as u64,
        explanations: Vec::new(),
        warnings: Vec::new(),
    }
}

fn report_progress<F>(on_progress: &mut F, processed: u64, total: u64)
where
    F: FnMut(&ProgressEvent),
{
    on_progress(&ProgressEvent {
        phase: AnalysisPhase::ExplainingCandidates,
        items_processed: processed,
        bytes_processed: 0,
        total_items: Some(total),
        total_bytes: None,
        current_path: None,
    });
}

fn check_cancelled(cancellation: &CancellationToken) -> Result<(), AiError> {
    if cancellation.is_cancelled() {
        Err(AiError::Cancelled)
    } else {
        Ok(())
    }
}

fn percent(value: f32) -> u8 {
    (value.clamp(0.0, 1.0) * 100.0).round() as u8
}

fn risk_rank(risk: RiskLevel) -> u8 {
    match risk {
        RiskLevel::Low => 0,
        RiskLevel::Medium => 1,
        RiskLevel::High => 2,
    }
}

fn finding_category_rank(category: FindingCategory) -> u8 {
    match category {
        FindingCategory::LargeItem => 0,
        FindingCategory::OldArchive => 1,
        FindingCategory::OldInstaller => 2,
        FindingCategory::NodeModules => 3,
        FindingCategory::RustBuildArtifacts => 4,
        FindingCategory::GradleCache => 5,
        FindingCategory::AndroidEmulator => 6,
        FindingCategory::VirtualMachine => 7,
        FindingCategory::IsoImage => 8,
        FindingCategory::OperatingSystemCache => 9,
        FindingCategory::GeneratedDirectory => 10,
        FindingCategory::CacheDirectory => 11,
    }
}

fn serialize_lossy_path<S>(path: &Path, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&path.to_string_lossy())
}

#[cfg(test)]
mod tests {
    use super::*;
    use spacemind_core::{ItemKind, ScannedItem, SuggestedAction};
    use std::sync::Mutex;

    fn sample_analysis() -> (ScanResult, Vec<Finding>, DuplicateReport, RelationshipReport) {
        let path = PathBuf::from("/tmp/large.bin");
        let scan = ScanResult {
            root: PathBuf::from("/tmp"),
            started_at_epoch_seconds: 1,
            completed_at_epoch_seconds: 864_001,
            total_size_bytes: 20,
            total_allocated_size_bytes: Some(24),
            file_count: 1,
            directory_count: 1,
            items: vec![ScannedItem {
                path: path.clone(),
                kind: ItemKind::File,
                size_bytes: 20,
                allocated_size_bytes: Some(24),
                file_identity: None,
                hard_link_count: None,
                created_at_epoch_seconds: None,
                modified_at_epoch_seconds: Some(1),
                modified_at_epoch_nanoseconds: None,
                accessed_at_epoch_seconds: None,
                extension: Some("bin".to_owned()),
            }],
            ignored_paths: Vec::new(),
            warnings: Vec::new(),
        };
        let findings = vec![Finding {
            category: FindingCategory::LargeItem,
            path,
            potential_recovery_bytes: 20,
            confidence: 1.0,
            risk: RiskLevel::High,
            evidence: vec!["Large file".to_owned()],
            suggested_action: SuggestedAction::ReviewForArchive,
        }];
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
            items_analyzed: 1,
        };
        (scan, findings, duplicates, relationships)
    }

    #[test]
    fn shortlists_ambiguous_large_items_without_file_contents() {
        let (scan, findings, duplicates, relationships) = sample_analysis();
        let candidates = shortlist_candidates(&scan, &findings, &duplicates, &relationships, 8);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].candidate_id, 1);
        assert_eq!(candidates[0].modified_days_ago, Some(10));
        assert!(!serde_json::to_string(&candidates).unwrap().contains("contents"));
        assert!(!candidates[0].protected);
    }

    #[test]
    fn rejects_remote_and_malformed_endpoints() {
        assert!(validate_local_endpoint("http://localhost:11434").is_ok());
        assert!(validate_local_endpoint("http://127.0.0.1").is_ok());
        assert!(validate_local_endpoint("http://[::1]:11434").is_ok());
        assert!(validate_local_endpoint("https://localhost:11434").is_err());
        assert!(validate_local_endpoint("http://example.com:11434").is_err());
        assert!(validate_local_endpoint("http://localhost:0").is_err());
    }

    #[test]
    fn rejects_invalid_or_unmapped_model_output() {
        let (scan, findings, duplicates, relationships) = sample_analysis();
        let candidates = shortlist_candidates(&scan, &findings, &duplicates, &relationships, 8);
        let response = GenerateResponse {
            response: json!({"explanations": [{
                "candidate_id": 99,
                "category": "unknown",
                "risk": "high",
                "confidence": 0.5,
                "reason": "Unknown",
                "suggested_action": "keep_or_review"
            }]})
            .to_string(),
            done: true,
        };
        let (explanations, warnings) = validate_output(&response, &candidates);

        assert!(explanations.is_empty());
        assert_eq!(warnings.len(), 2);
    }

    #[test]
    fn rejects_terminal_control_characters_in_model_reasons() {
        let (scan, findings, duplicates, relationships) = sample_analysis();
        let candidates = shortlist_candidates(&scan, &findings, &duplicates, &relationships, 8);
        let response = GenerateResponse {
            response: json!({"explanations": [{
                "candidate_id": 1,
                "category": "unknown",
                "risk": "high",
                "confidence": 0.5,
                "reason": "unsafe\u{001b}[2Jtext",
                "suggested_action": "keep_or_review"
            }]})
            .to_string(),
            done: true,
        };

        let (explanations, warnings) = validate_output(&response, &candidates);

        assert!(explanations.is_empty());
        assert_eq!(warnings.len(), 1);
    }

    #[test]
    fn cancellation_stops_before_contacting_ollama() {
        let (scan, findings, duplicates, relationships) = sample_analysis();
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        let error = analyze_with_ollama(
            &scan,
            &findings,
            &duplicates,
            &relationships,
            &OllamaOptions::default(),
            &cancellation,
            |_| {},
        )
        .unwrap_err();

        assert!(matches!(error, AiError::Cancelled));
    }

    #[test]
    fn calls_a_mocked_local_ollama_and_validates_structured_output() {
        let (scan, findings, duplicates, relationships) = sample_analysis();
        let candidates = shortlist_candidates(&scan, &findings, &duplicates, &relationships, 8);
        let api = MockOllamaApi::default();
        let options = OllamaOptions::default();
        let report = analyze_candidates_with_api(
            candidates,
            &options,
            &CancellationToken::new(),
            &mut |_| {},
            &api,
        )
        .unwrap();

        let request = api.request.lock().unwrap().clone().unwrap();
        assert!(matches!(report.status, AiStatus::Complete { .. }));
        assert_eq!(report.explanations.len(), 1);
        assert_eq!(report.explanations[0].path, PathBuf::from("/tmp/large.bin"));
        assert_eq!(request["stream"], false);
        assert!(request["format"].is_object());
        assert!(request["prompt"].as_str().unwrap().contains("large.bin"));
        assert!(request.get("images").is_none());
    }

    #[test]
    fn missing_local_model_becomes_a_non_fatal_fallback() {
        let (scan, findings, duplicates, relationships) = sample_analysis();
        let candidates = shortlist_candidates(&scan, &findings, &duplicates, &relationships, 8);
        let api = MockOllamaApi::default();
        let options = OllamaOptions {
            model: "missing:4b".to_owned(),
            ..OllamaOptions::default()
        };

        let report = analyze_candidates_with_api(
            candidates,
            &options,
            &CancellationToken::new(),
            &mut |_| {},
            &api,
        )
        .unwrap();

        assert!(matches!(report.status, AiStatus::Unavailable { .. }));
        assert!(report.explanations.is_empty());
        assert!(api.request.lock().unwrap().is_none());
    }

    #[test]
    fn refuses_models_that_ollama_marks_as_remote() {
        let (scan, findings, duplicates, relationships) = sample_analysis();
        let candidates = shortlist_candidates(&scan, &findings, &duplicates, &relationships, 8);
        let api = MockOllamaApi {
            remote: true,
            ..MockOllamaApi::default()
        };

        let report = analyze_candidates_with_api(
            candidates,
            &OllamaOptions::default(),
            &CancellationToken::new(),
            &mut |_| {},
            &api,
        )
        .unwrap();

        assert!(matches!(report.status, AiStatus::Unavailable { .. }));
        assert!(api.request.lock().unwrap().is_none());
    }

    #[derive(Default)]
    struct MockOllamaApi {
        request: Mutex<Option<Value>>,
        remote: bool,
    }

    impl OllamaApi for MockOllamaApi {
        fn list_models(&self) -> Result<TagsResponse, String> {
            Ok(TagsResponse {
                models: vec![ModelSummary {
                    name: "qwen3:4b".to_owned(),
                    model: "qwen3:4b".to_owned(),
                    remote_model: self.remote.then(|| "qwen3:4b".to_owned()),
                    remote_host: self
                        .remote
                        .then(|| "https://ollama.example.invalid".to_owned()),
                }],
            })
        }

        fn generate(
            &self,
            request: Value,
            _cancellation: &CancellationToken,
        ) -> Result<Result<GenerateResponse, String>, AiError> {
            *self.request.lock().unwrap() = Some(request);
            let output = json!({
                "explanations": [{
                    "candidate_id": 1,
                    "category": "unknown",
                    "risk": "high",
                    "confidence": 0.72,
                    "reason": "This is large, but the supplied metadata does not show \
                               why it exists.",
                    "suggested_action": "keep_or_review"
                }]
            });
            Ok(Ok(GenerateResponse {
                response: output.to_string(),
                done: true,
            }))
        }
    }
}
