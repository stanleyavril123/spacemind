use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};

/// A path safety rule supplied by the user or by SpaceMind defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum PathRule {
    /// Matches this path and everything below it.
    Exact(PathBuf),
    /// Matches paths using `*`, `?`, and `**` wildcards.
    Glob(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathRuleError {
    pattern: String,
    message: &'static str,
}

impl PathRuleError {
    fn new(pattern: String, message: &'static str) -> Self {
        Self { pattern, message }
    }
}

impl fmt::Display for PathRuleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid path pattern {:?}: {}",
            self.pattern, self.message
        )
    }
}

impl Error for PathRuleError {}

/// Compiled path policy used consistently by scanning and recommendation code.
#[derive(Debug, Clone)]
pub struct PathMatcher {
    root: PathBuf,
    exact_paths: Vec<PathBuf>,
    globs: Vec<GlobPattern>,
}

impl PathMatcher {
    pub fn new(root: impl Into<PathBuf>, rules: &[PathRule]) -> Result<Self, PathRuleError> {
        let root = canonicalize_if_possible(normalize_path(root.into()));
        let mut exact_paths = Vec::new();
        let mut globs = Vec::new();

        for rule in rules {
            match rule {
                PathRule::Exact(path) => {
                    let path = if path.is_absolute() {
                        path.clone()
                    } else {
                        root.join(path)
                    };
                    exact_paths.push(canonicalize_if_possible(normalize_path(path)));
                }
                PathRule::Glob(pattern) => globs.push(GlobPattern::parse(pattern)?),
            }
        }

        exact_paths.sort();
        exact_paths.dedup();
        Ok(Self {
            root,
            exact_paths,
            globs,
        })
    }

    /// Returns true for a matched path and all descendants of a matched path.
    pub fn is_match(&self, path: &Path) -> bool {
        let path = normalize_path(path.to_path_buf());
        if self.exact_paths
            .iter()
            .any(|exact| exact_path_matches(&path, exact)) {
            return true;
        }

        let Ok(relative) = path.strip_prefix(&self.root) else {
            return false;
        };
        let components = path_components(relative);
        (0..=components.len()).any(|length| {
            let prefix = &components[..length];
            self.globs.iter().any(|pattern| pattern.matches(prefix))
        })
    }
}

#[derive(Debug, Clone)]
struct GlobPattern {
    segments: Vec<String>,
    anchored: bool,
}

impl GlobPattern {
    fn parse(pattern: &str) -> Result<Self, PathRuleError> {
        let pattern = pattern.trim();
        if pattern.is_empty() {
            return Err(PathRuleError::new(
                pattern.to_owned(),
                "pattern cannot be empty",
            ));
        }

        let normalized = pattern.replace('\\', "/");
        let anchored = normalized.starts_with('/') || normalized.starts_with("./");
        let normalized = normalized.trim_start_matches("./").trim_matches('/');
        if normalized.is_empty() {
            return Err(PathRuleError::new(
                pattern.to_owned(),
                "pattern must identify a path",
            ));
        }

        Ok(Self {
            segments: normalized
                .split('/')
                .filter(|segment| !segment.is_empty())
                .map(normalize_case)
                .collect(),
            anchored,
        })
    }

    fn matches(&self, path: &[String]) -> bool {
        if self.anchored {
            return match_segments(&self.segments, path);
        }
        (0..=path.len()).any(|start| match_segments(&self.segments, &path[start..]))
    }
}

fn match_segments(pattern: &[String], path: &[String]) -> bool {
    let Some((first, remaining_pattern)) = pattern.split_first() else {
        return path.is_empty();
    };
    if first == "**" {
        return match_segments(remaining_pattern, path)
            || (!path.is_empty() && match_segments(pattern, &path[1..]));
    }
    let Some((path_segment, remaining_path)) = path.split_first() else {
        return false;
    };
    wildcard_segment_matches(first, path_segment)
        && match_segments(remaining_pattern, remaining_path)
}

fn wildcard_segment_matches(pattern: &str, value: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let value: Vec<char> = value.chars().collect();
    let mut matches = vec![vec![false; value.len() + 1]; pattern.len() + 1];
    matches[0][0] = true;

    for pattern_index in 1..=pattern.len() {
        if pattern[pattern_index - 1] == '*' {
            matches[pattern_index][0] = matches[pattern_index - 1][0];
        }
        for value_index in 1..=value.len() {
            matches[pattern_index][value_index] = match pattern[pattern_index - 1] {
                '*' => {
                    matches[pattern_index - 1][value_index]
                        || matches[pattern_index][value_index - 1]
                }
                '?' => matches[pattern_index - 1][value_index - 1],
                character => {
                    character == value[value_index - 1]
                        && matches[pattern_index - 1][value_index - 1]
                }
            };
        }
    }
    matches[pattern.len()][value.len()]
}

fn canonicalize_if_possible(path: PathBuf) -> PathBuf {
    fs::canonicalize(&path).unwrap_or(path)
}

fn normalize_path(path: PathBuf) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

#[cfg(not(windows))]
fn exact_path_matches(path: &Path, exact: &Path) -> bool {
    path.starts_with(exact)
}

#[cfg(windows)]
fn exact_path_matches(path: &Path, exact: &Path) -> bool {
    let path = path
        .components()
        .map(|component| normalize_case(component.as_os_str().to_string_lossy()))
        .collect::<Vec<_>>();
    let exact = exact
        .components()
        .map(|component| normalize_case(component.as_os_str().to_string_lossy()))
        .collect::<Vec<_>>();
    path.starts_with(&exact)
}

#[cfg(not(windows))]
fn normalize_case(value: impl Into<String>) -> String {
    value.into()
}

#[cfg(windows)]
fn normalize_case(value: impl Into<String>) -> String {
    value.into().to_lowercase()
}

fn path_components(path: &Path) -> Vec<String> {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(normalize_case(value.to_string_lossy())),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_rules_match_the_path_and_descendants() {
        let matcher = PathMatcher::new(
            "/home/user",
            &[PathRule::Exact(PathBuf::from("Documents"))],
        )
        .unwrap();

        assert!(matcher.is_match(Path::new("/home/user/Documents")));
        assert!(matcher.is_match(Path::new("/home/user/Documents/report.txt")));
        assert!(!matcher.is_match(Path::new("/home/user/Downloads/report.txt")));
    }

    #[test]
    fn glob_rules_match_nested_paths_and_descendants() {
        let matcher = PathMatcher::new(
            "/workspace",
            &[
                PathRule::Glob("node_modules".to_owned()),
                PathRule::Glob("*.git/*".to_owned()),
            ],
        )
        .unwrap();

        assert!(matcher.is_match(Path::new(
            "/workspace/app/node_modules/pkg/index.js"
        )));
        assert!(matcher.is_match(Path::new("/workspace/app/.git/objects/a")));
        assert!(!matcher.is_match(Path::new("/workspace/app/src/index.js")));
    }

    #[test]
    fn question_mark_matches_one_character() {
        let matcher = PathMatcher::new(
            "/workspace",
            &[PathRule::Glob("cache-?".to_owned())],
        )
        .unwrap();

        assert!(matcher.is_match(Path::new("/workspace/tmp/cache-a/file")));
        assert!(!matcher.is_match(Path::new(
            "/workspace/tmp/cache-old/file"
        )));
    }
}
