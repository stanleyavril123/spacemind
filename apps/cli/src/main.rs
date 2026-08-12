use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;
use spacemind_core::{
    AnalysisPhase, CancellationToken, DuplicateReport, Finding, FindingCategory, ItemKind,
    PathRule, ProgressEvent, RiskLevel, ScanResult, ScannedItem, SuggestedAction,
};
use spacemind_duplicates::{detect_duplicates_with_progress, DuplicateOptions};
use spacemind_rules::{evaluate_with_policy_progress, RuleOptions};
use spacemind_scanner::{scan_with_progress, ScanOptions};
use std::collections::HashSet;
use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

#[derive(Debug, Parser)]
#[command(
    name = "spacemind",
    version,
    about = "Understand what is using disk space — privately and safely",
    long_about = "SpaceMind scans local storage, explains what is taking space, and highlights \
                  items worth reviewing. It never deletes files automatically."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Scan a folder without modifying its contents.
    Scan(ScanArgs),
}

#[derive(Debug, Args)]
struct ScanArgs {
    /// Folder to scan. Omit it to choose interactively.
    path: Option<PathBuf>,

    /// Maximum number of items, recommendations, and duplicate groups shown.
    #[arg(long, default_value_t = 20)]
    top: usize,

    /// Hide items smaller than this size (for example: 100MB or 2GiB).
    #[arg(long, value_parser = parse_size, default_value = "0")]
    min_size: u64,

    /// Only hash duplicate candidates at least this large.
    #[arg(long, value_parser = parse_size, default_value = "1MiB")]
    duplicate_min_size: u64,

    /// Output format. JSON contains the complete analysis.
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    format: OutputFormat,

    /// Allow traversal into mounted filesystems below the scan root.
    #[arg(long)]
    cross_filesystems: bool,

    /// Do not scan a path or subtree. Repeat for more rules; quote wildcard patterns.
    #[arg(long, value_name = "PATH_OR_GLOB", value_parser = parse_path_rule)]
    ignore: Vec<PathRule>,

    /// Scan a path for totals, but never recommend it. Repeat for more rules.
    #[arg(long, value_name = "PATH_OR_GLOB", value_parser = parse_path_rule)]
    protect: Vec<PathRule>,

    /// Disable SpaceMind built-in operating-system path protections.
    #[arg(long)]
    no_default_protections: bool,

    /// Size at which deterministic rules flag a large item.
    #[arg(long, value_parser = parse_size, default_value = "1GiB")]
    large_threshold: u64,

    /// Age at which archives and installers are considered old.
    #[arg(long, default_value_t = 180)]
    old_days: u64,
}

impl Default for ScanArgs {
    fn default() -> Self {
        Self {
            path: None,
            top: 20,
            min_size: 0,
            duplicate_min_size: 1024 * 1024,
            format: OutputFormat::Human,
            cross_filesystems: false,
            ignore: Vec::new(),
            protect: Vec::new(),
            no_default_protections: false,
            large_threshold: 1024 * 1024 * 1024,
            old_days: 180,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    Human,
    Json,
}

#[derive(Serialize)]
struct JsonOutput {
    scan: ScanResult,
    findings: Vec<Finding>,
    duplicates: DuplicateReport,
    policy: PolicySummary,
}

#[derive(Debug, Clone, Serialize)]
struct PolicySummary {
    ignored_rule_count: usize,
    protected_rule_count: usize,
    default_protections_enabled: bool,
    ignored_paths: Vec<PathBuf>,
    protected_items: u64,
    protected_duplicate_copies: u64,
    suppressed_recommendations: u64,
}

#[derive(Clone, Copy)]
struct Theme {
    colors: bool,
}

impl Theme {
    fn stdout() -> Self {
        Self::for_terminal(io::stdout().is_terminal())
    }

    fn stderr() -> Self {
        Self::for_terminal(io::stderr().is_terminal())
    }

    #[cfg(test)]
    fn plain() -> Self {
        Self { colors: false }
    }

    fn for_terminal(is_terminal: bool) -> Self {
        let colors = is_terminal
            && env::var_os("NO_COLOR").is_none()
            && env::var("TERM").map(|term| term != "dumb").unwrap_or(true);
        Self { colors }
    }

    fn paint(self, text: impl AsRef<str>, code: &str) -> String {
        if self.colors {
            format!("\x1b[{code}m{}\x1b[0m", text.as_ref())
        } else {
            text.as_ref().to_owned()
        }
    }

    fn brand(self, text: impl AsRef<str>) -> String {
        self.paint(text, "1;38;2;255;111;97")
    }

    fn accent(self, text: impl AsRef<str>) -> String {
        self.paint(text, "1;38;2;255;105;180")
    }

    fn aqua(self, text: impl AsRef<str>) -> String {
        self.paint(text, "1;38;2;94;234;212")
    }

    fn green(self, text: impl AsRef<str>) -> String {
        self.paint(text, "1;38;2;106;219;153")
    }

    fn yellow(self, text: impl AsRef<str>) -> String {
        self.paint(text, "1;38;2;246;193;119")
    }

    fn red(self, text: impl AsRef<str>) -> String {
        self.paint(text, "1;38;2;255;107;107")
    }

    fn text(self, text: impl AsRef<str>) -> String {
        self.paint(text, "1;38;2;245;245;250")
    }

    fn muted(self, text: impl AsRef<str>) -> String {
        self.paint(text, "38;2;139;143;166")
    }

    fn border(self, text: impl AsRef<str>) -> String {
        self.paint(text, "38;2;91;84;138")
    }
}

fn main() -> ExitCode {
    let cancellation = CancellationToken::new();
    let signal = cancellation.clone();
    if let Err(error) = ctrlc::set_handler(move || signal.cancel()) {
        eprintln!("Could not install the Ctrl+C handler: {error}");
        return ExitCode::FAILURE;
    }

    match run(Cli::parse(), &cancellation) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) if cancellation.is_cancelled() => {
            eprintln!("Scan cancelled safely. No files were changed.");
            ExitCode::from(130)
        }
        Err(error) => {
            eprintln!("SpaceMind could not complete the scan: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli, cancellation: &CancellationToken) -> Result<(), Box<dyn Error>> {
    let args = match cli.command {
        Some(Command::Scan(args)) => args,
        None => ScanArgs::default(),
    };
    let theme = Theme::stdout();
    let path = resolve_scan_path(args.path, args.format, theme)?;
    let ignored_rules = args.ignore;
    let mut protected_rules = if args.no_default_protections {
        Vec::new()
    } else {
        default_protected_rules()
    };
    protected_rules.extend(args.protect);

    if args.format == OutputFormat::Human && io::stdout().is_terminal() {
        print_scan_start(&path, theme);
    }

    let mut progress = CliProgress::new();
    let result = scan_with_progress(
        &ScanOptions {
            root: path,
            cross_filesystems: args.cross_filesystems,
            ignored_rules: ignored_rules.clone(),
        },
        cancellation,
        |event| progress.report(event),
    )?;
    let duplicates = detect_duplicates_with_progress(
        &result,
        &DuplicateOptions {
            minimum_size_bytes: args.duplicate_min_size,
            protected_rules: protected_rules.clone(),
        },
        cancellation,
        |event| progress.report(event),
    )?;
    let recommendation_total = result.items.len() as u64;
    let evaluation = evaluate_with_policy_progress(
        &result,
        &RuleOptions {
            large_item_threshold_bytes: args.large_threshold,
            old_item_threshold_days: args.old_days,
            protected_rules: protected_rules.clone(),
            ..RuleOptions::default()
        },
        cancellation,
        |event| progress.report(event),
    )?;
    progress.report(&ProgressEvent {
        phase: AnalysisPhase::Complete,
        items_processed: recommendation_total,
        bytes_processed: result.total_size_bytes,
        total_items: Some(recommendation_total),
        total_bytes: Some(result.total_size_bytes),
        current_path: None,
    });
    progress.finish();

    let policy = PolicySummary {
        ignored_rule_count: ignored_rules.len(),
        protected_rule_count: protected_rules.len(),
        default_protections_enabled: !args.no_default_protections,
        ignored_paths: result.ignored_paths.clone(),
        protected_items: evaluation.protected_items,
        protected_duplicate_copies: duplicates
            .groups
            .iter()
            .map(|group| group.protected_file_count)
            .sum(),
        suppressed_recommendations: evaluation.suppressed_findings,
    };
    let findings = evaluation.findings;

    match args.format {
        OutputFormat::Human => print_human(
            &result,
            &findings,
            &duplicates,
            &policy,
            args.top,
            args.min_size,
            theme,
        ),
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&JsonOutput {
                scan: result,
                findings,
                duplicates,
                policy,
            })?
        ),
    }
    Ok(())
}

fn resolve_scan_path(
    requested: Option<PathBuf>,
    format: OutputFormat,
    theme: Theme,
) -> Result<PathBuf, Box<dyn Error>> {
    if let Some(path) = requested {
        return Ok(expand_home(path));
    }

    let current = env::current_dir()?;
    if format == OutputFormat::Json || !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Ok(current);
    }

    let home = home_directory();
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let stdout = io::stdout();
    let mut writer = stdout.lock();
    choose_directory(&mut reader, &mut writer, current, home, theme).map_err(Into::into)
}

fn choose_directory<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    current: PathBuf,
    home: Option<PathBuf>,
    theme: Theme,
) -> io::Result<PathBuf> {
    let mut choices = vec![("Current folder".to_owned(), current)];
    if let Some(home) = home {
        add_directory_choice(&mut choices, "Home", home.clone());
        add_directory_choice(&mut choices, "Downloads", home.join("Downloads"));
        add_directory_choice(&mut choices, "Documents", home.join("Documents"));
        add_directory_choice(&mut choices, "Desktop", home.join("Desktop"));
    }

    writeln!(writer)?;
    write_brand_header(writer, theme, "SCAN")?;
    writeln!(
        writer,
        "\n  {}  Private storage analysis, entirely on your machine.",
        theme.accent("discover your space.")
    )?;
    writeln!(writer, "\n  {}", theme.aqua("Choose a folder to scan"))?;
    writeln!(writer, "  {}", theme.border("─".repeat(terminal_width() - 4)))?;
    for (index, (label, path)) in choices.iter().enumerate() {
        let marker = if index == 0 {
            theme.brand("›")
        } else {
            " ".to_owned()
        };
        writeln!(
            writer,
            "  {marker} {}  {}  {}",
            theme.accent(format!("{:02}", index + 1)),
            theme.text(format!("{label:<16}")),
            theme.muted(path.display().to_string())
        )?;
    }
    let custom_choice = choices.len() + 1;
    writeln!(
        writer,
        "    {}  {}",
        theme.accent(format!("{custom_choice:02}")),
        theme.text("Enter another path")
    )?;
    writeln!(writer, "\n  {}", theme.border("─".repeat(terminal_width() - 4)))?;
    writeln!(
        writer,
        "  {} select   {} current folder   {} cancel",
        theme.accent("1–9"),
        theme.aqua("enter"),
        theme.muted("ctrl+c")
    )?;

    loop {
        write!(writer, "\n  {} ", theme.brand("select ›"))?;
        writer.flush()?;
        let mut input = String::new();
        if reader.read_line(&mut input)? == 0 {
            return Ok(choices[0].1.clone());
        }
        let trimmed = input.trim();
        let selected = if trimmed.is_empty() {
            1
        } else if let Ok(value) = trimmed.parse::<usize>() {
            value
        } else {
            writeln!(
                writer,
                "  {} Please enter one of the numbers shown above.",
                theme.red("!")
            )?;
            continue;
        };

        if let Some((_, path)) = choices.get(selected.saturating_sub(1)) {
            return Ok(path.clone());
        }
        if selected != custom_choice {
            writeln!(
                writer,
                "  {} Please choose a number from 1 to {custom_choice}.",
                theme.red("!")
            )?;
            continue;
        }

        loop {
            write!(writer, "  {} ", theme.brand("path ›"))?;
            writer.flush()?;
            let mut custom = String::new();
            if reader.read_line(&mut custom)? == 0 {
                return Ok(choices[0].1.clone());
            }
            let path = expand_home(PathBuf::from(custom.trim()));
            if path.is_dir() {
                return Ok(path);
            }
            writeln!(
                writer,
                "  {} That folder does not exist. Try again.",
                theme.red("!")
            )?;
        }
    }
}

fn add_directory_choice(choices: &mut Vec<(String, PathBuf)>, label: &str, path: PathBuf) {
    if path.is_dir() && !choices.iter().any(|(_, existing)| existing == &path) {
        choices.push((label.to_owned(), path));
    }
}

fn home_directory() -> Option<PathBuf> {
    env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

fn expand_home(path: PathBuf) -> PathBuf {
    if path == Path::new("~") {
        return home_directory().unwrap_or(path);
    }
    let mut components = path.components();
    if components.next().is_some_and(|part| part.as_os_str() == "~") {
        if let Some(home) = home_directory() {
            return components.fold(home, |expanded, part| expanded.join(part.as_os_str()));
        }
    }
    path
}

fn parse_path_rule(input: &str) -> Result<PathRule, String> {
    let input = input.trim();
    if input.is_empty() {
        return Err("path rule cannot be empty".to_owned());
    }
    if input.contains('*') || input.contains('?') {
        Ok(PathRule::Glob(input.to_owned()))
    } else {
        Ok(PathRule::Exact(expand_home(PathBuf::from(input))))
    }
}

fn default_protected_rules() -> Vec<PathRule> {
    let mut paths = Vec::new();

    #[cfg(target_os = "linux")]
    paths.extend([
        "/boot", "/dev", "/etc", "/lib", "/lib64", "/opt", "/proc", "/root", "/run",
        "/sbin", "/sys", "/usr", "/var/lib", "/var/log",
    ]
    .into_iter()
    .map(PathBuf::from));

    #[cfg(windows)]
    for variable in ["SystemRoot", "WINDIR", "ProgramFiles", "ProgramFiles(x86)", "ProgramData"] {
        if let Some(path) = env::var_os(variable).map(PathBuf::from) {
            paths.push(path);
        }
    }

    paths.sort();
    paths.dedup();
    paths.into_iter().map(PathRule::Exact).collect()
}

fn terminal_width() -> usize {
    env::var("COLUMNS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(76)
        .clamp(56, 96)
}

fn write_brand_header<W: Write>(writer: &mut W, theme: Theme, active: &str) -> io::Result<()> {
    let width = terminal_width();
    let scan = if active == "SCAN" {
        theme.accent("scan")
    } else {
        theme.muted("scan")
    };
    let report = if active == "REPORT" {
        theme.accent("report")
    } else {
        theme.muted("report")
    };
    let left_width = "SPACEMIND   scan   report".chars().count();
    let right = "LOCAL • READ ONLY";
    let padding = width.saturating_sub(left_width + right.chars().count() + 4);

    writeln!(writer, "{}", theme.border(format!("╭{}╮", "─".repeat(width - 2))))?;
    writeln!(
        writer,
        "{} {}   {}   {}{}{} {}",
        theme.border("│"),
        theme.brand("SPACEMIND"),
        scan,
        report,
        " ".repeat(padding),
        theme.green(right),
        theme.border("│")
    )?;
    writeln!(writer, "{}", theme.border(format!("╰{}╯", "─".repeat(width - 2))))
}

fn print_brand_header(theme: Theme, active: &str) {
    let stdout = io::stdout();
    let mut writer = stdout.lock();
    let _ = write_brand_header(&mut writer, theme, active);
}

fn print_scan_start(path: &Path, theme: Theme) {
    print_brand_header(theme, "SCAN");
    println!(
        "\n  {}  Understand what is taking space without changing anything.",
        theme.accent("storage, understood.")
    );
    println!("\n  {}  {}", theme.muted("target"), theme.text(path.display().to_string()));
    println!(
        "  {}  {}",
        theme.muted("safety"),
        theme.green("read-only • local only • nothing is deleted")
    );
    println!(
        "  {}  {}\n",
        theme.muted("cancel"),
        theme.text("ctrl+c at any time")
    );
}

struct CliProgress {
    enabled: bool,
    line_visible: bool,
    last_phase: Option<AnalysisPhase>,
    last_rendered_at: Option<Instant>,
    last_message: Option<String>,
    theme: Theme,
}

impl CliProgress {
    fn new() -> Self {
        Self {
            enabled: io::stderr().is_terminal(),
            line_visible: false,
            last_phase: None,
            last_rendered_at: None,
            last_message: None,
            theme: Theme::stderr(),
        }
    }

    fn report(&mut self, event: &ProgressEvent) {
        if !self.enabled {
            return;
        }
        let now = Instant::now();
        let phase_changed = self.last_phase != Some(event.phase);
        let phase_complete = event
            .total_items
            .is_some_and(|total| event.items_processed >= total);
        let refresh_due = self
            .last_rendered_at
            .map(|last| now.duration_since(last) >= Duration::from_millis(100))
            .unwrap_or(true);
        if !phase_changed && !phase_complete && !refresh_due {
            return;
        }

        let message = progress_message(event);
        if self.last_message.as_ref() == Some(&message) {
            return;
        }
        let rendered = match event.phase {
            AnalysisPhase::Scanning => self.theme.aqua(&message),
            AnalysisPhase::HashingDuplicates => self.theme.accent(&message),
            AnalysisPhase::BuildingRecommendations => self.theme.yellow(&message),
            AnalysisPhase::Complete => self.theme.green(&message),
        };
        eprint!("\r\x1b[2K  {rendered}");
        let _ = io::stderr().flush();
        self.line_visible = true;
        self.last_phase = Some(event.phase);
        self.last_rendered_at = Some(now);
        self.last_message = Some(message);
    }

    fn finish(&mut self) {
        if self.enabled && self.line_visible {
            eprintln!();
            self.line_visible = false;
        }
    }
}

impl Drop for CliProgress {
    fn drop(&mut self) {
        self.finish();
    }
}

fn progress_message(event: &ProgressEvent) -> String {
    if event.phase == AnalysisPhase::Complete {
        return format!(
            "✓ Analysis complete    {} across {} items",
            format_bytes(event.bytes_processed),
            format_count(event.items_processed)
        );
    }

    let phase = match event.phase {
        AnalysisPhase::Scanning => "Scanning files",
        AnalysisPhase::HashingDuplicates => "Checking duplicates",
        AnalysisPhase::BuildingRecommendations => "Building advice",
        AnalysisPhase::Complete => unreachable!(),
    };
    let progress = match event.total_items {
        Some(total) if total > 0 => format!(
            "{} {:>3}%  {}/{}",
            progress_bar(event.items_processed, total, 12),
            event.items_processed.saturating_mul(100) / total,
            format_count(event.items_processed),
            format_count(total)
        ),
        Some(_) => "[────────────]   —  0/0".to_owned(),
        None => format!("{} items", format_count(event.items_processed)),
    };
    let bytes = (event.bytes_processed > 0)
        .then(|| format!(" • {}", format_bytes(event.bytes_processed)))
        .unwrap_or_default();
    let path = event
        .current_path
        .as_ref()
        .map(|path| format!(" • {}", compact_path(path)))
        .unwrap_or_default();
    format!("◐ {phase:<20} {progress}{bytes}{path}")
}

fn progress_bar(current: u64, total: u64, width: usize) -> String {
    let filled = if total == 0 {
        0
    } else {
        ((current.min(total) as u128 * width as u128) / total as u128) as usize
    };
    format!("[{}{}]", "━".repeat(filled), "─".repeat(width - filled))
}

fn compact_path(path: &Path) -> String {
    let components: Vec<OsString> = path
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(value) => Some(value.to_os_string()),
            _ => None,
        })
        .collect();
    let start = components.len().saturating_sub(2);
    components[start..]
        .iter()
        .collect::<PathBuf>()
        .display()
        .to_string()
}

fn print_human(
    scan: &ScanResult,
    findings: &[Finding],
    duplicates: &DuplicateReport,
    policy: &PolicySummary,
    top: usize,
    min_size: u64,
    theme: Theme,
) {
    println!();
    print_brand_header(theme, "REPORT");

    print_section("SUMMARY", theme);
    print_metric(theme, "location", scan.root.display().to_string());
    print_metric(
        theme,
        "space analyzed",
        format!("{} logical", format_bytes(scan.total_size_bytes)),
    );
    if let Some(size) = scan.total_allocated_size_bytes {
        print_metric(
            theme,
            "space on disk",
            format!("{} allocated", format_bytes(size)),
        );
    }
    print_metric(
        theme,
        "contents",
        format!(
            "{} files • {} folders",
            format_count(scan.file_count),
            format_count(scan.directory_count)
        ),
    );
    let warning_count = scan.warnings.len() + duplicates.warnings.len();
    if warning_count == 0 {
        print_metric(
            theme,
            "scan quality",
            theme.green("complete • no unreadable items"),
        );
    } else {
        print_metric(
            theme,
            "scan quality",
            theme.yellow(format!("{warning_count} items skipped or changed")),
        );
    }

    print_section("SAFETY POLICY", theme);
    print_metric(
        theme,
        "system defaults",
        if policy.default_protections_enabled {
            theme.green("enabled")
        } else {
            theme.yellow("disabled by user")
        },
    );
    print_metric(
        theme,
        "ignored",
        format!(
            "{} matched paths • {} configured rules • not scanned",
            policy.ignored_paths.len(),
            policy.ignored_rule_count
        ),
    );
    print_metric(
        theme,
        "protected",
        format!(
            "{} scanned items • {} active rules",
            format_count(policy.protected_items),
            policy.protected_rule_count
        ),
    );
    print_metric(
        theme,
        "advice withheld",
        format!(
            "{} recommendations • {} duplicate copies",
            format_count(policy.suppressed_recommendations),
            format_count(policy.protected_duplicate_copies)
        ),
    );
    for path in policy.ignored_paths.iter().take(5) {
        println!(
            "      {} {} {}",
            theme.muted("ignored"),
            theme.accent("•"),
            theme.muted(display_relative(&scan.root, path))
        );
    }
    if policy.ignored_paths.len() > 5 {
        println!(
            "      {}",
            theme.muted(format!("… {} more ignored paths", policy.ignored_paths.len() - 5))
        );
    }

    print_section("WORTH REVIEWING", theme);
    if findings.is_empty() {
        println!(
            "  {} {}",
            theme.green("✓"),
            theme.text("No deterministic cleanup candidates were found.")
        );
    } else {
        println!(
            "  {} {}",
            theme.accent(format!("{} candidates", findings.len())),
            theme.muted("• suggestions only, never automatic deletions")
        );
        println!();
        for (index, finding) in findings.iter().take(top).enumerate() {
            println!(
                "  {}. {}  •  {}",
                theme.brand(format!("{:02}", index + 1)),
                theme.text(category_label(finding.category)),
                theme.yellow(format_bytes(finding.potential_recovery_bytes))
            );
            println!(
                "      {}",
                theme.aqua(display_relative(&scan.root, &finding.path))
            );
            println!(
                "      {} {}  {} {}  {}",
                theme.muted("risk"),
                styled_risk(theme, finding.risk),
                theme.muted("confidence"),
                theme.aqua(format!("{:.0}%", finding.confidence * 100.0)),
                theme.text(action_label(finding.suggested_action))
            );
            if !finding.evidence.is_empty() {
                println!(
                    "      {} {}",
                    theme.muted("why"),
                    theme.muted(
                        finding
                            .evidence
                            .iter()
                            .map(|evidence| humanize_evidence(evidence))
                            .collect::<Vec<_>>()
                            .join("; ")
                    )
                );
            }
            println!();
        }
        print_more(findings.len(), top, "recommendations", theme);
    }

    print_section("EXACT DUPLICATES", theme);
    if duplicates.groups.is_empty() {
        println!(
            "  {} {}",
            theme.green("✓"),
            theme.text("No exact duplicate groups found among the files checked.")
        );
    } else {
        println!(
            "  {} {}",
            theme.accent(format!("{} groups", duplicates.groups.len())),
            theme.muted(format!(
                "• {} physical files hashed",
                format_count(duplicates.files_hashed)
            ))
        );
        print_metric(
            theme,
            "duplicate data",
            theme.yellow(format_bytes(duplicates.logical_duplicate_bytes)),
        );
        match duplicates.potential_recovery_allocated_bytes {
            Some(bytes) => print_metric(
                theme,
                "safe recovery",
                theme.green(format_bytes(bytes)),
            ),
            None => print_metric(theme, "safe recovery", theme.muted("unavailable")),
        }

        for (index, group) in duplicates.groups.iter().take(top).enumerate() {
            println!();
            let recovery = group
                .potential_recovery_allocated_bytes
                .map(format_bytes)
                .unwrap_or_else(|| "unknown".to_owned());
            println!(
                "  Group {}  •  {} each  •  {} physical copies  •  {} recoverable",
                theme.brand(format!("{:02}", index + 1)),
                theme.yellow(format_bytes(group.size_bytes_per_file)),
                group.unique_file_count,
                theme.green(recovery)
            );
            let mut identities = HashSet::new();
            for entry in &group.entries {
                let hard_link_alias = entry
                    .file_identity
                    .map(|identity| !identities.insert(identity))
                    .unwrap_or(false);
                let suffix = match (entry.protected, hard_link_alias) {
                    (true, true) => "  [protected • same physical file]",
                    (true, false) => "  [protected]",
                    (false, true) => "  [same physical file]",
                    (false, false) => "",
                };
                println!(
                    "      {} {}{}",
                    theme.accent("•"),
                    theme.aqua(display_relative(&scan.root, &entry.path)),
                    theme.muted(suffix)
                );
            }
            println!(
                "      {} {}…",
                theme.muted("fingerprint"),
                theme.muted(&group.blake3_hash[..12.min(group.blake3_hash.len())])
            );
        }
        print_more(duplicates.groups.len(), top, "duplicate groups", theme);
    }

    let mut items: Vec<&ScannedItem> = scan
        .items
        .iter()
        .filter(|item| {
            item.path != scan.root
                && matches!(item.kind, ItemKind::File | ItemKind::Directory)
                && item.size_bytes >= min_size
        })
        .collect();
    items.sort_by(|left, right| {
        right
            .size_bytes
            .cmp(&left.size_bytes)
            .then_with(|| left.path.cmp(&right.path))
    });

    print_section("LARGEST ITEMS", theme);
    if items.is_empty() {
        println!("  No items matched the configured minimum size.");
    } else {
        for (index, item) in items.iter().take(top).enumerate() {
            let kind = match item.kind {
                ItemKind::Directory => "folder",
                ItemKind::File => "file",
                ItemKind::Symlink | ItemKind::Other => "item",
            };
            println!(
                "  {}. {}  {}  {}",
                theme.brand(format!("{:>2}", index + 1)),
                theme.yellow(format!("{:>10}", format_bytes(item.size_bytes))),
                theme.muted(format!("{kind:<6}")),
                theme.text(display_relative(&scan.root, &item.path))
            );
        }
        print_more(items.len(), top, "items", theme);
    }

    if warning_count > 0 {
        print_section("SKIPPED SAFELY", theme);
        println!(
            "  {}",
            theme.muted("These items were skipped; the rest of the scan is still usable.\n")
        );
        for warning in scan.warnings.iter().take(10) {
            match &warning.path {
                Some(path) => println!(
                    "  {} {} — {}",
                    theme.red("!"),
                    theme.text(display_relative(&scan.root, path)),
                    theme.muted(&warning.message)
                ),
                None => println!("  {} {}", theme.red("!"), theme.muted(&warning.message)),
            }
        }
        for warning in duplicates.warnings.iter().take(10) {
            println!(
                "  {} {} — {}",
                theme.red("!"),
                theme.text(display_relative(&scan.root, &warning.path)),
                theme.muted(&warning.message)
            );
        }
        if warning_count > 20 {
            println!("  • … and {} more warnings", warning_count - 20);
        }
    }

    println!(
        "\n  {} {}\n",
        theme.green("✓"),
        theme.green("Nothing was deleted or modified.")
    );
}

fn print_section(title: &str, theme: Theme) {
    let remaining = terminal_width().saturating_sub(title.chars().count() + 8);
    println!(
        "\n  {} {} {}",
        theme.border("╭─"),
        theme.accent(title.to_ascii_lowercase()),
        theme.border(format!("{}╮", "─".repeat(remaining)))
    );
}

fn print_metric(theme: Theme, label: &str, value: impl AsRef<str>) {
    println!(
        "  {}  {}",
        theme.muted(format!("{label:<17}")),
        theme.text(value)
    );
}

fn print_more(total: usize, shown: usize, label: &str, theme: Theme) {
    if total > shown {
        println!(
            "  {}",
            theme.muted(format!("… {} more {label} hidden by --top", total - shown))
        );
    }
}

fn display_relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .ok()
        .filter(|relative| !relative.as_os_str().is_empty())
        .unwrap_or(path)
        .display()
        .to_string()
}

fn category_label(category: FindingCategory) -> &'static str {
    match category {
        FindingCategory::LargeItem => "Large item",
        FindingCategory::OldArchive => "Old archive",
        FindingCategory::OldInstaller => "Old installer",
        FindingCategory::GeneratedDirectory => "Generated build folder",
        FindingCategory::CacheDirectory => "Cache folder",
    }
}

fn risk_label(risk: RiskLevel) -> &'static str {
    match risk {
        RiskLevel::Low => "Low",
        RiskLevel::Medium => "Medium",
        RiskLevel::High => "High",
    }
}

fn styled_risk(theme: Theme, risk: RiskLevel) -> String {
    match risk {
        RiskLevel::Low => theme.green(risk_label(risk)),
        RiskLevel::Medium => theme.yellow(risk_label(risk)),
        RiskLevel::High => theme.red(risk_label(risk)),
    }
}

fn action_label(action: SuggestedAction) -> &'static str {
    match action {
        SuggestedAction::ReviewForDeletion => "Review before deleting",
        SuggestedAction::ReviewForArchive => "Review for archiving",
    }
}

fn humanize_evidence(evidence: &str) -> String {
    if let Some(bytes) = evidence
        .strip_prefix("Item is at least ")
        .and_then(|value| value.strip_suffix(" bytes, the configured large-item threshold"))
        .and_then(|value| value.parse::<u64>().ok())
    {
        return format!("Larger than the configured {} threshold", format_bytes(bytes));
    }
    if let Some(bytes) = evidence
        .strip_prefix("Directory occupies ")
        .and_then(|value| value.strip_suffix(" bytes"))
        .and_then(|value| value.parse::<u64>().ok())
    {
        return format!("Folder contains {} of data", format_bytes(bytes));
    }
    evidence.to_owned()
}

fn format_count(value: u64) -> String {
    let digits = value.to_string();
    let mut formatted = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, character) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            formatted.push(',');
        }
        formatted.push(character);
    }
    formatted
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn parse_size(input: &str) -> Result<u64, String> {
    let normalized = input.trim().to_ascii_lowercase();
    let split_at = normalized
        .find(|character: char| !character.is_ascii_digit() && character != '.')
        .unwrap_or(normalized.len());
    let (number, suffix) = normalized.split_at(split_at);
    let value: f64 = number
        .parse()
        .map_err(|_| format!("invalid size: {input}"))?;
    if !value.is_finite() || value < 0.0 {
        return Err(format!("invalid size: {input}"));
    }

    let multiplier = match suffix.trim() {
        "" | "b" => 1_f64,
        "kb" => 1_000_f64,
        "mb" => 1_000_000_f64,
        "gb" => 1_000_000_000_f64,
        "tb" => 1_000_000_000_000_f64,
        "kib" => 1024_f64,
        "mib" => 1024_f64.powi(2),
        "gib" => 1024_f64.powi(3),
        "tib" => 1024_f64.powi(4),
        _ => return Err(format!("unknown size suffix in: {input}")),
    };
    let bytes = value * multiplier;
    if bytes > u64::MAX as f64 {
        return Err(format!("size is too large: {input}"));
    }
    Ok(bytes as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn parses_decimal_and_binary_sizes() {
        assert_eq!(parse_size("100MB").unwrap(), 100_000_000);
        assert_eq!(parse_size("2GiB").unwrap(), 2 * 1024 * 1024 * 1024);
        assert_eq!(parse_size("512").unwrap(), 512);
    }

    #[test]
    fn rejects_unknown_size_suffixes() {
        assert!(parse_size("12 elephants").is_err());
    }

    #[test]
    fn formats_progress_with_known_totals() {
        let event = ProgressEvent {
            phase: AnalysisPhase::HashingDuplicates,
            items_processed: 2,
            bytes_processed: 1024,
            total_items: Some(4),
            total_bytes: Some(4096),
            current_path: Some(PathBuf::from("folder/example.bin")),
        };

        assert_eq!(
            progress_message(&event),
            "◐ Checking duplicates  [━━━━━━──────]  50%  2/4 • 1.0 KiB • folder/example.bin"
        );
    }

    #[test]
    fn formats_counts_with_thousands_separators() {
        assert_eq!(format_count(12), "12");
        assert_eq!(format_count(1_234_567), "1,234,567");
    }

    #[test]
    fn colors_are_optional_and_reset_after_styled_text() {
        assert_eq!(Theme::plain().accent("SpaceMind"), "SpaceMind");

        let colored = Theme { colors: true }.brand("SpaceMind");
        assert!(colored.starts_with("\x1b["));
        assert!(colored.ends_with("\x1b[0m"));
    }

    #[test]
    fn selector_defaults_to_the_current_directory() {
        let current = env::temp_dir();
        let mut input = Cursor::new("\n");
        let mut output = Vec::new();

        let selected = choose_directory(
            &mut input,
            &mut output,
            current.clone(),
            None,
            Theme::plain(),
        )
        .unwrap();

        assert_eq!(selected, current);
        assert!(String::from_utf8(output).unwrap().contains("Choose a folder to scan"));
    }

    #[test]
    fn makes_rule_evidence_readable() {
        assert_eq!(
            humanize_evidence(
                "Item is at least 1073741824 bytes, the configured large-item threshold"
            ),
            "Larger than the configured 1.0 GiB threshold"
        );
        assert_eq!(
            humanize_evidence("Directory occupies 1822195905 bytes"),
            "Folder contains 1.7 GiB of data"
        );
    }
}
