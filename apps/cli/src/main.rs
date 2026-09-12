use clap::{Args, Parser, Subcommand, ValueEnum};
use crossterm::cursor;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{self, ClearType};
use serde::Serialize;
use spacemind_ai::{analyze_with_ollama, AiError, OllamaOptions};
use spacemind_core::{
    AiReport, AiStatus, AiSuggestedAction, AnalysisPhase, CancellationToken, DuplicateReport,
    Finding, FindingCategory, ItemKind, PathRule, ProgressEvent, RelationshipKind,
    RelationshipReport, RiskLevel, ScanResult, ScannedItem, SuggestedAction,
};
use spacemind_db::{
    default_database_path, Analysis, Database, ScanHistoryEntry, StoredAnalysis,
};
use spacemind_duplicates::{detect_duplicates_with_progress, DuplicateOptions};
use spacemind_relationships::{
    detect_relationships_with_progress, enrich_findings_with_relationships,
};
use spacemind_rules::{evaluate_with_policy_progress, RuleOptions};
use spacemind_scanner::{scan_with_progress, ScanOptions};
use std::collections::HashSet;
use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

#[derive(Debug, Parser)]
#[command(
    name = "spacemind",
    version,
    about = "Understand what is using disk space — privately and safely",
    long_about = "SpaceMind scans local storage, explains what is taking space, and highlights \
                  items worth reviewing. It never deletes files automatically."
)]
struct Cli {
    /// SQLite database path. Defaults to SpaceMind's local user data directory.
    #[arg(long, global = true, value_name = "PATH")]
    database: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Scan a folder without modifying its contents.
    Scan(ScanArgs),
    /// Show locally stored scan history.
    History(HistoryArgs),
}

#[derive(Debug, Args)]
struct HistoryArgs {
    /// Maximum number of recent scans to show.
    #[arg(long, default_value_t = 20)]
    limit: usize,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    format: OutputFormat,
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

    /// Do not save this scan to local history.
    #[arg(long)]
    no_history: bool,

    /// Do not ask a local Ollama model to explain ambiguous candidates.
    #[arg(long)]
    no_ai: bool,

    /// Locally installed Ollama model used for explanations.
    #[arg(long, default_value = "qwen3:4b")]
    ollama_model: String,

    /// Local Ollama API endpoint. Remote endpoints are rejected.
    #[arg(long, default_value = "http://127.0.0.1:11434")]
    ollama_url: String,

    /// Maximum shortlisted items sent to the local model (capped at 32).
    #[arg(long, default_value_t = 8)]
    ai_limit: usize,
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
            no_history: false,
            no_ai: false,
            ollama_model: "qwen3:4b".to_owned(),
            ollama_url: "http://127.0.0.1:11434".to_owned(),
            ai_limit: 8,
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
    relationships: RelationshipReport,
    ai: AiReport,
    policy: PolicySummary,
    history_scan_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
struct PolicySummary {
    ignored_rule_count: usize,
    automatic_ignore_rule_count: usize,
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
    terminal: bool,
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
        Self {
            colors: false,
            terminal: false,
        }
    }

    fn for_terminal(is_terminal: bool) -> Self {
        let terminal = is_terminal
            && env::var("TERM")
                .map(|term| term != "dumb")
                .unwrap_or(true);
        let colors = terminal && env::var_os("NO_COLOR").is_none();
        Self {
            colors,
            terminal,
        }
    }

    fn paint(self, text: impl AsRef<str>, code: &str) -> String {
        if self.colors {
            format!("\x1b[{code}m{}\x1b[0m", text.as_ref())
        } else {
            text.as_ref().to_owned()
        }
    }

    fn brand(self, text: impl AsRef<str>) -> String {
        self.paint(text, "1;38;2;255;96;0")
    }

    fn accent(self, text: impl AsRef<str>) -> String {
        self.paint(text, "38;2;255;96;0")
    }

    fn selected(self, text: impl AsRef<str>) -> String {
        self.paint(text, "1;38;2;22;24;27;48;2;255;96;0")
    }

    fn aqua(self, text: impl AsRef<str>) -> String {
        self.paint(text, "1;38;2;214;217;222")
    }

    fn green(self, text: impl AsRef<str>) -> String {
        self.paint(text, "1;38;2;132;187;132")
    }

    fn yellow(self, text: impl AsRef<str>) -> String {
        self.paint(text, "1;38;2;214;170;96")
    }

    fn red(self, text: impl AsRef<str>) -> String {
        self.paint(text, "1;38;2;211;112;112")
    }

    fn text(self, text: impl AsRef<str>) -> String {
        self.paint(text, "1;38;2;225;228;232")
    }

    fn muted(self, text: impl AsRef<str>) -> String {
        self.paint(text, "38;2;132;137;145")
    }

    fn border(self, text: impl AsRef<str>) -> String {
        self.paint(text, "38;2;62;68;75")
    }
}

const MAX_CANVAS_WIDTH: usize = 86;
const PLAIN_CANVAS_WIDTH: usize = 76;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TerminalLayout {
    columns: usize,
    rows: usize,
    width: usize,
    margin: usize,
}

impl TerminalLayout {
    fn detect(theme: Theme) -> Self {
        if !theme.terminal {
            return Self::for_size(PLAIN_CANVAS_WIDTH, 24);
        }

        let (columns, rows) = terminal::size()
            .map(|(columns, rows)| (usize::from(columns), usize::from(rows)))
            .or_else(|_| {
                env::var("COLUMNS")
                    .ok()
                    .and_then(|value| value.parse::<usize>().ok())
                    .map(|columns| (columns, 24))
                    .ok_or(())
            })
            .unwrap_or((PLAIN_CANVAS_WIDTH, 24));
        Self::for_size(columns, rows)
    }

    fn for_size(columns: usize, rows: usize) -> Self {
        let available = columns.saturating_sub(2);
        let width = available.min(MAX_CANVAS_WIDTH).max(32).min(columns.max(1));
        let margin = columns.saturating_sub(width) / 2;
        Self {
            columns,
            rows,
            width,
            margin,
        }
    }

    fn prefix(self) -> String {
        " ".repeat(self.margin)
    }

    fn selector_top_padding(self, line_count: usize) -> usize {
        self.rows.saturating_sub(line_count) / 3
    }
}

fn terminal_layout(theme: Theme) -> TerminalLayout {
    TerminalLayout::detect(theme)
}

fn terminal_width(theme: Theme) -> usize {
    terminal_layout(theme).width
}

fn ui_margin(theme: Theme) -> String {
    terminal_layout(theme).prefix()
}

fn write_ui_line<W: Write>(writer: &mut W, theme: Theme, line: impl AsRef<str>) -> io::Result<()> {
    writeln!(writer, "{}{}", ui_margin(theme), line.as_ref())
}

macro_rules! ui_println {
    ($theme:expr) => {
        println!()
    };
    ($theme:expr, $($argument:tt)*) => {{
        println!("{}{}", ui_margin($theme), format!($($argument)*))
    }};
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
        Err(error) if cancellation.is_cancelled() || is_interrupted(error.as_ref()) => {
            eprintln!("Scan cancelled safely. No files were changed.");
            ExitCode::from(130)
        }
        Err(error) => {
            eprintln!("SpaceMind could not complete the scan: {error}");
            ExitCode::FAILURE
        }
    }
}

fn is_interrupted(error: &(dyn Error + 'static)) -> bool {
    error.downcast_ref::<AiError>().is_some_and(|error| matches!(error, AiError::Cancelled))
        || error
        .downcast_ref::<io::Error>()
        .is_some_and(|error| error.kind() == io::ErrorKind::Interrupted)
}

fn run(cli: Cli, cancellation: &CancellationToken) -> Result<(), Box<dyn Error>> {
    let Cli { database, command } = cli;
    let theme = Theme::stdout();
    match command {
        Some(Command::History(args)) => run_history(args, database, theme),
        Some(Command::Scan(args)) => {
            run_scan(args, database, cancellation, theme, true).map(|_| ())
        }
        None if io::stdin().is_terminal() && io::stdout().is_terminal() && theme.terminal => {
            run_interactive(database, cancellation, theme)
        }
        None => run_scan(ScanArgs::default(), database, cancellation, theme, true).map(|_| ()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InteractiveAction {
    Scan,
    History,
    Quit,
}

fn run_interactive(
    database_path: Option<PathBuf>,
    cancellation: &CancellationToken,
    theme: Theme,
) -> Result<(), Box<dyn Error>> {
    let database_path = database_path.map(Ok).unwrap_or_else(default_database_path)?;
    let database_path = absolute_path(database_path)?;
    loop {
        match choose_main_action(theme)? {
            InteractiveAction::Scan => {
                let current = env::current_dir()?;
                let home = home_directory();
                let stdout = io::stdout();
                let mut writer = stdout.lock();
                let path = match choose_directory(&mut writer, current, home, theme) {
                    Ok(path) => path,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error.into()),
                };
                drop(writer);

                let mut args = ScanArgs::default();
                args.path = Some(path);
                if let Some(scan_id) = run_scan(
                    args,
                    Some(database_path.clone()),
                    cancellation,
                    theme,
                    false,
                )? {
                    let database = Database::open(&database_path)?;
                    if let Some(analysis) = database.analysis(scan_id)? {
                        review_analysis(&analysis, theme)?;
                    }
                }
            }
            InteractiveAction::History => browse_history(&database_path, theme)?,
            InteractiveAction::Quit => return Ok(()),
        }
    }
}

fn choose_main_action(theme: Theme) -> io::Result<InteractiveAction> {
    let stdout = io::stdout();
    let mut writer = stdout.lock();
    let mut selected = 0_usize;
    let actions = [
        InteractiveAction::Scan,
        InteractiveAction::History,
        InteractiveAction::Quit,
    ];
    let _raw_mode = RawModeGuard::enter(&mut writer)?;

    let action = loop {
        render_main_menu(&mut writer, selected, theme)?;
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
            continue;
        }
        if matches!(
            key,
            KeyEvent {
                code: KeyCode::Char('c'),
                modifiers: KeyModifiers::CONTROL,
                ..
            }
        ) {
            break Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "application closed",
            ));
        }

        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                selected = selected.checked_sub(1).unwrap_or(actions.len() - 1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                selected = (selected + 1) % actions.len();
            }
            KeyCode::Char('s') | KeyCode::Char('1') => break Ok(InteractiveAction::Scan),
            KeyCode::Char('h') | KeyCode::Char('2') => break Ok(InteractiveAction::History),
            KeyCode::Char('q') | KeyCode::Char('3') | KeyCode::Esc => {
                break Ok(InteractiveAction::Quit)
            }
            KeyCode::Enter => break Ok(actions[selected]),
            _ => {}
        }
    };

    execute!(
        writer,
        cursor::Show,
        terminal::Clear(ClearType::All),
        cursor::MoveTo(0, 0)
    )?;
    action
}

fn render_main_menu<W: Write>(writer: &mut W, selected: usize, theme: Theme) -> io::Result<()> {
    let layout = terminal_layout(theme);
    let lines = main_menu_lines(selected, theme, layout);
    execute!(writer, terminal::Clear(ClearType::All), cursor::MoveTo(0, 0))?;
    let top = layout.selector_top_padding(lines.len());
    for (index, line) in lines.iter().enumerate() {
        execute!(
            writer,
            cursor::MoveTo(layout.margin as u16, (top + index) as u16),
            crossterm::style::Print(line)
        )?;
    }
    writer.flush()
}

fn main_menu_lines(selected: usize, theme: Theme, layout: TerminalLayout) -> Vec<String> {
    let mut lines = brand_header_lines_for_width(theme, "HOME", layout.width).to_vec();
    lines.push(String::new());
    lines.push(format!(
        "  {}",
        theme.accent(truncate_end(
            "storage, understood.  Private analysis on this computer.",
            layout.width.saturating_sub(2)
        ))
    ));
    lines.push(String::new());
    lines.push(format!("  {}", theme.text("What would you like to do?")));
    lines.push(format!(
        "  {}",
        theme.border("─".repeat(layout.width.saturating_sub(4)))
    ));

    let choices = [
        ("Scan storage", "analyze a folder"),
        ("Scan history", "review previous results"),
        ("Quit", "leave without changing files"),
    ];
    let label_width = layout.width.saturating_sub(18).clamp(8, 18);
    let description_width = layout.width.saturating_sub(12 + label_width);
    for (index, (label, description)) in choices.iter().enumerate() {
        let marker = if selected == index { "›" } else { " " };
        let label = pad_right(label, label_width);
        let choice = format!(" {:02}  {label} ", index + 1);
        let choice = if selected == index {
            theme.selected(choice)
        } else {
            theme.text(choice)
        };
        lines.push(format!(
            "  {} {choice}  {}",
            theme.accent(marker),
            theme.muted(truncate_end(description, description_width))
        ));
    }

    lines.push(String::new());
    lines.push(format!(
        "  {}",
        theme.border("─".repeat(layout.width.saturating_sub(4)))
    ));
    let help = truncate_end(
        "↑/↓  j/k move    enter select    q quit",
        layout.width.saturating_sub(2),
    );
    lines.push(format!("  {}", theme.muted(help)));
    lines
}

fn run_scan(
    args: ScanArgs,
    database_path: Option<PathBuf>,
    cancellation: &CancellationToken,
    theme: Theme,
    render_report: bool,
) -> Result<Option<i64>, Box<dyn Error>> {
    let history_database_path = if args.no_history {
        None
    } else {
        let path = database_path.map(Ok).unwrap_or_else(default_database_path)?;
        Some(absolute_path(path)?)
    };
    let mut database = history_database_path
        .as_ref()
        .map(Database::open)
        .transpose()?;
    let path = resolve_scan_path(args.path, args.format, theme)?;
    let mut ignored_rules = args.ignore;
    let user_ignored_rule_count = ignored_rules.len();
    let mut automatic_ignore_rule_count = 0;
    if let Some(path) = &history_database_path {
        let database_rules = database_artifact_paths(path);
        automatic_ignore_rule_count = database_rules.len();
        ignored_rules.extend(database_rules.into_iter().map(PathRule::Exact));
    }
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
    let relationships = detect_relationships_with_progress(
        &result,
        &duplicates,
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
    let policy = PolicySummary {
        ignored_rule_count: user_ignored_rule_count,
        automatic_ignore_rule_count,
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
    let mut findings = evaluation.findings;
    enrich_findings_with_relationships(&mut findings, &relationships);
    let ai = if args.no_ai {
        AiReport::disabled()
    } else {
        analyze_with_ollama(
            &result,
            &findings,
            &duplicates,
            &relationships,
            &OllamaOptions {
                endpoint: args.ollama_url,
                model: args.ollama_model,
                maximum_candidates: args.ai_limit,
                ..OllamaOptions::default()
            },
            cancellation,
            |event| progress.report(event),
        )?
    };
    progress.report(&ProgressEvent {
        phase: AnalysisPhase::Complete,
        items_processed: recommendation_total,
        bytes_processed: result.total_size_bytes,
        total_items: Some(recommendation_total),
        total_bytes: Some(result.total_size_bytes),
        current_path: None,
    });
    progress.finish();
    let history_scan_id = database
        .as_mut()
        .map(|database| {
            database.save_analysis_with_cancellation(
                Analysis {
                    scan: &result,
                    findings: &findings,
                    duplicates: &duplicates,
                    relationships: &relationships,
                    ai: &ai,
                },
                cancellation,
            )
        })
        .transpose()?;

    if render_report {
        match args.format {
        OutputFormat::Human => print_human(
            &result,
            &findings,
            &duplicates,
            &relationships,
            &ai,
            &policy,
            args.top,
            args.min_size,
            history_scan_id,
            theme,
        ),
            OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&JsonOutput {
                scan: result,
                findings,
                duplicates,
                relationships,
                ai,
                policy,
                history_scan_id,
            })?
            ),
        }
    }
    Ok(history_scan_id)
}

fn run_history(
    args: HistoryArgs,
    database_path: Option<PathBuf>,
    theme: Theme,
) -> Result<(), Box<dyn Error>> {
    let path = database_path.map(Ok).unwrap_or_else(default_database_path)?;
    let path = absolute_path(path)?;
    let database = Database::open(&path)?;
    let history = database.scan_history(args.limit)?;
    match args.format {
        OutputFormat::Human => print_history(&history, &path, theme),
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&history)?),
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReviewSection {
    Overview,
    Recommendations,
    Duplicates,
    Relationships,
    Warnings,
}

impl ReviewSection {
    const ALL: [Self; 5] = [
        Self::Overview,
        Self::Recommendations,
        Self::Duplicates,
        Self::Relationships,
        Self::Warnings,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Overview => "overview",
            Self::Recommendations => "review",
            Self::Duplicates => "duplicates",
            Self::Relationships => "related",
            Self::Warnings => "warnings",
        }
    }
}

fn browse_history(database_path: &Path, theme: Theme) -> Result<(), Box<dyn Error>> {
    let database = Database::open(database_path)?;
    let history = database.scan_history(100)?;
    let mut selected = 0_usize;

    loop {
        let stdout = io::stdout();
        let mut writer = stdout.lock();
        let chosen = {
            let _raw_mode = RawModeGuard::enter(&mut writer)?;
            loop {
                render_history_browser(&mut writer, &history, selected, database_path, theme)?;
                let Event::Key(key) = event::read()? else {
                    continue;
                };
                if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
                    continue;
                }
                if is_control_c(key) {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "application closed",
                    )
                    .into());
                }
                match key.code {
                    KeyCode::Up | KeyCode::Char('k') if !history.is_empty() => {
                        selected = selected.checked_sub(1).unwrap_or(history.len() - 1);
                    }
                    KeyCode::Down | KeyCode::Char('j') if !history.is_empty() => {
                        selected = (selected + 1) % history.len();
                    }
                    KeyCode::Home if !history.is_empty() => selected = 0,
                    KeyCode::End if !history.is_empty() => selected = history.len() - 1,
                    KeyCode::Enter if !history.is_empty() => break Some(history[selected].id),
                    KeyCode::Esc | KeyCode::Char('q') => break None,
                    _ => {}
                }
            }
        };
        execute!(
            writer,
            cursor::Show,
            terminal::Clear(ClearType::All),
            cursor::MoveTo(0, 0)
        )?;
        drop(writer);

        let Some(scan_id) = chosen else {
            return Ok(());
        };
        if let Some(analysis) = database.analysis(scan_id)? {
            review_analysis(&analysis, theme)?;
        }
    }
}

fn render_history_browser<W: Write>(
    writer: &mut W,
    history: &[ScanHistoryEntry],
    selected: usize,
    database_path: &Path,
    theme: Theme,
) -> io::Result<()> {
    let layout = terminal_layout(theme);
    let lines = history_browser_lines(history, selected, database_path, theme, layout);
    execute!(writer, terminal::Clear(ClearType::All), cursor::MoveTo(0, 0))?;
    for (row, line) in lines.iter().take(layout.rows).enumerate() {
        execute!(
            writer,
            cursor::MoveTo(layout.margin as u16, row as u16),
            crossterm::style::Print(line)
        )?;
    }
    writer.flush()
}

fn history_browser_lines(
    history: &[ScanHistoryEntry],
    selected: usize,
    database_path: &Path,
    theme: Theme,
    layout: TerminalLayout,
) -> Vec<String> {
    let mut lines = brand_header_lines_for_width(theme, "HISTORY", layout.width).to_vec();
    lines.push(String::new());
    lines.push(format!(
        "  {}",
        theme.text(truncate_end(
            "Open a previous scan and continue reviewing its results",
            layout.width.saturating_sub(2)
        ))
    ));
    lines.push(format!(
        "  {}",
        theme.muted(truncate_start(
            &database_path.display().to_string(),
            layout.width.saturating_sub(2)
        ))
    ));
    lines.push(format!(
        "  {}",
        theme.border("─".repeat(layout.width.saturating_sub(4)))
    ));

    if history.is_empty() {
        lines.push(String::new());
        lines.push(format!("  {}", theme.text("No scans have been saved yet.")));
        lines.push(format!(
            "  {}",
            theme.muted("Return home and run a storage scan first.")
        ));
    } else {
        let visible = layout.rows.saturating_sub(13).clamp(3, 12);
        let start = visible_window_start(selected, history.len(), visible);
        for (index, entry) in history.iter().enumerate().skip(start).take(visible) {
            let marker = if index == selected { "›" } else { " " };
            let row = if layout.width >= 58 {
                let path_width = layout.width.saturating_sub(36);
                format!(
                    " {marker} #{:<4} {:>9}  {:>3} items  {} ",
                    entry.id,
                    format_bytes(entry.total_size_bytes),
                    entry.recommendation_count,
                    truncate_start(&entry.root.display().to_string(), path_width)
                )
            } else {
                let path_width = layout.width.saturating_sub(20);
                format!(
                    " {marker} #{:<3} {:>9}  {} ",
                    entry.id,
                    format_bytes(entry.total_size_bytes),
                    truncate_start(&entry.root.display().to_string(), path_width)
                )
            };
            lines.push(format!(
                "  {}",
                if index == selected {
                    theme.selected(row)
                } else {
                    theme.text(row)
                }
            ));
        }
        let entry = &history[selected];
        lines.push(String::new());
        let summary = format!(
            "{} recommendations • {} duplicate groups • {} relationships",
            entry.recommendation_count,
            entry.duplicate_group_count,
            entry.relationship_count
        );
        for (index, part) in wrap_text(&summary, layout.width.saturating_sub(14))
            .iter()
            .enumerate()
        {
            let prefix = if index == 0 { "selected" } else { "" };
            lines.push(format!(
                "  {}  {}",
                theme.accent(format!("{prefix:<8}")),
                theme.text(part)
            ));
        }
        lines.push(format!(
            "  {}",
            theme.muted(format!("completed {}", format_age(entry.completed_at_epoch_seconds)))
        ));
    }

    lines.push(String::new());
    lines.push(format!(
        "  {}",
        theme.border("─".repeat(layout.width.saturating_sub(4)))
    ));
    lines.push(format!(
        "  {}",
        theme.muted(truncate_end(
            "↑/↓  j/k move    enter open scan    q back",
            layout.width.saturating_sub(2)
        ))
    ));
    lines
}

fn review_analysis(analysis: &StoredAnalysis, theme: Theme) -> io::Result<()> {
    let stdout = io::stdout();
    let mut writer = stdout.lock();
    let mut section = ReviewSection::Recommendations;
    let mut selected = [0_usize; 5];
    let _raw_mode = RawModeGuard::enter(&mut writer)?;

    loop {
        render_review(&mut writer, analysis, section, selected[section_index(section)], theme)?;
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
            continue;
        }
        if is_control_c(key) {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "application closed"));
        }
        let section_position = section_index(section);
        let item_count = review_item_count(analysis, section);
        match key.code {
            KeyCode::Left | KeyCode::Char('h') => {
                section = ReviewSection::ALL
                    [(section_position + ReviewSection::ALL.len() - 1) % ReviewSection::ALL.len()];
            }
            KeyCode::Right | KeyCode::Char('l') | KeyCode::Tab => {
                section = ReviewSection::ALL[(section_position + 1) % ReviewSection::ALL.len()];
            }
            KeyCode::BackTab => {
                section = ReviewSection::ALL
                    [(section_position + ReviewSection::ALL.len() - 1) % ReviewSection::ALL.len()];
            }
            KeyCode::Up | KeyCode::Char('k') if item_count > 0 => {
                selected[section_position] = selected[section_position]
                    .checked_sub(1)
                    .unwrap_or(item_count - 1);
            }
            KeyCode::Down | KeyCode::Char('j') if item_count > 0 => {
                selected[section_position] = (selected[section_position] + 1) % item_count;
            }
            KeyCode::Home if item_count > 0 => selected[section_position] = 0,
            KeyCode::End if item_count > 0 => selected[section_position] = item_count - 1,
            KeyCode::Char(character @ '1'..='5') => {
                section = ReviewSection::ALL[(character as usize) - ('1' as usize)];
            }
            KeyCode::Esc | KeyCode::Char('q') => break,
            _ => {}
        }
    }

    execute!(
        writer,
        cursor::Show,
        terminal::Clear(ClearType::All),
        cursor::MoveTo(0, 0)
    )?;
    Ok(())
}

fn render_review<W: Write>(
    writer: &mut W,
    analysis: &StoredAnalysis,
    section: ReviewSection,
    selected: usize,
    theme: Theme,
) -> io::Result<()> {
    let layout = terminal_layout(theme);
    let lines = review_lines(analysis, section, selected, theme, layout);
    execute!(writer, terminal::Clear(ClearType::All), cursor::MoveTo(0, 0))?;
    for (row, line) in lines.iter().take(layout.rows).enumerate() {
        execute!(
            writer,
            cursor::MoveTo(layout.margin as u16, row as u16),
            crossterm::style::Print(line)
        )?;
    }
    writer.flush()
}

fn review_lines(
    analysis: &StoredAnalysis,
    section: ReviewSection,
    selected: usize,
    theme: Theme,
    layout: TerminalLayout,
) -> Vec<String> {
    let summary = &analysis.summary;
    let mut lines = brand_header_lines_for_width(theme, "REVIEW", layout.width).to_vec();
    lines.push(format!(
        "  {}  {}",
        theme.accent(format!("scan #{}", summary.id)),
        theme.muted(truncate_start(
            &summary.root.display().to_string(),
            layout.width.saturating_sub(16)
        ))
    ));
    lines.push(format!(
        "  {}",
        theme.text(truncate_end(
            &format!(
                "{} analyzed • {} recommendations • nothing changed",
                format_bytes(summary.total_size_bytes),
                summary.recommendation_count
            ),
            layout.width.saturating_sub(2)
        ))
    ));
    lines.push(String::new());
    lines.push(review_tab_line(section, theme, layout.width));
    lines.push(format!(
        "  {}",
        theme.border("─".repeat(layout.width.saturating_sub(4)))
    ));

    match section {
        ReviewSection::Overview => {
            push_review_overview(&mut lines, analysis, theme, layout.width)
        }
        ReviewSection::Recommendations => {
            push_review_recommendations(&mut lines, analysis, selected, theme, layout)
        }
        ReviewSection::Duplicates => {
            push_review_duplicates(&mut lines, analysis, selected, theme, layout)
        }
        ReviewSection::Relationships => {
            push_review_relationships(&mut lines, analysis, selected, theme, layout)
        }
        ReviewSection::Warnings => {
            push_review_warnings(&mut lines, analysis, selected, theme, layout)
        }
    }

    lines.push(String::new());
    lines.push(format!(
        "  {}",
        theme.border("─".repeat(layout.width.saturating_sub(4)))
    ));
    lines.push(format!(
        "  {}",
        theme.muted(truncate_end(
            "←/→  h/l section    ↑/↓  j/k item    1–5 jump    q back",
            layout.width.saturating_sub(2)
        ))
    ));
    lines
}

fn review_tab_line(section: ReviewSection, theme: Theme, width: usize) -> String {
    let mut tabs = String::from("  ");
    let compact = width < 66;
    let minimal = width < 50;
    for (index, candidate) in ReviewSection::ALL.iter().enumerate() {
        let label = if minimal {
            format!(" {}{} ", index + 1, review_minimal_label(*candidate))
        } else if compact {
            format!(" {} {} ", index + 1, review_compact_label(*candidate))
        } else {
            format!(" {} {} ", index + 1, candidate.label())
        };
        if *candidate == section {
            tabs.push_str(&theme.selected(label));
        } else {
            tabs.push_str(&theme.muted(label));
        }
        tabs.push(' ');
    }
    tabs
}

fn review_minimal_label(section: ReviewSection) -> char {
    match section {
        ReviewSection::Overview => 'i',
        ReviewSection::Recommendations => 'r',
        ReviewSection::Duplicates => 'd',
        ReviewSection::Relationships => 'l',
        ReviewSection::Warnings => 'w',
    }
}

fn review_compact_label(section: ReviewSection) -> &'static str {
    match section {
        ReviewSection::Overview => "info",
        ReviewSection::Recommendations => "review",
        ReviewSection::Duplicates => "dupes",
        ReviewSection::Relationships => "links",
        ReviewSection::Warnings => "warn",
    }
}

fn push_review_overview(
    lines: &mut Vec<String>,
    analysis: &StoredAnalysis,
    theme: Theme,
    width: usize,
) {
    let summary = &analysis.summary;
    lines.push(format!("  {}", theme.text("What this scan found")));
    lines.push(String::new());
    lines.push(review_metric(
        "space analyzed",
        &format_bytes(summary.total_size_bytes),
        theme,
        width,
    ));
    lines.push(review_metric(
        "contents",
        &format!("{} files • {} folders", summary.file_count, summary.directory_count),
        theme,
        width,
    ));
    lines.push(review_metric(
        "review queue",
        &format!("{} recommendations", analysis.findings.len()),
        theme,
        width,
    ));
    lines.push(review_metric(
        "duplicates",
        &format!("{} exact groups", analysis.duplicate_groups.len()),
        theme,
        width,
    ));
    lines.push(review_metric(
        "relationships",
        &format!("{} connections", analysis.relationships.len()),
        theme,
        width,
    ));
    lines.push(review_metric(
        "local AI",
        &format!("{} saved explanations", analysis.ai_explanations.len()),
        theme,
        width,
    ));
    lines.push(String::new());
    lines.push(format!(
        "  {} {}",
        theme.green("✓"),
        theme.text(truncate_end(
            "This scan only observed metadata. It did not change any files.",
            width.saturating_sub(4)
        ))
    ));
}

fn push_review_recommendations(
    lines: &mut Vec<String>,
    analysis: &StoredAnalysis,
    selected: usize,
    theme: Theme,
    layout: TerminalLayout,
) {
    if analysis.findings.is_empty() {
        lines.push(format!(
            "  {} {}",
            theme.green("✓"),
            theme.text(truncate_end(
                "No cleanup candidates were found.",
                layout.width.saturating_sub(6)
            ))
        ));
        return;
    }
    lines.push(format!(
        "  {}",
        theme.text(truncate_end(
            "Safest and clearest candidates appear first — size is not the only factor",
            layout.width.saturating_sub(2)
        ))
    ));
    let visible = review_list_height(layout);
    let start = visible_window_start(selected, analysis.findings.len(), visible);
    for (index, finding) in analysis.findings.iter().enumerate().skip(start).take(visible) {
        let marker = if index == selected { "›" } else { " " };
        let row = if layout.width >= 60 {
            let path_width = layout.width.saturating_sub(48);
            format!(
                " {marker} {:>9}  {:<6} {:<19} {} ",
                format_bytes(finding.potential_recovery_bytes),
                risk_label(finding.risk),
                truncate_end(category_label(finding.category), 19),
                truncate_start(
                    &display_relative(&analysis.summary.root, &finding.path),
                    path_width
                )
            )
        } else {
            let path_width = layout.width.saturating_sub(24);
            format!(
                " {marker} {:>9} {:<6} {} ",
                format_bytes(finding.potential_recovery_bytes),
                risk_label(finding.risk),
                truncate_start(
                    &display_relative(&analysis.summary.root, &finding.path),
                    path_width
                )
            )
        };
        lines.push(format!(
            "  {}",
            if index == selected {
                theme.selected(row)
            } else {
                theme.text(row)
            }
        ));
    }
    push_recommendation_detail(lines, analysis, selected, theme, layout.width);
}

fn push_recommendation_detail(
    lines: &mut Vec<String>,
    analysis: &StoredAnalysis,
    selected: usize,
    theme: Theme,
    width: usize,
) {
    let finding = &analysis.findings[selected];
    lines.push(String::new());
    if width >= 48 {
        lines.push(format!(
            "  {}  {}",
            theme.accent("WHY REVIEW THIS"),
            theme.muted("deterministic evidence")
        ));
    } else {
        lines.push(format!("  {}", theme.accent("WHY REVIEW THIS")));
    }
    lines.push(review_metric(
        "item",
        &display_relative(&analysis.summary.root, &finding.path),
        theme,
        width,
    ));
    lines.push(review_metric(
        "potential space",
        &format_bytes(finding.potential_recovery_bytes),
        theme,
        width,
    ));
    lines.push(review_metric(
        "risk / confidence",
        &format!("{} / {:.0}%", risk_label(finding.risk), finding.confidence * 100.0),
        theme,
        width,
    ));
    lines.push(review_metric(
        "next step",
        action_label(finding.suggested_action),
        theme,
        width,
    ));
    lines.push(review_metric(
        "guidance",
        recommendation_guidance(finding.risk, finding.suggested_action),
        theme,
        width,
    ));
    for evidence in &finding.evidence {
        push_review_bullet(lines, &humanize_evidence(evidence), theme, width);
    }
    if let Some(explanation) = analysis
        .ai_explanations
        .iter()
        .find(|explanation| explanation.path == finding.path)
    {
        if width >= 58 {
            lines.push(format!(
                "  {}  {}",
                theme.accent("LOCAL AI"),
                theme.muted("context only • never deletion permission")
            ));
        } else {
            lines.push(format!("  {}", theme.accent("LOCAL AI • ADVISORY")));
        }
        push_review_bullet(lines, &explanation.reason, theme, width);
    }
}

fn push_review_duplicates(
    lines: &mut Vec<String>,
    analysis: &StoredAnalysis,
    selected: usize,
    theme: Theme,
    layout: TerminalLayout,
) {
    if analysis.duplicate_groups.is_empty() {
        lines.push(format!(
            "  {} {}",
            theme.green("✓"),
            theme.text(truncate_end(
                "No exact duplicate groups were found.",
                layout.width.saturating_sub(6)
            ))
        ));
        return;
    }
    lines.push(format!(
        "  {}",
        theme.text(truncate_end(
            "Exact byte-for-byte matches; keep at least one physical copy",
            layout.width.saturating_sub(2)
        ))
    ));
    let visible = review_list_height(layout);
    let start = visible_window_start(selected, analysis.duplicate_groups.len(), visible);
    for (index, group) in analysis
        .duplicate_groups
        .iter()
        .enumerate()
        .skip(start)
        .take(visible)
    {
        let marker = if index == selected { "›" } else { " " };
        let recovery = group
            .potential_recovery_allocated_bytes
            .map(format_bytes)
            .unwrap_or_else(|| "unknown".to_owned());
        let row = if layout.width >= 56 {
            format!(
                " {marker} {:>9} recoverable  {:>3} copies  {}… ",
                recovery,
                group.unique_file_count,
                &group.blake3_hash[..12.min(group.blake3_hash.len())]
            )
        } else {
            format!(
                " {marker} {:>9}  {:>3} copies ",
                recovery, group.unique_file_count
            )
        };
        lines.push(format!(
            "  {}",
            if index == selected {
                theme.selected(row)
            } else {
                theme.text(row)
            }
        ));
    }
    let group = &analysis.duplicate_groups[selected];
    lines.push(String::new());
    lines.push(format!("  {}", theme.accent("FILES IN THIS GROUP")));
    for entry in group.entries.iter().take(6) {
        let suffix = if entry.protected { "  [protected]" } else { "" };
        push_review_bullet(
            lines,
            &format!(
                "{}{}",
                display_relative(&analysis.summary.root, &entry.path),
                suffix
            ),
            theme,
            layout.width,
        );
    }
}

fn push_review_relationships(
    lines: &mut Vec<String>,
    analysis: &StoredAnalysis,
    selected: usize,
    theme: Theme,
    layout: TerminalLayout,
) {
    if analysis.relationships.is_empty() {
        lines.push(format!(
            "  {} {}",
            theme.green("✓"),
            theme.text(truncate_end(
                "No related items were detected.",
                layout.width.saturating_sub(6)
            ))
        ));
        return;
    }
    lines.push(format!(
        "  {}",
        theme.text(truncate_end(
            "Connections are evidence, never permission to delete",
            layout.width.saturating_sub(2)
        ))
    ));
    let visible = review_list_height(layout);
    let start = visible_window_start(selected, analysis.relationships.len(), visible);
    for (index, relationship) in analysis
        .relationships
        .iter()
        .enumerate()
        .skip(start)
        .take(visible)
    {
        let marker = if index == selected { "›" } else { " " };
        let label_width = if layout.width >= 60 { 24 } else { 12 };
        let path_width = layout.width.saturating_sub(label_width + 8);
        let row = format!(
            " {marker} {:<label_width$} {} ",
            truncate_end(relationship_kind_label(relationship.kind), label_width),
            truncate_start(
                &display_relative(&analysis.summary.root, &relationship.source_path),
                path_width
            )
        );
        lines.push(format!(
            "  {}",
            if index == selected {
                theme.selected(row)
            } else {
                theme.text(row)
            }
        ));
    }
    let relationship = &analysis.relationships[selected];
    lines.push(String::new());
    lines.push(format!("  {}", theme.accent("CONNECTED ITEMS")));
    lines.push(review_metric(
        "source",
        &display_relative(&analysis.summary.root, &relationship.source_path),
        theme,
        layout.width,
    ));
    lines.push(review_metric(
        "related",
        &display_relative(&analysis.summary.root, &relationship.target_path),
        theme,
        layout.width,
    ));
    lines.push(review_metric(
        "confidence",
        &format!("{:.0}%", relationship.confidence * 100.0),
        theme,
        layout.width,
    ));
    for evidence in &relationship.evidence {
        push_review_bullet(lines, evidence, theme, layout.width);
    }
}

fn push_review_warnings(
    lines: &mut Vec<String>,
    analysis: &StoredAnalysis,
    selected: usize,
    theme: Theme,
    layout: TerminalLayout,
) {
    let warning_count = analysis.summary.warning_count;
    if warning_count == 0 {
        lines.push(format!(
            "  {} {}",
            theme.green("✓"),
            theme.text(truncate_end(
                "The scan completed without skipped or changing files.",
                layout.width.saturating_sub(6)
            ))
        ));
    } else if !analysis.warnings.is_empty() {
        lines.push(format!(
            "  {}",
            theme.text(truncate_end(
                "Skipped or changing items; the rest of the scan remains usable",
                layout.width.saturating_sub(2)
            ))
        ));
        let visible = review_list_height(layout);
        let start = visible_window_start(selected, analysis.warnings.len(), visible);
        for (index, warning) in analysis.warnings.iter().enumerate().skip(start).take(visible) {
            let marker = if index == selected { "›" } else { " " };
            let location = warning
                .path
                .as_deref()
                .map(|path| display_relative(&analysis.summary.root, path))
                .unwrap_or_else(|| "scan".to_owned());
            let path_width = layout.width.saturating_sub(18);
            let row = format!(
                " {marker} {:<10} {} ",
                truncate_end(&warning.source, 10),
                truncate_start(&location, path_width)
            );
            lines.push(format!(
                "  {}",
                if index == selected {
                    theme.selected(row)
                } else {
                    theme.text(row)
                }
            ));
        }
        let warning = &analysis.warnings[selected];
        lines.push(String::new());
        lines.push(format!("  {}", theme.accent("WHAT HAPPENED")));
        push_review_bullet(lines, &warning.message, theme, layout.width);
        if let Some(kind) = &warning.kind {
            lines.push(review_metric(
                "warning type",
                &kind.replace('_', " "),
                theme,
                layout.width,
            ));
        }
    } else {
        push_review_bullet(
            lines,
            &format!("{warning_count} items were skipped or changed while scanning."),
            theme,
            layout.width,
        );
        lines.push(String::new());
        push_review_bullet(
            lines,
            "History stores the warning count, not each warning message.",
            theme,
            layout.width,
        );
        push_review_bullet(
            lines,
            "Run the scan again to inspect current filesystem results.",
            theme,
            layout.width,
        );
    }
}

fn review_metric(label: &str, value: &str, theme: Theme, width: usize) -> String {
    let value_width = width.saturating_sub(22).max(1);
    format!(
        "  {}  {}",
        theme.muted(format!("{label:<18}")),
        theme.text(truncate_start(value, value_width))
    )
}

fn push_review_bullet(lines: &mut Vec<String>, value: &str, theme: Theme, width: usize) {
    let content_width = width.saturating_sub(8).max(1);
    for (index, part) in wrap_text(value, content_width).iter().enumerate() {
        let marker = if index == 0 { "•" } else { " " };
        lines.push(format!(
            "    {} {}",
            theme.accent(marker),
            theme.muted(part)
        ));
    }
}

fn review_list_height(layout: TerminalLayout) -> usize {
    layout.rows.saturating_sub(24).clamp(1, 7)
}

fn visible_window_start(selected: usize, total: usize, visible: usize) -> usize {
    if total <= visible || selected < visible {
        0
    } else {
        (selected + 1 - visible).min(total.saturating_sub(visible))
    }
}

fn review_item_count(analysis: &StoredAnalysis, section: ReviewSection) -> usize {
    match section {
        ReviewSection::Overview => 0,
        ReviewSection::Recommendations => analysis.findings.len(),
        ReviewSection::Duplicates => analysis.duplicate_groups.len(),
        ReviewSection::Relationships => analysis.relationships.len(),
        ReviewSection::Warnings => analysis.warnings.len(),
    }
}

fn section_index(section: ReviewSection) -> usize {
    ReviewSection::ALL
        .iter()
        .position(|candidate| *candidate == section)
        .expect("review section belongs to the static section list")
}

fn is_control_c(key: KeyEvent) -> bool {
    matches!(
        key,
        KeyEvent {
            code: KeyCode::Char('c'),
            modifiers: KeyModifiers::CONTROL,
            ..
        }
    )
}

fn absolute_path(path: PathBuf) -> io::Result<PathBuf> {
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(env::current_dir()?.join(path))
    }
}

fn database_artifact_paths(path: &Path) -> Vec<PathBuf> {
    let mut paths = vec![path.to_path_buf()];
    let Some(file_name) = path.file_name() else {
        return paths;
    };
    for suffix in ["-journal", "-wal", "-shm"] {
        let mut sidecar = file_name.to_os_string();
        sidecar.push(suffix);
        paths.push(path.with_file_name(sidecar));
    }
    paths
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
    if format == OutputFormat::Json
        || !io::stdin().is_terminal()
        || !io::stdout().is_terminal()
        || !theme.terminal
    {
        return Ok(current);
    }

    let home = home_directory();
    let stdout = io::stdout();
    let mut writer = stdout.lock();
    choose_directory(&mut writer, current, home, theme).map_err(Into::into)
}

fn choose_directory<W: Write>(
    writer: &mut W,
    current: PathBuf,
    home: Option<PathBuf>,
    theme: Theme,
) -> io::Result<PathBuf> {
    let choices = directory_choices(current, home);
    let mut selected = 0_usize;
    let mut custom_input: Option<String> = None;
    let mut message: Option<String> = None;
    let _raw_mode = RawModeGuard::enter(writer)?;

    let result = loop {
        render_directory_selector(
            writer,
            &choices,
            selected,
            custom_input.as_deref(),
            message.as_deref(),
            theme,
        )?;

        let Event::Key(key) = event::read()? else {
            continue;
        };
        if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
            continue;
        }
        if matches!(
            key,
            KeyEvent {
                code: KeyCode::Char('c'),
                modifiers: KeyModifiers::CONTROL,
                ..
            }
        ) {
            break Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "folder selection cancelled",
            ));
        }

        if let Some(input) = custom_input.as_mut() {
            match key.code {
                KeyCode::Enter => {
                    let path = expand_home(PathBuf::from(input.trim()));
                    if path.is_dir() {
                        break Ok(path);
                    }
                    message = Some("That folder does not exist. Check the path and try again.".to_owned());
                }
                KeyCode::Esc => {
                    custom_input = None;
                    message = None;
                }
                KeyCode::Backspace => {
                    input.pop();
                    message = None;
                }
                KeyCode::Char(character) => {
                    input.push(character);
                    message = None;
                }
                _ => {}
            }
            continue;
        }

        match key {
            KeyEvent {
                code: KeyCode::Char('q'),
                ..
            } => {
                break Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "folder selection cancelled",
                ))
            }
            KeyEvent {
                code: KeyCode::Up | KeyCode::Char('k'),
                ..
            } => {
                selected = selected.checked_sub(1).unwrap_or(choices.len());
                message = None;
            }
            KeyEvent {
                code: KeyCode::Down | KeyCode::Char('j'),
                ..
            } => {
                selected = (selected + 1) % (choices.len() + 1);
                message = None;
            }
            KeyEvent {
                code: KeyCode::Char('c'),
                ..
            } => {
                selected = choices.len();
                custom_input = Some(String::new());
                message = None;
            }
            KeyEvent {
                code: KeyCode::Char(character),
                ..
            } if character.is_ascii_digit() => {
                if let Some(index) = character
                    .to_digit(10)
                    .map(|value| value as usize)
                    .and_then(|value| value.checked_sub(1))
                    .filter(|index| *index <= choices.len())
                {
                    selected = index;
                }
            }
            KeyEvent {
                code: KeyCode::Enter,
                ..
            } => {
                if let Some((_, path)) = choices.get(selected) {
                    break Ok(path.clone());
                }
                custom_input = Some(String::new());
                message = None;
            }
            _ => {}
        }
    };

    execute!(
        writer,
        cursor::Show,
        terminal::Clear(ClearType::All),
        cursor::MoveTo(0, 0)
    )?;
    result
}

fn directory_choices(current: PathBuf, home: Option<PathBuf>) -> Vec<(String, PathBuf)> {
    let mut choices = vec![("Current folder".to_owned(), current)];
    if let Some(home) = home {
        add_directory_choice(&mut choices, "Home", home.clone());
        add_directory_choice(&mut choices, "Downloads", home.join("Downloads"));
        add_directory_choice(&mut choices, "Documents", home.join("Documents"));
        add_directory_choice(&mut choices, "Desktop", home.join("Desktop"));
    }
    choices
}

fn render_directory_selector<W: Write>(
    writer: &mut W,
    choices: &[(String, PathBuf)],
    selected: usize,
    custom_input: Option<&str>,
    message: Option<&str>,
    theme: Theme,
) -> io::Result<()> {
    let layout = terminal_layout(theme);
    let lines = directory_selector_lines(
        choices,
        selected,
        custom_input,
        message,
        theme,
        layout,
    );

    execute!(writer, terminal::Clear(ClearType::All), cursor::MoveTo(0, 0))?;
    let top = layout.selector_top_padding(lines.len());
    for (index, line) in lines.iter().enumerate() {
        execute!(
            writer,
            cursor::MoveTo(layout.margin as u16, (top + index) as u16),
            crossterm::style::Print(line)
        )?;
    }
    writer.flush()
}

fn directory_selector_lines(
    choices: &[(String, PathBuf)],
    selected: usize,
    custom_input: Option<&str>,
    message: Option<&str>,
    theme: Theme,
    layout: TerminalLayout,
) -> Vec<String> {
    let mut lines = brand_header_lines_for_width(theme, "SCAN", layout.width).to_vec();
    lines.push(String::new());

    let tagline = "storage, understood.  Private analysis on this computer.";
    lines.push(format!(
        "  {}",
        theme.accent(truncate_end(tagline, layout.width.saturating_sub(2)))
    ));
    lines.push(String::new());
    lines.push(format!(
        "  {}",
        theme.text(truncate_end(
            "Choose a folder to scan",
            layout.width.saturating_sub(2)
        ))
    ));
    lines.push(format!(
        "  {}",
        theme.border("─".repeat(layout.width.saturating_sub(4)))
    ));

    let label_width = layout.width.saturating_sub(16).clamp(4, 16);
    let path_width = layout.width.saturating_sub(12 + label_width);
    for (index, (label, path)) in choices.iter().enumerate() {
        let marker = if selected == index { "›" } else { " " };
        let label = pad_right(label, label_width);
        let choice = format!(" {:02}  {label} ", index + 1);
        let choice = if selected == index {
            theme.selected(choice)
        } else {
            theme.text(choice)
        };
        let path = truncate_start(&path.display().to_string(), path_width);
        lines.push(format!(
            "  {} {choice}  {}",
            theme.accent(marker),
            theme.muted(path)
        ));
    }

    let custom_index = choices.len();
    let marker = if selected == custom_index { "›" } else { " " };
    let custom_label = pad_right("Custom path", label_width);
    let custom_choice = format!(" {:02}  {custom_label} ", custom_index + 1);
    let custom_choice = if selected == custom_index {
        theme.selected(custom_choice)
    } else {
        theme.text(custom_choice)
    };
    let custom_hint = truncate_end("enter any folder", path_width);
    lines.push(format!(
        "  {} {custom_choice}  {}",
        theme.accent(marker),
        theme.muted(custom_hint)
    ));
    lines.push(String::new());
    lines.push(format!(
        "  {}",
        theme.border("─".repeat(layout.width.saturating_sub(4)))
    ));

    if let Some(input) = custom_input {
        let prefix = "  path › ";
        let available = layout.width.saturating_sub(display_width(prefix));
        let input = truncate_start(&format!("{input}▌"), available);
        lines.push(format!(
            "  {} {}",
            theme.accent("path ›"),
            theme.text(input)
        ));
        let help = truncate_end(
            "enter accept    esc go back",
            layout.width.saturating_sub(2),
        );
        lines.push(format!("  {}", theme.muted(help)));
    } else {
        let full_help = "↑/↓  j/k move    enter scan    c custom    q quit";
        let compact_help = "j/k move  enter scan  q quit";
        let available = layout.width.saturating_sub(2);
        let help = if display_width(full_help) <= available {
            full_help.to_owned()
        } else {
            truncate_end(compact_help, available)
        };
        lines.push(format!("  {}", theme.muted(help)));
    }
    if let Some(message) = message {
        let message = truncate_end(message, layout.width.saturating_sub(4));
        lines.push(format!("  {} {}", theme.red("!"), theme.muted(message)));
    }
    lines
}

struct RawModeGuard;

impl RawModeGuard {
    fn enter<W: Write>(writer: &mut W) -> io::Result<Self> {
        terminal::enable_raw_mode()?;
        if let Err(error) = execute!(writer, cursor::Hide) {
            let _ = terminal::disable_raw_mode();
            return Err(error);
        }
        Ok(Self)
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
        let _ = execute!(io::stdout(), cursor::Show);
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
        "/sbin", "/sys", "/usr", "/var/cache", "/var/lib", "/var/log",
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

fn brand_header_lines(theme: Theme, active: &str) -> [String; 3] {
    brand_header_lines_for_width(theme, active, terminal_width(theme))
}

fn brand_header_lines_for_width(theme: Theme, active: &str, width: usize) -> [String; 3] {
    let scan_label = if active == "SCAN" { "[scan]" } else { " scan " };
    let report_label = if active == "REPORT" {
        "[report]"
    } else {
        " report "
    };
    let scan = if active == "SCAN" {
        theme.selected(scan_label)
    } else {
        theme.muted(scan_label)
    };
    let report = if active == "REPORT" {
        theme.selected(report_label)
    } else {
        theme.muted(report_label)
    };
    let interior_width = width.saturating_sub(2);
    let full_left_width = display_width(" SPACEMIND   ")
        + display_width(scan_label)
        + 3
        + display_width(report_label);
    let right = "local / read only ";

    let middle = if full_left_width + 1 + display_width(right) <= interior_width {
        let padding = interior_width - full_left_width - display_width(right);
        format!(
            "{} {}   {}   {}{}{}{}",
            theme.border("│"),
            theme.brand("SPACEMIND"),
            scan,
            report,
            " ".repeat(padding),
            theme.muted(right),
            theme.border("│")
        )
    } else {
        let active_label = format!("[{}]", active.to_ascii_lowercase());
        let compact_width = display_width(" SPACEMIND   ") + display_width(&active_label);
        if compact_width <= interior_width {
            let padding = interior_width - compact_width;
            format!(
                "{} {}   {}{}{}",
                theme.border("│"),
                theme.brand("SPACEMIND"),
                theme.selected(active_label),
                " ".repeat(padding),
                theme.border("│")
            )
        } else {
            let content = pad_right(
                &truncate_end(" SPACEMIND", interior_width),
                interior_width,
            );
            format!(
                "{}{}{}",
                theme.border("│"),
                theme.brand(content),
                theme.border("│")
            )
        }
    };

    [
        theme.border(format!("┌{}┐", "─".repeat(width.saturating_sub(2)))),
        middle,
        theme.border(format!("└{}┘", "─".repeat(width.saturating_sub(2)))),
    ]
}

fn write_brand_header<W: Write>(writer: &mut W, theme: Theme, active: &str) -> io::Result<()> {
    for line in brand_header_lines(theme, active) {
        write_ui_line(writer, theme, line)?;
    }
    Ok(())
}

fn print_brand_header(theme: Theme, active: &str) {
    let stdout = io::stdout();
    let mut writer = stdout.lock();
    let _ = write_brand_header(&mut writer, theme, active);
}

fn print_scan_start(path: &Path, theme: Theme) {
    print_brand_header(theme, "SCAN");
    ui_println!(theme);
    ui_println!(
        theme,
        "  {}  {}",
        theme.accent("storage, understood."),
        theme.muted("A private look at what is using your disk.")
    );
    ui_println!(theme);
    ui_println!(theme, "  {}  {}", theme.muted("target"), theme.text(path.display().to_string()));
    ui_println!(
        theme,
        "  {}  {}",
        theme.muted("safety"),
        theme.green("local / read only / nothing is deleted")
    );
    ui_println!(
        theme,
        "  {}  {}",
        theme.muted("cancel"),
        theme.text("ctrl+c at any time")
    );
    ui_println!(theme);
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
            AnalysisPhase::DetectingRelationships => self.theme.aqua(&message),
            AnalysisPhase::ExplainingCandidates => self.theme.aqua(&message),
            AnalysisPhase::Complete => self.theme.green(&message),
        };
        eprint!("\r\x1b[2K{}  {rendered}", ui_margin(self.theme));
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
        AnalysisPhase::DetectingRelationships => "Connecting context",
        AnalysisPhase::ExplainingCandidates => "Explaining context",
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

fn truncate_start(value: &str, maximum_width: usize) -> String {
    if display_width(value) <= maximum_width {
        return value.to_owned();
    }
    if maximum_width == 0 {
        return String::new();
    }

    let tail_width = maximum_width.saturating_sub(display_width("…"));
    let mut used = 0;
    let mut visible_tail = Vec::new();
    for character in value.chars().rev() {
        let character_width = UnicodeWidthChar::width(character).unwrap_or(0);
        if used + character_width > tail_width {
            break;
        }
        used += character_width;
        visible_tail.push(character);
    }
    visible_tail.reverse();
    let visible_tail = visible_tail.into_iter().collect::<String>();
    format!("…{visible_tail}")
}

fn display_width(value: &str) -> usize {
    UnicodeWidthStr::width(value)
}

fn pad_right(value: &str, width: usize) -> String {
    let value = truncate_end(value, width);
    format!(
        "{value}{}",
        " ".repeat(width.saturating_sub(display_width(&value)))
    )
}

fn truncate_end(value: &str, maximum_width: usize) -> String {
    if display_width(value) <= maximum_width {
        return value.to_owned();
    }
    if maximum_width == 0 {
        return String::new();
    }

    let content_width = maximum_width.saturating_sub(display_width("…"));
    let mut used = 0;
    let mut visible = String::new();
    for character in value.chars() {
        let character_width = UnicodeWidthChar::width(character).unwrap_or(0);
        if used + character_width > content_width {
            break;
        }
        used += character_width;
        visible.push(character);
    }
    visible.push('…');
    visible
}

fn warning_display_counts(
    scan_warnings: usize,
    duplicate_warnings: usize,
) -> (usize, usize, usize) {
    let shown_scan = scan_warnings.min(10);
    let shown_duplicates = duplicate_warnings.min(10);
    let hidden = scan_warnings
        .saturating_sub(shown_scan)
        .saturating_add(duplicate_warnings.saturating_sub(shown_duplicates));
    (shown_scan, shown_duplicates, hidden)
}

fn print_human(
    scan: &ScanResult,
    findings: &[Finding],
    duplicates: &DuplicateReport,
    relationships: &RelationshipReport,
    ai: &AiReport,
    policy: &PolicySummary,
    top: usize,
    min_size: u64,
    history_scan_id: Option<i64>,
    theme: Theme,
) {
    ui_println!(theme);
    print_brand_header(theme, "REPORT");

    let warning_count = scan.warnings.len() + duplicates.warnings.len();
    print_report_index(theme);
    print_section("01", "OVERVIEW", "What was scanned and what SpaceMind found", theme);
    print_overview_counts(
        theme,
        findings.len(),
        duplicates.groups.len(),
        relationships.relationships.len(),
    );
    ui_println!(theme);
    print_metric(
        theme,
        "location",
        &scan.root.display().to_string(),
        RecordTone::Text,
    );
    print_metric(
        theme,
        "space analyzed",
        &format!("{} logical", format_bytes(scan.total_size_bytes)),
        RecordTone::Text,
    );
    if let Some(size) = scan.total_allocated_size_bytes {
        print_metric(
            theme,
            "space on disk",
            &format!("{} allocated", format_bytes(size)),
            RecordTone::Text,
        );
    }
    print_metric(
        theme,
        "contents",
        &format!(
            "{} files • {} folders",
            format_count(scan.file_count),
            format_count(scan.directory_count)
        ),
        RecordTone::Text,
    );
    if warning_count == 0 {
        print_metric(
            theme,
            "scan quality",
            "complete • no unreadable items",
            RecordTone::Positive,
        );
    } else {
        print_metric(
            theme,
            "scan quality",
            &format!("{warning_count} items skipped or changed"),
            RecordTone::Warning,
        );
    }
    match history_scan_id {
        Some(scan_id) => print_metric(
            theme,
            "history",
            &format!("saved locally as scan #{scan_id}"),
            RecordTone::Positive,
        ),
        None => print_metric(
            theme,
            "history",
            "disabled for this scan",
            RecordTone::Text,
        ),
    }
    let (ai_label, ai_tone) = match &ai.status {
        AiStatus::Disabled => ("disabled by user".to_owned(), RecordTone::Text),
        AiStatus::NoCandidates => (
            "not needed • no ambiguous candidates".to_owned(),
            RecordTone::Positive,
        ),
        AiStatus::Unavailable { reason } => {
            (format!("unavailable • {reason}"), RecordTone::Warning)
        }
        AiStatus::Complete { model } => (
            format!("{model} • {} local explanations", ai.explanations.len()),
            RecordTone::Positive,
        ),
        AiStatus::Partial { model } => (
            format!(
                "{model} • {} explanations • some output rejected",
                ai.explanations.len()
            ),
            RecordTone::Warning,
        ),
    };
    print_metric(theme, "local AI", &ai_label, ai_tone);

    print_section(
        "02",
        "SAFETY",
        "Paths excluded from cleanup advice",
        theme,
    );
    print_metric(
        theme,
        "system defaults",
        if policy.default_protections_enabled {
            "enabled"
        } else {
            "disabled by user"
        },
        if policy.default_protections_enabled {
            RecordTone::Positive
        } else {
            RecordTone::Warning
        },
    );
    print_metric(
        theme,
        "ignored",
        &format!(
            "{} matched paths • {} user rules • {} automatic rules • not scanned",
            policy.ignored_paths.len(),
            policy.ignored_rule_count,
            policy.automatic_ignore_rule_count
        ),
        RecordTone::Text,
    );
    print_metric(
        theme,
        "protected",
        &format!(
            "{} scanned items • {} active rules",
            format_count(policy.protected_items),
            policy.protected_rule_count
        ),
        RecordTone::Text,
    );
    print_metric(
        theme,
        "advice withheld",
        &format!(
            "{} recommendations • {} duplicate copies",
            format_count(policy.suppressed_recommendations),
            format_count(policy.protected_duplicate_copies)
        ),
        RecordTone::Text,
    );
    for path in policy.ignored_paths.iter().take(5) {
        ui_println!(
            theme,
            "      {} {} {}",
            theme.muted("ignored"),
            theme.accent("•"),
            theme.muted(display_relative(&scan.root, path))
        );
    }
    if policy.ignored_paths.len() > 5 {
        ui_println!(
            theme,
            "      {}",
            theme.muted(format!("… {} more ignored paths", policy.ignored_paths.len() - 5))
        );
    }

    print_section(
        "03",
        "RECOMMENDATIONS",
        "Items that may be worth reviewing",
        theme,
    );
    if findings.is_empty() {
        ui_println!(
            theme,
            "  {} {}",
            theme.green("✓"),
            theme.text("No deterministic cleanup candidates were found.")
        );
    } else {
        ui_println!(
            theme,
            "  {} {}",
            theme.accent(format!("{} candidates", findings.len())),
            theme.muted("• suggestions only, never automatic deletions")
        );
        let mut explained_paths = HashSet::new();
        for (index, finding) in findings.iter().take(top).enumerate() {
            if index > 0 {
                print_record_divider(theme);
            }
            ui_println!(
                theme,
                "  {}  {}",
                theme.selected(format!(" {:02} ", index + 1)),
                theme.text(category_label(finding.category)),
            );
            print_record_field(
                theme,
                "item",
                &display_relative(&scan.root, &finding.path),
                RecordTone::Text,
            );
            print_record_field(
                theme,
                "recovery",
                &format_bytes(finding.potential_recovery_bytes),
                RecordTone::Accent,
            );
            print_record_field(theme, "risk", risk_label(finding.risk), risk_tone(finding.risk));
            print_record_field(
                theme,
                "confidence",
                &format!("{:.0}%", finding.confidence * 100.0),
                RecordTone::Text,
            );
            print_record_field(
                theme,
                "action",
                action_label(finding.suggested_action),
                RecordTone::Text,
            );
            if !finding.evidence.is_empty() {
                ui_println!(theme, "      {}", theme.muted("evidence"));
                for evidence in &finding.evidence {
                    print_wrapped_bullet(
                        theme,
                        &humanize_evidence(evidence),
                    );
                }
            }
            if explained_paths.insert(&finding.path) {
                if let Some(explanation) = ai
                    .explanations
                    .iter()
                    .find(|explanation| explanation.path == finding.path)
                {
                    ui_println!(
                        theme,
                        "      {}",
                        theme.muted("local AI context • advisory only")
                    );
                    print_wrapped_bullet(theme, &explanation.reason);
                    print_record_field(
                        theme,
                        "AI assessment",
                        &format!(
                            "{} risk • {:.0}% confidence • {}",
                            risk_label(explanation.risk),
                            explanation.confidence * 100.0,
                            ai_action_label(explanation.suggested_action)
                        ),
                        risk_tone(explanation.risk),
                    );
                }
            }
        }
        if findings.len() > top {
            ui_println!(theme);
        }
        print_more(findings.len(), top, "recommendations", theme);
    }

    print_section(
        "04",
        "RELATIONSHIPS",
        "Filesystem context connecting related items",
        theme,
    );
    if relationships.relationships.is_empty() {
        ui_println!(
            theme,
            "  {} {}",
            theme.green("✓"),
            theme.text("No deterministic item relationships were found.")
        );
    } else {
        ui_println!(
            theme,
            "  {} {}",
            theme.accent(format!("{} connections", relationships.relationships.len())),
            theme.muted("• evidence only, never deletion authorization")
        );
        for (index, relationship) in relationships.relationships.iter().take(top).enumerate() {
            if index > 0 {
                print_record_divider(theme);
            }
            ui_println!(
                theme,
                "  {}  {}",
                theme.selected(format!(" {:02} ", index + 1)),
                theme.text(relationship_kind_label(relationship.kind)),
            );
            print_record_field(
                theme,
                "source",
                &display_relative(&scan.root, &relationship.source_path),
                RecordTone::Text,
            );
            print_record_field(
                theme,
                "related",
                &display_relative(&scan.root, &relationship.target_path),
                RecordTone::Text,
            );
            print_record_field(
                theme,
                "confidence",
                &format!("{:.0}%", relationship.confidence * 100.0),
                RecordTone::Text,
            );
            if !relationship.evidence.is_empty() {
                ui_println!(theme, "      {}", theme.muted("evidence"));
                for evidence in &relationship.evidence {
                    print_wrapped_bullet(theme, evidence);
                }
            }
        }
        if relationships.relationships.len() > top {
            ui_println!(theme);
        }
        print_more(
            relationships.relationships.len(),
            top,
            "relationships",
            theme,
        );
    }

    print_section(
        "05",
        "DUPLICATES",
        "Exact content matches verified with BLAKE3",
        theme,
    );
    if duplicates.groups.is_empty() {
        ui_println!(
            theme,
            "  {} {}",
            theme.green("✓"),
            theme.text("No exact duplicate groups found among the files checked.")
        );
    } else {
        ui_println!(
            theme,
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
            &format_bytes(duplicates.logical_duplicate_bytes),
            RecordTone::Warning,
        );
        match duplicates.potential_recovery_allocated_bytes {
            Some(bytes) => print_metric(
                theme,
                "safe recovery",
                &format_bytes(bytes),
                RecordTone::Positive,
            ),
            None => print_metric(theme, "safe recovery", "unavailable", RecordTone::Text),
        }

        for (index, group) in duplicates.groups.iter().take(top).enumerate() {
            if index > 0 {
                print_record_divider(theme);
            }
            let recovery = group
                .potential_recovery_allocated_bytes
                .map(format_bytes)
                .unwrap_or_else(|| "unknown".to_owned());
            ui_println!(
                theme,
                "  {}  {}",
                theme.selected(format!(" {:02} ", index + 1)),
                theme.text("Exact duplicate group")
            );
            print_record_field(
                theme,
                "each file",
                &format_bytes(group.size_bytes_per_file),
                RecordTone::Text,
            );
            print_record_field(
                theme,
                "copies",
                &format!("{} physical files", group.unique_file_count),
                RecordTone::Text,
            );
            print_record_field(
                theme,
                "recovery",
                &recovery,
                RecordTone::Positive,
            );
            print_record_field(
                theme,
                "fingerprint",
                &format!("{}…", &group.blake3_hash[..12.min(group.blake3_hash.len())]),
                RecordTone::Text,
            );
            let mut identities = HashSet::new();
            ui_println!(theme, "      {}", theme.muted("files"));
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
                print_wrapped_bullet(
                    theme,
                    &format!("{}{}", display_relative(&scan.root, &entry.path), suffix),
                );
            }
        }
        if duplicates.groups.len() > top {
            ui_println!(theme);
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

    print_section(
        "06",
        "LARGEST ITEMS",
        "Files and folders ordered by logical size",
        theme,
    );
    if items.is_empty() {
        ui_println!(theme, "  No items matched the configured minimum size.");
    } else {
        ui_println!(
            theme,
            "  {}  {}  {}  {}",
            theme.muted(format!("{:<4}", "#")),
            theme.muted(format!("{:>10}", "SIZE")),
            theme.muted(format!("{:<8}", "TYPE")),
            theme.muted("PATH")
        );
        ui_println!(
            theme,
            "  {}",
            theme.border("─".repeat(terminal_width(theme).saturating_sub(4)))
        );
        for (index, item) in items.iter().take(top).enumerate() {
            let kind = match item.kind {
                ItemKind::Directory => "folder",
                ItemKind::File => "file",
                ItemKind::Symlink | ItemKind::Other => "item",
            };
            ui_println!(
                theme,
                "  {}  {}  {}  {}",
                theme.brand(format!("{:>2}", index + 1)),
                theme.yellow(format!("{:>10}", format_bytes(item.size_bytes))),
                theme.muted(format!("{kind:<8}")),
                theme.text(truncate_start(
                    &display_relative(&scan.root, &item.path),
                    terminal_width(theme).saturating_sub(33)
                ))
            );
        }
        print_more(items.len(), top, "items", theme);
    }

    if warning_count > 0 {
        print_section(
            "07",
            "WARNINGS",
            "Items skipped without stopping the scan",
            theme,
        );
        ui_println!(
            theme,
            "  {}",
            theme.muted("These items were skipped; the rest of the scan is still usable.")
        );
        ui_println!(theme);
        let (shown_scan_warnings, shown_duplicate_warnings, hidden_warnings) =
            warning_display_counts(scan.warnings.len(), duplicates.warnings.len());
        for warning in scan.warnings.iter().take(shown_scan_warnings) {
            match &warning.path {
                Some(path) => ui_println!(
                    theme,
                    "  {} {} — {}",
                    theme.red("!"),
                    theme.text(display_relative(&scan.root, path)),
                    theme.muted(&warning.message)
                ),
                None => ui_println!(
                    theme,
                    "  {} {}",
                    theme.red("!"),
                    theme.muted(&warning.message)
                ),
            }
        }
        for warning in duplicates
            .warnings
            .iter()
            .take(shown_duplicate_warnings)
        {
            ui_println!(
                theme,
                "  {} {} — {}",
                theme.red("!"),
                theme.text(display_relative(&scan.root, &warning.path)),
                theme.muted(&warning.message)
            );
        }
        if hidden_warnings > 0 {
            ui_println!(theme, "  • … and {hidden_warnings} more warnings");
        }
    }

    ui_println!(theme);
    ui_println!(
        theme,
        "  {}",
        theme.border("─".repeat(terminal_width(theme).saturating_sub(4)))
    );
    ui_println!(
        theme,
        "  {} {}",
        theme.green("✓"),
        theme.green("Nothing was deleted or modified.")
    );
    ui_println!(theme);
}

fn print_history(entries: &[ScanHistoryEntry], database_path: &Path, theme: Theme) {
    ui_println!(theme);
    print_brand_header(theme, "REPORT");
    print_section(
        "01",
        "SCAN HISTORY",
        "Previous analyses stored only on this computer",
        theme,
    );
    print_metric(
        theme,
        "database",
        &database_path.display().to_string(),
        RecordTone::Text,
    );
    print_metric(
        theme,
        "scans shown",
        &format_count(entries.len() as u64),
        RecordTone::Accent,
    );

    if entries.is_empty() {
        ui_println!(theme);
        ui_println!(
            theme,
            "  {} {}",
            theme.muted("—"),
            theme.text("No scan history yet. Run spacemind to create the first entry.")
        );
    } else {
        for entry in entries {
            print_record_divider(theme);
            ui_println!(
                theme,
                "  {}  {}",
                theme.selected(format!(" #{:<4} ", entry.id)),
                theme.text(entry.root.display().to_string())
            );
            print_record_field(
                theme,
                "analyzed",
                &format_bytes(entry.total_size_bytes),
                RecordTone::Text,
            );
            print_record_field(
                theme,
                "contents",
                &format!(
                    "{} files • {} folders",
                    format_count(entry.file_count),
                    format_count(entry.directory_count)
                ),
                RecordTone::Text,
            );
            print_record_field(
                theme,
                "results",
                &format!(
                    "{} recommendations • {} duplicate groups • {} relationships",
                    format_count(entry.recommendation_count),
                    format_count(entry.duplicate_group_count),
                    format_count(entry.relationship_count)
                ),
                RecordTone::Accent,
            );
            let ai_history = match &entry.ai_model {
                Some(model) => format!(
                    "{} • {} explanations",
                    model,
                    format_count(entry.ai_explanation_count)
                ),
                None => entry.ai_status.replace('_', " "),
            };
            print_record_field(theme, "local AI", &ai_history, RecordTone::Text);
            if let Some(bytes) = entry.duplicate_recovery_bytes {
                print_record_field(
                    theme,
                    "recoverable",
                    &format_bytes(bytes),
                    RecordTone::Positive,
                );
            }
            print_record_field(
                theme,
                "completed",
                &format_age(entry.completed_at_epoch_seconds),
                RecordTone::Text,
            );
        }
    }

    ui_println!(theme);
    ui_println!(
        theme,
        "  {}",
        theme.border("─".repeat(terminal_width(theme).saturating_sub(4)))
    );
    ui_println!(
        theme,
        "  {} {}",
        theme.green("✓"),
        theme.green("History contains metadata only, never file contents.")
    );
    ui_println!(theme);
}

fn format_age(epoch_seconds: u64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(epoch_seconds);
    let elapsed = now.saturating_sub(epoch_seconds);
    match elapsed {
        0..=59 => "just now".to_owned(),
        60..=3_599 => format!("{} minutes ago", elapsed / 60),
        3_600..=86_399 => format!("{} hours ago", elapsed / 3_600),
        _ => format!("{} days ago", elapsed / 86_400),
    }
}

fn print_report_index(theme: Theme) {
    ui_println!(theme);
    if terminal_width(theme) >= 74 {
        ui_println!(
            theme,
            "  {}  {}  {}  {}  {}  {}",
            theme.accent("01 overview"),
            theme.muted("02 safety"),
            theme.muted("03 review"),
            theme.muted("04 related"),
            theme.muted("05 duplicates"),
            theme.muted("06 largest")
        );
    } else {
        ui_println!(
            theme,
            "  {}  {}  {}",
            theme.accent("01 overview"),
            theme.muted("02 safety"),
            theme.muted("03 review")
        );
        ui_println!(
            theme,
            "  {}  {}  {}",
            theme.muted("04 related"),
            theme.muted("05 duplicates"),
            theme.muted("06 largest")
        );
    }
}

fn print_overview_counts(
    theme: Theme,
    recommendations: usize,
    duplicate_groups: usize,
    relationships: usize,
) {
    let review = format_count(recommendations as u64);
    let duplicates = format_count(duplicate_groups as u64);
    let connections = format_count(relationships as u64);
    if terminal_width(theme) >= 62 {
        ui_println!(
            theme,
            "  {}  {}    {}  {}    {}  {}",
            theme.muted("review"),
            theme.accent(review),
            theme.muted("duplicates"),
            theme.accent(duplicates),
            theme.muted("connections"),
            theme.accent(connections)
        );
    } else {
        ui_println!(
            theme,
            "  {}  {}    {}  {}",
            theme.muted("review"),
            theme.accent(review),
            theme.muted("duplicates"),
            theme.accent(duplicates)
        );
        ui_println!(
            theme,
            "  {}  {}",
            theme.muted("connections"),
            theme.accent(connections)
        );
    }
}

fn print_section(number: &str, title: &str, description: &str, theme: Theme) {
    let heading = format!("{number}  {title}");
    let remaining = terminal_width(theme).saturating_sub(heading.chars().count() + 5);
    ui_println!(theme);
    ui_println!(
        theme,
        "  {} {}",
        theme.accent(heading),
        theme.border("─".repeat(remaining))
    );
    for line in wrap_text(description, terminal_width(theme).saturating_sub(8)) {
        ui_println!(theme, "      {}", theme.muted(line));
    }
    ui_println!(theme);
}

fn print_record_divider(theme: Theme) {
    ui_println!(
        theme,
        "      {}",
        theme.border("·".repeat(terminal_width(theme).saturating_sub(8)))
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecordTone {
    Text,
    Accent,
    Positive,
    Warning,
    Danger,
}

fn print_record_field(theme: Theme, label: &str, value: &str, tone: RecordTone) {
    let value_width = terminal_width(theme).saturating_sub(24).max(12);
    let lines = wrap_text(value, value_width);
    for (index, line) in lines.iter().enumerate() {
        let label = if index == 0 { label } else { "" };
        let value = match tone {
            RecordTone::Text => theme.text(line),
            RecordTone::Accent => theme.accent(line),
            RecordTone::Positive => theme.green(line),
            RecordTone::Warning => theme.yellow(line),
            RecordTone::Danger => theme.red(line),
        };
        ui_println!(
            theme,
            "      {}  {}",
            theme.muted(format!("{label:<12}")),
            value
        );
    }
}

fn print_wrapped_bullet(theme: Theme, value: &str) {
    let value_width = terminal_width(theme).saturating_sub(14).max(12);
    for (index, line) in wrap_text(value, value_width).iter().enumerate() {
        let marker = if index == 0 { "•" } else { " " };
        ui_println!(
            theme,
            "        {} {}",
            theme.accent(marker),
            theme.muted(line)
        );
    }
}

fn wrap_text(value: &str, width: usize) -> Vec<String> {
    if value.is_empty() {
        return vec![String::new()];
    }

    let width = width.max(1);
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in value.split_whitespace() {
        let word_width = display_width(word);
        if word_width > width {
            if !current.is_empty() {
                lines.push(std::mem::take(&mut current));
            }
            lines.extend(split_by_display_width(word, width));
            continue;
        }

        let separator = usize::from(!current.is_empty());
        if display_width(&current) + separator + word_width > width {
            lines.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

fn split_by_display_width(value: &str, width: usize) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut current = String::new();
    let mut current_width = 0;

    for character in value.chars() {
        let character_width = UnicodeWidthChar::width(character).unwrap_or(0);
        if !current.is_empty() && current_width + character_width > width {
            chunks.push(std::mem::take(&mut current));
            current_width = 0;
        }
        current.push(character);
        current_width += character_width;
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

fn print_metric(theme: Theme, label: &str, value: &str, tone: RecordTone) {
    let value_width = terminal_width(theme).saturating_sub(25).max(12);
    for (index, line) in wrap_text(value, value_width).iter().enumerate() {
        let label = if index == 0 { label } else { "" };
        let value = match tone {
            RecordTone::Text => theme.text(line),
            RecordTone::Accent => theme.accent(line),
            RecordTone::Positive => theme.green(line),
            RecordTone::Warning => theme.yellow(line),
            RecordTone::Danger => theme.red(line),
        };
        ui_println!(
            theme,
            "  {}  {}",
            theme.muted(format!("{label:<17}")),
            value
        );
    }
}

fn print_more(total: usize, shown: usize, label: &str, theme: Theme) {
    if total > shown {
        ui_println!(
            theme,
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

fn relationship_kind_label(kind: RelationshipKind) -> &'static str {
    match kind {
        RelationshipKind::ArchiveExtractedDirectory => "Archive and extracted folder",
        RelationshipKind::InstallerApplicationDirectory => "Installer and application folder",
        RelationshipKind::BuildDirectoryProject => "Build output and source project",
        RelationshipKind::VirtualMachineComponent => "Virtual-machine components",
        RelationshipKind::AndroidEmulatorConfiguration => "Android emulator configuration",
        RelationshipKind::ExactDuplicate => "Exact duplicate files",
    }
}

fn category_label(category: FindingCategory) -> &'static str {
    match category {
        FindingCategory::LargeItem => "Large item",
        FindingCategory::OldArchive => "Old archive",
        FindingCategory::OldInstaller => "Old installer",
        FindingCategory::NodeModules => "Node.js dependencies",
        FindingCategory::RustBuildArtifacts => "Rust build artifacts",
        FindingCategory::GradleCache => "Gradle cache",
        FindingCategory::AndroidEmulator => "Android emulator",
        FindingCategory::VirtualMachine => "Virtual machine",
        FindingCategory::IsoImage => "Old ISO image",
        FindingCategory::OperatingSystemCache => "Operating-system cache",
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

fn risk_tone(risk: RiskLevel) -> RecordTone {
    match risk {
        RiskLevel::Low => RecordTone::Positive,
        RiskLevel::Medium => RecordTone::Warning,
        RiskLevel::High => RecordTone::Danger,
    }
}

fn action_label(action: SuggestedAction) -> &'static str {
    match action {
        SuggestedAction::ReviewForDeletion => "Review before deleting",
        SuggestedAction::ReviewForArchive => "Review for archiving",
    }
}

fn recommendation_guidance(risk: RiskLevel, action: SuggestedAction) -> &'static str {
    match (risk, action) {
        (RiskLevel::Low, SuggestedAction::ReviewForDeletion) => {
            "Good cleanup candidate; verify it before deleting"
        }
        (RiskLevel::Low, SuggestedAction::ReviewForArchive) => {
            "Low detected risk; consider archiving it first"
        }
        (RiskLevel::Medium, _) => "Inspect its project or application context first",
        (RiskLevel::High, _) => "Do not delete until you understand and back up this item",
    }
}

fn ai_action_label(action: AiSuggestedAction) -> &'static str {
    match action {
        AiSuggestedAction::ReviewForDeletion => "review for deletion",
        AiSuggestedAction::ReviewForArchive => "review for archive",
        AiSuggestedAction::KeepOrReview => "keep or inspect manually",
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

    fn sample_stored_analysis() -> StoredAnalysis {
        let root = PathBuf::from("/home/example/Downloads");
        let path = root.join("large-archive.zip");
        StoredAnalysis {
            summary: ScanHistoryEntry {
                id: 7,
                root: root.clone(),
                started_at_epoch_seconds: 100,
                completed_at_epoch_seconds: 200,
                total_size_bytes: 4 * 1024 * 1024 * 1024,
                total_allocated_size_bytes: Some(4 * 1024 * 1024 * 1024),
                file_count: 12,
                directory_count: 4,
                recommendation_count: 1,
                duplicate_group_count: 0,
                relationship_count: 0,
                warning_count: 0,
                duplicate_recovery_bytes: Some(0),
                recovered_space_bytes: 0,
                ai_status: "complete".to_owned(),
                ai_model: Some("qwen3:4b".to_owned()),
                ai_candidate_count: 1,
                ai_explanation_count: 1,
            },
            findings: vec![Finding {
                category: FindingCategory::OldArchive,
                path: path.clone(),
                potential_recovery_bytes: 2 * 1024 * 1024 * 1024,
                confidence: 0.92,
                risk: RiskLevel::Low,
                evidence: vec!["Archive has not changed in 220 days".to_owned()],
                suggested_action: SuggestedAction::ReviewForDeletion,
            }],
            duplicate_groups: Vec::new(),
            relationships: Vec::new(),
            ai_explanations: vec![spacemind_core::AiExplanation {
                path,
                category: spacemind_core::AiCategory::ArchiveWithExtractedCopy,
                risk: RiskLevel::Low,
                confidence: 0.88,
                reason: "This looks replaceable, but verify the extracted folder first.".to_owned(),
                suggested_action: AiSuggestedAction::ReviewForDeletion,
            }],
            warnings: Vec::new(),
        }
    }

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

        let colored = Theme {
            colors: true,
            terminal: true,
        }
        .brand("SpaceMind");
        assert!(colored.starts_with("\x1b["));
        assert!(colored.ends_with("\x1b[0m"));
    }

    #[test]
    fn centers_the_canvas_in_wide_terminals() {
        let layout = TerminalLayout::for_size(120, 36);

        assert_eq!(layout.width, MAX_CANVAS_WIDTH);
        assert_eq!(layout.margin, 17);
        assert_eq!(layout.prefix(), " ".repeat(17));
    }

    #[test]
    fn keeps_the_canvas_inside_narrow_terminals() {
        let layout = TerminalLayout::for_size(50, 24);

        assert_eq!(layout.width, 48);
        assert_eq!(layout.margin, 1);
    }

    #[test]
    fn keeps_header_and_selector_lines_inside_a_small_canvas() {
        let layout = TerminalLayout::for_size(32, 24);
        let choices = vec![(
            "Current folder".to_owned(),
            PathBuf::from("/a/very/long/path/to/a/folder"),
        )];
        let lines = directory_selector_lines(
            &choices,
            0,
            Some("/another/very/long/custom/path"),
            Some("That folder does not exist. Check the path and try again."),
            Theme::plain(),
            layout,
        );

        assert!(lines.iter().all(|line| display_width(line) <= layout.width));
        assert!(lines[1].contains("[scan]"));
    }

    #[test]
    fn home_menu_is_navigable_without_colors_and_fits_a_small_canvas() {
        let layout = TerminalLayout::for_size(32, 24);
        let lines = main_menu_lines(1, Theme::plain(), layout);

        assert!(lines.iter().all(|line| display_width(line) <= layout.width));
        assert!(lines.iter().any(|line| line.contains("›  02")));
        assert!(lines.iter().any(|line| line.contains("Scan history")));
    }

    #[test]
    fn history_browser_makes_saved_scans_selectable() {
        let analysis = sample_stored_analysis();
        let layout = TerminalLayout::for_size(48, 24);
        let lines = history_browser_lines(
            &[analysis.summary],
            0,
            Path::new("/tmp/spacemind.db"),
            Theme::plain(),
            layout,
        );

        assert!(lines.iter().all(|line| display_width(line) <= layout.width));
        assert!(lines.iter().any(|line| line.contains("enter open scan")));
        assert!(lines.iter().any(|line| line.contains("› #7")));
    }

    #[test]
    fn review_screen_prioritizes_a_clear_recommendation_detail() {
        let analysis = sample_stored_analysis();
        let layout = TerminalLayout::for_size(86, 30);
        let lines = review_lines(
            &analysis,
            ReviewSection::Recommendations,
            0,
            Theme::plain(),
            layout,
        );
        let output = lines.join("\n");

        assert!(output.contains("WHY REVIEW THIS"));
        assert!(output.contains("potential space"));
        assert!(output.contains("LOCAL AI"));
        assert!(output.contains("never deletion permission"));
    }

    #[test]
    fn every_review_section_fits_a_narrow_terminal() {
        let analysis = sample_stored_analysis();
        let layout = TerminalLayout::for_size(32, 24);

        for section in ReviewSection::ALL {
            let lines = review_lines(&analysis, section, 0, Theme::plain(), layout);
            assert!(
                lines.iter().all(|line| display_width(line) <= layout.width),
                "{section:?} contained an overflowing line: {lines:?}"
            );
        }
    }

    #[test]
    fn selector_lists_the_current_directory_first() {
        let current = env::temp_dir();
        let choices = directory_choices(current.clone(), None);

        assert_eq!(choices, vec![("Current folder".to_owned(), current)]);
    }

    #[test]
    fn selector_renders_navigation_help_and_custom_path() {
        let choices = vec![("Current folder".to_owned(), PathBuf::from("/example"))];
        let mut output = Vec::new();

        render_directory_selector(&mut output, &choices, 0, None, None, Theme::plain()).unwrap();
        let output = String::from_utf8(output).unwrap();

        assert!(output.contains("Choose a folder to scan"));
        assert!(output.contains("Custom path"));
        assert!(output.contains("j/k"));
        assert!(output.contains("›  01"));
    }

    #[test]
    fn truncates_paths_using_terminal_column_width() {
        assert_eq!(truncate_start("/one/two/three", 10), "…two/three");
        assert_eq!(truncate_start("short", 10), "short");
        assert_eq!(display_width("文件"), 4);
        assert_eq!(truncate_start("/文件", 4), "…件");
        assert_eq!(truncate_end("文件/report", 4), "文…");
    }

    #[test]
    fn reports_every_hidden_warning() {
        assert_eq!(warning_display_counts(11, 0), (10, 0, 1));
        assert_eq!(warning_display_counts(15, 2), (10, 2, 5));
        assert_eq!(warning_display_counts(15, 12), (10, 10, 7));
    }

    #[test]
    fn wraps_report_text_without_exceeding_the_field_width() {
        assert_eq!(
            wrap_text("This explanation is easy to scan", 12),
            vec!["This", "explanation", "is easy to", "scan"]
        );
        assert_eq!(
            wrap_text("downloads/very-long-folder-name", 10),
            vec!["downloads/", "very-long-", "folder-nam", "e"]
        );
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
