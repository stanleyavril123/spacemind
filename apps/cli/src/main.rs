use clap::{Args, Parser, Subcommand, ValueEnum};
use crossterm::cursor;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{self, ClearType};
use serde::Serialize;
use spacemind_core::{
    AnalysisPhase, CancellationToken, DuplicateReport, Finding, FindingCategory, ItemKind,
    PathRule, ProgressEvent, RelationshipKind, RelationshipReport, RiskLevel, ScanResult,
    ScannedItem, SuggestedAction,
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
    relationships: RelationshipReport,
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
        let colors = is_terminal
            && env::var_os("NO_COLOR").is_none()
            && env::var("TERM").map(|term| term != "dumb").unwrap_or(true);
        Self {
            colors,
            terminal: is_terminal,
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
    error
        .downcast_ref::<io::Error>()
        .is_some_and(|error| error.kind() == io::ErrorKind::Interrupted)
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
    let mut findings = evaluation.findings;
    enrich_findings_with_relationships(&mut findings, &relationships);

    match args.format {
        OutputFormat::Human => print_human(
            &result,
            &findings,
            &duplicates,
            &relationships,
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
                relationships,
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
    let mut lines = brand_header_lines(theme, "SCAN").to_vec();
    lines.push(String::new());
    lines.push(format!(
        "  {}  {}",
        theme.accent("storage, understood."),
        theme.muted("Private analysis on this computer.")
    ));
    lines.push(String::new());
    lines.push(format!("  {}", theme.text("Choose a folder to scan")));
    lines.push(format!(
        "  {}",
        theme.border("─".repeat(layout.width.saturating_sub(4)))
    ));

    let path_width = layout.width.saturating_sub(29);
    for (index, (label, path)) in choices.iter().enumerate() {
        let choice = format!(" {:02}  {label:<16} ", index + 1);
        let choice = if selected == index {
            theme.selected(choice)
        } else {
            theme.text(choice)
        };
        lines.push(format!(
            "  {choice}  {}",
            theme.muted(truncate_start(&path.display().to_string(), path_width))
        ));
    }

    let custom_index = choices.len();
    let custom_choice = format!(" {:02}  {:<16} ", custom_index + 1, "Custom path");
    let custom_choice = if selected == custom_index {
        theme.selected(custom_choice)
    } else {
        theme.text(custom_choice)
    };
    lines.push(format!("  {custom_choice}  {}", theme.muted("enter any folder")));
    lines.push(String::new());
    lines.push(format!(
        "  {}",
        theme.border("─".repeat(layout.width.saturating_sub(4)))
    ));

    if let Some(input) = custom_input {
        lines.push(format!(
            "  {} {}",
            theme.accent("path ›"),
            theme.text(format!("{input}▌"))
        ));
        lines.push(format!(
            "  {} accept    {} go back",
            theme.text("enter"),
            theme.muted("esc")
        ));
    } else {
        lines.push(format!(
            "  {} move    {} scan    {} custom    {} quit",
            theme.text("↑/↓  j/k"),
            theme.text("enter"),
            theme.accent("c"),
            theme.muted("q")
        ));
    }
    if let Some(message) = message {
        lines.push(format!("  {} {}", theme.red("!"), theme.muted(message)));
    }

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
    let width = terminal_width(theme);
    let scan = if active == "SCAN" {
        theme.selected(" scan ")
    } else {
        theme.muted(" scan ")
    };
    let report = if active == "REPORT" {
        theme.selected(" report ")
    } else {
        theme.muted(" report ")
    };
    let right = "local / read only";
    let fixed_width = " SPACEMIND    scan     report ".chars().count() + right.chars().count() + 1;
    let padding = width.saturating_sub(fixed_width + 2);

    [
        theme.border(format!("┌{}┐", "─".repeat(width.saturating_sub(2)))),
        format!(
            "{} {}   {}   {}{}{} {}",
            theme.border("│"),
            theme.brand("SPACEMIND"),
            scan,
            report,
            " ".repeat(padding),
            theme.muted(right),
            theme.border("│")
        ),
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
    let length = value.chars().count();
    if length <= maximum_width {
        return value.to_owned();
    }
    if maximum_width <= 1 {
        return "…".chars().take(maximum_width).collect();
    }

    let visible_tail = value
        .chars()
        .skip(length - (maximum_width - 1))
        .collect::<String>();
    format!("…{visible_tail}")
}

fn print_human(
    scan: &ScanResult,
    findings: &[Finding],
    duplicates: &DuplicateReport,
    relationships: &RelationshipReport,
    policy: &PolicySummary,
    top: usize,
    min_size: u64,
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
            "{} matched paths • {} configured rules • not scanned",
            policy.ignored_paths.len(),
            policy.ignored_rule_count
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
        for warning in scan.warnings.iter().take(10) {
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
        for warning in duplicates.warnings.iter().take(10) {
            ui_println!(
                theme,
                "  {} {} — {}",
                theme.red("!"),
                theme.text(display_relative(&scan.root, &warning.path)),
                theme.muted(&warning.message)
            );
        }
        if warning_count > 20 {
            ui_println!(theme, "  • … and {} more warnings", warning_count - 20);
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
        let word_length = word.chars().count();
        if word_length > width {
            if !current.is_empty() {
                lines.push(std::mem::take(&mut current));
            }
            let characters = word.chars().collect::<Vec<_>>();
            for chunk in characters.chunks(width) {
                lines.push(chunk.iter().collect());
            }
            continue;
        }

        let separator = usize::from(!current.is_empty());
        if current.chars().count() + separator + word_length > width {
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
    }

    #[test]
    fn truncates_long_paths_from_the_start() {
        assert_eq!(truncate_start("/one/two/three", 10), "…two/three");
        assert_eq!(truncate_start("short", 10), "short");
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
