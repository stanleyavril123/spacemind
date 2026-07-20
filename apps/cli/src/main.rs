use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;
use spacemind_core::{Finding, ItemKind, ScanResult, ScannedItem};
use spacemind_rules::{evaluate, RuleOptions};
use spacemind_scanner::{scan, ScanOptions};
use std::error::Error;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Debug, Parser)]
#[command(name = "spacemind", version, about = "Privacy-first storage analysis")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Recursively scan a directory without modifying it.
    Scan {
        /// Directory to scan.
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Maximum number of large items shown in human output.
        #[arg(long, default_value_t = 20)]
        top: usize,

        /// Hide items smaller than this size (for example: 100MB or 2GiB).
        #[arg(long, value_parser = parse_size, default_value = "0")]
        min_size: u64,

        /// Output format. JSON contains the complete scan and all findings.
        #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
        format: OutputFormat,

        /// Allow traversal into mounted filesystems below the scan root.
        #[arg(long)]
        cross_filesystems: bool,

        /// Size at which the deterministic rules flag a large item.
        #[arg(long, value_parser = parse_size, default_value = "1GiB")]
        large_threshold: u64,

        /// Age at which archives and installers are considered old.
        #[arg(long, default_value_t = 180)]
        old_days: u64,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Human,
    Json,
}

#[derive(Serialize)]
struct JsonOutput {
    scan: ScanResult,
    findings: Vec<Finding>,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn Error>> {
    match cli.command {
        Command::Scan {
            path,
            top,
            min_size,
            format,
            cross_filesystems,
            large_threshold,
            old_days,
        } => {
            let result = scan(&ScanOptions {
                root: path,
                cross_filesystems,
            })?;
            let findings = evaluate(
                &result,
                &RuleOptions {
                    large_item_threshold_bytes: large_threshold,
                    old_item_threshold_days: old_days,
                    ..RuleOptions::default()
                },
            );

            match format {
                OutputFormat::Human => print_human(&result, &findings, top, min_size),
                OutputFormat::Json => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&JsonOutput {
                            scan: result,
                            findings,
                        })?
                    );
                }
            }
        }
    }
    Ok(())
}

fn print_human(scan: &ScanResult, findings: &[Finding], top: usize, min_size: u64) {
    println!("Scanned: {}", scan.root.display());
    println!("Files: {}", scan.file_count);
    println!("Directories: {}", scan.directory_count);
    println!("Total size: {}", format_bytes(scan.total_size_bytes));
    println!("Warnings: {}", scan.warnings.len());

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

    println!();
    println!("Largest items:");
    for item in items.into_iter().take(top) {
        println!("{:>10}  {}", format_bytes(item.size_bytes), item.path.display());
    }

    if !findings.is_empty() {
        println!();
        println!("Deterministic findings:");
        for finding in findings.iter().take(top) {
            println!(
                "{:>10}  {:?}  {}",
                format_bytes(finding.potential_recovery_bytes),
                finding.category,
                finding.path.display()
            );
            for evidence in &finding.evidence {
                println!("              - {evidence}");
            }
        }
    }

    if !scan.warnings.is_empty() {
        println!();
        println!("Scan warnings:");
        for warning in scan.warnings.iter().take(20) {
            match &warning.path {
                Some(path) => println!("- {}: {}", path.display(), warning.message),
                None => println!("- {}", warning.message),
            }
        }
        if scan.warnings.len() > 20 {
            println!("- ... {} more warnings", scan.warnings.len() - 20);
        }
    }
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
}
