mod cli;
mod config;
mod modules;
mod platform;
mod report;
mod tui;

use anyhow::Result;
use cli::{Cli, Commands};
use clap::Parser;
use colored::Colorize;
use modules::{
    file_integrity::FileIntegrityScanner,
    log_analyzer::LogAnalyzer,
    network_hunter::NetworkHunter,
    process_scanner::ProcessScanner,
    ScanResult, Severity,
};
use report::ReportGenerator;
use std::time::Instant;

fn print_banner() {
    println!(
        "{}",
        r#"
 ██╗  ████████╗██╗  ██╗███████╗
 ██║  ╚══██╔══╝██║  ██║██╔════╝
 ██║     ██║   ███████║█████╗
 ██║     ██║   ██╔══██║██╔══╝
 ███████╗██║   ██║  ██║██║
 ╚══════╝╚═╝   ╚═╝  ╚═╝╚═╝
"#
        .bright_red()
        .bold()
    );
    println!(
        "{}",
        "  Linux Threat Hunting Framework v1.0.0".bright_cyan().bold()
    );
    println!(
        "{}",
        "  Advanced Threat Detection & Forensics Engine".bright_white()
    );
    println!(
        "{}",
        "  ─────────────────────────────────────────────".bright_blue()
    );
    println!();
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    if !cli.no_banner {
        print_banner();
    }

    // Environment detection and compatibility warnings
    let env_desc = platform::describe_environment();
    let is_wsl = platform::is_wsl();
    let is_root = platform::is_root();

    if is_wsl {
        println!(
            "  {} Running in {} — some kernel-level checks may be limited",
            "ℹ".bright_blue(),
            env_desc.bright_cyan()
        );
    }
    if !is_root {
        println!(
            "  {} Not running as root — some checks require elevated privileges (sudo lthf ...)",
            "⚠".bright_yellow()
        );
    }
    if is_wsl || !is_root {
        println!();
    }

    let cfg = if let Some(ref path) = cli.config {
        config::Config::from_file(path)?
    } else {
        config::Config::default()
    };

    match cli.command {
        Commands::Scan(ref opts) => {
            run_scan(&cli, opts, &cfg).await?;
        }
        Commands::Watch(ref opts) => {
            tui::run_tui(opts, &cfg).await?;
        }
        Commands::Report(ref opts) => {
            generate_report_cmd(opts, &cfg).await?;
        }
    }

    Ok(())
}

async fn run_scan(
    cli: &Cli,
    opts: &cli::ScanOptions,
    cfg: &config::Config,
) -> Result<()> {
    let start = Instant::now();
    let mut all_findings: Vec<ScanResult> = Vec::new();
    let mut total_threats = 0usize;

    // ── Process Scanner ────────────────────────────────────────────────────
    if opts.all || opts.processes {
        println!(
            "{} {}",
            "▶".bright_yellow(),
            "Scanning processes...".bold()
        );
        let mut scanner = ProcessScanner::new(cfg.clone());
        let findings = scanner.scan().await?;
        let count = findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::High | Severity::Critical))
            .count();
        if count > 0 {
            println!(
                "  {} {} suspicious processes found",
                "⚠".bright_red(),
                count.to_string().bright_red().bold()
            );
        } else {
            println!("  {} No critical threats in processes", "✓".bright_green());
        }
        total_threats += count;
        all_findings.extend(findings);
    }

    // ── File Integrity Monitor ─────────────────────────────────────────────
    if opts.all || opts.files {
        println!(
            "{} {}",
            "▶".bright_yellow(),
            "Scanning file integrity...".bold()
        );
        let mut fim = FileIntegrityScanner::new(cfg.clone());
        let findings = fim.scan().await?;
        let count = findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::High | Severity::Critical))
            .count();
        if count > 0 {
            println!(
                "  {} {} file integrity violations",
                "⚠".bright_red(),
                count.to_string().bright_red().bold()
            );
        } else {
            println!("  {} File system looks clean", "✓".bright_green());
        }
        total_threats += count;
        all_findings.extend(findings);
    }

    // ── Log Analyzer ──────────────────────────────────────────────────────
    if opts.all || opts.logs {
        println!(
            "{} {}",
            "▶".bright_yellow(),
            "Analyzing system logs...".bold()
        );
        let mut la = LogAnalyzer::new(cfg.clone());
        let findings = la.scan().await?;
        let count = findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::High | Severity::Critical))
            .count();
        if count > 0 {
            println!(
                "  {} {} critical log anomalies",
                "⚠".bright_red(),
                count.to_string().bright_red().bold()
            );
        } else {
            println!("  {} Logs appear normal", "✓".bright_green());
        }
        total_threats += count;
        all_findings.extend(findings);
    }

    // ── Network Hunter ────────────────────────────────────────────────────
    if opts.all || opts.network {
        println!(
            "{} {}",
            "▶".bright_yellow(),
            "Hunting network threats...".bold()
        );
        let mut nh = NetworkHunter::new(cfg.clone());
        let findings = nh.scan().await?;
        let count = findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::High | Severity::Critical))
            .count();
        if count > 0 {
            println!(
                "  {} {} suspicious network activities",
                "⚠".bright_red(),
                count.to_string().bright_red().bold()
            );
        } else {
            println!("  {} Network activity looks normal", "✓".bright_green());
        }
        total_threats += count;
        all_findings.extend(findings);
    }

    let elapsed = start.elapsed();
    println!();
    println!(
        "{}",
        "  ═══════════════════════════════════════════════".bright_blue()
    );
    println!(
        "  {} Scan completed in {:.2}s | {} findings | {} high/critical",
        "✦".bright_cyan(),
        elapsed.as_secs_f64(),
        all_findings.len().to_string().bright_white().bold(),
        if total_threats > 0 {
            total_threats.to_string().bright_red().bold()
        } else {
            total_threats.to_string().bright_green().bold()
        }
    );
    println!();

    // Print detailed findings if requested
    if opts.verbose || cli.verbose {
        print_findings(&all_findings);
    }

    // Generate report
    if let Some(ref out) = opts.output {
        let gen = ReportGenerator::new(all_findings.clone(), cfg.clone());
        match opts.format.as_deref().unwrap_or("json") {
            "html" => gen.export_html(out)?,
            "csv" => gen.export_csv(out)?,
            _ => gen.export_json(out)?,
        }
        println!(
            "  {} Report saved to: {}",
            "✓".bright_green(),
            out.bright_cyan()
        );
    }

    Ok(())
}

fn print_findings(findings: &[ScanResult]) {
    use tabled::{Table, Tabled};

    #[derive(Tabled)]
    struct Row {
        #[tabled(rename = "Severity")]
        severity: String,
        #[tabled(rename = "Category")]
        category: String,
        #[tabled(rename = "Title")]
        title: String,
        #[tabled(rename = "Score")]
        score: String,
    }

    let rows: Vec<Row> = findings
        .iter()
        .filter(|f| !matches!(f.severity, Severity::Info))
        .map(|f| Row {
            severity: format_severity(&f.severity),
            category: f.category.clone(),
            title: if f.title.len() > 55 {
                format!("{}…", &f.title[..54])
            } else {
                f.title.clone()
            },
            score: f.threat_score.to_string(),
        })
        .collect();

    if rows.is_empty() {
        println!(
            "  {} No significant findings to display",
            "ℹ".bright_blue()
        );
        return;
    }

    let table = Table::new(rows).to_string();
    println!("{}", table);
    println!();
}

fn format_severity(s: &Severity) -> String {
    match s {
        Severity::Critical => "CRITICAL".bright_red().bold().to_string(),
        Severity::High => "HIGH    ".bright_red().to_string(),
        Severity::Medium => "MEDIUM  ".bright_yellow().to_string(),
        Severity::Low => "LOW     ".bright_blue().to_string(),
        Severity::Info => "INFO    ".bright_white().to_string(),
    }
}

async fn generate_report_cmd(
    opts: &cli::ReportOptions,
    cfg: &config::Config,
) -> Result<()> {
    println!(
        "{} {}",
        "▶".bright_yellow(),
        "Generating comprehensive report...".bold()
    );
    let mut all_findings: Vec<ScanResult> = Vec::new();
    let mut scanner = ProcessScanner::new(cfg.clone());
    all_findings.extend(scanner.scan().await?);
    let mut fim = FileIntegrityScanner::new(cfg.clone());
    all_findings.extend(fim.scan().await?);
    let mut la = LogAnalyzer::new(cfg.clone());
    all_findings.extend(la.scan().await?);
    let mut nh = NetworkHunter::new(cfg.clone());
    all_findings.extend(nh.scan().await?);

    let gen = ReportGenerator::new(all_findings, cfg.clone());
    match opts.format.as_deref().unwrap_or("html") {
        "html" => gen.export_html(&opts.output)?,
        "csv" => gen.export_csv(&opts.output)?,
        _ => gen.export_json(&opts.output)?,
    }
    println!(
        "  {} Full report saved to: {}",
        "✓".bright_green(),
        opts.output.bright_cyan()
    );
    Ok(())
}
