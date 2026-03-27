use clap::{Args, Parser, Subcommand};

/// Linux Threat Hunting Framework — Advanced threat detection engine
#[derive(Parser, Debug)]
#[command(
    name = "lthf",
    version = "2.0.0",
    about = "Linux Threat Hunting Framework — Detect, analyze & hunt threats in real-time",
    long_about = None,
    propagate_version = true,
)]
pub struct Cli {
    /// Enable verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Suppress the startup banner
    #[arg(long, global = true)]
    pub no_banner: bool,

    /// Path to custom config file
    #[arg(short, long, global = true, value_name = "FILE")]
    pub config: Option<String>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Run a one-shot threat scan
    Scan(ScanOptions),

    /// Launch the interactive real-time TUI dashboard
    Watch(WatchOptions),

    /// Generate a standalone HTML/JSON/CSV report
    Report(ReportOptions),
}

#[derive(Args, Debug)]
pub struct ScanOptions {
    /// Run all scan modules
    #[arg(short, long)]
    pub all: bool,

    /// Scan running processes
    #[arg(short, long)]
    pub processes: bool,

    /// Scan file integrity (SUID, world-writable, hashes)
    #[arg(short, long)]
    pub files: bool,

    /// Analyze system logs
    #[arg(short, long)]
    pub logs: bool,

    /// Hunt network threats
    #[arg(short, long)]
    pub network: bool,

    /// Hunt persistence mechanisms (cron, systemd, rc.local, PAM, sudoers, etc.)
    #[arg(short = 'P', long)]
    pub persistence: bool,

    /// Detect rootkit indicators (hidden procs, kernel hooks, LKM tampering)
    #[arg(short = 'r', long)]
    pub rootkit: bool,

    /// Audit container security (Docker, Kubernetes, Podman environments)
    #[arg(short = 'C', long)]
    pub container: bool,

    /// Verbose findings output
    #[arg(short, long)]
    pub verbose: bool,

    /// Save findings to file
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<String>,

    /// Output format: json | html | csv  [default: json]
    #[arg(long, value_name = "FORMAT")]
    pub format: Option<String>,
}

#[derive(Args, Debug)]
pub struct WatchOptions {
    /// Refresh interval in seconds
    #[arg(short, long, default_value = "5")]
    pub interval: u64,
}

#[derive(Args, Debug)]
pub struct ReportOptions {
    /// Output file path
    #[arg(short, long, default_value = "lthf-report.html")]
    pub output: String,

    /// Format: json | html | csv
    #[arg(short, long, default_value = "html")]
    pub format: String,
}
