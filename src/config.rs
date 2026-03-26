use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub general: GeneralConfig,
    pub process: ProcessConfig,
    pub file_integrity: FileIntegrityConfig,
    pub log_analyzer: LogAnalyzerConfig,
    pub network: NetworkConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    pub max_threads: usize,
    pub threat_score_threshold: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessConfig {
    pub check_hidden: bool,
    pub check_deleted_executables: bool,
    pub check_memfd: bool,
    pub check_network_namespaces: bool,
    pub suspicious_names: Vec<String>,
    pub whitelist_processes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileIntegrityConfig {
    pub watch_dirs: Vec<String>,
    pub check_suid: bool,
    pub check_world_writable: bool,
    pub check_hidden_files: bool,
    pub check_large_files: bool,
    pub max_file_size_mb: u64,
    pub critical_files: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogAnalyzerConfig {
    pub log_dirs: Vec<String>,
    pub brute_force_threshold: u32,
    pub brute_force_window_secs: u64,
    pub check_privilege_escalation: bool,
    pub check_cron_changes: bool,
    pub check_new_users: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub suspicious_ports: Vec<u16>,
    pub known_c2_ips: Vec<String>,
    pub known_c2_domains: Vec<String>,
    pub check_dns_tunneling: bool,
    pub check_tor: bool,
    pub check_reverse_shells: bool,
    pub high_entropy_dns_threshold: f64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            general: GeneralConfig {
                max_threads: 8,
                threat_score_threshold: 30,
            },
            process: ProcessConfig {
                check_hidden: true,
                check_deleted_executables: true,
                check_memfd: true,
                check_network_namespaces: true,
                suspicious_names: vec![
                    "nc".into(), "ncat".into(), "netcat".into(),
                    "socat".into(), "msfconsole".into(), "metasploit".into(),
                    "mimikatz".into(), "empire".into(), "cobalt".into(),
                    "meterpreter".into(), "payload".into(), "shell.py".into(),
                    "rev_shell".into(), "reverse_shell".into(),
                ],
                whitelist_processes: vec![
                    "systemd".into(), "kthread".into(), "rcu_sched".into(),
                    "migration".into(), "watchdog".into(),
                ],
            },
            file_integrity: FileIntegrityConfig {
                watch_dirs: vec![
                    "/etc".into(),
                    "/bin".into(),
                    "/sbin".into(),
                    "/usr/bin".into(),
                    "/usr/sbin".into(),
                    "/usr/local/bin".into(),
                    "/tmp".into(),
                    "/var/tmp".into(),
                ],
                check_suid: true,
                check_world_writable: true,
                check_hidden_files: true,
                check_large_files: true,
                max_file_size_mb: 500,
                critical_files: vec![
                    "/etc/passwd".into(),
                    "/etc/shadow".into(),
                    "/etc/sudoers".into(),
                    "/etc/crontab".into(),
                    "/etc/hosts".into(),
                    "/etc/ld.so.preload".into(),
                    "/etc/ld.so.conf".into(),
                    "/root/.bashrc".into(),
                    "/root/.profile".into(),
                    "/root/.ssh/authorized_keys".into(),
                ],
            },
            log_analyzer: LogAnalyzerConfig {
                log_dirs: vec![
                    "/var/log".into(),
                ],
                brute_force_threshold: 5,
                brute_force_window_secs: 300,
                check_privilege_escalation: true,
                check_cron_changes: true,
                check_new_users: true,
            },
            network: NetworkConfig {
                suspicious_ports: vec![
                    4444, 4445, 4446, 4447,  // Metasploit defaults
                    1337, 31337,              // Common backdoor ports
                    6667, 6668, 6669, 6697,  // IRC (C2)
                    8080, 8443, 8888,         // Alt HTTP (proxy/C2)
                    9001, 9030,               // Tor
                    12345, 54321, 65535,      // Common reverse shells
                    2222, 2323,               // Alt SSH/telnet
                    11211, 27017, 6379,       // Exposed DBs
                ],
                known_c2_ips: vec![
                    // Reserved/private ranges used suspiciously
                ],
                known_c2_domains: vec![
                    "pastebin.com".into(),
                    "ngrok.io".into(),
                    "serveo.net".into(),
                    "localhost.run".into(),
                ],
                check_dns_tunneling: true,
                check_tor: true,
                check_reverse_shells: true,
                high_entropy_dns_threshold: 3.5,
            },
        }
    }
}

impl Config {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let cfg: Config = toml::from_str(&content)?;
        Ok(cfg)
    }
}
