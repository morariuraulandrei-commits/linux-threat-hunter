use super::{ScanResult, Severity};
use crate::config::Config;
use anyhow::Result;
use regex::Regex;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::Path;

pub struct LogAnalyzer {
    cfg: Config,
}

struct BruteForceEntry {
    count: u32,
    ips: Vec<String>,
    users: Vec<String>,
}

impl LogAnalyzer {
    pub fn new(cfg: Config) -> Self {
        Self { cfg }
    }

    pub async fn scan(&mut self) -> Result<Vec<ScanResult>> {
        let mut findings: Vec<ScanResult> = Vec::new();

        // Auth log analysis
        let auth_logs = self.find_log_files(&["auth.log", "secure", "messages"]);
        for log in &auth_logs {
            findings.extend(self.analyze_auth_log(log));
        }

        // Syslog analysis
        let syslogs = self.find_log_files(&["syslog", "kern.log"]);
        for log in &syslogs {
            findings.extend(self.analyze_syslog(log));
        }

        // Bash history analysis for all users
        findings.extend(self.analyze_bash_histories());

        // Audit log analysis
        let audit_logs = self.find_log_files(&["audit/audit.log"]);
        for log in &audit_logs {
            findings.extend(self.analyze_audit_log(log));
        }

        // Check for log tampering (truncation, gaps)
        findings.extend(self.check_log_tampering(&auth_logs));

        // Check wtmp/btmp for suspicious logins
        findings.extend(self.check_login_records());

        // Check for unusual cron execution
        findings.extend(self.check_cron_logs());

        Ok(findings)
    }

    fn find_log_files(&self, names: &[&str]) -> Vec<String> {
        let mut found = Vec::new();
        for dir in &self.cfg.log_analyzer.log_dirs {
            for name in names {
                let path = format!("{}/{}", dir, name);
                if Path::new(&path).exists() {
                    found.push(path);
                }
                // Also check rotated versions
                for suffix in &["1", "2"] {
                    let rotated = format!("{}/{}.{}", dir, name, suffix);
                    if Path::new(&rotated).exists() {
                        found.push(rotated);
                    }
                }
            }
        }
        found
    }

    fn read_log_lines(&self, path: &str, max_lines: usize) -> Vec<String> {
        let file = match File::open(path) {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };
        let reader = BufReader::new(file);
        reader
            .lines()
            .filter_map(|l| l.ok())
            .take(max_lines)
            .collect()
    }

    fn analyze_auth_log(&self, path: &str) -> Vec<ScanResult> {
        let mut findings = Vec::new();
        let lines = self.read_log_lines(path, 100_000);

        // SSH brute force detection
        let re_failed = Regex::new(
            r"Failed password for (?:invalid user )?(\S+) from ([\d\.]+)"
        ).unwrap();
        let re_invalid = Regex::new(
            r"Invalid user (\S+) from ([\d\.]+)"
        ).unwrap();
        let re_accepted = Regex::new(
            r"Accepted (\w+) for (\S+) from ([\d\.]+)"
        ).unwrap();
        let re_su = Regex::new(
            r"su(?:\[\d+\])?: (?:FAILED su|pam_unix.*authentication failure)"
        ).unwrap();
        let re_sudo_fail = Regex::new(
            r"sudo.*command not allowed|sudo.*incorrect password attempts"
        ).unwrap();
        let re_useradd = Regex::new(
            r"useradd\[|new user: name=(\S+)"
        ).unwrap();
        let re_userdel = Regex::new(
            r"userdel\[|delete user '(\S+)'"
        ).unwrap();
        let re_passwd = Regex::new(
            r"passwd\[.*changed password|chpasswd:"
        ).unwrap();

        // IP-based brute force counter
        let mut ip_failures: HashMap<String, BruteForceEntry> = HashMap::new();
        // User-based brute force counter
        let mut user_failures: HashMap<String, u32> = HashMap::new();
        // Successful logins
        let mut successful_logins: Vec<String> = Vec::new();
        // Privilege events
        let mut privilege_events: Vec<String> = Vec::new();
        // User management events
        let mut user_mgmt_events: Vec<String> = Vec::new();

        for line in &lines {
            // Failed SSH logins
            if let Some(cap) = re_failed.captures(line) {
                let user = cap[1].to_string();
                let ip = cap[2].to_string();
                let entry = ip_failures.entry(ip.clone()).or_insert(BruteForceEntry {
                    count: 0,
                    ips: vec![ip.clone()],
                    users: Vec::new(),
                });
                entry.count += 1;
                if !entry.users.contains(&user) {
                    entry.users.push(user.clone());
                }
                *user_failures.entry(user).or_insert(0) += 1;
            }

            // Invalid user attempts
            if let Some(cap) = re_invalid.captures(line) {
                let user = cap[1].to_string();
                let ip = cap[2].to_string();
                let entry = ip_failures.entry(ip).or_insert(BruteForceEntry {
                    count: 0,
                    ips: Vec::new(),
                    users: Vec::new(),
                });
                entry.count += 1;
                *user_failures.entry(user).or_insert(0) += 1;
            }

            // Successful logins
            if let Some(cap) = re_accepted.captures(line) {
                let method = &cap[1];
                let user = &cap[2];
                let ip = &cap[3];
                successful_logins.push(format!("{} via {} from {}", user, method, ip));
            }

            // SU/sudo failures
            if re_su.is_match(line) || re_sudo_fail.is_match(line) {
                privilege_events.push(line.trim().to_string());
            }

            // User management
            if re_useradd.is_match(line) || re_userdel.is_match(line) || re_passwd.is_match(line) {
                user_mgmt_events.push(line.trim().to_string());
            }
        }

        let threshold = self.cfg.log_analyzer.brute_force_threshold;

        // Report brute force by IP
        for (ip, entry) in &ip_failures {
            if entry.count >= threshold {
                let severity = if entry.count > 100 {
                    Severity::Critical
                } else if entry.count > 50 {
                    Severity::High
                } else {
                    Severity::Medium
                };

                let score = (entry.count.min(200) / 2).min(95) as u32 + 40;

                let mut r = ScanResult::new(
                    format!("SSH brute force from {} ({} attempts)", ip, entry.count),
                    format!(
                        "IP address {} made {} failed SSH login attempts. \
                         Target usernames: {}. \
                         This is a clear brute force or credential stuffing attack.",
                        ip,
                        entry.count,
                        entry.users.iter().take(5).cloned().collect::<Vec<_>>().join(", ")
                    ),
                    severity,
                    "LogAnalyzer",
                    score.min(99),
                );
                r = r
                    .with_artifacts(vec![
                        format!("Source IP: {}", ip),
                        format!("Attempt count: {}", entry.count),
                        format!("Targeted users: {}", entry.users.join(", ")),
                    ])
                    .with_mitre("T1110.001 - Brute Force: Password Guessing")
                    .with_recommendations(vec![
                        format!("Block IP: iptables -A INPUT -s {} -j DROP", ip),
                        format!("Or: ufw deny from {} to any", ip),
                        "Enable fail2ban to automate blocking".into(),
                        "Consider moving SSH to non-standard port".into(),
                        "Enable SSH key-only authentication".into(),
                    ]);
                findings.push(r);
            }
        }

        // Report user accounts with many failures (password spraying)
        for (user, count) in &user_failures {
            if *count >= threshold * 3 && user != "root" {
                let mut r = ScanResult::new(
                    format!("Password spray targeting user '{}' ({} failures)", user, count),
                    format!(
                        "User '{}' has received {} failed login attempts from multiple sources. \
                         This pattern is consistent with password spraying attacks.",
                        user, count
                    ),
                    Severity::High,
                    "LogAnalyzer",
                    72,
                );
                r = r
                    .with_artifacts(vec![
                        format!("Username: {}", user),
                        format!("Failure count: {}", count),
                    ])
                    .with_mitre("T1110.003 - Brute Force: Password Spraying");
                findings.push(r);
            }
        }

        // Report root brute force (always critical)
        if let Some(count) = user_failures.get("root") {
            if *count >= threshold {
                let mut r = ScanResult::new(
                    format!("Root account brute force: {} failed attempts", count),
                    format!(
                        "The root account received {} failed login attempts. \
                         Successful root compromise would give full system control.",
                        count
                    ),
                    Severity::Critical,
                    "LogAnalyzer",
                    96,
                );
                r = r
                    .with_artifacts(vec![format!("Root failure count: {}", count)])
                    .with_mitre("T1110 - Brute Force")
                    .with_recommendations(vec![
                        "Disable root SSH login: PermitRootLogin no in /etc/ssh/sshd_config".into(),
                        "Use sudo for administrative access".into(),
                    ]);
                findings.push(r);
            }
        }

        // Privilege escalation attempts
        if privilege_events.len() > 3 {
            let mut r = ScanResult::new(
                format!("{} privilege escalation attempts detected", privilege_events.len()),
                "Multiple failed su/sudo attempts were found in authentication logs. \
                 This may indicate an attacker attempting to escalate privileges \
                 after gaining a foothold.",
                Severity::High,
                "LogAnalyzer",
                78,
            );
            r = r
                .with_artifacts(privilege_events.iter().take(5).cloned().collect())
                .with_mitre("T1548 - Abuse Elevation Control Mechanism");
            findings.push(r);
        }

        // User management (could indicate attacker adding backdoor accounts)
        if self.cfg.log_analyzer.check_new_users && !user_mgmt_events.is_empty() {
            let mut r = ScanResult::new(
                format!("{} user management events detected", user_mgmt_events.len()),
                "User account changes were detected in authentication logs. \
                 Review these changes to ensure they were authorized. \
                 Attackers often create new accounts for persistence.",
                Severity::Medium,
                "LogAnalyzer",
                60,
            );
            r = r
                .with_artifacts(user_mgmt_events.iter().take(10).cloned().collect())
                .with_mitre("T1136.001 - Create Account: Local Account");
            findings.push(r);
        }

        // Unusual successful logins
        if !successful_logins.is_empty() {
            // Check for password logins (should ideally be key-based)
            let password_logins: Vec<_> = successful_logins.iter()
                .filter(|l| l.contains("via password"))
                .cloned()
                .collect();

            if password_logins.len() > 5 {
                let mut r = ScanResult::new(
                    format!("{} successful password-based SSH logins", password_logins.len()),
                    "Multiple successful SSH logins using passwords were detected. \
                     Password-based SSH authentication is less secure than key-based auth \
                     and may indicate compromised credentials.",
                    Severity::Low,
                    "LogAnalyzer",
                    35,
                );
                r = r
                    .with_artifacts(password_logins.iter().take(5).cloned().collect())
                    .with_mitre("T1078 - Valid Accounts")
                    .with_recommendations(vec![
                        "Enable key-only SSH: PasswordAuthentication no".into(),
                        "Enable MFA for SSH access".into(),
                    ]);
                findings.push(r);
            }
        }

        findings
    }

    fn analyze_syslog(&self, path: &str) -> Vec<ScanResult> {
        let mut findings = Vec::new();
        let lines = self.read_log_lines(path, 50_000);

        let re_oom = Regex::new(r"Out of memory: Kill process|oom-kill|OOM score").unwrap();
        let re_segfault = Regex::new(r"segfault at").unwrap();
        let re_kernel_panic = Regex::new(r"Kernel panic|BUG:|general protection fault").unwrap();
        let re_usb = Regex::new(r"usb.*new.*USB device|New USB device found").unwrap();
        let re_module = Regex::new(r"insmod|modprobe|Module.*loaded").unwrap();

        let mut oom_count = 0u32;
        let mut segfault_count = 0u32;
        let mut panic_events: Vec<String> = Vec::new();
        let mut usb_events: Vec<String> = Vec::new();
        let mut module_events: Vec<String> = Vec::new();

        for line in &lines {
            if re_oom.is_match(line) {
                oom_count += 1;
            }
            if re_segfault.is_match(line) {
                segfault_count += 1;
            }
            if re_kernel_panic.is_match(line) {
                panic_events.push(line.trim().to_string());
            }
            if re_usb.is_match(line) {
                usb_events.push(line.trim().to_string());
            }
            if re_module.is_match(line) {
                module_events.push(line.trim().to_string());
            }
        }

        if oom_count > 5 {
            let mut r = ScanResult::new(
                format!("{} OOM kill events — possible resource exhaustion attack", oom_count),
                format!(
                    "{} Out-Of-Memory kill events detected. This could indicate a fork bomb, \
                     memory exhaustion attack, or cryptominer consuming all RAM.",
                    oom_count
                ),
                Severity::High,
                "LogAnalyzer",
                65,
            );
            r = r
                .with_artifacts(vec![format!("OOM event count: {}", oom_count)])
                .with_mitre("T1499 - Endpoint Denial of Service");
            findings.push(r);
        }

        if segfault_count > 20 {
            let mut r = ScanResult::new(
                format!("{} segfault events — possible exploitation attempt", segfault_count),
                format!(
                    "{} segmentation fault events detected in kernel logs. \
                     A high number of segfaults may indicate active exploitation attempts \
                     (stack overflow, heap spray, UAF exploits).",
                    segfault_count
                ),
                Severity::Medium,
                "LogAnalyzer",
                55,
            );
            r = r
                .with_artifacts(vec![format!("Segfault count: {}", segfault_count)])
                .with_mitre("T1203 - Exploitation for Client Execution");
            findings.push(r);
        }

        if !panic_events.is_empty() {
            let mut r = ScanResult::new(
                format!("{} kernel panic/BUG events", panic_events.len()),
                "Kernel panic or BUG events were detected. These can result from kernel \
                 exploits, rootkit installation, or hardware-level attacks.",
                Severity::Critical,
                "LogAnalyzer",
                85,
            );
            r = r
                .with_artifacts(panic_events.iter().take(3).cloned().collect())
                .with_mitre("T1014 - Rootkit");
            findings.push(r);
        }

        if !usb_events.is_empty() {
            let mut r = ScanResult::new(
                format!("{} USB device connection(s) detected", usb_events.len()),
                "New USB devices were connected to the system. USB devices can be used for \
                 data exfiltration (rubber ducky), dropping malware, or hardware keyloggers.",
                Severity::Low,
                "LogAnalyzer",
                30,
            );
            r = r
                .with_artifacts(usb_events.iter().take(5).cloned().collect())
                .with_mitre("T1200 - Hardware Additions");
            findings.push(r);
        }

        findings
    }

    fn analyze_bash_histories(&self) -> Vec<ScanResult> {
        let mut findings = Vec::new();

        let suspicious_commands = [
            (r"nc\s+-[el]|ncat\s+-[el]|socat.*exec", "Reverse shell via nc/ncat/socat", "T1059.004"),
            (r"python.*-c.*socket|perl.*-e.*socket|ruby.*-e.*TCPSocket", "Script-based reverse shell", "T1059"),
            (r"curl.*\|\s*bash|wget.*\|\s*bash|curl.*\|\s*sh", "Pipe-to-shell execution (supply chain risk)", "T1105"),
            (r"chmod\s+[74]\d\d\s+", "Setting high-permission chmod", "T1222"),
            (r"base64\s+-d.*\|\s*(bash|sh|python|perl)", "Base64 decoded execution (obfuscation)", "T1027"),
            (r"/etc/shadow|/etc/passwd|/etc/sudoers", "Accessing credential files", "T1003"),
            (r"iptables\s+-F|ufw\s+disable|systemctl\s+stop\s+firewall", "Disabling firewall", "T1562.004"),
            (r"pkill\s+-(KILL|9)\s+.*antivirus|systemctl\s+stop.*clamav", "Disabling security software", "T1562.001"),
            (r"history\s+-c|rm\s+.*bash_history|shred.*bash_history|>\s+~/\.bash_history", "Clearing bash history (anti-forensics)", "T1070.003"),
            (r"dd\s+if=.*of=.*\|", "Data exfiltration via dd", "T1041"),
            (r"find\s+/\s+.*-name.*passwd|find\s+.*-perm.*4000", "Reconnaissance for SUID or credentials", "T1083"),
            (r"crontab\s+-[el].*>&|echo.*crontab|cron.*\|\s*", "Crontab modification", "T1053.003"),
            (r"insmod|modprobe|rmmod", "Kernel module manipulation", "T1547.006"),
        ];

        let passwd = fs::read_to_string("/etc/passwd").unwrap_or_default();

        for line in passwd.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() < 6 {
                continue;
            }
            let username = parts[0];
            let home = parts[5];

            let history_paths = [
                format!("{}/.bash_history", home),
                format!("{}/.zsh_history", home),
                format!("{}/.history", home),
            ];

            for history_path in &history_paths {
                if !Path::new(history_path).exists() {
                    continue;
                }

                let content = fs::read_to_string(history_path).unwrap_or_default();

                for (pattern, desc, mitre) in &suspicious_commands {
                    let re = match Regex::new(*pattern) {
                        Ok(r) => r,
                        Err(_) => continue,
                    };

                    let matching_lines: Vec<String> = content
                        .lines()
                        .filter(|l| re.is_match(l))
                        .take(5)
                        .map(|l| l.to_string())
                        .collect();

                    if !matching_lines.is_empty() {
                        let mut r = ScanResult::new(
                            format!("{} in history of user '{}'", desc, username),
                            format!(
                                "Found suspicious command pattern '{}' in bash history of user '{}'. \
                                 File: {}. Matching lines: {}",
                                desc, username, history_path,
                                matching_lines.join(" | ")
                            ),
                            Severity::High,
                            "LogAnalyzer",
                            76,
                        );
                        r = r
                            .with_artifacts(vec![
                                format!("User: {}", username),
                                format!("History file: {}", history_path),
                                format!("Commands: {}", matching_lines.join("\n")),
                            ])
                            .with_mitre(*mitre);
                        findings.push(r);
                        break; // one finding per pattern per user per file
                    }
                }

                // Check if history was cleared (very small or empty for active user)
                let metadata = fs::metadata(history_path).ok();
                if let Some(meta) = metadata {
                    if meta.len() == 0 {
                        let uid: u32 = parts[2].parse().unwrap_or(0);
                        if uid >= 1000 || username == "root" {
                            let mut r = ScanResult::new(
                                format!("Empty bash history for active user '{}'", username),
                                format!(
                                    "User '{}' has an empty history file at '{}'. \
                                     Active users clearing their bash history is a common \
                                     anti-forensics technique used by attackers.",
                                    username, history_path
                                ),
                                Severity::Medium,
                                "LogAnalyzer",
                                55,
                            );
                            r = r
                                .with_artifacts(vec![
                                    format!("User: {}", username),
                                    format!("History file: {} (empty)", history_path),
                                ])
                                .with_mitre("T1070.003 - Indicator Removal: Clear Command History");
                            findings.push(r);
                        }
                    }
                }
            }
        }
        findings
    }

    fn analyze_audit_log(&self, path: &str) -> Vec<ScanResult> {
        let mut findings = Vec::new();
        let lines = self.read_log_lines(path, 50_000);

        let mut execve_count: HashMap<String, u32> = HashMap::new();
        let re_execve = Regex::new(r#"type=EXECVE.*a0="([^"]+)""#).unwrap();
        let re_syscall_fail = Regex::new(r"type=SYSCALL.*success=no.*syscall=(\d+)").unwrap();
        let re_priv_change = Regex::new(r"type=SYSCALL.*syscall=(?:105|106|setuid|setgid)").unwrap();

        let mut syscall_failures = 0u32;
        let mut priv_changes = Vec::new();

        for line in &lines {
            if let Some(cap) = re_execve.captures(line) {
                let cmd = cap[1].to_string();
                *execve_count.entry(cmd).or_insert(0) += 1;
            }
            if re_syscall_fail.is_match(line) {
                syscall_failures += 1;
            }
            if re_priv_change.is_match(line) {
                priv_changes.push(line.trim().to_string());
            }
        }

        // Unusual privilege change volume
        if priv_changes.len() > 50 {
            let mut r = ScanResult::new(
                format!("{} setuid/setgid syscall events in audit log", priv_changes.len()),
                "An unusually high number of privilege-change syscalls were detected in audit logs. \
                 This may indicate privilege escalation attempts or exploit activity.",
                Severity::High,
                "LogAnalyzer",
                75,
            );
            r = r
                .with_artifacts(priv_changes.iter().take(5).cloned().collect())
                .with_mitre("T1548 - Abuse Elevation Control Mechanism");
            findings.push(r);
        }

        if syscall_failures > 1000 {
            let mut r = ScanResult::new(
                format!("{} failed syscalls — exploitation/fuzzing activity suspected", syscall_failures),
                format!(
                    "{} failed system calls detected in audit log. A high rate of syscall \
                     failures can indicate active exploit attempts, fuzzing, or sandbox-aware malware.",
                    syscall_failures
                ),
                Severity::Medium,
                "LogAnalyzer",
                58,
            );
            r = r
                .with_artifacts(vec![format!("Failed syscall count: {}", syscall_failures)])
                .with_mitre("T1203 - Exploitation for Client Execution");
            findings.push(r);
        }

        findings
    }

    fn check_log_tampering(&self, log_paths: &[String]) -> Vec<ScanResult> {
        let mut findings = Vec::new();

        for path in log_paths {
            if let Ok(meta) = fs::metadata(path) {
                // Suspicious: very small auth.log for production system
                if meta.len() < 100 && path.contains("auth") {
                    let mut r = ScanResult::new(
                        format!("Suspiciously small log file: {} ({} bytes)", path, meta.len()),
                        format!(
                            "Log file '{}' is unusually small ({} bytes). \
                             Attackers commonly truncate or delete log files to cover their tracks.",
                            path, meta.len()
                        ),
                        Severity::High,
                        "LogAnalyzer",
                        80,
                    );
                    r = r
                        .with_artifacts(vec![
                            format!("Path: {}", path),
                            format!("Size: {} bytes", meta.len()),
                        ])
                        .with_mitre("T1070.002 - Indicator Removal: Clear Linux or Mac System Logs")
                        .with_recommendations(vec![
                            "Check if log was truncated: ls -la /var/log/".into(),
                            "Review syslog configuration".into(),
                            "Check for log rotation tampering".into(),
                        ]);
                    findings.push(r);
                }
            }
        }
        findings
    }

    fn check_login_records(&self) -> Vec<ScanResult> {
        let mut findings = Vec::new();

        // Parse /var/run/utmp or /var/log/wtmp for current/recent logins
        // We check /var/log/lastlog for unusual patterns via commands
        // Since we can't easily parse binary wtmp in pure Rust without external deps,
        // we'll check /proc/net/tcp for active SSH sessions
        let who_output = std::process::Command::new("who")
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string());

        if let Some(output) = who_output {
            let logins: Vec<&str> = output.lines().collect();
            // Check for root logins
            for login in &logins {
                if login.starts_with("root") {
                    let mut r = ScanResult::new(
                        format!("Active root login session detected"),
                        format!("Root is currently logged in: {}", login.trim()),
                        Severity::Medium,
                        "LogAnalyzer",
                        50,
                    );
                    r = r
                        .with_artifacts(vec![format!("Session: {}", login.trim())])
                        .with_mitre("T1078.003 - Valid Accounts: Local Accounts");
                    findings.push(r);
                }
            }

            // Multiple concurrent sessions
            if logins.len() > 10 {
                let mut r = ScanResult::new(
                    format!("{} concurrent login sessions", logins.len()),
                    format!(
                        "Unusually high number of active login sessions: {}. \
                         This may indicate a botnet, unauthorized access, or compromised credentials.",
                        logins.len()
                    ),
                    Severity::Medium,
                    "LogAnalyzer",
                    52,
                );
                r = r.with_artifacts(logins.iter().take(5).map(|s| s.to_string()).collect());
                findings.push(r);
            }
        }

        // Check for failed logins in btmp
        if Path::new("/var/log/btmp").exists() {
            if let Ok(meta) = fs::metadata("/var/log/btmp") {
                // Each btmp record is 384 bytes (utmp struct)
                let btmp_records = meta.len() / 384;
                if btmp_records > 100 {
                    let mut r = ScanResult::new(
                        format!("{} failed login records in btmp", btmp_records),
                        format!(
                            "/var/log/btmp contains {} failed login records. \
                             A high number indicates sustained brute force activity.",
                            btmp_records
                        ),
                        Severity::High,
                        "LogAnalyzer",
                        70,
                    );
                    r = r
                        .with_artifacts(vec![format!("btmp records: {}", btmp_records)])
                        .with_mitre("T1110 - Brute Force")
                        .with_recommendations(vec![
                            "Analyze with: lastb | head -50".into(),
                            "Install and configure fail2ban".into(),
                        ]);
                    findings.push(r);
                }
            }
        }

        findings
    }

    fn check_cron_logs(&self) -> Vec<ScanResult> {
        let mut findings = Vec::new();
        let cron_logs = self.find_log_files(&["cron", "cron.log"]);

        for log in &cron_logs {
            let lines = self.read_log_lines(log, 10_000);
            let re_error = Regex::new(r"ERROR|FAILED|error|failed").unwrap();
            let re_root_cron = Regex::new(r"CRON.*\(root\).*CMD").unwrap();

            let mut errors = Vec::new();
            let mut root_cron_cmds = Vec::new();

            for line in &lines {
                if re_error.is_match(line) {
                    errors.push(line.trim().to_string());
                }
                if re_root_cron.is_match(line) {
                    root_cron_cmds.push(line.trim().to_string());
                }
            }

            if !errors.is_empty() && errors.len() > 5 {
                let mut r = ScanResult::new(
                    format!("{} cron error events in {}", errors.len(), log),
                    "Multiple cron errors detected. Repeated cron failures can indicate \
                     tampered cron jobs or attacker-planted jobs that are failing.",
                    Severity::Low,
                    "LogAnalyzer",
                    35,
                );
                r = r.with_artifacts(errors.iter().take(5).cloned().collect());
                findings.push(r);
            }
        }

        findings
    }
}
