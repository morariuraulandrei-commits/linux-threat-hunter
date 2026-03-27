use super::{ScanResult, Severity};
use crate::config::Config;
use anyhow::Result;
use regex::Regex;
use std::fs;
use std::path::Path;

pub struct PersistenceHunter {
    cfg: Config,
}

impl PersistenceHunter {
    pub fn new(cfg: Config) -> Self {
        Self { cfg }
    }

    pub async fn scan(&mut self) -> Result<Vec<ScanResult>> {
        let mut findings: Vec<ScanResult> = Vec::new();

        // Check cron backdoors
        findings.extend(self.check_cron_backdoors());

        // Check systemd malicious services
        findings.extend(self.check_systemd_services());

        // Check shell RC file injection
        findings.extend(self.check_shell_rc_injection());

        // Check SSH authorized_keys backdoors
        findings.extend(self.check_ssh_authorized_keys());

        // Check LD_PRELOAD persistence
        if let Some(finding) = self.check_ld_preload_persistence() {
            findings.push(finding);
        }

        // Check rc.local backdoor
        findings.extend(self.check_rc_local());

        // Check profile.d injection
        findings.extend(self.check_profiled_injection());

        // Check at job persistence
        findings.extend(self.check_at_jobs());

        // Check PAM backdoor
        findings.extend(self.check_pam_backdoor());

        // Check sudoers privilege escalation
        findings.extend(self.check_sudoers_privesc());

        // Check passwd for root-equivalent accounts
        findings.extend(self.check_passwd_backdoor());

        // Check MOTD/update-motd backdoor
        findings.extend(self.check_motd_backdoor());

        // Check git hooks
        findings.extend(self.check_git_hooks());

        // Check XDG autostart
        findings.extend(self.check_xdg_autostart());

        Ok(findings)
    }

    fn check_cron_backdoors(&self) -> Vec<ScanResult> {
        let mut findings = Vec::new();

        // Check /etc/crontab
        if let Ok(content) = fs::read_to_string("/etc/crontab") {
            findings.extend(self.analyze_crontab(&content, "/etc/crontab"));
        }

        // Check /etc/cron.d/*
        if let Ok(entries) = fs::read_dir("/etc/cron.d") {
            for entry in entries.flatten() {
                if let Ok(path) = entry.path().into_os_string().into_string() {
                    if let Ok(content) = fs::read_to_string(&path) {
                        findings.extend(self.analyze_crontab(&content, &path));
                    }
                }
            }
        }

        // Check /var/spool/cron/crontabs/*
        if let Ok(entries) = fs::read_dir("/var/spool/cron/crontabs") {
            for entry in entries.flatten() {
                if let Ok(path) = entry.path().into_os_string().into_string() {
                    if let Ok(content) = fs::read_to_string(&path) {
                        let filename = Path::new(&path)
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("unknown");
                        findings.extend(self.analyze_crontab_user(&content, &path, filename));
                    }
                }
            }
        }

        findings
    }

    fn analyze_crontab(&self, content: &str, path: &str) -> Vec<ScanResult> {
        let mut findings = Vec::new();
        let suspicious_patterns = [
            (r"curl|bash", "curl piped to bash"),
            (r"wget.*\|.*sh", "wget piped to shell"),
            (r"base64.*-d", "base64 decoding"),
            (r"nc.*-l", "netcat listener"),
            (r"/tmp|/dev/shm", "temporary directory execution"),
            (r"\$\(.*\)", "command substitution"),
            (r"bash.*-i", "interactive bash shell"),
            (r"python.*-c.*socket", "Python reverse shell"),
        ];

        for (pattern, desc) in &suspicious_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for (line_num, line) in content.lines().enumerate() {
                    if re.is_match(line) && !line.trim().starts_with('#') {
                        let finding = ScanResult::new(
                            format!("Suspicious Cron Entry in {}", path),
                            format!(
                                "Cron job at line {} contains suspicious pattern ({}): {}. Cron jobs are executed at scheduled intervals and can be used for persistence. This pattern suggests potential malware execution.",
                                line_num + 1,
                                desc,
                                line.trim()
                            ),
                            Severity::High,
                            "Persistence",
                            75,
                        )
                        .with_artifacts(vec![
                            path.to_string(),
                            format!("Line {}: {}", line_num + 1, line.trim()),
                        ])
                        .with_mitre("T1053.003 - Scheduled Task/Job: Cron")
                        .with_recommendations(vec![
                            "Review the cron job and verify its legitimacy".to_string(),
                            "Check the audit logs for when this cron job was added".to_string(),
                            "If suspicious, remove the cron job immediately".to_string(),
                            "Monitor cron execution logs for related activity".to_string(),
                        ]);

                        findings.push(finding);
                    }
                }
            }
        }

        findings
    }

    fn analyze_crontab_user(&self, content: &str, path: &str, user: &str) -> Vec<ScanResult> {
        let mut findings = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            if line.trim().is_empty() || line.trim().starts_with('#') {
                continue;
            }

            // Check for unusual users running cron
            if user != "root" && user != "cron" {
                let finding = ScanResult::new(
                    format!("Non-standard User Cron Job: {}", user),
                    format!(
                        "User '{}' has a cron job scheduled. While not necessarily malicious, attackers often add cron jobs for non-standard users to persist access. Verify the legitimacy of this cron file.",
                        user
                    ),
                    Severity::Medium,
                    "Persistence",
                    55,
                )
                .with_artifacts(vec![path.to_string(), format!("User: {}", user)])
                .with_mitre("T1053.003 - Scheduled Task/Job: Cron")
                .with_recommendations(vec![
                    format!("Verify that user {} should have scheduled tasks", user),
                    "Check when the cron file was last modified".to_string(),
                    "Review all cron entries for this user".to_string(),
                ]);

                findings.push(finding);
                break;
            }

            // Check for suspicious commands in entries
            if line.contains("curl") && line.contains("bash") {
                let finding = ScanResult::new(
                    format!("Curl-Bash Pattern in Cron ({})", user),
                    "Cron job uses curl piped to bash, a common malware download-and-execute pattern. This is a critical indicator of potential persistence mechanism.".to_string(),
                    Severity::Critical,
                    "Persistence",
                    85,
                )
                .with_artifacts(vec![
                    path.to_string(),
                    format!("Line {}: {}", line_num + 1, line.trim()),
                ])
                .with_mitre("T1053.003 - Scheduled Task/Job: Cron")
                .with_recommendations(vec![
                    "Immediately remove this cron job".to_string(),
                    "Investigate the source of the malicious payload".to_string(),
                    "Check system logs for execution history".to_string(),
                    "Conduct forensic analysis to identify compromise timeline".to_string(),
                ]);

                findings.push(finding);
            }
        }

        findings
    }

    fn check_systemd_services(&self) -> Vec<ScanResult> {
        let mut findings = Vec::new();
        let service_dirs = vec!["/etc/systemd/system", "/lib/systemd/system"];

        for dir in service_dirs {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    if let Ok(path) = entry.path().into_os_string().into_string() {
                        if path.ends_with(".service") {
                            if let Ok(content) = fs::read_to_string(&path) {
                                findings.extend(self.analyze_systemd_service(&content, &path));
                            }
                        }
                    }
                }
            }
        }

        findings
    }

    fn analyze_systemd_service(&self, content: &str, path: &str) -> Vec<ScanResult> {
        let mut findings = Vec::new();
        let filename = Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");

        let suspicious_names = [
            "updater", "checker", "monitor", "sync", "helper", "service", "agent", "daemon",
        ];

        for name in &suspicious_names {
            if filename.to_lowercase().contains(name) && filename != "systemd-*.service" {
                let finding = ScanResult::new(
                    format!("Suspicious Systemd Service Name: {}", filename),
                    format!(
                        "Service '{}' has a suspicious name commonly used in malware. Service names like '{}' are often used to disguise malicious background processes.",
                        filename,
                        name
                    ),
                    Severity::Medium,
                    "Persistence",
                    60,
                )
                .with_artifacts(vec![path.to_string()])
                .with_mitre("T1543.002 - Create or Modify System Process: Systemd Service")
                .with_recommendations(vec![
                    "Verify the service's purpose and legitimacy".to_string(),
                    "Check the ExecStart path and verify the binary exists and is legitimate".to_string(),
                    "Review service logs with journalctl".to_string(),
                ]);

                findings.push(finding);
                break;
            }
        }

        // Check for suspicious ExecStart paths
        if content.contains("ExecStart=/tmp") || content.contains("ExecStart=/dev/shm") {
            let finding = ScanResult::new(
                format!("Systemd Service with /tmp or /dev/shm Execution"),
                "Systemd service executes binaries from /tmp or /dev/shm. These temporary directories are commonly used by attackers to store and execute malware.".to_string(),
                Severity::Critical,
                "Persistence",
                90,
            )
            .with_artifacts(vec![path.to_string()])
            .with_mitre("T1543.002 - Create or Modify System Process: Systemd Service")
            .with_recommendations(vec![
                "Disable and remove this service immediately".to_string(),
                "Investigate the binary in /tmp or /dev/shm".to_string(),
                "Check systemd logs for service execution history".to_string(),
                "Scan the system for related malware".to_string(),
            ]);

            findings.push(finding);
        }

        // Check for shell execution in ExecStart
        if content.contains("ExecStart=/bin/bash") || content.contains("ExecStart=/bin/sh")
            || content.contains("ExecStart=/usr/bin/python")
            || content.contains("ExecStart=/usr/bin/perl")
        {
            let finding = ScanResult::new(
                format!("Systemd Service with Shell Interpreter: {}", filename),
                "Service uses a shell interpreter (bash, sh, python, perl) as its main executable. This is highly suspicious as legitimate services typically run compiled binaries or specific applications.".to_string(),
                Severity::High,
                "Persistence",
                80,
            )
            .with_artifacts(vec![path.to_string()])
            .with_mitre("T1543.002 - Create or Modify System Process: Systemd Service")
            .with_recommendations(vec![
                "Review the full service configuration".to_string(),
                "Verify the actual command being executed".to_string(),
                "Check for environment variables that might execute malicious scripts".to_string(),
                "Monitor service execution".to_string(),
            ]);

            findings.push(finding);
        }

        // Check for Restart=always which would auto-respawn
        if content.contains("Restart=always") {
            if let Some(exec_line) = content.lines().find(|l| l.contains("ExecStart=")) {
                let exec_path = exec_line
                    .split("ExecStart=")
                    .nth(1)
                    .unwrap_or("")
                    .split_whitespace()
                    .next()
                    .unwrap_or("");

                if !exec_path.starts_with("/usr/bin")
                    && !exec_path.starts_with("/usr/sbin")
                    && !exec_path.starts_with("/usr/local/bin")
                {
                    let finding = ScanResult::new(
                        format!("Systemd Service with Auto-Restart: {}", filename),
                        format!(
                            "Service '{}' has 'Restart=always' configured and executes from suspicious path '{}'. This combination ensures malware persistence even if the process is killed.",
                            filename,
                            exec_path
                        ),
                        Severity::High,
                        "Persistence",
                        78,
                    )
                    .with_artifacts(vec![path.to_string()])
                    .with_mitre("T1543.002 - Create or Modify System Process: Systemd Service")
                    .with_recommendations(vec![
                        "Disable the service: systemctl disable <service>".to_string(),
                        "Stop the service: systemctl stop <service>".to_string(),
                        "Remove the service file".to_string(),
                        "Investigate the executable at specified path".to_string(),
                    ]);

                    findings.push(finding);
                }
            }
        }

        findings
    }

    fn check_shell_rc_injection(&self) -> Vec<ScanResult> {
        let mut findings = Vec::new();

        let rc_files = vec![
            "/root/.bashrc",
            "/root/.profile",
            "/root/.bash_profile",
            "/root/.zshrc",
            "/etc/bash.bashrc",
            "/etc/profile",
            "/etc/profile.d/*",
        ];

        // Check root shell files
        for pattern in &["/root/.bashrc", "/root/.profile", "/root/.bash_profile", "/root/.zshrc"] {
            if let Ok(content) = fs::read_to_string(pattern) {
                findings.extend(self.analyze_shell_rc(&content, pattern));
            }
        }

        // Check system-wide shell files
        for pattern in &["/etc/bash.bashrc", "/etc/profile"] {
            if let Ok(content) = fs::read_to_string(pattern) {
                findings.extend(self.analyze_shell_rc(&content, pattern));
            }
        }

        // Check home directories for user shell files
        if let Ok(entries) = fs::read_dir("/home") {
            for entry in entries.flatten() {
                if let Ok(meta) = entry.metadata() {
                    if meta.is_dir() {
                        let user_dir = entry.path();
                        for file in &[".bashrc", ".profile", ".bash_profile", ".zshrc"] {
                            let rc_path = user_dir.join(file);
                            if let Ok(content) = fs::read_to_string(&rc_path) {
                                if let Ok(path_str) = rc_path.into_os_string().into_string() {
                                    findings.extend(self.analyze_shell_rc(&content, &path_str));
                                }
                            }
                        }
                    }
                }
            }
        }

        findings
    }

    fn analyze_shell_rc(&self, content: &str, path: &str) -> Vec<ScanResult> {
        let mut findings = Vec::new();

        let suspicious_patterns = [
            (r"curl.*\|.*bash", "curl piped to bash"),
            (r"wget.*\|.*sh", "wget piped to shell"),
            (r"base64.*-d", "base64 decoding"),
            (r"nc\s+-l.*-e", "netcat with -e flag (reverse shell)"),
            (r"/bin/bash.*-i", "interactive bash shell"),
            (r"bash.*-i.*<&", "bash reverse shell redirection"),
            (r"bash.*>.*&1", "shell output redirection"),
        ];

        for (pattern, desc) in &suspicious_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for (line_num, line) in content.lines().enumerate() {
                    if re.is_match(line) && !line.trim().starts_with('#') {
                        let severity = if desc.contains("reverse shell") {
                            Severity::Critical
                        } else {
                            Severity::High
                        };

                        let threat_score = if desc.contains("reverse shell") { 85 } else { 75 };

                        let finding = ScanResult::new(
                            format!("Suspicious Command in Shell RC File ({})", path),
                            format!(
                                "Shell RC file contains suspicious command ({}): {}. RC files are loaded every time a shell is spawned, making them ideal for persistence. This pattern indicates potential attacker modification.",
                                desc,
                                line.trim()
                            ),
                            severity,
                            "Persistence",
                            threat_score,
                        )
                        .with_artifacts(vec![
                            path.to_string(),
                            format!("Line {}: {}", line_num + 1, line.trim()),
                        ])
                        .with_mitre("T1546.004 - Trap: .bashrc and .bash_profile")
                        .with_recommendations(vec![
                            "Review the suspicious line and verify its purpose".to_string(),
                            "Check git history if the file is version controlled".to_string(),
                            "Remove the suspicious command if unauthorized".to_string(),
                            "Check shell history for related commands".to_string(),
                        ]);

                        findings.push(finding);
                    }
                }
            }
        }

        findings
    }

    fn check_ssh_authorized_keys(&self) -> Vec<ScanResult> {
        let mut findings = Vec::new();

        // Check root's SSH keys
        let root_keys = "/root/.ssh/authorized_keys";
        if let Ok(content) = fs::read_to_string(root_keys) {
            findings.extend(self.analyze_authorized_keys(&content, root_keys, "root"));
        }

        // Check user SSH keys
        if let Ok(entries) = fs::read_dir("/home") {
            for entry in entries.flatten() {
                if let Ok(meta) = entry.metadata() {
                    if meta.is_dir() {
                        let user_dir = entry.path();
                        let user_name = user_dir
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("unknown")
                            .to_string();

                        let auth_keys_path = user_dir.join(".ssh").join("authorized_keys");
                        if let Ok(content) = fs::read_to_string(&auth_keys_path) {
                            if let Ok(path_str) = auth_keys_path.into_os_string().into_string() {
                                findings.extend(self.analyze_authorized_keys(
                                    &content, &path_str, &user_name,
                                ));
                            }
                        }
                    }
                }
            }
        }

        findings
    }

    fn analyze_authorized_keys(
        &self,
        content: &str,
        path: &str,
        user: &str,
    ) -> Vec<ScanResult> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        // Check for unusually many keys
        if lines.len() > 5 {
            let finding = ScanResult::new(
                format!("Excessive SSH Keys for user {}", user),
                format!(
                    "User {} has {} SSH keys in authorized_keys. An unusually high number of keys may indicate an attacker has added backdoor keys. Typical legitimate use involves 1-3 keys.",
                    user,
                    lines.len()
                ),
                Severity::Medium,
                "Persistence",
                65,
            )
            .with_artifacts(vec![
                path.to_string(),
                format!("Key count: {}", lines.len()),
            ])
            .with_mitre("T1098.004 - Account Manipulation: SSH Authorized Keys")
            .with_recommendations(vec![
                "Review each SSH key to verify ownership".to_string(),
                "Check the modification timestamp of authorized_keys".to_string(),
                "Remove unauthorized keys".to_string(),
                "Rotate your own SSH keys".to_string(),
            ]);

            findings.push(finding);
        }

        // Check for command restrictions in keys
        for (idx, line) in lines.iter().enumerate() {
            if line.contains("command=") {
                let finding = ScanResult::new(
                    format!("SSH Key with Command Restriction ({}:{})", path, idx + 1),
                    format!(
                        "SSH key at line {} has a command restriction. This could indicate an attacker has restricted what commands this key can execute, potentially hiding their presence.",
                        idx + 1
                    ),
                    Severity::High,
                    "Persistence",
                    70,
                )
                .with_artifacts(vec![path.to_string(), format!("Line {}", idx + 1)])
                .with_mitre("T1098.004 - Account Manipulation: SSH Authorized Keys")
                .with_recommendations(vec![
                    "Inspect the command restriction to understand its purpose".to_string(),
                    "Verify this key belongs to an authorized user".to_string(),
                    "Remove the key if unauthorized".to_string(),
                ]);

                findings.push(finding);
            }

            // Check for root SSH keys added to non-root users
            if user != "root" && line.contains("ssh-rsa") {
                let finding = ScanResult::new(
                    format!("SSH Key in Non-root User Account: {}", user),
                    format!(
                        "SSH public key found in {} authorized_keys. Attackers often add their own keys to user accounts for persistence.",
                        user
                    ),
                    Severity::Medium,
                    "Persistence",
                    60,
                )
                .with_artifacts(vec![path.to_string()])
                .with_mitre("T1098.004 - Account Manipulation: SSH Authorized Keys")
                .with_recommendations(vec![
                    "Verify the key belongs to the user".to_string(),
                    "Check when the key was added using file timestamps".to_string(),
                    "Remove suspicious keys".to_string(),
                ]);

                findings.push(finding);
                break;
            }
        }

        findings
    }

    fn check_ld_preload_persistence(&self) -> Option<ScanResult> {
        match fs::read_to_string("/etc/ld.so.preload") {
            Ok(content) => {
                if !content.trim().is_empty() {
                    return Some(
                        ScanResult::new(
                            "LD_PRELOAD Persistence Detected",
                            format!(
                                "File /etc/ld.so.preload is not empty. LD_PRELOAD allows loading malicious shared libraries before standard ones, enabling rootkit functionality. Content: {}",
                                content.trim()
                            ),
                            Severity::Critical,
                            "Persistence",
                            95,
                        )
                        .with_artifacts(vec![
                            "/etc/ld.so.preload".to_string(),
                            content.trim().to_string(),
                        ])
                        .with_mitre("T1574.006 - Hijack Execution Flow: LD_PRELOAD")
                        .with_recommendations(vec![
                            "Immediately investigate the preloaded library".to_string(),
                            "Verify the library file exists and check its contents".to_string(),
                            "Clear /etc/ld.so.preload if unauthorized".to_string(),
                            "Perform system-wide malware scan".to_string(),
                        ]),
                    );
                }
                None
            }
            Err(_) => None,
        }
    }

    fn check_rc_local(&self) -> Vec<ScanResult> {
        let mut findings = Vec::new();

        let rc_paths = vec!["/etc/rc.local", "/etc/rc.d/rc.local"];

        for path in rc_paths {
            if let Ok(content) = fs::read_to_string(path) {
                if content.contains("curl") && content.contains("bash") {
                    let finding = ScanResult::new(
                        format!("Malicious Command in {}", path),
                        format!(
                            "File {} contains curl piped to bash. rc.local is executed at startup, making it ideal for persistence. This is a critical malware indicator.",
                            path
                        ),
                        Severity::Critical,
                        "Persistence",
                        90,
                    )
                    .with_artifacts(vec![path.to_string()])
                    .with_mitre("T1037.004 - Boot or Logon Initialization Scripts: RC Scripts")
                    .with_recommendations(vec![
                        "Remove the malicious command immediately".to_string(),
                        "Investigate the source of the malware".to_string(),
                        "Check system logs for execution history".to_string(),
                        "Perform full system scan".to_string(),
                    ]);

                    findings.push(finding);
                }

                // Check for other suspicious patterns
                for (line_num, line) in content.lines().enumerate() {
                    if line.trim().is_empty() || line.trim().starts_with('#') {
                        continue;
                    }

                    if line.contains("nc ") || line.contains("ncat ") || line.contains("netcat ") {
                        let finding = ScanResult::new(
                            format!("Network Tool in {}", path),
                            format!(
                                "Line {} contains network tool (netcat, nc, ncat) which may indicate reverse shell setup.",
                                line_num + 1
                            ),
                            Severity::High,
                            "Persistence",
                            75,
                        )
                        .with_artifacts(vec![
                            path.to_string(),
                            format!("Line {}: {}", line_num + 1, line.trim()),
                        ])
                        .with_mitre("T1037.004 - Boot or Logon Initialization Scripts: RC Scripts")
                        .with_recommendations(vec![
                            "Review the command and verify legitimacy".to_string(),
                            "Remove if unauthorized".to_string(),
                        ]);

                        findings.push(finding);
                    }
                }
            }
        }

        findings
    }

    fn check_profiled_injection(&self) -> Vec<ScanResult> {
        let mut findings = Vec::new();

        if let Ok(entries) = fs::read_dir("/etc/profile.d") {
            for entry in entries.flatten() {
                if let Ok(path) = entry.path().into_os_string().into_string() {
                    if path.ends_with(".sh") {
                        if let Ok(content) = fs::read_to_string(&path) {
                            // Check for suspicious patterns
                            if content.contains("curl") && content.contains("bash") {
                                let finding = ScanResult::new(
                                    format!("Curl-Bash in profile.d Script"),
                                    "Profile.d script contains curl piped to bash. These scripts run on login, ideal for persistence.".to_string(),
                                    Severity::Critical,
                                    "Persistence",
                                    85,
                                )
                                .with_artifacts(vec![path.clone()])
                                .with_mitre("T1156 - Modify Shell Command-Line Interface Configuration Files")
                                .with_recommendations(vec![
                                    "Remove the script immediately".to_string(),
                                    "Investigate the source".to_string(),
                                ]);

                                findings.push(finding);
                            }

                            // Check for exfiltration patterns
                            if content.contains("ncat") && content.contains("/dev/tcp") {
                                let finding = ScanResult::new(
                                    format!("Data Exfiltration Pattern in profile.d"),
                                    "Profile.d script contains network exfiltration pattern.".to_string(),
                                    Severity::High,
                                    "Persistence",
                                    80,
                                )
                                .with_artifacts(vec![path.clone()])
                                .with_mitre("T1156 - Modify Shell Command-Line Interface Configuration Files")
                                .with_recommendations(vec![
                                    "Investigate script purpose immediately".to_string(),
                                    "Remove if unauthorized".to_string(),
                                ]);

                                findings.push(finding);
                            }
                        }
                    }
                }
            }
        }

        findings
    }

    fn check_at_jobs(&self) -> Vec<ScanResult> {
        let mut findings = Vec::new();

        if let Ok(entries) = fs::read_dir("/var/spool/at") {
            for entry in entries.flatten() {
                if let Ok(path) = entry.path().into_os_string().into_string() {
                    if let Ok(content) = fs::read_to_string(&path) {
                        let job_id = Path::new(&path)
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("unknown");

                        // Check for suspicious commands in at jobs
                        if content.contains("curl") && content.contains("bash") {
                            let finding = ScanResult::new(
                                format!("Malicious At Job: {}", job_id),
                                "At job contains curl piped to bash, a malware execution pattern.".to_string(),
                                Severity::Critical,
                                "Persistence",
                                85,
                            )
                            .with_artifacts(vec![path.clone()])
                            .with_mitre("T1053.001 - Scheduled Task/Job: At")
                            .with_recommendations(vec![
                                format!("Remove at job: atrm {}", job_id),
                                "Investigate the job's purpose".to_string(),
                            ]);

                            findings.push(finding);
                        }
                    }
                }
            }
        }

        findings
    }

    fn check_pam_backdoor(&self) -> Vec<ScanResult> {
        let mut findings = Vec::new();

        if let Ok(entries) = fs::read_dir("/etc/pam.d") {
            for entry in entries.flatten() {
                if let Ok(path) = entry.path().into_os_string().into_string() {
                    if let Ok(content) = fs::read_to_string(&path) {
                        let filename = Path::new(&path)
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("unknown");

                        // Check for pam_permit (auth bypass)
                        if content.contains("pam_permit") {
                            let finding = ScanResult::new(
                                format!("PAM Permit Module in {}", filename),
                                format!(
                                    "PAM configuration {} uses pam_permit which allows authentication bypass.",
                                    filename
                                ),
                                Severity::Critical,
                                "Persistence",
                                90,
                            )
                            .with_artifacts(vec![path.clone()])
                            .with_mitre("T1556 - Modify Authentication Process")
                            .with_recommendations(vec![
                                "Review PAM configuration immediately".to_string(),
                                "Remove pam_permit if unauthorized".to_string(),
                            ]);

                            findings.push(finding);
                        }

                        // Check for pam_exec with suspicious commands
                        for line in content.lines() {
                            if line.contains("pam_exec.so") {
                                let finding = ScanResult::new(
                                    format!("PAM Exec Module in {}", filename),
                                    format!(
                                        "PAM configuration {} uses pam_exec.so which can execute arbitrary commands during authentication.",
                                        filename
                                    ),
                                    Severity::High,
                                    "Persistence",
                                    75,
                                )
                                .with_artifacts(vec![path.clone(), line.to_string()])
                                .with_mitre("T1556 - Modify Authentication Process")
                                .with_recommendations(vec![
                                    "Verify the executed script is legitimate".to_string(),
                                    "Check what command is being executed".to_string(),
                                ]);

                                findings.push(finding);
                                break;
                            }
                        }
                    }
                }
            }
        }

        findings
    }

    fn check_sudoers_privesc(&self) -> Vec<ScanResult> {
        let mut findings = Vec::new();

        // Check /etc/sudoers
        if let Ok(content) = fs::read_to_string("/etc/sudoers") {
            findings.extend(self.analyze_sudoers(&content, "/etc/sudoers"));
        }

        // Check /etc/sudoers.d/*
        if let Ok(entries) = fs::read_dir("/etc/sudoers.d") {
            for entry in entries.flatten() {
                if let Ok(path) = entry.path().into_os_string().into_string() {
                    if let Ok(content) = fs::read_to_string(&path) {
                        findings.extend(self.analyze_sudoers(&content, &path));
                    }
                }
            }
        }

        findings
    }

    fn analyze_sudoers(&self, content: &str, path: &str) -> Vec<ScanResult> {
        let mut findings = Vec::new();

        for line in content.lines() {
            if line.trim().is_empty() || line.trim().starts_with('#') {
                continue;
            }

            // Check for NOPASSWD entries for non-standard users
            if line.contains("NOPASSWD") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let user = parts[0];

                    if user != "root" && user != "%sudo" && user != "%wheel" {
                        let severity = if line.contains("ALL=(ALL)") {
                            Severity::Critical
                        } else {
                            Severity::High
                        };

                        let threat_score = if line.contains("ALL=(ALL)") { 95 } else { 80 };

                        let finding = ScanResult::new(
                            format!("Sudoers NOPASSWD for {}", user),
                            format!(
                                "User {} can execute sudo commands without a password. This is a critical privilege escalation vector if the user account is compromised.",
                                user
                            ),
                            severity,
                            "Persistence",
                            threat_score,
                        )
                        .with_artifacts(vec![path.to_string(), line.to_string()])
                        .with_mitre("T1548.003 - Abuse Elevation Control Mechanism: Sudo and Sudo Caching")
                        .with_recommendations(vec![
                            "Remove NOPASSWD from sudoers entry".to_string(),
                            "Use sudo -l to check user privileges".to_string(),
                            "Require password for sudo commands".to_string(),
                        ]);

                        findings.push(finding);
                    }
                }
            }

            // Check for ALL=(ALL) NOPASSWD:ALL
            if line.contains("ALL=(ALL)") && line.contains("NOPASSWD:ALL") {
                let user = line.split_whitespace().next().unwrap_or("unknown");

                let finding = ScanResult::new(
                    format!("Full Sudo Access for {}", user),
                    format!(
                        "User {} has full sudo access without password. This is an immediate critical privilege escalation vulnerability.",
                        user
                    ),
                    Severity::Critical,
                    "Persistence",
                    95,
                )
                .with_artifacts(vec![path.to_string(), line.to_string()])
                .with_mitre("T1548.003 - Abuse Elevation Control Mechanism: Sudo and Sudo Caching")
                .with_recommendations(vec![
                    "Remove this sudoers entry immediately".to_string(),
                    "Verify no unauthorized users were added".to_string(),
                    "Check sudo logs for suspicious activity".to_string(),
                ]);

                findings.push(finding);
            }
        }

        findings
    }

    fn check_passwd_backdoor(&self) -> Vec<ScanResult> {
        let mut findings = Vec::new();

        if let Ok(content) = fs::read_to_string("/etc/passwd") {
            for line in content.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 3 {
                    let username = parts[0];
                    let uid = parts[2];
                    let shell = parts[6];

                    // Check for UID 0 accounts other than root
                    if uid == "0" && username != "root" {
                        let finding = ScanResult::new(
                            format!("Non-root Account with UID 0: {}", username),
                            format!(
                                "Account {} has UID 0 (root equivalent). This is a critical backdoor indicator.",
                                username
                            ),
                            Severity::Critical,
                            "Persistence",
                            95,
                        )
                        .with_artifacts(vec!["/etc/passwd".to_string(), line.to_string()])
                        .with_mitre("T1136 - Create Account")
                        .with_recommendations(vec![
                            format!("Remove or modify account {}", username),
                            "Investigate account creation timestamp".to_string(),
                            "Check for related activity in auth logs".to_string(),
                        ]);

                        findings.push(finding);
                    }

                    // Check for accounts with empty passwords (in shadow, but indicator here)
                    if parts[1].is_empty() || parts[1] == "!" {
                        // This is a high-risk config
                        let finding = ScanResult::new(
                            format!("Account with Empty Password Field: {}", username),
                            format!(
                                "Account {} might have an empty password or be disabled. Verify in /etc/shadow.",
                                username
                            ),
                            Severity::Medium,
                            "Persistence",
                            65,
                        )
                        .with_artifacts(vec!["/etc/passwd".to_string()])
                        .with_mitre("T1136 - Create Account")
                        .with_recommendations(vec![
                            "Check /etc/shadow for actual password status".to_string(),
                            "Verify account legitimacy".to_string(),
                        ]);

                        findings.push(finding);
                        break;
                    }
                }
            }
        }

        findings
    }

    fn check_motd_backdoor(&self) -> Vec<ScanResult> {
        let mut findings = Vec::new();

        if let Ok(entries) = fs::read_dir("/etc/update-motd.d") {
            for entry in entries.flatten() {
                if let Ok(path) = entry.path().into_os_string().into_string() {
                    if let Ok(content) = fs::read_to_string(&path) {
                        let filename = Path::new(&path)
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("unknown");

                        // Check for curl|bash pattern
                        if content.contains("curl") && content.contains("bash") {
                            let finding = ScanResult::new(
                                format!("Malicious MOTD Script: {}", filename),
                                "MOTD script contains curl piped to bash. MOTD scripts run for every login.".to_string(),
                                Severity::Critical,
                                "Persistence",
                                85,
                            )
                            .with_artifacts(vec![path.clone()])
                            .with_mitre("T1037.001 - Boot or Logon Initialization Scripts: Logon Script (Linux)")
                            .with_recommendations(vec![
                                "Remove the script immediately".to_string(),
                                "Verify MOTD functionality".to_string(),
                            ]);

                            findings.push(finding);
                        }
                    }
                }
            }
        }

        findings
    }

    fn check_git_hooks(&self) -> Vec<ScanResult> {
        let mut findings = Vec::new();

        let common_repo_paths = vec![
            "/root/.git",
            "/var/www/.git",
            "/opt/.git",
            "/srv/.git",
            "/home",
        ];

        for base_path in common_repo_paths {
            if base_path == "/home" {
                if let Ok(entries) = fs::read_dir("/home") {
                    for entry in entries.flatten() {
                        if let Ok(meta) = entry.metadata() {
                            if meta.is_dir() {
                                let git_dir = entry.path().join(".git");
                                findings.extend(self.check_git_hooks_in_dir(git_dir));
                            }
                        }
                    }
                }
            } else {
                let hooks_path = Path::new(base_path).join("hooks");
                findings.extend(self.check_git_hooks_in_dir(hooks_path));
            }
        }

        findings
    }

    fn check_git_hooks_in_dir(&self, hooks_path: std::path::PathBuf) -> Vec<ScanResult> {
        let mut findings = Vec::new();

        if let Ok(entries) = fs::read_dir(&hooks_path) {
            for entry in entries.flatten() {
                if let Ok(path) = entry.path().into_os_string().into_string() {
                    if let Ok(content) = fs::read_to_string(&path) {
                        if content.contains("curl") && content.contains("bash") {
                            let finding = ScanResult::new(
                                format!("Malicious Git Hook: {}", path),
                                "Git hook contains curl piped to bash. Git hooks execute on repository operations.".to_string(),
                                Severity::High,
                                "Persistence",
                                75,
                            )
                            .with_artifacts(vec![path.clone()])
                            .with_mitre("T1543 - Create or Modify System Process")
                            .with_recommendations(vec![
                                "Inspect the hook".to_string(),
                                "Remove if malicious".to_string(),
                            ]);

                            findings.push(finding);
                        }
                    }
                }
            }
        }

        findings
    }

    fn check_xdg_autostart(&self) -> Vec<ScanResult> {
        let mut findings = Vec::new();

        // Check /etc/xdg/autostart
        if let Ok(entries) = fs::read_dir("/etc/xdg/autostart") {
            for entry in entries.flatten() {
                if let Ok(path) = entry.path().into_os_string().into_string() {
                    if path.ends_with(".desktop") {
                        if let Ok(content) = fs::read_to_string(&path) {
                            findings.extend(self.analyze_desktop_file(&content, &path));
                        }
                    }
                }
            }
        }

        // Check user autostart directories
        if let Ok(entries) = fs::read_dir("/home") {
            for entry in entries.flatten() {
                if let Ok(meta) = entry.metadata() {
                    if meta.is_dir() {
                        let autostart_dir = entry.path().join(".config/autostart");
                        if let Ok(desktop_entries) = fs::read_dir(&autostart_dir) {
                            for desktop_entry in desktop_entries.flatten() {
                                if let Ok(path) = desktop_entry.path().into_os_string().into_string() {
                                    if path.ends_with(".desktop") {
                                        if let Ok(content) = fs::read_to_string(&path) {
                                            findings.extend(self.analyze_desktop_file(&content, &path));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        findings
    }

    fn analyze_desktop_file(&self, content: &str, path: &str) -> Vec<ScanResult> {
        let mut findings = Vec::new();

        if let Some(exec_line) = content.lines().find(|l| l.starts_with("Exec=")) {
            let command = exec_line.split('=').nth(1).unwrap_or("");

            if command.contains("curl") && command.contains("bash") {
                let finding = ScanResult::new(
                    format!("Malicious XDG Autostart Entry"),
                    format!(
                        "Desktop file {} contains curl piped to bash. XDG autostart entries run on user login.",
                        path
                    ),
                    Severity::High,
                    "Persistence",
                    75,
                )
                .with_artifacts(vec![path.to_string(), command.to_string()])
                .with_mitre("T1547.009 - Boot or Logon Autostart Execution: Shortcut Modification")
                .with_recommendations(vec![
                    "Remove the desktop file".to_string(),
                    "Verify autostart directory contents".to_string(),
                ]);

                findings.push(finding);
            }
        }

        findings
    }
}
