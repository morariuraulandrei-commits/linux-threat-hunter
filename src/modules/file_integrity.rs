use super::{ScanResult, Severity};
use crate::config::Config;
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use walkdir::WalkDir;

pub struct FileIntegrityScanner {
    cfg: Config,
}

impl FileIntegrityScanner {
    pub fn new(cfg: Config) -> Self {
        Self { cfg }
    }

    pub async fn scan(&mut self) -> Result<Vec<ScanResult>> {
        let mut findings: Vec<ScanResult> = Vec::new();

        // Check critical system files
        findings.extend(self.check_critical_files());

        // Check for SUID/SGID files in unexpected locations
        if self.cfg.file_integrity.check_suid {
            findings.extend(self.check_suid_files());
        }

        // Check world-writable directories
        if self.cfg.file_integrity.check_world_writable {
            findings.extend(self.check_world_writable());
        }

        // Check for suspicious files in /tmp, /dev/shm etc.
        findings.extend(self.check_temp_executables());

        // Check /etc/ld.so.preload (rootkit indicator)
        findings.extend(self.check_ld_so_preload());

        // Check /etc/crontab and cron directories
        findings.extend(self.check_cron_files());

        // Check for unusual kernel modules
        findings.extend(self.check_kernel_modules());

        // Check SSH authorized_keys for all users
        findings.extend(self.check_ssh_keys());

        // Check for recently modified binaries in system dirs
        findings.extend(self.check_recently_modified_binaries());

        // Check /proc/sys kernel params for hardening
        findings.extend(self.check_kernel_params());

        // Check for world-readable /etc/shadow
        findings.extend(self.check_shadow_permissions());

        Ok(findings)
    }

    fn sha256_file(&self, path: &str) -> Option<String> {
        let mut file = File::open(path).ok()?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 65536];
        loop {
            let n = file.read(&mut buffer).ok()?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }
        Some(hex::encode(hasher.finalize()))
    }

    fn check_critical_files(&self) -> Vec<ScanResult> {
        let mut findings = Vec::new();

        // Known baseline hashes for common distributions (partial list)
        // In a real deployment these would be updated per-distro
        let suspicious_patterns = [
            ("/etc/ld.so.preload", true),       // Should usually be empty
            ("/etc/passwd", false),
            ("/etc/shadow", false),
            ("/etc/sudoers", false),
        ];

        for (path, is_critical) in &suspicious_patterns {
            if let Ok(meta) = fs::metadata(path) {
                let mode = meta.mode();

                // Check /etc/shadow permissions (should be 640 or 000)
                if *path == "/etc/shadow" {
                    let world_readable = (mode & 0o004) != 0;
                    if world_readable {
                        let mut r = ScanResult::new(
                            "/etc/shadow is world-readable — credentials exposed",
                            "The /etc/shadow file containing hashed passwords is readable \
                             by all users. This allows any local user to attempt offline \
                             password cracking.",
                            Severity::Critical,
                            "FileIntegrity",
                            98,
                        );
                        r = r
                            .with_artifacts(vec![
                                format!("Path: {}", path),
                                format!("Permissions: {:o}", mode & 0o777),
                            ])
                            .with_mitre("T1003.008 - OS Credential Dumping: /etc/passwd and /etc/shadow")
                            .with_recommendations(vec![
                                "Fix immediately: chmod 640 /etc/shadow".into(),
                                "Rotate all user passwords".into(),
                                "Audit who may have accessed the file".into(),
                            ]);
                        findings.push(r);
                    }
                }

                // Check /etc/ld.so.preload
                if *path == "/etc/ld.so.preload" && *is_critical {
                    if let Ok(content) = fs::read_to_string(path) {
                        let content = content.trim();
                        if !content.is_empty() {
                            let mut r = ScanResult::new(
                                "/etc/ld.so.preload contains entries — possible rootkit",
                                format!(
                                    "/etc/ld.so.preload is non-empty with content: '{}'. \
                                     This file forces shared libraries to load into every process \
                                     and is a classic rootkit/userland persistence mechanism.",
                                    content
                                ),
                                Severity::Critical,
                                "FileIntegrity",
                                99,
                            );
                            r = r
                                .with_artifacts(vec![
                                    "Path: /etc/ld.so.preload".into(),
                                    format!("Content: {}", content),
                                ])
                                .with_mitre("T1574.006 - Hijack Execution Flow: LD_PRELOAD")
                                .with_recommendations(vec![
                                    "Remove or truncate /etc/ld.so.preload".into(),
                                    "Analyze the listed library immediately".into(),
                                    "Check for kernel-level rootkits: chkrootkit, rkhunter".into(),
                                ]);
                            findings.push(r);
                        }
                    }
                }

                // Check sudoers for NOPASSWD
                if *path == "/etc/sudoers" {
                    if let Ok(content) = fs::read_to_string(path) {
                        for (i, line) in content.lines().enumerate() {
                            let trimmed = line.trim();
                            if trimmed.contains("NOPASSWD") && !trimmed.starts_with('#') {
                                let mut r = ScanResult::new(
                                    format!("NOPASSWD sudo rule detected at line {}", i + 1),
                                    format!(
                                        "Found NOPASSWD in /etc/sudoers: '{}'. \
                                         This allows privilege escalation without a password.",
                                        trimmed
                                    ),
                                    Severity::High,
                                    "FileIntegrity",
                                    80,
                                );
                                r = r
                                    .with_artifacts(vec![
                                        format!("File: /etc/sudoers line {}", i + 1),
                                        format!("Rule: {}", trimmed),
                                    ])
                                    .with_mitre("T1548.003 - Abuse Elevation Control Mechanism: Sudo and Sudo Caching")
                                    .with_recommendations(vec![
                                        "Review and remove unnecessary NOPASSWD rules".into(),
                                        "Enforce least privilege for sudo access".into(),
                                    ]);
                                findings.push(r);
                            }
                        }
                    }
                }
            }
        }
        findings
    }

    fn check_suid_files(&self) -> Vec<ScanResult> {
        let mut findings = Vec::new();

        // Known legitimate SUID binaries (whitelist)
        let known_suid = [
            "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd", "/usr/bin/newgrp",
            "/usr/bin/chfn", "/usr/bin/chsh", "/usr/bin/gpasswd", "/usr/bin/mount",
            "/usr/bin/umount", "/usr/bin/pkexec", "/bin/ping", "/bin/su",
            "/bin/mount", "/bin/umount", "/sbin/unix_chkpwd",
            "/usr/bin/at", "/usr/bin/crontab",
        ];

        let scan_dirs = ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin", "/tmp", "/var/tmp"];

        for dir in &scan_dirs {
            for entry in WalkDir::new(dir)
                .max_depth(3)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if entry.file_type().is_file() {
                    if let Ok(meta) = entry.metadata() {
                        let mode = meta.mode();
                        let is_suid = (mode & 0o4000) != 0;
                        let is_sgid = (mode & 0o2000) != 0;

                        if is_suid || is_sgid {
                            let path = entry.path().to_string_lossy().to_string();

                            // Skip known legitimate SUID binaries
                            if known_suid.iter().any(|k| path == *k) {
                                continue;
                            }

                            let suid_type = if is_suid { "SUID" } else { "SGID" };
                            let severity = if dir.starts_with("/tmp") || dir.starts_with("/var/tmp") {
                                Severity::Critical
                            } else {
                                Severity::High
                            };
                            let score = if severity == Severity::Critical { 95 } else { 75 };

                            let hash = self.sha256_file(&path).unwrap_or_else(|| "N/A".into());

                            let mut r = ScanResult::new(
                                format!("Unexpected {} binary: {}", suid_type, path),
                                format!(
                                    "Found a {} binary at '{}' that is not in the known-good whitelist. \
                                     Attackers plant SUID binaries to enable privilege escalation.",
                                    suid_type, path
                                ),
                                severity,
                                "FileIntegrity",
                                score,
                            );
                            r = r
                                .with_artifacts(vec![
                                    format!("Path: {}", path),
                                    format!("Mode: {:o}", mode & 0o7777),
                                    format!("SHA256: {}", hash),
                                    format!("Size: {} bytes", meta.len()),
                                ])
                                .with_mitre("T1548.001 - Abuse Elevation Control Mechanism: Setuid and Setgid")
                                .with_recommendations(vec![
                                    format!("Inspect: file {} && strings {}", path, path),
                                    format!("Remove SUID if unexpected: chmod u-s {}", path),
                                    "Check creation time with: stat ".to_string() + &path,
                                ]);
                            findings.push(r);
                        }
                    }
                }
            }
        }
        findings
    }

    fn check_world_writable(&self) -> Vec<ScanResult> {
        let mut findings = Vec::new();
        let expected_writable = ["/tmp", "/var/tmp", "/dev/shm"];

        let sensitive_dirs = ["/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/boot"];

        for dir in &sensitive_dirs {
            for entry in WalkDir::new(dir)
                .max_depth(2)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if let Ok(meta) = entry.metadata() {
                    let mode = meta.mode();
                    let world_writable = (mode & 0o002) != 0;

                    if world_writable {
                        let path = entry.path().to_string_lossy().to_string();
                        if expected_writable.iter().any(|e| path.starts_with(e)) {
                            continue;
                        }

                        let mut r = ScanResult::new(
                            format!("World-writable file/dir in sensitive location: {}", path),
                            format!(
                                "'{}' is world-writable (mode {:o}). \
                                 World-writable files in system directories can allow any local \
                                 user to tamper with system configurations or plant malicious code.",
                                path,
                                mode & 0o7777
                            ),
                            Severity::High,
                            "FileIntegrity",
                            77,
                        );
                        r = r
                            .with_artifacts(vec![
                                format!("Path: {}", path),
                                format!("Mode: {:o}", mode & 0o7777),
                            ])
                            .with_mitre("T1222 - File and Directory Permissions Modification")
                            .with_recommendations(vec![
                                format!("Fix permissions: chmod o-w {}", path),
                                "Audit recent modifications to this file".into(),
                            ]);
                        findings.push(r);
                    }
                }
            }
        }
        findings
    }

    fn check_temp_executables(&self) -> Vec<ScanResult> {
        let mut findings = Vec::new();
        let temp_dirs = ["/tmp", "/dev/shm", "/var/tmp", "/run/shm"];

        for dir in &temp_dirs {
            if !std::path::Path::new(dir).exists() {
                continue;
            }
            for entry in WalkDir::new(dir)
                .max_depth(3)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if entry.file_type().is_file() {
                    if let Ok(meta) = entry.metadata() {
                        let mode = meta.mode();
                        let is_executable = (mode & 0o111) != 0;

                        if is_executable {
                            let path = entry.path().to_string_lossy().to_string();

                            // Read magic bytes to check if it's ELF
                            let is_elf = File::open(&path)
                                .ok()
                                .and_then(|mut f| {
                                    let mut buf = [0u8; 4];
                                    f.read_exact(&mut buf).ok().map(|_| buf)
                                })
                                .map(|b| &b == b"\x7fELF")
                                .unwrap_or(false);

                            let severity = if is_elf {
                                Severity::Critical
                            } else {
                                Severity::High
                            };

                            let file_type = if is_elf { "ELF binary" } else { "executable" };
                            let hash = self.sha256_file(&path).unwrap_or_else(|| "N/A".into());

                            let mut r = ScanResult::new(
                                format!("Executable {} in temporary directory: {}", file_type, path),
                                format!(
                                    "Found executable file '{}' in a temporary/world-writable directory. \
                                     Malware commonly drops and executes binaries from /tmp, /dev/shm, \
                                     or similar locations to avoid leaving traces in system directories.",
                                    path
                                ),
                                severity,
                                "FileIntegrity",
                                88,
                            );
                            r = r
                                .with_artifacts(vec![
                                    format!("Path: {}", path),
                                    format!("Mode: {:o}", mode & 0o777),
                                    format!("Size: {} bytes", meta.len()),
                                    format!("SHA256: {}", hash),
                                    format!("Type: {}", file_type),
                                ])
                                .with_mitre("T1036.005 - Masquerading: Match Legitimate Name or Location")
                                .with_recommendations(vec![
                                    format!("Analyze: file {} && strings {}", path, path),
                                    format!("Check which process owns it: lsof {}", path),
                                    format!("Remove if malicious: rm -f {}", path),
                                ]);
                            findings.push(r);
                        }
                    }
                }
            }
        }
        findings
    }

    fn check_ld_so_preload(&self) -> Vec<ScanResult> {
        let mut findings = Vec::new();
        let path = "/etc/ld.so.preload";

        if let Ok(content) = fs::read_to_string(path) {
            let content = content.trim();
            if !content.is_empty() {
                for lib_path in content.lines() {
                    let lib_path = lib_path.trim();
                    if lib_path.is_empty() || lib_path.starts_with('#') {
                        continue;
                    }
                    let exists = std::path::Path::new(lib_path).exists();
                    let mut r = ScanResult::new(
                        format!("ld.so.preload entry: {} ({})", lib_path, if exists { "EXISTS" } else { "MISSING" }),
                        format!(
                            "/etc/ld.so.preload references '{}'. This library will be \
                             injected into every process on the system. This is a strong \
                             indicator of a userland rootkit or library injection attack.",
                            lib_path
                        ),
                        Severity::Critical,
                        "FileIntegrity",
                        99,
                    );
                    let hash = if exists {
                        self.sha256_file(lib_path).unwrap_or_else(|| "N/A".into())
                    } else {
                        "FILE NOT FOUND".into()
                    };
                    r = r
                        .with_artifacts(vec![
                            format!("Library: {}", lib_path),
                            format!("SHA256: {}", hash),
                            format!("Exists: {}", exists),
                        ])
                        .with_mitre("T1574.006 - Hijack Execution Flow: LD_PRELOAD")
                        .with_recommendations(vec![
                            "Truncate file: > /etc/ld.so.preload".into(),
                            format!("Analyze library: strings {}", lib_path),
                            "Reboot to clear injected libraries from memory".into(),
                        ]);
                    findings.push(r);
                }
            }
        }
        findings
    }

    fn check_cron_files(&self) -> Vec<ScanResult> {
        let mut findings = Vec::new();
        let cron_paths = [
            "/etc/crontab",
            "/var/spool/cron",
            "/etc/cron.d",
            "/etc/cron.daily",
            "/etc/cron.weekly",
            "/etc/cron.monthly",
            "/etc/cron.hourly",
        ];

        for path in &cron_paths {
            let p = std::path::Path::new(path);
            if !p.exists() {
                continue;
            }
            let files: Vec<std::path::PathBuf> = if p.is_file() {
                vec![p.to_path_buf()]
            } else {
                WalkDir::new(p)
                    .max_depth(2)
                    .into_iter()
                    .filter_map(|e| e.ok())
                    .filter(|e| e.file_type().is_file())
                    .map(|e| e.path().to_path_buf())
                    .collect()
            };

            for file in &files {
                if let Ok(content) = fs::read_to_string(file) {
                    let suspicious_patterns = [
                        ("curl", "Network download in cron"),
                        ("wget", "Network download in cron"),
                        ("bash -i", "Interactive shell in cron (reverse shell indicator)"),
                        ("nc ", "Netcat in cron"),
                        ("ncat", "Ncat in cron"),
                        ("python -c", "Python one-liner in cron"),
                        ("python3 -c", "Python3 one-liner in cron"),
                        ("base64 -d", "Base64 decode in cron (obfuscation)"),
                        ("/tmp/", "Execution from /tmp in cron"),
                        ("/dev/shm/", "Execution from /dev/shm in cron"),
                        ("chmod +x", "Making file executable via cron"),
                    ];

                    for (i, line) in content.lines().enumerate() {
                        let line_lower = line.to_lowercase();
                        if line.trim().starts_with('#') {
                            continue;
                        }
                        for (pattern, desc) in &suspicious_patterns {
                            if line_lower.contains(pattern) {
                                let mut r = ScanResult::new(
                                    format!("{} in {}", desc, file.display()),
                                    format!(
                                        "Suspicious cron entry at line {}: '{}'. \
                                         {} This could be a persistence mechanism planted by an attacker.",
                                        i + 1, line.trim(), desc
                                    ),
                                    Severity::High,
                                    "FileIntegrity",
                                    82,
                                );
                                r = r
                                    .with_artifacts(vec![
                                        format!("File: {}", file.display()),
                                        format!("Line {}: {}", i + 1, line.trim()),
                                    ])
                                    .with_mitre("T1053.003 - Scheduled Task/Job: Cron")
                                    .with_recommendations(vec![
                                        format!("Review cron file: {}", file.display()),
                                        "Remove suspicious cron entry if unauthorized".into(),
                                        "Check if the executed file/URL is malicious".into(),
                                    ]);
                                findings.push(r);
                                break; // one finding per line
                            }
                        }
                    }
                }
            }
        }
        findings
    }

    fn check_kernel_modules(&self) -> Vec<ScanResult> {
        let mut findings = Vec::new();

        if let Ok(content) = fs::read_to_string("/proc/modules") {
            for line in content.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if let Some(name) = parts.first() {
                    // Check for modules with suspicious names or characteristics
                    let suspicious_module_names = [
                        "hide", "rootkit", "hook", "stealth", "cloak", "diamorphine",
                        "reptile", "adore", "suterusu", "azazel", "jynx",
                    ];

                    for suspicious in &suspicious_module_names {
                        if name.to_lowercase().contains(suspicious) {
                            let mut r = ScanResult::new(
                                format!("Suspicious kernel module loaded: {}", name),
                                format!(
                                    "Kernel module '{}' matches a known rootkit pattern. \
                                     Malicious kernel modules can hide files, processes, \
                                     and network connections from userland tools.",
                                    name
                                ),
                                Severity::Critical,
                                "FileIntegrity",
                                99,
                            );
                            r = r
                                .with_artifacts(vec![
                                    format!("Module: {}", name),
                                    format!("Module info: {}", line),
                                ])
                                .with_mitre("T1014 - Rootkit")
                                .with_recommendations(vec![
                                    format!("Remove module: rmmod {}", name),
                                    "Reboot from trusted media".into(),
                                    "Forensic analysis required — system may be compromised".into(),
                                ]);
                            findings.push(r);
                        }
                    }
                }
            }
        }
        findings
    }

    fn check_ssh_keys(&self) -> Vec<ScanResult> {
        let mut findings = Vec::new();

        // Get all users from /etc/passwd
        let passwd = fs::read_to_string("/etc/passwd").unwrap_or_default();
        for line in passwd.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() < 6 {
                continue;
            }
            let username = parts[0];
            let home = parts[5];
            let uid: u32 = parts[2].parse().unwrap_or(999);

            // Check system users vs real users
            if uid < 1000 && username != "root" {
                continue;
            }

            let auth_keys = format!("{}/.ssh/authorized_keys", home);
            if let Ok(content) = fs::read_to_string(&auth_keys) {
                let key_count = content.lines()
                    .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
                    .count();

                if key_count > 0 {
                    // Check for suspicious key options
                    for (i, line) in content.lines().enumerate() {
                        if line.contains("command=") || line.contains("no-pty") {
                            let mut r = ScanResult::new(
                                format!("Restricted SSH key with forced command for user {}", username),
                                format!(
                                    "Found SSH key with command restriction for user '{}' at line {}: {}. \
                                     Attackers use forced-command keys to establish persistent access \
                                     via command restrictions that bypass normal shell access.",
                                    username, i + 1, line.trim()
                                ),
                                Severity::Medium,
                                "FileIntegrity",
                                55,
                            );
                            r = r.with_artifacts(vec![
                                format!("User: {}", username),
                                format!("File: {}", auth_keys),
                                format!("Key: {}", &line[..line.len().min(60)]),
                            ])
                            .with_mitre("T1098.004 - Account Manipulation: SSH Authorized Keys");
                            findings.push(r);
                        }
                    }

                    // Flag root having authorized_keys (unless expected)
                    if username == "root" {
                        let mut r = ScanResult::new(
                            format!("Root account has {} SSH authorized key(s)", key_count),
                            "The root account has SSH authorized keys configured. \
                             If not intentional, this could be an attacker's persistence mechanism \
                             providing direct root access via SSH.",
                            Severity::Medium,
                            "FileIntegrity",
                            60,
                        );
                        r = r
                            .with_artifacts(vec![
                                format!("File: {}", auth_keys),
                                format!("Key count: {}", key_count),
                            ])
                            .with_mitre("T1098.004 - Account Manipulation: SSH Authorized Keys")
                            .with_recommendations(vec![
                                "Review and audit all root SSH keys".into(),
                                "Consider disabling root SSH login: PermitRootLogin no".into(),
                            ]);
                        findings.push(r);
                    }
                }
            }
        }
        findings
    }

    fn check_recently_modified_binaries(&self) -> Vec<ScanResult> {
        let mut findings = Vec::new();
        let system_dirs = ["/bin", "/sbin", "/usr/bin", "/usr/sbin"];

        // Check files modified in the last 24 hours
        let cutoff = std::time::SystemTime::now()
            .checked_sub(std::time::Duration::from_secs(86400))
            .unwrap_or(std::time::UNIX_EPOCH);

        for dir in &system_dirs {
            for entry in WalkDir::new(dir)
                .max_depth(1)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if entry.file_type().is_file() {
                    if let Ok(meta) = entry.metadata() {
                        if let Ok(modified) = meta.modified() {
                            if modified > cutoff {
                                let path = entry.path().to_string_lossy().to_string();
                                let hash = self.sha256_file(&path).unwrap_or_else(|| "N/A".into());

                                let modified_secs = modified
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs();

                                let mut r = ScanResult::new(
                                    format!("System binary modified recently: {}", path),
                                    format!(
                                        "System binary '{}' was modified within the last 24 hours. \
                                         Unexpected modifications to system binaries can indicate \
                                         trojanized/backdoored tools or attacker tampering.",
                                        path
                                    ),
                                    Severity::High,
                                    "FileIntegrity",
                                    83,
                                );
                                r = r
                                    .with_artifacts(vec![
                                        format!("Path: {}", path),
                                        format!("Modified: {} secs ago (epoch: {})",
                                            std::time::SystemTime::now()
                                                .duration_since(modified)
                                                .unwrap_or_default()
                                                .as_secs(),
                                            modified_secs
                                        ),
                                        format!("SHA256: {}", hash),
                                        format!("Size: {} bytes", meta.len()),
                                    ])
                                    .with_mitre("T1574 - Hijack Execution Flow")
                                    .with_recommendations(vec![
                                        format!("Verify with package manager: dpkg -V {} or rpm -Va", path),
                                        "Compare hash with known-good baseline".into(),
                                        "Check file history: git log if version-controlled".into(),
                                    ]);
                                findings.push(r);
                            }
                        }
                    }
                }
            }
        }
        findings
    }

    fn check_kernel_params(&self) -> Vec<ScanResult> {
        let mut findings = Vec::new();

        let security_params = [
            ("/proc/sys/kernel/dmesg_restrict", "1", "dmesg unrestricted (info leak)"),
            ("/proc/sys/kernel/kptr_restrict", "2", "Kernel pointers exposed"),
            ("/proc/sys/net/ipv4/ip_forward", "0", "IP forwarding enabled (NAT/pivot risk)"),
            ("/proc/sys/kernel/randomize_va_space", "2", "ASLR not fully enabled"),
            ("/proc/sys/net/ipv4/tcp_syncookies", "1", "SYN cookies disabled (SYN flood risk)"),
        ];

        for (param, expected, issue) in &security_params {
            if let Ok(val) = fs::read_to_string(param) {
                let val = val.trim();
                // For ip_forward we warn if it's 1 (enabled), others if not matching expected
                let is_issue = if param.contains("ip_forward") {
                    val == "1"
                } else if param.contains("randomize_va_space") {
                    val != "2"
                } else {
                    val != *expected
                };

                if is_issue {
                    let mut r = ScanResult::new(
                        format!("Insecure kernel parameter: {} = {}", param, val),
                        format!(
                            "Kernel parameter '{}' is set to '{}'. {}. \
                             This weakens system security and may have been changed by an attacker.",
                            param, val, issue
                        ),
                        Severity::Medium,
                        "FileIntegrity",
                        45,
                    );
                    r = r
                        .with_artifacts(vec![
                            format!("Parameter: {}", param),
                            format!("Current value: {}", val),
                            format!("Recommended: {}", expected),
                        ])
                        .with_mitre("T1562.001 - Impair Defenses: Disable or Modify Tools")
                        .with_recommendations(vec![
                            format!("Fix: sysctl -w {}={}",
                                param.trim_start_matches("/proc/sys/").replace('/', "."),
                                expected
                            ),
                        ]);
                    findings.push(r);
                }
            }
        }
        findings
    }

    fn check_shadow_permissions(&self) -> Vec<ScanResult> {
        let mut findings = Vec::new();
        if let Ok(meta) = fs::metadata("/etc/shadow") {
            let mode = meta.mode();
            if (mode & 0o777) > 0o640 {
                let mut r = ScanResult::new(
                    format!("/etc/shadow has overly permissive mode: {:o}", mode & 0o777),
                    "The shadow password file has permissions more permissive than recommended (640). \
                     This could allow unauthorized access to password hashes.",
                    Severity::Critical,
                    "FileIntegrity",
                    95,
                );
                r = r
                    .with_artifacts(vec![format!("Mode: {:o}", mode & 0o777)])
                    .with_mitre("T1003.008 - OS Credential Dumping: /etc/passwd and /etc/shadow")
                    .with_recommendations(vec!["chmod 640 /etc/shadow && chown root:shadow /etc/shadow".into()]);
                findings.push(r);
            }
        }
        findings
    }
}
