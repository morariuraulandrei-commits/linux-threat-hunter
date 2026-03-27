use super::{ScanResult, Severity};
use crate::config::Config;
use anyhow::Result;
use std::fs;
use std::path::Path;

pub struct ProcessScanner {
    cfg: Config,
}

impl ProcessScanner {
    pub fn new(cfg: Config) -> Self {
        Self { cfg }
    }

    pub async fn scan(&mut self) -> Result<Vec<ScanResult>> {
        let mut findings: Vec<ScanResult> = Vec::new();

        let pids = self.list_pids();

        for pid in &pids {
            let proc_path = format!("/proc/{}", pid);

            // Check for deleted executable (process running from deleted file)
            if self.cfg.process.check_deleted_executables {
                if let Some(f) = self.check_deleted_exe(*pid, &proc_path) {
                    findings.push(f);
                }
            }

            // Check for memfd (fileless malware)
            if self.cfg.process.check_memfd {
                if let Some(f) = self.check_memfd(*pid, &proc_path) {
                    findings.push(f);
                }
            }

            // Check suspicious process names
            if let Some(f) = self.check_suspicious_name(*pid, &proc_path) {
                findings.push(f);
            }

            // Check for hidden processes
            if self.cfg.process.check_hidden {
                if let Some(f) = self.check_hidden_process(*pid, &proc_path) {
                    findings.push(f);
                }
            }

            // Check network connections per process
            if let Some(f) = self.check_suspicious_network(*pid, &proc_path) {
                findings.push(f);
            }

            // Check for LD_PRELOAD injection
            if let Some(f) = self.check_ld_preload(*pid, &proc_path) {
                findings.push(f);
            }

            // Check for ptrace (debugging/injection)
            if let Some(f) = self.check_ptrace(*pid, &proc_path) {
                findings.push(f);
            }

            // Check for anomalous parent-child relationships
            if let Some(f) = self.check_suspicious_ppid(*pid, &proc_path) {
                findings.push(f);
            }

            // Check for processes running from /tmp or /dev/shm (common malware locations)
            if let Some(f) = self.check_suspicious_cwd(*pid, &proc_path) {
                findings.push(f);
            }
        }

        // Check for PID gaps (possible kernel-level hiding)
        if self.cfg.process.check_hidden {
            let gap_findings = self.check_pid_gaps(&pids);
            findings.extend(gap_findings);
        }

        // Check for zombie process accumulation (possible resource exhaustion attack)
        let zombie_findings = self.check_zombie_processes();
        findings.extend(zombie_findings);

        // Check for high CPU usage by unusual processes
        let cpu_findings = self.check_high_cpu_processes(&pids);
        findings.extend(cpu_findings);

        Ok(findings)
    }

    fn list_pids(&self) -> Vec<u32> {
        let mut pids = Vec::new();
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                if let Ok(name) = entry.file_name().into_string() {
                    if let Ok(pid) = name.parse::<u32>() {
                        pids.push(pid);
                    }
                }
            }
        }
        pids.sort();
        pids
    }

    fn read_proc_field(&self, pid: u32, field: &str) -> Option<String> {
        fs::read_to_string(format!("/proc/{}/{}", pid, field)).ok()
    }

    fn get_process_name(&self, pid: u32) -> Option<String> {
        self.read_proc_field(pid, "comm")
            .map(|s| s.trim().to_string())
    }

    fn get_process_exe(&self, pid: u32) -> Option<String> {
        fs::read_link(format!("/proc/{}/exe", pid))
            .ok()
            .map(|p| p.to_string_lossy().to_string())
    }

    fn check_deleted_exe(&self, pid: u32, _proc_path: &str) -> Option<ScanResult> {
        let exe = self.get_process_exe(pid)?;
        if exe.contains("(deleted)") {
            let name = self.get_process_name(pid).unwrap_or_default();
            if !self.cfg.process.whitelist_processes.iter().any(|w| name.contains(w.as_str())) {
                let mut r = ScanResult::new(
                    format!("Process running from deleted executable: {} (PID {})", name, pid),
                    "A process is executing from a file that has been deleted from disk. \
                     This is a common technique used by malware to evade detection — the binary \
                     is loaded into memory and then the on-disk copy is removed.",
                    Severity::High,
                    "Process",
                    75,
                );
                r = r
                    .with_artifacts(vec![format!("PID: {}", pid), format!("EXE: {}", exe)])
                    .with_mitre("T1055.012 - Process Injection: Process Hollowing")
                    .with_recommendations(vec![
                        format!("Investigate process {} (PID {})", name, pid),
                        "Capture memory dump for forensic analysis".into(),
                        "Check parent process and command line arguments".into(),
                    ]);
                return Some(r);
            }
        }
        None
    }

    fn check_memfd(&self, pid: u32, _proc_path: &str) -> Option<ScanResult> {
        let maps = self.read_proc_field(pid, "maps")?;
        if maps.contains("memfd:") {
            let name = self.get_process_name(pid).unwrap_or_default();
            if !self.cfg.process.whitelist_processes.iter().any(|w| name.contains(w.as_str())) {
                let mut r = ScanResult::new(
                    format!("Fileless execution detected via memfd_create: {} (PID {})", name, pid),
                    "Process has memory-mapped file descriptors created with memfd_create(). \
                     This is a hallmark of fileless malware that executes entirely in memory \
                     without touching the filesystem.",
                    Severity::Critical,
                    "Process",
                    95,
                );
                r = r
                    .with_artifacts(vec![format!("PID: {}", pid), format!("Process: {}", name)])
                    .with_mitre("T1620 - Reflective Code Loading")
                    .with_recommendations(vec![
                        "Immediately isolate the affected system".into(),
                        format!("Kill process {} (PID {}): kill -9 {}", name, pid, pid),
                        "Capture volatile memory for forensic analysis".into(),
                        "Review parent process chain".into(),
                    ]);
                return Some(r);
            }
        }
        None
    }

    fn check_suspicious_name(&self, pid: u32, _proc_path: &str) -> Option<ScanResult> {
        let name = self.get_process_name(pid)?;
        let cmdline = self.read_proc_field(pid, "cmdline")
            .unwrap_or_default()
            .replace('\0', " ");

        for suspicious in &self.cfg.process.suspicious_names {
            if name.to_lowercase().contains(suspicious.as_str())
                || cmdline.to_lowercase().contains(suspicious.as_str())
            {
                let mut r = ScanResult::new(
                    format!("Suspicious process name detected: {} (PID {})", name, pid),
                    format!(
                        "Process '{}' matches a known suspicious pattern '{}'. \
                         Command line: {}",
                        name, suspicious, cmdline.trim()
                    ),
                    Severity::High,
                    "Process",
                    80,
                );
                r = r
                    .with_artifacts(vec![
                        format!("PID: {}", pid),
                        format!("Process: {}", name),
                        format!("Cmdline: {}", cmdline.trim()),
                    ])
                    .with_mitre("T1059 - Command and Scripting Interpreter")
                    .with_recommendations(vec![
                        format!("Investigate process (PID {}): {}", pid, cmdline.trim()),
                        "Review network connections for this process".into(),
                        "Check process open files and sockets".into(),
                    ]);
                return Some(r);
            }
        }
        None
    }

    fn check_hidden_process(&self, pid: u32, _proc_path: &str) -> Option<ScanResult> {
        // Check if process exists in /proc but not in ps output (basic check)
        let status = self.read_proc_field(pid, "status")?;
        let name_line = status.lines().find(|l| l.starts_with("Name:"))?;
        let name = name_line.trim_start_matches("Name:").trim();

        // Check for processes with empty or suspicious names
        if name.is_empty() || name == "." || name.starts_with('\0') {
            let mut r = ScanResult::new(
                format!("Potentially hidden process detected (PID {})", pid),
                "A process has been detected with an empty or obfuscated name. \
                 Rootkits and kernel-level malware often manipulate process names \
                 to hide from system administrators.",
                Severity::Critical,
                "Process",
                90,
            );
            r = r
                .with_artifacts(vec![format!("PID: {}", pid), format!("Name: '{}'", name)])
                .with_mitre("T1564.001 - Hide Artifacts: Hidden Files and Directories")
                .with_recommendations(vec![
                    "Investigate with: ls -la /proc/".to_string() + &pid.to_string(),
                    "Check for rootkit signs with: chkrootkit or rkhunter".into(),
                    "Review kernel modules: lsmod | grep suspicious".into(),
                ]);
            return Some(r);
        }
        None
    }

    fn check_suspicious_network(&self, pid: u32, _proc_path: &str) -> Option<ScanResult> {
        let fd_dir = format!("/proc/{}/fd", pid);
        let mut socket_count = 0u32;

        if let Ok(entries) = fs::read_dir(&fd_dir) {
            for entry in entries.flatten() {
                if let Ok(target) = fs::read_link(entry.path()) {
                    let t = target.to_string_lossy();
                    if t.starts_with("socket:") {
                        socket_count += 1;
                    }
                }
            }
        }

        // Flag processes with unusually high socket counts
        if socket_count > 50 {
            let name = self.get_process_name(pid).unwrap_or_default();
            if !self.cfg.process.whitelist_processes.iter().any(|w| name.contains(w.as_str())) {
                let mut r = ScanResult::new(
                    format!("Process with excessive network connections: {} (PID {}, {} sockets)", name, pid, socket_count),
                    format!(
                        "Process '{}' has an abnormally high number of open sockets ({}). \
                         This could indicate a port scanner, DDoS tool, botnet agent, or C2 beacon.",
                        name, socket_count
                    ),
                    Severity::Medium,
                    "Process",
                    55,
                );
                r = r
                    .with_artifacts(vec![
                        format!("PID: {}", pid),
                        format!("Process: {}", name),
                        format!("Socket count: {}", socket_count),
                    ])
                    .with_mitre("T1043 - Commonly Used Port")
                    .with_recommendations(vec![
                        format!("Inspect sockets: ss -tp | grep {}", pid),
                        format!("List all connections: lsof -p {}", pid),
                    ]);
                return Some(r);
            }
        }
        None
    }

    fn check_ld_preload(&self, pid: u32, _proc_path: &str) -> Option<ScanResult> {
        let environ = self.read_proc_field(pid, "environ")?;
        let environ_str = environ.replace('\0', "\n");

        if let Some(line) = environ_str.lines().find(|l| l.starts_with("LD_PRELOAD=")) {
            let val = line.trim_start_matches("LD_PRELOAD=");
            if !val.is_empty() {
                let name = self.get_process_name(pid).unwrap_or_default();
                let mut r = ScanResult::new(
                    format!("LD_PRELOAD injection detected in process {} (PID {})", name, pid),
                    format!(
                        "Process '{}' is running with LD_PRELOAD set to '{}'. \
                         Attackers use LD_PRELOAD to inject malicious shared libraries \
                         that can intercept system calls and hide malicious activity.",
                        name, val
                    ),
                    Severity::Critical,
                    "Process",
                    92,
                );
                r = r
                    .with_artifacts(vec![
                        format!("PID: {}", pid),
                        format!("Process: {}", name),
                        format!("LD_PRELOAD: {}", val),
                    ])
                    .with_mitre("T1574.006 - Hijack Execution Flow: LD_PRELOAD")
                    .with_recommendations(vec![
                        "Investigate the preloaded library immediately".into(),
                        format!("Kill process: kill -9 {}", pid),
                        "Check /etc/ld.so.preload for persistence".into(),
                        "Analyze the library: file & strings on the .so file".into(),
                    ]);
                return Some(r);
            }
        }
        None
    }

    fn check_ptrace(&self, pid: u32, _proc_path: &str) -> Option<ScanResult> {
        let status = self.read_proc_field(pid, "status")?;
        for line in status.lines() {
            if line.starts_with("TracerPid:") {
                let tracer_pid_str = line.trim_start_matches("TracerPid:").trim();
                if let Ok(tracer_pid) = tracer_pid_str.parse::<u32>() {
                    if tracer_pid != 0 {
                        let name = self.get_process_name(pid).unwrap_or_default();
                        let tracer_name = self.get_process_name(tracer_pid).unwrap_or_default();
                        // Skip debuggers in dev environments
                        let known_debuggers = ["gdb", "strace", "lldb", "valgrind", "perf"];
                        if !known_debuggers.iter().any(|d| tracer_name.contains(d)) {
                            let mut r = ScanResult::new(
                                format!("Process being traced (possible injection): {} (PID {}) by {} (PID {})",
                                    name, pid, tracer_name, tracer_pid),
                                format!(
                                    "Process '{}' (PID {}) is being traced by '{}' (PID {}). \
                                     Unexpected ptrace activity may indicate process injection, \
                                     credential dumping, or anti-analysis bypass.",
                                    name, pid, tracer_name, tracer_pid
                                ),
                                Severity::High,
                                "Process",
                                78,
                            );
                            r = r
                                .with_artifacts(vec![
                                    format!("Traced PID: {}", pid),
                                    format!("Tracer PID: {}", tracer_pid),
                                    format!("Tracer Name: {}", tracer_name),
                                ])
                                .with_mitre("T1055 - Process Injection");
                            return Some(r);
                        }
                    }
                }
            }
        }
        None
    }

    fn check_suspicious_ppid(&self, pid: u32, _proc_path: &str) -> Option<ScanResult> {
        let status = self.read_proc_field(pid, "status")?;
        let name = self.get_process_name(pid)?;

        // Find PPid line
        let ppid_line = status.lines().find(|l| l.starts_with("PPid:"))?;
        let ppid: u32 = ppid_line
            .trim_start_matches("PPid:")
            .trim()
            .parse()
            .ok()?;

        let parent_name = self.get_process_name(ppid).unwrap_or_default();

        // Detect web server spawning shell (webshell)
        let web_servers = ["apache2", "nginx", "httpd", "lighttpd", "caddy"];
        let shell_names = ["bash", "sh", "dash", "zsh", "ksh", "csh", "tcsh", "python", "python3", "perl", "ruby"];

        let is_web_parent = web_servers.iter().any(|w| parent_name.contains(w));
        let is_shell_child = shell_names.iter().any(|s| name == *s);

        if is_web_parent && is_shell_child {
            let cmdline = self.read_proc_field(pid, "cmdline")
                .unwrap_or_default()
                .replace('\0', " ");
            let mut r = ScanResult::new(
                format!("Webshell suspected: {} spawned {} (PID {})", parent_name, name, pid),
                format!(
                    "Web server process '{}' spawned a shell '{}'. \
                     This is a strong indicator of webshell exploitation or \
                     remote code execution via a web application vulnerability.",
                    parent_name, name
                ),
                Severity::Critical,
                "Process",
                95,
            );
            r = r
                .with_artifacts(vec![
                    format!("Shell PID: {}", pid),
                    format!("Web server PID: {}", ppid),
                    format!("Cmdline: {}", cmdline.trim()),
                ])
                .with_mitre("T1505.003 - Server Software Component: Web Shell")
                .with_recommendations(vec![
                    format!("Immediately kill PID {}", pid),
                    "Check web server access logs for exploitation".into(),
                    "Audit web application files for planted webshells".into(),
                    "Run: find /var/www -name '*.php' -newer /var/www/html/index.php".into(),
                ]);
            return Some(r);
        }
        None
    }

    fn check_suspicious_cwd(&self, pid: u32, _proc_path: &str) -> Option<ScanResult> {
        let cwd = fs::read_link(format!("/proc/{}/cwd", pid))
            .ok()
            .map(|p| p.to_string_lossy().to_string())?;

        let suspicious_dirs = ["/tmp", "/dev/shm", "/var/tmp", "/run/shm", "/dev/mqueue"];
        let suspicious = suspicious_dirs.iter().any(|d| cwd.starts_with(d));

        if suspicious {
            let name = self.get_process_name(pid).unwrap_or_default();
            if self.cfg.process.whitelist_processes.iter().any(|w| name.contains(w.as_str())) {
                return None;
            }
            // Check if it also has network connections
            let fd_dir = format!("/proc/{}/fd", pid);
            let has_sockets = fs::read_dir(&fd_dir)
                .ok()
                .map(|entries| {
                    entries.flatten().any(|e| {
                        fs::read_link(e.path())
                            .ok()
                            .map(|t| t.to_string_lossy().starts_with("socket:"))
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false);

            if has_sockets {
                let cmdline = self.read_proc_field(pid, "cmdline")
                    .unwrap_or_default()
                    .replace('\0', " ");
                let mut r = ScanResult::new(
                    format!("Process in suspicious directory with network activity: {} (PID {})", name, pid),
                    format!(
                        "Process '{}' is running from '{}' (a world-writable directory) \
                         and has active network connections. This pattern is common in \
                         dropper malware and reverse shell persistence mechanisms.",
                        name, cwd
                    ),
                    Severity::High,
                    "Process",
                    82,
                );
                r = r
                    .with_artifacts(vec![
                        format!("PID: {}", pid),
                        format!("CWD: {}", cwd),
                        format!("Cmdline: {}", cmdline.trim()),
                    ])
                    .with_mitre("T1036 - Masquerading");
                return Some(r);
            }
        }
        None
    }

    fn check_pid_gaps(&self, pids: &[u32]) -> Vec<ScanResult> {
        let mut findings = Vec::new();
        if pids.len() < 2 {
            return findings;
        }

        let mut large_gaps: Vec<(u32, u32, u32)> = Vec::new();
        for window in pids.windows(2) {
            let gap = window[1].saturating_sub(window[0]);
            if gap > 100 && window[0] > 10 {
                large_gaps.push((window[0], window[1], gap));
            }
        }

        if large_gaps.len() > 3 {
            let mut r = ScanResult::new(
                format!("Unusual PID gaps detected ({} gaps > 100)", large_gaps.len()),
                "Multiple large gaps in the process ID space were detected. \
                 Rootkits sometimes hide processes by removing them from /proc \
                 while still allocating PIDs in the kernel.",
                Severity::Medium,
                "Process",
                45,
            );
            r = r
                .with_artifacts(
                    large_gaps.iter().take(5)
                        .map(|(a, b, g)| format!("Gap between PID {} and {}: {}", a, b, g))
                        .collect()
                )
                .with_mitre("T1014 - Rootkit");
            findings.push(r);
        }
        findings
    }

    fn check_zombie_processes(&self) -> Vec<ScanResult> {
        let mut zombie_count = 0u32;
        let mut zombies: Vec<String> = Vec::new();

        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                if let Ok(name) = entry.file_name().into_string() {
                    if let Ok(pid) = name.parse::<u32>() {
                        if let Ok(stat) = fs::read_to_string(format!("/proc/{}/stat", pid)) {
                            // State is the 3rd field; Z = zombie
                            let fields: Vec<&str> = stat.split_whitespace().collect();
                            if fields.get(2) == Some(&"Z") {
                                zombie_count += 1;
                                let pname = self.get_process_name(pid).unwrap_or_default();
                                zombies.push(format!("PID {} ({})", pid, pname));
                            }
                        }
                    }
                }
            }
        }

        let mut findings = Vec::new();
        if zombie_count > 10 {
            let mut r = ScanResult::new(
                format!("Excessive zombie processes: {} zombies detected", zombie_count),
                "An unusually high number of zombie processes were found. \
                 This can indicate a fork bomb attack, a poorly written malicious script, \
                 or deliberate resource exhaustion.",
                Severity::Medium,
                "Process",
                50,
            );
            r = r.with_artifacts(zombies.into_iter().take(10).collect());
            findings.push(r);
        }
        findings
    }

    fn check_high_cpu_processes(&self, pids: &[u32]) -> Vec<ScanResult> {
        let mut findings = Vec::new();
        let mut high_cpu: Vec<(u32, String, u64)> = Vec::new();

        for &pid in pids {
            if let Ok(stat) = fs::read_to_string(format!("/proc/{}/stat", pid)) {
                let fields: Vec<&str> = stat.split_whitespace().collect();
                // utime is field 14, stime is field 15 (0-indexed: 13, 14)
                if let (Some(utime), Some(stime)) = (
                    fields.get(13).and_then(|v| v.parse::<u64>().ok()),
                    fields.get(14).and_then(|v| v.parse::<u64>().ok()),
                ) {
                    let total = utime + stime;
                    if total > 500_000 {
                        let name = self.get_process_name(pid).unwrap_or_default();
                        if !self.cfg.process.whitelist_processes.iter().any(|w| name.contains(w.as_str())) {
                            high_cpu.push((pid, name, total));
                        }
                    }
                }
            }
        }

        // Sort by CPU usage descending
        high_cpu.sort_by(|a, b| b.2.cmp(&a.2));

        for (pid, name, ticks) in high_cpu.iter().take(3) {
            let exe = self.get_process_exe(*pid).unwrap_or_default();
            let cmdline = self.read_proc_field(*pid, "cmdline")
                .unwrap_or_default()
                .replace('\0', " ");

            // Check if in suspicious location
            let sus_paths = ["/tmp/", "/dev/shm/", "/var/tmp/"];
            let is_suspicious = sus_paths.iter().any(|p| exe.starts_with(p));

            if is_suspicious {
                let mut r = ScanResult::new(
                    format!("Suspicious high-CPU process from temp dir: {} (PID {})", name, pid),
                    format!(
                        "Process '{}' (PID {}) is consuming high CPU ({} ticks) and \
                         was launched from a suspicious temporary directory: {}. \
                         This is consistent with cryptominer or compute-heavy malware.",
                        name, pid, ticks, exe
                    ),
                    Severity::High,
                    "Process",
                    85,
                );
                r = r
                    .with_artifacts(vec![
                        format!("PID: {}", pid),
                        format!("EXE: {}", exe),
                        format!("CPU ticks: {}", ticks),
                        format!("Cmdline: {}", cmdline.trim()),
                    ])
                    .with_mitre("T1496 - Resource Hijacking")
                    .with_recommendations(vec![
                        "This may be a cryptominer — check for pool connections".into(),
                        format!("Inspect open connections: ss -tp | grep {}", pid),
                        format!("Kill if confirmed malicious: kill -9 {}", pid),
                    ]);
                findings.push(r);
            }
        }
        findings
    }
}
