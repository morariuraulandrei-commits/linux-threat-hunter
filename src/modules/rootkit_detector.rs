// === FILE: src/modules/rootkit_detector.rs ===

use super::{ScanResult, Severity};
use crate::config::Config;
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::Path;

pub struct RootkitDetector {
    cfg: Config,
}

impl RootkitDetector {
    pub fn new(cfg: Config) -> Self {
        Self { cfg }
    }

    pub async fn scan(&mut self) -> Result<Vec<ScanResult>> {
        let mut findings: Vec<ScanResult> = Vec::new();

        // Check 1: Hidden process detection
        if let Ok(f) = self.check_hidden_processes() {
            findings.extend(f);
        }

        // Check 2: Kernel module tampering
        if let Ok(f) = self.check_kernel_module_tampering() {
            findings.extend(f);
        }

        // Check 3: Syscall table hooks
        if let Ok(f) = self.check_syscall_hooks() {
            findings.extend(f);
        }

        // Check 4: Filesystem discrepancies
        if let Ok(f) = self.check_filesystem_discrepancies() {
            findings.extend(f);
        }

        // Check 5: Network stack manipulation
        if let Ok(f) = self.check_network_stack_manipulation() {
            findings.extend(f);
        }

        // Check 6: dmesg exploit indicators
        if let Ok(f) = self.check_dmesg_exploits() {
            findings.extend(f);
        }

        // Check 7: System binary tampering
        if let Ok(f) = self.check_system_binary_tampering() {
            findings.extend(f);
        }

        // Check 8: Anomalous kernel memory
        if let Ok(f) = self.check_anomalous_kernel_memory() {
            findings.extend(f);
        }

        // Check 9: LD_PRELOAD injection
        if let Ok(f) = self.check_ld_preload_injection() {
            findings.extend(f);
        }

        // Check 10: Interrupt handler hijacking
        if let Ok(f) = self.check_interrupt_hijacking() {
            findings.extend(f);
        }

        Ok(findings)
    }

    fn check_hidden_processes(&self) -> Result<Vec<ScanResult>> {
        let mut findings = Vec::new();

        // Enumerate /proc/[0-9]+ to get visible PIDs
        let mut visible_pids = HashSet::new();
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                if let Ok(name) = entry.file_name().into_string() {
                    if let Ok(pid) = name.parse::<u32>() {
                        visible_pids.insert(pid);
                    }
                }
            }
        }

        // Check /proc/*/status for additional PIDs
        let mut status_pids = HashSet::new();
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                if let Ok(name) = entry.file_name().into_string() {
                    if let Ok(pid) = name.parse::<u32>() {
                        if let Ok(status) = fs::read_to_string(format!("/proc/{}/status", pid)) {
                            status_pids.insert(pid);
                        }
                    }
                }
            }
        }

        // Find PIDs in status but not in visible listing
        for pid in &status_pids {
            if !visible_pids.contains(pid) {
                let proc_path = format!("/proc/{}", pid);
                if Path::new(&proc_path).exists() {
                    if let Ok(comm) = fs::read_to_string(format!("{}/comm", proc_path)) {
                        let mut r = ScanResult::new(
                            format!("Hidden process detected via status mismatch: PID {}", pid),
                            format!(
                                "Process {} (PID {}) exists in /proc/*/status but is not visible in /proc directory listing. \
                                 This indicates kernel-level process hiding, typically used by rootkits to conceal malicious processes.",
                                comm.trim(),
                                pid
                            ),
                            Severity::Critical,
                            "Rootkit",
                            95,
                        );
                        r = r
                            .with_artifacts(vec![
                                format!("PID: {}", pid),
                                format!("Process: {}", comm.trim()),
                                "Status file: readable, /proc listing: invisible".to_string(),
                            ])
                            .with_mitre("T1014 - Rootkit")
                            .with_recommendations(vec![
                                "Immediate system isolation recommended".into(),
                                "Capture volatile memory for forensic analysis".into(),
                                "Boot into rescue mode and perform full filesystem audit".into(),
                                "Check kernel module list with: lsmod | sort".into(),
                            ]);
                        findings.push(r);
                    }
                }
            }
        }

        // Check for PIDs in range but missing status (possible FTRACE hiding)
        for pid in 1..=65535 {
            let proc_path = format!("/proc/{}", pid);
            let status_path = format!("{}/status", proc_path);

            if !visible_pids.contains(&pid) && !Path::new(&status_path).exists() {
                // Try accessing via kill(0) signal to confirm process existence
                if unsafe { nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid as i32), None).is_ok() } {
                    if let Ok(entries) = fs::read_dir("/proc") {
                        let mut found_in_listing = false;
                        for entry in entries.flatten() {
                            if let Ok(name) = entry.file_name().into_string() {
                                if let Ok(check_pid) = name.parse::<u32>() {
                                    if check_pid == pid {
                                        found_in_listing = true;
                                        break;
                                    }
                                }
                            }
                        }

                        if !found_in_listing {
                            let mut r = ScanResult::new(
                                format!("Hidden process detected via signal test: PID {}", pid),
                                format!(
                                    "Process with PID {} responds to kill(0) signal but does not appear in /proc listing. \
                                     This indicates advanced kernel-level process hiding."
                                ),
                                Severity::Critical,
                                "Rootkit",
                                90,
                            );
                            r = r
                                .with_artifacts(vec![
                                    format!("PID: {}", pid),
                                    "Signal test: responsive, /proc listing: invisible".to_string(),
                                ])
                                .with_mitre("T1014 - Rootkit")
                                .with_recommendations(vec![
                                    "System likely compromised with kernel-level rootkit".into(),
                                    "Perform memory forensics immediately".into(),
                                    "Review system for recent privilege escalation events".into(),
                                ]);
                            findings.push(r);
                        }
                    }
                }
            }
        }

        Ok(findings)
    }

    fn check_kernel_module_tampering(&self) -> Result<Vec<ScanResult>> {
        let mut findings = Vec::new();

        // Read /proc/modules
        if let Ok(modules_content) = fs::read_to_string("/proc/modules") {
            let suspicious_patterns = vec![
                "hide", "rootkit", "bd", "backdoor", "adore", "diamorphine",
                "reptile", "suterusu", "kernel_", "sys_", "net_",
            ];

            for line in modules_content.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    let module_name = parts[0];
                    let module_size = parts[1].parse::<u64>().unwrap_or(0);

                    // Check for suspicious module names
                    for pattern in &suspicious_patterns {
                        if module_name.to_lowercase().contains(pattern) {
                            let mut r = ScanResult::new(
                                format!("Suspicious kernel module detected: {}", module_name),
                                format!(
                                    "Kernel module '{}' matches a known rootkit pattern '{}'. \
                                     Size: {} bytes. Rootkits commonly use hidden or obfuscated module names.",
                                    module_name, pattern, module_size
                                ),
                                Severity::Critical,
                                "Rootkit",
                                85,
                            );
                            r = r
                                .with_artifacts(vec![
                                    format!("Module: {}", module_name),
                                    format!("Size: {}", module_size),
                                ])
                                .with_mitre("T1014 - Rootkit")
                                .with_recommendations(vec![
                                    format!("Remove module: modprobe -r {}", module_name),
                                    "Analyze module binary for malicious code".into(),
                                    "Check module load time and origin".into(),
                                ]);
                            findings.push(r);
                            break;
                        }
                    }

                    // Check for zero-size modules (indicator of hidden modules)
                    if module_size == 0 {
                        let mut r = ScanResult::new(
                            format!("Zero-size kernel module detected: {}", module_name),
                            format!(
                                "Kernel module '{}' reports zero size, which is anomalous. \
                                 This may indicate a hidden module or FTRACE-based rootkit.",
                                module_name
                            ),
                            Severity::High,
                            "Rootkit",
                            75,
                        );
                        r = r
                            .with_artifacts(vec![format!("Module: {}", module_name)])
                            .with_mitre("T1014 - Rootkit")
                            .with_recommendations(vec![
                                "Investigate module origin and purpose".into(),
                                "Check kernel log for module load events".into(),
                            ]);
                        findings.push(r);
                    }

                    // Check for permanent flag on suspicious modules
                    if parts.len() >= 4 && parts[2] != "0" && parts[3].contains("(permanent)") {
                        if module_name.contains("test") || module_name.contains("test_") {
                            let mut r = ScanResult::new(
                                format!("Permanent kernel module flag detected: {}", module_name),
                                format!(
                                    "Module '{}' is marked as (permanent) which prevents removal. \
                                     This is unusual outside development contexts.",
                                    module_name
                                ),
                                Severity::High,
                                "Rootkit",
                                70,
                            );
                            r = r
                                .with_artifacts(vec![format!("Module: {}", module_name)])
                                .with_mitre("T1014 - Rootkit")
                                .with_recommendations(vec![
                                    "Verify module is legitimate and authorized".into(),
                                    "Check build system and module sources".into(),
                                ]);
                            findings.push(r);
                        }
                    }
                }
            }

            // Cross-check with /sys/module
            if let Ok(sys_entries) = fs::read_dir("/sys/module") {
                let mut sys_modules = HashSet::new();
                for entry in sys_entries.flatten() {
                    if let Ok(name) = entry.file_name().into_string() {
                        sys_modules.insert(name);
                    }
                }

                for line in modules_content.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if !parts.is_empty() {
                        let module_name = parts[0];
                        if !sys_modules.contains(module_name) {
                            let mut r = ScanResult::new(
                                format!("Module in /proc/modules but not in /sys/module: {}", module_name),
                                format!(
                                    "Module '{}' appears in /proc/modules but not in /sys/module. \
                                     This discrepancy may indicate a hidden or unloaded module.",
                                    module_name
                                ),
                                Severity::High,
                                "Rootkit",
                                72,
                            );
                            r = r
                                .with_artifacts(vec![format!("Module: {}", module_name)])
                                .with_mitre("T1014 - Rootkit")
                                .with_recommendations(vec![
                                    "Verify module status: lsmod | grep {}".into(),
                                    "Check dmesg for related events".into(),
                                ]);
                            findings.push(r);
                        }
                    }
                }
            }
        }

        Ok(findings)
    }

    fn check_syscall_hooks(&self) -> Result<Vec<ScanResult>> {
        let mut findings = Vec::new();

        // Read /proc/kallsyms to check for syscall table hooks
        if let Ok(kallsyms) = fs::read_to_string("/proc/kallsyms") {
            let hook_targets = vec![
                "do_getdents64", "do_getdents", "security_file_open",
                "tcp_seq_show", "inet_ctl_sock_create", "sys_open",
            ];

            for target in &hook_targets {
                let mut target_addr: Option<u64> = None;

                for line in kallsyms.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 3 {
                        if parts[2] == *target {
                            if let Ok(addr) = u64::from_str_radix(parts[0], 16) {
                                target_addr = Some(addr);
                                break;
                            }
                        }
                    }
                }

                // Check if address is in expected kernel range
                if let Some(addr) = target_addr {
                    // Typical kernel text range on x86_64: 0xffffffff80000000+
                    if addr < 0xffffffff80000000 && addr > 0xffffffff00000000 {
                        let mut r = ScanResult::new(
                            format!("Potential syscall hook detected: {}", target),
                            format!(
                                "Kernel function '{}' is located at address 0x{:x}, which is outside the typical kernel text range. \
                                 This may indicate a syscall table hook installed by a rootkit.",
                                target, addr
                            ),
                            Severity::Critical,
                            "Rootkit",
                            88,
                        );
                        r = r
                            .with_artifacts(vec![
                                format!("Function: {}", target),
                                format!("Address: 0x{:x}", addr),
                            ])
                            .with_mitre("T1562.001 - Disable or Modify Tools: Disable or Modify System Firewall")
                            .with_recommendations(vec![
                                "Dump kernel memory around hooked function".into(),
                                "Compare with clean kernel image".into(),
                                "Check for rootkit-specific patterns in kernel module list".into(),
                            ]);
                        findings.push(r);
                    }
                }
            }
        }

        Ok(findings)
    }

    fn check_filesystem_discrepancies(&self) -> Result<Vec<ScanResult>> {
        let mut findings = Vec::new();

        let critical_dirs = vec!["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/etc", "/lib", "/lib64"];

        for dir in critical_dirs {
            if let Ok(entries) = fs::read_dir(dir) {
                let mut readdir_files = HashSet::new();

                for entry in entries.flatten() {
                    if let Ok(name) = entry.file_name().into_string() {
                        readdir_files.insert(name);
                    }
                }

                // Now check via stat for additional files
                let dir_path = Path::new(dir);
                if let Ok(metadata) = fs::metadata(dir_path) {
                    // Try to find files that exist via stat but not in readdir
                    // This is a simplified approach; in production, you'd enumerate more exhaustively
                    if dir == "/etc" {
                        let critical_files = vec!["passwd", "shadow", "sudoers", "hosts"];
                        for file in critical_files {
                            let full_path = format!("{}/{}", dir, file);
                            if Path::new(&full_path).exists() && !readdir_files.contains(file) {
                                let mut r = ScanResult::new(
                                    format!("File hidden from readdir: {}", full_path),
                                    format!(
                                        "File '{}' exists (stat succeeds) but is not visible in directory listing. \
                                         This is a classic rootkit hiding technique.",
                                        full_path
                                    ),
                                    Severity::Critical,
                                    "Rootkit",
                                    85,
                                );
                                r = r
                                    .with_artifacts(vec![format!("File: {}", full_path)])
                                    .with_mitre("T1036 - Masquerading")
                                    .with_recommendations(vec![
                                        "Inspect file using direct system calls".into(),
                                        "Check for getdents64 hooking in kernel".into(),
                                        "Examine file for malicious content".into(),
                                    ]);
                                findings.push(r);
                            }
                        }
                    }
                }
            }
        }

        Ok(findings)
    }

    fn check_network_stack_manipulation(&self) -> Result<Vec<ScanResult>> {
        let mut findings = Vec::new();

        // Read /proc/net/tcp and /proc/net/tcp6
        let mut connection_count = 0;
        if let Ok(tcp_content) = fs::read_to_string("/proc/net/tcp") {
            for line in tcp_content.lines().skip(1) {
                if !line.trim().is_empty() {
                    connection_count += 1;
                }
            }
        }

        // Check for raw sockets in /proc/net/packet
        if let Ok(packet_content) = fs::read_to_string("/proc/net/packet") {
            for line in packet_content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 6 {
                    let pkt_type = parts[2];
                    let dev = parts[4];

                    // Type 3 is packet capture, 4 is packet user
                    if pkt_type == "3" || pkt_type == "4" {
                        let mut r = ScanResult::new(
                            format!("Suspicious raw socket detected on {}", dev),
                            format!(
                                "Raw packet socket of type {} detected on device {}. \
                                 Rootkits sometimes use raw sockets for network manipulation and traffic interception.",
                                pkt_type, dev
                            ),
                            Severity::High,
                            "Rootkit",
                            70,
                        );
                        r = r
                            .with_artifacts(vec![
                                format!("Device: {}", dev),
                                format!("Socket Type: {}", pkt_type),
                            ])
                            .with_mitre("T1014 - Rootkit")
                            .with_recommendations(vec![
                                "Identify process owning the raw socket with ss/netstat".into(),
                                "Check process for signs of malware".into(),
                                "Verify network packets for anomalies".into(),
                            ]);
                        findings.push(r);
                    }
                }
            }
        }

        Ok(findings)
    }

    fn check_dmesg_exploits(&self) -> Result<Vec<ScanResult>> {
        let mut findings = Vec::new();

        // Try reading kernel log
        let dmesg_paths = vec!["/var/log/kern.log", "/dev/kmsg"];
        let mut dmesg_content = String::new();

        for path in dmesg_paths {
            if let Ok(content) = fs::read_to_string(path) {
                dmesg_content = content;
                break;
            }
        }

        let exploit_patterns = vec![
            ("BUG:", "Kernel BUG detected - possible exploitation attempt"),
            ("kernel BUG", "Kernel BUG message - stability concern"),
            ("segfault", "Segmentation fault - memory corruption indicator"),
            ("Call trace", "Kernel call trace - crash or exploit indicator"),
            ("RIP:", "Instruction pointer error - potential exploitation"),
            ("Oops:", "Kernel oops - crash indicator"),
            ("heap spray", "Heap spray attempt detected"),
            ("use-after-free", "Use-after-free vulnerability trigger"),
            ("buffer overflow", "Buffer overflow attempt"),
        ];

        for (pattern, description) in &exploit_patterns {
            if dmesg_content.to_lowercase().contains(pattern) {
                let mut r = ScanResult::new(
                    format!("Exploit indicator in kernel log: {}", pattern),
                    format!(
                        "Kernel log contains '{}' which indicates: {}. \
                         This suggests a potential exploit attempt or kernel vulnerability exploitation.",
                        pattern, description
                    ),
                    Severity::Critical,
                    "Rootkit",
                    80,
                );
                r = r
                    .with_artifacts(vec![format!("Pattern: {}", pattern)])
                    .with_mitre("T1014 - Rootkit")
                    .with_recommendations(vec![
                        "Review full kernel log: dmesg | grep -i crash".into(),
                        "Check for corresponding privilege escalation in auth logs".into(),
                        "Analyze timing against system compromise indicators".into(),
                    ]);
                findings.push(r);
            }
        }

        Ok(findings)
    }

    fn check_system_binary_tampering(&self) -> Result<Vec<ScanResult>> {
        let mut findings = Vec::new();

        let critical_binaries = vec![
            "/bin/ls", "/bin/ps", "/bin/netstat", "/bin/ss",
            "/usr/bin/lsof", "/bin/find", "/usr/bin/sudo",
        ];

        let thirty_days_ago = std::time::SystemTime::now()
            - std::time::Duration::from_secs(30 * 24 * 60 * 60);

        for binary in critical_binaries {
            if let Ok(metadata) = fs::metadata(binary) {
                if let Ok(modified) = metadata.modified() {
                    if modified > thirty_days_ago {
                        let mut r = ScanResult::new(
                            format!("Recently modified critical binary: {}", binary),
                            format!(
                                "Critical system binary '{}' was modified within the last 30 days. \
                                 Rootkits often replace system binaries to hide their presence.",
                                binary
                            ),
                            Severity::High,
                            "Rootkit",
                            75,
                        );
                        r = r
                            .with_artifacts(vec![format!("Binary: {}", binary)])
                            .with_mitre("T1036 - Masquerading")
                            .with_recommendations(vec![
                                format!("Verify binary checksum against package: dpkg -S {}", binary),
                                "Compare with known-good binary from installation media".into(),
                                "Check file integrity database (aide/tripwire) for changes".into(),
                            ]);
                        findings.push(r);
                    }
                }
            }
        }

        Ok(findings)
    }

    fn check_anomalous_kernel_memory(&self) -> Result<Vec<ScanResult>> {
        let mut findings = Vec::new();

        // Read /proc/iomem for unusual memory mappings
        if let Ok(iomem) = fs::read_to_string("/proc/iomem") {
            let mut prev_end = 0u64;

            for line in iomem.lines() {
                let parts: Vec<&str> = line.split('-').collect();
                if parts.len() >= 2 {
                    if let (Ok(start), Ok(end)) = (
                        u64::from_str_radix(parts[0].trim(), 16),
                        u64::from_str_radix(parts[1].split_whitespace().next().unwrap_or("0"), 16),
                    ) {
                        // Check for gaps or anomalies
                        if start > prev_end + 1024 && prev_end > 0 {
                            let gap = start - prev_end;
                            if gap > 1024 * 1024 {
                                let mut r = ScanResult::new(
                                    format!("Large memory gap detected in iomem"),
                                    format!(
                                        "Unusual gap in kernel memory mapping detected between 0x{:x} and 0x{:x} ({} bytes). \
                                         This may indicate memory allocated for rootkit code.",
                                        prev_end, start, gap
                                    ),
                                    Severity::Medium,
                                    "Rootkit",
                                    60,
                                );
                                r = r
                                    .with_artifacts(vec![
                                        format!("Gap start: 0x{:x}", prev_end),
                                        format!("Gap end: 0x{:x}", start),
                                        format!("Gap size: {} bytes", gap),
                                    ])
                                    .with_mitre("T1014 - Rootkit")
                                    .with_recommendations(vec![
                                        "Dump kernel memory in gap region for analysis".into(),
                                        "Compare with clean system iomem layout".into(),
                                    ]);
                                findings.push(r);
                            }
                        }
                        prev_end = end;
                    }
                }
            }
        }

        Ok(findings)
    }

    fn check_ld_preload_injection(&self) -> Result<Vec<ScanResult>> {
        let mut findings = Vec::new();

        // Read /proc/*/maps for all processes
        if let Ok(proc_dir) = fs::read_dir("/proc") {
            for entry in proc_dir.flatten() {
                if let Ok(name) = entry.file_name().into_string() {
                    if let Ok(pid) = name.parse::<u32>() {
                        let maps_path = format!("/proc/{}/maps", pid);
                        if let Ok(maps) = fs::read_to_string(&maps_path) {
                            // Look for memfd or anonymous executable mappings
                            for line in maps.lines() {
                                let parts: Vec<&str> = line.split_whitespace().collect();
                                if parts.len() >= 6 {
                                    let perms = parts[1];
                                    let mapping = parts[5];

                                    // Check for executable memfd
                                    if mapping.contains("memfd:") && perms.contains('x') {
                                        if let Ok(comm) = fs::read_to_string(format!("/proc/{}/comm", pid)) {
                                            let mut r = ScanResult::new(
                                                format!("LD_PRELOAD injection detected via memfd: PID {}", pid),
                                                format!(
                                                    "Process '{}' (PID {}) has executable memfd mapping '{}'. \
                                                     This indicates fileless injection or LD_PRELOAD-style library injection.",
                                                    comm.trim(), pid, mapping
                                                ),
                                                Severity::Critical,
                                                "Rootkit",
                                                85,
                                            );
                                            r = r
                                                .with_artifacts(vec![
                                                    format!("PID: {}", pid),
                                                    format!("Process: {}", comm.trim()),
                                                    format!("Mapping: {}", mapping),
                                                ])
                                                .with_mitre("T1055 - Process Injection")
                                                .with_recommendations(vec![
                                                    "Capture process memory dump immediately".into(),
                                                    format!("Kill suspicious process: kill -9 {}", pid),
                                                    "Analyze injected code for malware signatures".into(),
                                                ]);
                                            findings.push(r);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(findings)
    }

    fn check_interrupt_hijacking(&self) -> Result<Vec<ScanResult>> {
        let mut findings = Vec::new();

        // Read /proc/interrupts
        if let Ok(interrupts) = fs::read_to_string("/proc/interrupts") {
            let mut irq_counts: HashMap<String, u64> = HashMap::new();

            for line in interrupts.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if !parts.is_empty() {
                    let irq_line = parts[0].trim_end_matches(':');
                    if let Some(count_str) = parts.get(1) {
                        if let Ok(count) = count_str.parse::<u64>() {
                            irq_counts.insert(irq_line.to_string(), count);
                        }
                    }
                }
            }

            // Check for unusually high interrupt counts (potential hijacking)
            for (irq, count) in irq_counts {
                if count > 1_000_000 {
                    let mut r = ScanResult::new(
                        format!("Anomalously high interrupt count: IRQ {}", irq),
                        format!(
                            "IRQ {} has processed {} interrupts, which is unusually high. \
                             This may indicate interrupt handler hijacking by a rootkit.",
                            irq, count
                        ),
                        Severity::High,
                        "Rootkit",
                        65,
                    );
                    r = r
                        .with_artifacts(vec![
                            format!("IRQ: {}", irq),
                            format!("Count: {}", count),
                        ])
                        .with_mitre("T1014 - Rootkit")
                        .with_recommendations(vec![
                            "Compare interrupt counts with baseline".into(),
                            "Check associated device driver for anomalies".into(),
                        ]);
                    findings.push(r);
                }
            }
        }

        Ok(findings)
    }
}
