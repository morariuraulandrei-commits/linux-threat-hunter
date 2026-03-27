use super::{shannon_entropy, ScanResult, Severity};
use crate::config::Config;
use crate::platform;
use anyhow::Result;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::fs;

pub struct NetworkHunter {
    cfg: Config,
}

#[derive(Debug, Clone)]
struct TcpConnection {
    local_addr: String,
    local_port: u16,
    remote_addr: String,
    remote_port: u16,
    state: String,
    pid: Option<u32>,
    inode: u64,
}

impl NetworkHunter {
    pub fn new(cfg: Config) -> Self {
        Self { cfg }
    }

    pub async fn scan(&mut self) -> Result<Vec<ScanResult>> {
        let mut findings: Vec<ScanResult> = Vec::new();
        let is_wsl = platform::is_wsl();

        // /proc/net/* is available in both native Linux and WSL2
        // Parse /proc/net/tcp and /proc/net/tcp6
        let tcp4 = self.parse_proc_net_tcp("/proc/net/tcp");
        let tcp6 = self.parse_proc_net_tcp6("/proc/net/tcp6");
        let all_tcp: Vec<TcpConnection> = tcp4.into_iter().chain(tcp6.into_iter()).collect();

        // Parse /proc/net/udp
        let udp = self.parse_proc_net_udp("/proc/net/udp");

        // Build inode->pid map
        let inode_to_pid = self.build_inode_pid_map();

        let mut connections_with_pid: Vec<TcpConnection> = all_tcp
            .into_iter()
            .map(|mut c| {
                c.pid = inode_to_pid.get(&c.inode).copied();
                c
            })
            .collect();

        // Check for suspicious ports
        findings.extend(self.check_suspicious_ports(&connections_with_pid));

        // Check for C2 indicators
        findings.extend(self.check_c2_indicators(&connections_with_pid));

        // Check for Tor usage
        if self.cfg.network.check_tor {
            findings.extend(self.check_tor_connections(&connections_with_pid));
        }

        // Check for reverse shells
        if self.cfg.network.check_reverse_shells {
            findings.extend(self.check_reverse_shells(&connections_with_pid));
        }

        // Check for port scanners (many connections to different hosts)
        findings.extend(self.check_port_scanner(&connections_with_pid));

        // Check for listening services on unexpected ports
        findings.extend(self.check_unexpected_listeners(&connections_with_pid));

        // Check DNS for tunneling
        if self.cfg.network.check_dns_tunneling {
            findings.extend(self.check_dns_tunneling());
        }

        // Check ARP table for anomalies (ARP poisoning)
        // Note: /proc/net/arp is available in WSL2 but may show limited entries
        findings.extend(self.check_arp_table());

        // Check routing table for suspicious routes
        findings.extend(self.check_routing_table());

        // Check network interfaces for promiscuous mode
        // Note: WSL2 runs in a VM — host interfaces aren't directly exposed
        if !is_wsl {
            findings.extend(self.check_promiscuous_interfaces());
        }

        // Check iptables rules (not available in WSL1, limited in WSL2)
        if !is_wsl {
            findings.extend(self.check_iptables_rules());
        }

        // Check /proc/net/packet for raw socket users
        if platform::proc_net_available("packet") {
            findings.extend(self.check_raw_sockets());
        }

        Ok(findings)
    }

    fn parse_hex_ip(&self, hex: &str) -> Option<String> {
        if hex.len() == 8 {
            // IPv4
            let n = u32::from_str_radix(hex, 16).ok()?;
            let bytes = n.to_le_bytes();
            Some(format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]))
        } else {
            None
        }
    }

    fn parse_hex_port(&self, hex: &str) -> Option<u16> {
        u16::from_str_radix(hex, 16).ok()
    }

    fn tcp_state(&self, state_hex: &str) -> &'static str {
        match state_hex {
            "01" => "ESTABLISHED",
            "02" => "SYN_SENT",
            "03" => "SYN_RECV",
            "04" => "FIN_WAIT1",
            "05" => "FIN_WAIT2",
            "06" => "TIME_WAIT",
            "07" => "CLOSE",
            "08" => "CLOSE_WAIT",
            "09" => "LAST_ACK",
            "0A" => "LISTEN",
            "0B" => "CLOSING",
            _ => "UNKNOWN",
        }
    }

    fn parse_proc_net_tcp(&self, path: &str) -> Vec<TcpConnection> {
        let mut conns = Vec::new();
        let content = fs::read_to_string(path).unwrap_or_default();

        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 10 {
                continue;
            }

            let local_parts: Vec<&str> = parts[1].split(':').collect();
            let remote_parts: Vec<&str> = parts[2].split(':').collect();

            if local_parts.len() != 2 || remote_parts.len() != 2 {
                continue;
            }

            let local_ip = self.parse_hex_ip(local_parts[0]).unwrap_or_default();
            let local_port = self.parse_hex_port(local_parts[1]).unwrap_or(0);
            let remote_ip = self.parse_hex_ip(remote_parts[0]).unwrap_or_default();
            let remote_port = self.parse_hex_port(remote_parts[1]).unwrap_or(0);
            let state = self.tcp_state(parts[3]);
            let inode = parts[9].parse::<u64>().unwrap_or(0);

            conns.push(TcpConnection {
                local_addr: local_ip,
                local_port,
                remote_addr: remote_ip,
                remote_port,
                state: state.to_string(),
                pid: None,
                inode,
            });
        }
        conns
    }

    fn parse_proc_net_tcp6(&self, path: &str) -> Vec<TcpConnection> {
        let mut conns = Vec::new();
        let content = fs::read_to_string(path).unwrap_or_default();

        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 10 {
                continue;
            }

            // IPv6 addresses in /proc/net/tcp6 are 32 hex chars
            let local_parts: Vec<&str> = parts[1].split(':').collect();
            let remote_parts: Vec<&str> = parts[2].split(':').collect();

            let state = self.tcp_state(parts[3]);
            let inode = parts[9].parse::<u64>().unwrap_or(0);

            // Simplified: just grab the port
            let local_port = local_parts.last().and_then(|p| self.parse_hex_port(p)).unwrap_or(0);
            let remote_port = remote_parts.last().and_then(|p| self.parse_hex_port(p)).unwrap_or(0);

            conns.push(TcpConnection {
                local_addr: "IPv6".to_string(),
                local_port,
                remote_addr: "IPv6".to_string(),
                remote_port,
                state: state.to_string(),
                pid: None,
                inode,
            });
        }
        conns
    }

    fn parse_proc_net_udp(&self, path: &str) -> Vec<TcpConnection> {
        let mut conns = Vec::new();
        let content = fs::read_to_string(path).unwrap_or_default();

        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 10 {
                continue;
            }
            let local_parts: Vec<&str> = parts[1].split(':').collect();
            let remote_parts: Vec<&str> = parts[2].split(':').collect();

            if local_parts.len() != 2 || remote_parts.len() != 2 {
                continue;
            }

            let local_ip = self.parse_hex_ip(local_parts[0]).unwrap_or_default();
            let local_port = self.parse_hex_port(local_parts[1]).unwrap_or(0);
            let remote_ip = self.parse_hex_ip(remote_parts[0]).unwrap_or_default();
            let remote_port = self.parse_hex_port(remote_parts[1]).unwrap_or(0);
            let inode = parts[9].parse::<u64>().unwrap_or(0);

            conns.push(TcpConnection {
                local_addr: local_ip,
                local_port,
                remote_addr: remote_ip,
                remote_port,
                state: "UDP".to_string(),
                pid: None,
                inode,
            });
        }
        conns
    }

    fn build_inode_pid_map(&self) -> HashMap<u64, u32> {
        let mut map = HashMap::new();
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                if let Ok(name) = entry.file_name().into_string() {
                    if let Ok(pid) = name.parse::<u32>() {
                        let fd_dir = format!("/proc/{}/fd", pid);
                        if let Ok(fds) = fs::read_dir(&fd_dir) {
                            for fd in fds.flatten() {
                                if let Ok(target) = fs::read_link(fd.path()) {
                                    let t = target.to_string_lossy();
                                    if t.starts_with("socket:[") {
                                        if let Some(inode_str) = t.strip_prefix("socket:[")
                                            .and_then(|s| s.strip_suffix(']'))
                                        {
                                            if let Ok(inode) = inode_str.parse::<u64>() {
                                                map.insert(inode, pid);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        map
    }

    fn get_process_name(&self, pid: u32) -> String {
        fs::read_to_string(format!("/proc/{}/comm", pid))
            .unwrap_or_default()
            .trim()
            .to_string()
    }

    fn check_suspicious_ports(&self, conns: &[TcpConnection]) -> Vec<ScanResult> {
        let mut findings = Vec::new();
        let suspicious: HashSet<u16> = self.cfg.network.suspicious_ports.iter().copied().collect();

        for conn in conns {
            let is_remote_suspicious = suspicious.contains(&conn.remote_port);
            let is_local_listening = conn.state == "LISTEN" && suspicious.contains(&conn.local_port);

            if is_remote_suspicious || is_local_listening {
                let process_name = conn.pid.map(|p| self.get_process_name(p)).unwrap_or_default();
                let direction = if is_local_listening { "LISTENING on" } else { "connected to" };
                let port = if is_local_listening { conn.local_port } else { conn.remote_port };

                let (severity, score) = if [4444, 4445, 31337, 1337].contains(&port) {
                    (Severity::Critical, 94)
                } else if [9001, 9030].contains(&port) {
                    (Severity::High, 80) // Tor
                } else {
                    (Severity::High, 72)
                };

                let mut r = ScanResult::new(
                    format!("Suspicious port {} {} — process: {}", port, direction, process_name),
                    format!(
                        "Port {} is associated with malware/C2 frameworks. \
                         Process '{}' (PID {:?}) is {} port {}. \
                         Remote: {}:{}",
                        port, process_name, conn.pid, direction, port,
                        conn.remote_addr, conn.remote_port
                    ),
                    severity,
                    "Network",
                    score,
                );
                r = r
                    .with_artifacts(vec![
                        format!("Local: {}:{}", conn.local_addr, conn.local_port),
                        format!("Remote: {}:{}", conn.remote_addr, conn.remote_port),
                        format!("State: {}", conn.state),
                        format!("Process: {} (PID {:?})", process_name, conn.pid),
                    ])
                    .with_mitre("T1571 - Non-Standard Port")
                    .with_recommendations(vec![
                        format!("Investigate process: lsof -p {:?} -i", conn.pid),
                        format!("Block port: iptables -A OUTPUT -p tcp --dport {} -j DROP", port),
                    ]);
                findings.push(r);
            }
        }
        findings
    }

    fn check_c2_indicators(&self, conns: &[TcpConnection]) -> Vec<ScanResult> {
        let mut findings = Vec::new();

        for conn in conns {
            if conn.state != "ESTABLISHED" {
                continue;
            }

            // Check known C2 IPs
            for c2_ip in &self.cfg.network.known_c2_ips {
                if conn.remote_addr.contains(c2_ip.as_str()) {
                    let process_name = conn.pid.map(|p| self.get_process_name(p)).unwrap_or_default();
                    let mut r = ScanResult::new(
                        format!("Connection to known C2 IP: {} from {}", c2_ip, process_name),
                        format!(
                            "Active connection to known C2 IP '{}' detected. \
                             Process: '{}' (PID {:?})",
                            c2_ip, process_name, conn.pid
                        ),
                        Severity::Critical,
                        "Network",
                        99,
                    );
                    r = r
                        .with_mitre("T1071 - Application Layer Protocol")
                        .with_recommendations(vec![
                            format!("Block: iptables -A OUTPUT -d {} -j DROP", c2_ip),
                            "Isolate system immediately".into(),
                        ]);
                    findings.push(r);
                }
            }

            // Detect beaconing patterns: connections to non-RFC1918 on unusual ports
            let is_private = self.is_private_ip(&conn.remote_addr);
            let is_standard_port = [80u16, 443, 22, 25, 53, 8080, 8443].contains(&conn.remote_port);

            if !is_private && !is_standard_port && conn.remote_port > 1024 && conn.remote_port < 65535 {
                let process_name = conn.pid.map(|p| self.get_process_name(p)).unwrap_or_default();

                // Additional check: is this a system binary making unusual outbound connections?
                let system_bins = ["apache2", "nginx", "mysqld", "postgres", "sshd"];
                if system_bins.iter().any(|b| process_name.contains(b)) {
                    let mut r = ScanResult::new(
                        format!("System service '{}' making unusual outbound connection to {}:{}",
                            process_name, conn.remote_addr, conn.remote_port),
                        format!(
                            "System service '{}' has an established connection to {}:{} \
                             which is unusual for this service type. This may indicate \
                             compromise or backdoor in the service.",
                            process_name, conn.remote_addr, conn.remote_port
                        ),
                        Severity::High,
                        "Network",
                        82,
                    );
                    r = r
                        .with_artifacts(vec![
                            format!("Process: {}", process_name),
                            format!("Connection: {} -> {}:{}", conn.local_addr, conn.remote_addr, conn.remote_port),
                        ])
                        .with_mitre("T1071 - Application Layer Protocol");
                    findings.push(r);
                }
            }
        }
        findings
    }

    fn check_tor_connections(&self, conns: &[TcpConnection]) -> Vec<ScanResult> {
        let mut findings = Vec::new();
        let tor_ports: HashSet<u16> = [9001, 9030, 9050, 9051, 9150, 9151].iter().copied().collect();

        // Known Tor guard node port ranges
        for conn in conns {
            if conn.state != "ESTABLISHED" {
                continue;
            }
            if tor_ports.contains(&conn.remote_port) || tor_ports.contains(&conn.local_port) {
                let process_name = conn.pid.map(|p| self.get_process_name(p)).unwrap_or_default();
                let mut r = ScanResult::new(
                    format!("Possible Tor connection from {}", process_name),
                    format!(
                        "Connection involving Tor-associated port ({}) detected. \
                         Process '{}' may be using Tor for anonymous communications, \
                         commonly used by malware to hide C2 traffic.",
                        if tor_ports.contains(&conn.remote_port) { conn.remote_port } else { conn.local_port },
                        process_name
                    ),
                    Severity::High,
                    "Network",
                    78,
                );
                r = r
                    .with_artifacts(vec![
                        format!("Process: {} (PID {:?})", process_name, conn.pid),
                        format!("Connection: {}:{} -> {}:{}",
                            conn.local_addr, conn.local_port,
                            conn.remote_addr, conn.remote_port),
                    ])
                    .with_mitre("T1090.003 - Proxy: Multi-hop Proxy");
                findings.push(r);
            }
        }
        findings
    }

    fn check_reverse_shells(&self, conns: &[TcpConnection]) -> Vec<ScanResult> {
        let mut findings = Vec::new();

        // Common reverse shell indicators:
        // 1. Shell process (bash, sh, python) with network connection
        // 2. File descriptor redirection (stdin/stdout/stderr to socket)

        let shell_names = ["bash", "sh", "dash", "zsh", "python", "python3", "perl", "ruby", "nc", "ncat"];

        if let Ok(procs) = fs::read_dir("/proc") {
            for entry in procs.flatten() {
                if let Ok(name) = entry.file_name().into_string() {
                    if let Ok(pid) = name.parse::<u32>() {
                        let comm = fs::read_to_string(format!("/proc/{}/comm", pid))
                            .unwrap_or_default();
                        let comm = comm.trim();

                        if !shell_names.iter().any(|s| comm == *s) {
                            continue;
                        }

                        // Check if stdin (fd 0), stdout (fd 1), stderr (fd 2) are sockets
                        let mut redirected_fds = 0u8;
                        for fd in 0u8..3 {
                            let fd_path = format!("/proc/{}/fd/{}", pid, fd);
                            if let Ok(target) = fs::read_link(&fd_path) {
                                if target.to_string_lossy().starts_with("socket:") {
                                    redirected_fds += 1;
                                }
                            }
                        }

                        if redirected_fds >= 2 {
                            let cmdline = fs::read_to_string(format!("/proc/{}/cmdline", pid))
                                .unwrap_or_default()
                                .replace('\0', " ");

                            // Find the remote IP for this shell's socket
                            let remote = conns.iter()
                                .find(|c| c.pid == Some(pid) && c.state == "ESTABLISHED")
                                .map(|c| format!("{}:{}", c.remote_addr, c.remote_port))
                                .unwrap_or_else(|| "unknown".into());

                            let mut r = ScanResult::new(
                                format!("Reverse shell detected: {} (PID {}) connected to {}", comm, pid, remote),
                                format!(
                                    "Process '{}' (PID {}) has its standard I/O ({} of 3 streams) \
                                     redirected to network sockets. This is the definitive signature \
                                     of a reverse shell. Remote endpoint: {}. Cmdline: {}",
                                    comm, pid, redirected_fds, remote, cmdline.trim()
                                ),
                                Severity::Critical,
                                "Network",
                                100,
                            );
                            r = r
                                .with_artifacts(vec![
                                    format!("PID: {}", pid),
                                    format!("Process: {}", comm),
                                    format!("Remote: {}", remote),
                                    format!("Redirected FDs: {}", redirected_fds),
                                    format!("Cmdline: {}", cmdline.trim()),
                                ])
                                .with_mitre("T1059 - Command and Scripting Interpreter")
                                .with_recommendations(vec![
                                    format!("IMMEDIATELY kill: kill -9 {}", pid),
                                    format!("Block remote IP: iptables -A OUTPUT -d {} -j DROP",
                                        remote.split(':').next().unwrap_or("")),
                                    "Capture network traffic for forensics".into(),
                                    "Assume full system compromise — isolate immediately".into(),
                                ]);
                            findings.push(r);
                        }
                    }
                }
            }
        }
        findings
    }

    fn check_port_scanner(&self, conns: &[TcpConnection]) -> Vec<ScanResult> {
        let mut findings = Vec::new();

        // Group SYN_SENT connections by source process
        let mut pid_targets: HashMap<u32, HashSet<String>> = HashMap::new();

        for conn in conns {
            if conn.state == "SYN_SENT" {
                if let Some(pid) = conn.pid {
                    pid_targets.entry(pid)
                        .or_default()
                        .insert(format!("{}:{}", conn.remote_addr, conn.remote_port));
                }
            }
        }

        for (pid, targets) in &pid_targets {
            if targets.len() > 20 {
                let process_name = self.get_process_name(*pid);
                let mut r = ScanResult::new(
                    format!("Port scanner detected: {} (PID {}) scanning {} targets", process_name, pid, targets.len()),
                    format!(
                        "Process '{}' (PID {}) has {} simultaneous SYN_SENT connections \
                         to different hosts/ports. This is consistent with an active port scan \
                         or network reconnaissance.",
                        process_name, pid, targets.len()
                    ),
                    Severity::High,
                    "Network",
                    80,
                );
                r = r
                    .with_artifacts(vec![
                        format!("Process: {} (PID {})", process_name, pid),
                        format!("Targets: {} unique", targets.len()),
                        format!("Sample targets: {}", targets.iter().take(5).cloned().collect::<Vec<_>>().join(", ")),
                    ])
                    .with_mitre("T1046 - Network Service Discovery");
                findings.push(r);
            }
        }
        findings
    }

    fn check_unexpected_listeners(&self, conns: &[TcpConnection]) -> Vec<ScanResult> {
        let mut findings = Vec::new();

        let known_listeners: HashSet<u16> = [22, 80, 443, 25, 587, 465, 110, 143, 993, 995, 53, 123, 3306, 5432, 6379, 27017].iter().copied().collect();

        for conn in conns {
            if conn.state != "LISTEN" {
                continue;
            }
            if !known_listeners.contains(&conn.local_port) {
                let process_name = conn.pid.map(|p| self.get_process_name(p)).unwrap_or_default();

                // Skip high-numbered ports that are likely ephemeral/legitimate app ports
                if conn.local_port > 10000 {
                    continue;
                }

                let severity = if conn.local_addr == "0.0.0.0" {
                    Severity::Medium // Listening on all interfaces is more concerning
                } else {
                    Severity::Low
                };

                let mut r = ScanResult::new(
                    format!("Unexpected listener on port {} (process: {})", conn.local_port, process_name),
                    format!(
                        "Process '{}' is listening on {}:{} which is not a standard service port. \
                         Unexpected listeners may indicate backdoors, reverse proxies, or unauthorized services.",
                        process_name, conn.local_addr, conn.local_port
                    ),
                    severity,
                    "Network",
                    45,
                );
                r = r
                    .with_artifacts(vec![
                        format!("Listener: {}:{}", conn.local_addr, conn.local_port),
                        format!("Process: {} (PID {:?})", process_name, conn.pid),
                    ])
                    .with_mitre("T1049 - System Network Connections Discovery");
                findings.push(r);
            }
        }
        findings
    }

    fn check_dns_tunneling(&self) -> Vec<ScanResult> {
        let mut findings = Vec::new();

        // Check /proc/net/udp for DNS traffic patterns
        // We check /etc/resolv.conf for suspicious DNS servers
        if let Ok(resolv) = fs::read_to_string("/etc/resolv.conf") {
            for line in resolv.lines() {
                if line.starts_with("nameserver") {
                    let ip = line.trim_start_matches("nameserver").trim();
                    // Check for non-standard DNS servers (not 1.1.1.1, 8.8.8.8, 8.8.4.4, etc.)
                    let well_known_dns = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "208.67.222.222"];
                    let is_well_known = well_known_dns.contains(&ip)
                        || ip.starts_with("192.168.")
                        || ip.starts_with("10.")
                        || ip.starts_with("172.");

                    if !is_well_known {
                        let mut r = ScanResult::new(
                            format!("Non-standard DNS server configured: {}", ip),
                            format!(
                                "DNS resolver '{}' is configured in /etc/resolv.conf. \
                                 Unknown DNS servers may log all DNS queries (surveillance) or \
                                 be used for DNS tunneling C2 communication.",
                                ip
                            ),
                            Severity::Medium,
                            "Network",
                            50,
                        );
                        r = r
                            .with_artifacts(vec![format!("DNS server: {}", ip)])
                            .with_mitre("T1071.004 - Application Layer Protocol: DNS");
                        findings.push(r);
                    }
                }
            }
        }

        // Check for high-entropy subdomains in DNS cache
        // We can check /proc/net/fib_trie for cached routes but it's complex
        // Instead, parse any accessible DNS cache or recent DNS queries from logs
        let dns_log_paths = ["/var/log/dnsmasq.log", "/var/log/named/queries.log"];
        for log_path in &dns_log_paths {
            if let Ok(content) = fs::read_to_string(log_path) {
                let re_query = Regex::new(r"query\[A\] (\S+) from").unwrap();
                let mut high_entropy_domains = Vec::new();

                for line in content.lines().take(10_000) {
                    if let Some(cap) = re_query.captures(line) {
                        let domain = &cap[1];
                        let subdomain = domain.split('.').next().unwrap_or(domain);
                        let entropy = shannon_entropy(subdomain);
                        if entropy > self.cfg.network.high_entropy_dns_threshold && subdomain.len() > 15 {
                            high_entropy_domains.push(format!("{} (entropy: {:.2})", domain, entropy));
                        }
                    }
                }

                if !high_entropy_domains.is_empty() {
                    let mut r = ScanResult::new(
                        format!("{} high-entropy DNS queries detected (possible DNS tunneling)", high_entropy_domains.len()),
                        "DNS queries with unusually high entropy subdomains were detected. \
                         DNS tunneling malware encodes data in DNS labels, producing high-entropy \
                         (random-looking) subdomain strings.",
                        Severity::High,
                        "Network",
                        82,
                    );
                    r = r
                        .with_artifacts(high_entropy_domains.iter().take(5).cloned().collect())
                        .with_mitre("T1071.004 - Application Layer Protocol: DNS")
                        .with_recommendations(vec![
                            "Analyze DNS traffic with: tcpdump -i any port 53".into(),
                            "Install DNS monitoring: dnstap or dnscap".into(),
                        ]);
                    findings.push(r);
                }
            }
        }

        findings
    }

    fn check_arp_table(&self) -> Vec<ScanResult> {
        let mut findings = Vec::new();

        if let Ok(content) = fs::read_to_string("/proc/net/arp") {
            let mut ip_to_macs: HashMap<String, Vec<String>> = HashMap::new();
            let mut mac_to_ips: HashMap<String, Vec<String>> = HashMap::new();

            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 4 {
                    continue;
                }
                let ip = parts[0].to_string();
                let mac = parts[3].to_string();

                if mac == "00:00:00:00:00:00" {
                    continue;
                }

                ip_to_macs.entry(ip.clone()).or_default().push(mac.clone());
                mac_to_ips.entry(mac).or_default().push(ip);
            }

            // Check for IP with multiple MACs (ARP poisoning indicator)
            for (ip, macs) in &ip_to_macs {
                if macs.len() > 1 {
                    let mut r = ScanResult::new(
                        format!("ARP poisoning detected: {} has {} MAC addresses", ip, macs.len()),
                        format!(
                            "IP address '{}' is associated with multiple MAC addresses: {}. \
                             This is a strong indicator of ARP poisoning/spoofing, \
                             used for man-in-the-middle attacks.",
                            ip, macs.join(", ")
                        ),
                        Severity::Critical,
                        "Network",
                        95,
                    );
                    r = r
                        .with_artifacts(vec![
                            format!("IP: {}", ip),
                            format!("MACs: {}", macs.join(", ")),
                        ])
                        .with_mitre("T1557.002 - Adversary-in-the-Middle: ARP Cache Poisoning")
                        .with_recommendations(vec![
                            "Use static ARP entries for critical hosts".into(),
                            "Enable dynamic ARP inspection on managed switches".into(),
                            "Run: arp -d {} to clear cache".to_string().replace("{}", ip),
                        ]);
                    findings.push(r);
                }
            }

            // Check for MAC address with multiple IPs (gateway spoofing)
            for (mac, ips) in &mac_to_ips {
                if ips.len() > 3 {
                    let mut r = ScanResult::new(
                        format!("Single MAC {} claiming {} IPs — possible ARP spoof", mac, ips.len()),
                        format!(
                            "MAC address '{}' is associated with {} IP addresses: {}. \
                             A legitimate host rarely has this many IPs in the ARP table.",
                            mac, ips.len(), ips.join(", ")
                        ),
                        Severity::High,
                        "Network",
                        78,
                    );
                    r = r
                        .with_artifacts(vec![
                            format!("MAC: {}", mac),
                            format!("IPs: {}", ips.join(", ")),
                        ])
                        .with_mitre("T1557.002 - Adversary-in-the-Middle: ARP Cache Poisoning");
                    findings.push(r);
                }
            }
        }
        findings
    }

    fn check_routing_table(&self) -> Vec<ScanResult> {
        let mut findings = Vec::new();

        if let Ok(content) = fs::read_to_string("/proc/net/route") {
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 3 {
                    continue;
                }
                let iface = parts[0];
                let dest_hex = parts[1];
                let gateway_hex = parts[2];

                // Check for suspicious default routes
                if dest_hex == "00000000" {
                    if let Some(gw_ip) = self.parse_hex_ip(gateway_hex) {
                        // Default route to loopback is suspicious
                        if gw_ip == "127.0.0.1" {
                            let mut r = ScanResult::new(
                                "Default route points to loopback — possible traffic redirection",
                                format!(
                                    "Default network route (0.0.0.0/0) via interface '{}' points to \
                                     loopback address {}. This could indicate a local proxy \
                                     intercepting all outbound traffic.",
                                    iface, gw_ip
                                ),
                                Severity::High,
                                "Network",
                                80,
                            );
                            r = r
                                .with_artifacts(vec![
                                    format!("Interface: {}", iface),
                                    format!("Gateway: {}", gw_ip),
                                ])
                                .with_mitre("T1557 - Adversary-in-the-Middle");
                            findings.push(r);
                        }
                    }
                }
            }
        }
        findings
    }

    fn check_promiscuous_interfaces(&self) -> Vec<ScanResult> {
        let mut findings = Vec::new();

        if let Ok(content) = fs::read_to_string("/proc/net/dev") {
            // Check interface flags via /sys/class/net
            if let Ok(net_entries) = fs::read_dir("/sys/class/net") {
                for entry in net_entries.flatten() {
                    let iface = entry.file_name().to_string_lossy().to_string();
                    if iface == "lo" {
                        continue;
                    }

                    let flags_path = format!("/sys/class/net/{}/flags", iface);
                    if let Ok(flags_str) = fs::read_to_string(&flags_path) {
                        if let Ok(flags) = u32::from_str_radix(flags_str.trim().trim_start_matches("0x"), 16) {
                            let IFF_PROMISC = 0x100u32;
                            if flags & IFF_PROMISC != 0 {
                                let mut r = ScanResult::new(
                                    format!("Interface {} is in promiscuous mode (sniffing traffic)", iface),
                                    format!(
                                        "Network interface '{}' is in PROMISC mode, meaning it captures \
                                         ALL network traffic, not just packets addressed to this host. \
                                         This is a strong indicator of a network sniffer or man-in-the-middle attack.",
                                        iface
                                    ),
                                    Severity::Critical,
                                    "Network",
                                    93,
                                );
                                r = r
                                    .with_artifacts(vec![
                                        format!("Interface: {}", iface),
                                        format!("Flags: 0x{:08x}", flags),
                                    ])
                                    .with_mitre("T1040 - Network Sniffing")
                                    .with_recommendations(vec![
                                        format!("Disable: ip link set {} promisc off", iface),
                                        "Find what process enabled this: look for tcpdump, wireshark, etc.".into(),
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

    fn check_iptables_rules(&self) -> Vec<ScanResult> {
        let mut findings = Vec::new();

        // Check if iptables is available and read rules
        let output = std::process::Command::new("iptables")
            .args(["-L", "-n", "--line-numbers"])
            .output();

        if let Ok(out) = output {
            let rules = String::from_utf8_lossy(&out.stdout).to_string();
            if rules.contains("ACCEPT") && !rules.contains("DROP") && !rules.contains("REJECT") {
                let mut r = ScanResult::new(
                    "Firewall has ACCEPT-all policy — no DROP/REJECT rules",
                    "The iptables firewall appears to have no DROP or REJECT rules, \
                     only ACCEPT. This means the firewall is effectively disabled, \
                     allowing all inbound and outbound connections.",
                    Severity::High,
                    "Network",
                    75,
                );
                r = r
                    .with_mitre("T1562.004 - Impair Defenses: Disable or Modify System Firewall")
                    .with_recommendations(vec![
                        "Implement restrictive firewall rules".into(),
                        "Or enable UFW: ufw enable".into(),
                    ]);
                findings.push(r);
            }
        }

        findings
    }

    fn check_raw_sockets(&self) -> Vec<ScanResult> {
        let mut findings = Vec::new();

        if let Ok(content) = fs::read_to_string("/proc/net/packet") {
            let socket_count = content.lines().skip(1).count();
            if socket_count > 5 {
                let mut r = ScanResult::new(
                    format!("{} raw packet sockets open", socket_count),
                    format!(
                        "{} raw packet sockets are open. Raw sockets can capture all network \
                         traffic and craft arbitrary packets. This may indicate a network \
                         sniffer, packet injection tool, or advanced malware.",
                        socket_count
                    ),
                    Severity::Medium,
                    "Network",
                    55,
                );
                r = r
                    .with_artifacts(vec![format!("Raw socket count: {}", socket_count)])
                    .with_mitre("T1040 - Network Sniffing");
                findings.push(r);
            }
        }
        findings
    }

    fn is_private_ip(&self, ip: &str) -> bool {
        if let Ok(addr) = ip.parse::<std::net::Ipv4Addr>() {
            return addr.is_private() || addr.is_loopback() || addr.is_link_local() || addr.is_unspecified();
        }
        ip == "0.0.0.0" || ip.starts_with("127.") || ip.starts_with("192.168.")
            || ip.starts_with("10.") || ip.starts_with("172.")
    }
}
