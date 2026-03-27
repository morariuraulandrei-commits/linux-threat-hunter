// === FILE: src/modules/container_sentinel.rs ===

use super::{ScanResult, Severity};
use crate::config::Config;
use anyhow::Result;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

pub struct ContainerSentinel {
    cfg: Config,
}

impl ContainerSentinel {
    pub fn new(cfg: Config) -> Self {
        Self { cfg }
    }

    pub async fn scan(&mut self) -> Result<Vec<ScanResult>> {
        let mut findings: Vec<ScanResult> = Vec::new();

        // Check 1: Detect container environment
        if !self.detect_container_environment() {
            // Not running in a container, skip most checks
            return Ok(findings);
        }

        // Check 2: Privileged container detection
        if let Ok(f) = self.check_privileged_container() {
            findings.extend(f);
        }

        // Check 3: Dangerous capabilities
        if let Ok(f) = self.check_dangerous_capabilities() {
            findings.extend(f);
        }

        // Check 4: Docker socket exposure
        if let Ok(f) = self.check_docker_socket() {
            findings.extend(f);
        }

        // Check 5: Kubernetes service account token
        if let Ok(f) = self.check_kubernetes_token() {
            findings.extend(f);
        }

        // Check 6: Cloud metadata service
        if let Ok(f) = self.check_cloud_metadata() {
            findings.extend(f);
        }

        // Check 7: Host filesystem mounts
        if let Ok(f) = self.check_host_mounts() {
            findings.extend(f);
        }

        // Check 8: Namespace escape indicators
        if let Ok(f) = self.check_namespace_escape() {
            findings.extend(f);
        }

        // Check 9: Writable sensitive paths
        if let Ok(f) = self.check_writable_sensitive_paths() {
            findings.extend(f);
        }

        // Check 10: seccomp/AppArmor disabled
        if let Ok(f) = self.check_security_profiles() {
            findings.extend(f);
        }

        // Check 11: Container resource abuse
        if let Ok(f) = self.check_resource_limits() {
            findings.extend(f);
        }

        // Check 12: SUID binaries in container
        if let Ok(f) = self.check_suid_binaries() {
            findings.extend(f);
        }

        Ok(findings)
    }

    fn detect_container_environment(&self) -> bool {
        // Check for Docker
        if Path::new("/.dockerenv").exists() {
            return true;
        }

        // Check for LXC
        if let Ok(environ) = fs::read_to_string("/proc/1/environ") {
            if environ.contains("container=lxc") || environ.contains("container=docker") {
                return true;
            }
        }

        // Check for Kubernetes
        if Path::new("/run/secrets/kubernetes.io").exists() {
            return true;
        }

        // Check for Podman
        if Path::new("/run/.containerenv").exists() {
            return true;
        }

        false
    }

    fn check_privileged_container(&self) -> Result<Vec<ScanResult>> {
        let mut findings = Vec::new();

        // Read /proc/self/status for CapEff field
        if let Ok(status) = fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if line.starts_with("CapEff:") {
                    let cap_hex = line.split_whitespace().nth(1).unwrap_or("0");

                    // ffffffffffffffff indicates all capabilities (privileged)
                    if cap_hex == "ffffffffffffffff" {
                        let container_id = self.get_container_id();

                        let mut r = ScanResult::new(
                            "Privileged container detected",
                            format!(
                                "Container has all capabilities enabled (CapEff: {}), \
                                 indicating privileged mode. This allows the container to escape and compromise the host. {}",
                                cap_hex,
                                if let Some(id) = &container_id {
                                    format!("Container ID: {}", id)
                                } else {
                                    String::new()
                                }
                            ),
                            Severity::Critical,
                            "Container",
                            95,
                        );
                        r = r
                            .with_artifacts(vec![
                                format!("CapEff: {}", cap_hex),
                                "Container mode: PRIVILEGED".to_string(),
                                if let Some(id) = container_id {
                                    format!("Container ID: {}", id)
                                } else {
                                    String::new()
                                },
                            ])
                            .with_mitre("T1611 - Escape to Host")
                            .with_recommendations(vec![
                                "Do not run containers with --privileged flag".into(),
                                "Use fine-grained capability control instead".into(),
                                "Verify container runtime security policies".into(),
                                "Consider using seccomp and AppArmor profiles".into(),
                            ]);
                        findings.push(r);
                    }
                    break;
                }
            }
        }

        Ok(findings)
    }

    fn check_dangerous_capabilities(&self) -> Result<Vec<ScanResult>> {
        let mut findings = Vec::new();

        if let Ok(status) = fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if line.starts_with("CapEff:") {
                    let cap_hex = line.split_whitespace().nth(1).unwrap_or("0");

                    if let Ok(cap_val) = u64::from_str_radix(cap_hex, 16) {
                        let dangerous_caps = vec![
                            (21, "CAP_SYS_ADMIN", "Mount filesystems, use namespaces, module load"),
                            (19, "CAP_SYS_PTRACE", "Attach ptrace to any process"),
                            (12, "CAP_NET_ADMIN", "Configure network, modify firewall"),
                            (16, "CAP_SYS_MODULE", "Load and unload kernel modules"),
                            (7, "CAP_SETUID", "Change UID for privilege escalation"),
                            (6, "CAP_SETGID", "Change GID for privilege escalation"),
                            (1, "CAP_DAC_OVERRIDE", "Bypass file permission checks"),
                        ];

                        for (bit, cap_name, description) in dangerous_caps {
                            if (cap_val >> bit) & 1 == 1 {
                                let severity = match cap_name {
                                    "CAP_SYS_ADMIN" | "CAP_SYS_PTRACE" | "CAP_SYS_MODULE" => Severity::Critical,
                                    _ => Severity::High,
                                };
                                let threat_score = match cap_name {
                                    "CAP_SYS_ADMIN" | "CAP_SYS_PTRACE" | "CAP_SYS_MODULE" => 90,
                                    _ => 80,
                                };

                                let mut r = ScanResult::new(
                                    format!("Dangerous capability enabled: {}", cap_name),
                                    format!(
                                        "Container has capability {} (bit {}) which permits: {}. \
                                         This is a serious container escape vector.",
                                        cap_name, bit, description
                                    ),
                                    severity,
                                    "Container",
                                    threat_score,
                                );
                                r = r
                                    .with_artifacts(vec![
                                        format!("Capability: {}", cap_name),
                                        format!("Hex value: {}", cap_hex),
                                    ])
                                    .with_mitre("T1611 - Escape to Host")
                                    .with_recommendations(vec![
                                        format!("Remove capability: docker run --cap-drop {}", cap_name),
                                        "Use principle of least privilege".into(),
                                        "Define custom seccomp profiles".into(),
                                    ]);
                                findings.push(r);
                            }
                        }
                    }
                    break;
                }
            }
        }

        Ok(findings)
    }

    fn check_docker_socket(&self) -> Result<Vec<ScanResult>> {
        let mut findings = Vec::new();

        let docker_sockets = vec!["/var/run/docker.sock", "/run/docker.sock"];

        for socket_path in docker_sockets {
            if Path::new(socket_path).exists() {
                if let Ok(metadata) = fs::metadata(socket_path) {
                    let mut r = ScanResult::new(
                        format!("Docker socket exposed: {}", socket_path),
                        format!(
                            "Docker socket at {} is accessible from within the container. \
                             An attacker can use this to create privileged containers and escape to the host.",
                            socket_path
                        ),
                        Severity::Critical,
                        "Container",
                        95,
                    );
                    r = r
                        .with_artifacts(vec![
                            format!("Socket: {}", socket_path),
                            format!("Accessible: true"),
                        ])
                        .with_mitre("T1552.007 - Unsecured Credentials: Container API")
                        .with_recommendations(vec![
                            "Do not mount Docker socket into containers".into(),
                            "If necessary, use Docker Socket Proxy with restricted permissions".into(),
                            "Implement container runtime security policies".into(),
                            "Monitor docker.sock access from containers".into(),
                        ]);
                    findings.push(r);
                }
            }
        }

        Ok(findings)
    }

    fn check_kubernetes_token(&self) -> Result<Vec<ScanResult>> {
        let mut findings = Vec::new();

        let token_paths = vec![
            "/run/secrets/kubernetes.io/serviceaccount/token",
            "/var/run/secrets/kubernetes.io/serviceaccount/token",
        ];

        for token_path in token_paths {
            if Path::new(token_path).exists() {
                if let Ok(metadata) = fs::metadata(token_path) {
                    let mode = metadata.permissions().mode();
                    let world_readable = (mode & 0o004) != 0;

                    if world_readable {
                        let mut r = ScanResult::new(
                            "Kubernetes service account token exposed",
                            format!(
                                "Kubernetes service account token at {} is world-readable. \
                                 Any process in the container can use this token to access the Kubernetes API.",
                                token_path
                            ),
                            Severity::High,
                            "Container",
                            85,
                        );
                        r = r
                            .with_artifacts(vec![
                                format!("Token path: {}", token_path),
                                format!("Permissions: {:o}", mode & 0o777),
                            ])
                            .with_mitre("T1552.007 - Unsecured Credentials: Container API")
                            .with_recommendations(vec![
                                "Restrict token file permissions to 0600".into(),
                                "Use RBAC for service account permissions".into(),
                                "Enable pod security policies".into(),
                            ]);
                        findings.push(r);
                    }
                }
            }
        }

        Ok(findings)
    }

    fn check_cloud_metadata(&self) -> Result<Vec<ScanResult>> {
        let mut findings = Vec::new();

        // Check for metadata service routes
        if let Ok(route_content) = fs::read_to_string("/proc/net/route") {
            for line in route_content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let destination = parts[1];
                    // 169.254.169.254 in hex is 0xa9fea9fe (little-endian in route table)
                    if destination.contains("a9fe") || destination.contains("169.254") {
                        let mut r = ScanResult::new(
                            "Cloud metadata service route detected",
                            "Route to 169.254.169.254 (AWS/GCP/Azure metadata service) detected. \
                             Container may attempt to access cloud credentials through metadata endpoint.",
                            Severity::High,
                            "Container",
                            75,
                        );
                        r = r
                            .with_artifacts(vec![format!("Route destination: {}", destination)])
                            .with_mitre("T1613 - Container and Resource Discovery")
                            .with_recommendations(vec![
                                "Disable metadata service access from containers".into(),
                                "Use IMDSv2 with token requirement".into(),
                                "Implement network policies to block metadata endpoints".into(),
                            ]);
                        findings.push(r);
                    }
                }
            }
        }

        // Check for cloud credentials in environment
        let env_vars = vec![
            "AWS_SECRET_ACCESS_KEY",
            "AWS_ACCESS_KEY_ID",
            "GOOGLE_APPLICATION_CREDENTIALS",
            "AZURE_SECRET",
        ];

        for var in env_vars {
            if std::env::var(var).is_ok() {
                let mut r = ScanResult::new(
                    format!("Cloud credential exposed in environment: {}", var),
                    format!(
                        "Environment variable {} is set, potentially exposing cloud credentials. \
                         Any process in the container can read environment variables.",
                        var
                    ),
                    Severity::Critical,
                    "Container",
                    90,
                );
                r = r
                    .with_artifacts(vec![format!("Variable: {}", var)])
                    .with_mitre("T1552.001 - Unsecured Credentials: Credentials In Files")
                    .with_recommendations(vec![
                        "Use container secrets management instead of env vars".into(),
                        "Pass credentials via mounted secrets".into(),
                        "Use cloud provider's workload identity features".into(),
                    ]);
                findings.push(r);
            }
        }

        Ok(findings)
    }

    fn check_host_mounts(&self) -> Result<Vec<ScanResult>> {
        let mut findings = Vec::new();

        if let Ok(mounts) = fs::read_to_string("/proc/mounts") {
            for line in mounts.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let device = parts[0];
                    let mount_point = parts[1];

                    // Check for dangerous bind mounts
                    if device.starts_with('/') && !device.contains("tmpfs") && !device.contains("devtmpfs") {
                        let dangerous_paths = vec![
                            "/", "/etc", "/proc", "/sys", "/dev", "/root", "/home",
                            "/var", "/bin", "/sbin", "/usr/bin", "/usr/sbin",
                        ];

                        for dangerous in &dangerous_paths {
                            if device == *dangerous || (device.starts_with('/') && mount_point == *dangerous) {
                                let mut r = ScanResult::new(
                                    format!("Host filesystem mount exposed: {}", mount_point),
                                    format!(
                                        "Host path {} is mounted at {} in the container, \
                                         providing direct access to host filesystem. This is a critical escape vector.",
                                        device, mount_point
                                    ),
                                    Severity::Critical,
                                    "Container",
                                    90,
                                );
                                r = r
                                    .with_artifacts(vec![
                                        format!("Host path: {}", device),
                                        format!("Container path: {}", mount_point),
                                    ])
                                    .with_mitre("T1611 - Escape to Host")
                                    .with_recommendations(vec![
                                        "Avoid mounting sensitive host paths".into(),
                                        "Use read-only mounts where possible".into(),
                                        "Implement mount point monitoring".into(),
                                    ]);
                                findings.push(r);
                                break;
                            }
                        }
                    }
                }
            }
        }

        Ok(findings)
    }

    fn check_namespace_escape(&self) -> Result<Vec<ScanResult>> {
        let mut findings = Vec::new();

        let namespace_types = vec!["pid", "mnt", "net", "ipc", "uts", "user"];

        for ns_type in namespace_types {
            let container_ns_path = format!("/proc/self/ns/{}", ns_type);
            let host_ns_path = format!("/proc/1/ns/{}", ns_type);

            if let (Ok(container_ns), Ok(host_ns)) = (
                fs::read_link(&container_ns_path),
                fs::read_link(&host_ns_path),
            ) {
                if container_ns == host_ns {
                    let severity = match ns_type {
                        "pid" | "mnt" => Severity::Critical,
                        _ => Severity::High,
                    };
                    let threat_score = match ns_type {
                        "pid" | "mnt" => 90,
                        _ => 75,
                    };

                    let mut r = ScanResult::new(
                        format!("Shared {} namespace with host", ns_type),
                        format!(
                            "Container shares the {} namespace with the host (PID 1). \
                             This allows the container to see and interact with host processes/filesystems, \
                             enabling container escape.",
                            ns_type
                        ),
                        severity,
                        "Container",
                        threat_score,
                    );
                    r = r
                        .with_artifacts(vec![
                            format!("Namespace: {}", ns_type),
                            format!("Container ns: {}", container_ns.to_string_lossy()),
                            format!("Host ns: {}", host_ns.to_string_lossy()),
                        ])
                        .with_mitre("T1611 - Escape to Host")
                        .with_recommendations(vec![
                            format!("Do not use --{}=host flag", ns_type),
                            "Use container-specific namespaces for isolation".into(),
                            "Verify docker run flags and container specs".into(),
                        ]);
                    findings.push(r);
                }
            }
        }

        Ok(findings)
    }

    fn check_writable_sensitive_paths(&self) -> Result<Vec<ScanResult>> {
        let mut findings = Vec::new();

        let sensitive_files = vec![
            "/etc/crontab",
            "/etc/sudoers",
            "/root/.ssh/authorized_keys",
            "/etc/passwd",
            "/etc/shadow",
        ];

        for file_path in sensitive_files {
            if Path::new(file_path).exists() {
                if let Ok(metadata) = fs::metadata(file_path) {
                    let mode = metadata.permissions().mode();
                    let writable = (mode & 0o200) != 0; // User writable

                    if writable && (mode & 0o020) != 0 {
                        // Group writable
                        let mut r = ScanResult::new(
                            format!("Sensitive file is group-writable: {}", file_path),
                            format!(
                                "File {} has group-write permissions (mode {:o}). \
                                 Any group member can modify this file, compromising security.",
                                file_path,
                                mode & 0o777
                            ),
                            Severity::High,
                            "Container",
                            80,
                        );
                        r = r
                            .with_artifacts(vec![
                                format!("File: {}", file_path),
                                format!("Permissions: {:o}", mode & 0o777),
                            ])
                            .with_mitre("T1611 - Escape to Host")
                            .with_recommendations(vec![
                                format!("Fix permissions: chmod g-w {}", file_path),
                                "Audit file access logs".into(),
                                "Verify no unauthorized modifications".into(),
                            ]);
                        findings.push(r);
                    }

                    if (mode & 0o002) != 0 {
                        // World writable
                        let mut r = ScanResult::new(
                            format!("Sensitive file is world-writable: {}", file_path),
                            format!(
                                "File {} is world-writable (mode {:o}). \
                                 Any user can modify this critical file.",
                                file_path,
                                mode & 0o777
                            ),
                            Severity::Critical,
                            "Container",
                            90,
                        );
                        r = r
                            .with_artifacts(vec![
                                format!("File: {}", file_path),
                                format!("Permissions: {:o}", mode & 0o777),
                            ])
                            .with_mitre("T1611 - Escape to Host")
                            .with_recommendations(vec![
                                format!("Fix permissions: chmod o-w {}", file_path),
                                "Investigate unauthorized access".into(),
                                "Restore from backup if modified".into(),
                            ]);
                        findings.push(r);
                    }
                }
            }
        }

        Ok(findings)
    }

    fn check_security_profiles(&self) -> Result<Vec<ScanResult>> {
        let mut findings = Vec::new();

        // Check seccomp status
        if let Ok(status) = fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if line.starts_with("Seccomp:") {
                    let seccomp_val = line.split_whitespace().nth(1).unwrap_or("0");

                    if seccomp_val == "0" {
                        let mut r = ScanResult::new(
                            "seccomp is disabled",
                            "seccomp is disabled in this container (Seccomp: 0). \
                             This allows unrestricted syscalls, increasing container escape risk.",
                            Severity::High,
                            "Container",
                            80,
                        );
                        r = r
                            .with_artifacts(vec!["Seccomp: 0 (disabled)".to_string()])
                            .with_mitre("T1611 - Escape to Host")
                            .with_recommendations(vec![
                                "Enable seccomp with default profile".into(),
                                "Use: docker run --security-opt seccomp=default".into(),
                                "Create custom seccomp profiles for your application".into(),
                            ]);
                        findings.push(r);
                    }
                    break;
                }
            }
        }

        // Check AppArmor status
        if Path::new("/proc/self/attr/current").exists() {
            if let Ok(profile) = fs::read_to_string("/proc/self/attr/current") {
                let profile_str = profile.trim();

                if profile_str == "unconfined" {
                    let mut r = ScanResult::new(
                        "AppArmor is unconfined",
                        "AppArmor profile is 'unconfined', providing no mandatory access control. \
                         This allows the container to perform any operation.",
                        Severity::High,
                        "Container",
                        75,
                    );
                    r = r
                        .with_artifacts(vec![format!("Profile: {}", profile_str)])
                        .with_mitre("T1611 - Escape to Host")
                        .with_recommendations(vec![
                            "Apply a restrictive AppArmor profile".into(),
                            "Use: docker run --security-opt apparmor=<profile>".into(),
                            "Review container workload requirements and create minimal profile".into(),
                        ]);
                    findings.push(r);
                }
            }
        }

        Ok(findings)
    }

    fn check_resource_limits(&self) -> Result<Vec<ScanResult>> {
        let mut findings = Vec::new();

        // Check cgroup memory limits
        let cgroup_paths = vec![
            "/sys/fs/cgroup/memory/memory.limit_in_bytes",
            "/sys/fs/cgroup/memory.max",
        ];

        for cgroup_path in cgroup_paths {
            if let Ok(content) = fs::read_to_string(cgroup_path) {
                let limit: u64 = content.trim().parse().unwrap_or(0);

                // 9223372036854771712 is common "unlimited" value
                if limit == 9223372036854771712 || limit > 1_000_000_000_000_000 {
                    let mut r = ScanResult::new(
                        "Container memory limit not set",
                        "Container has unlimited memory available. \
                         A runaway process can exhaust host resources (denial of service).",
                        Severity::Medium,
                        "Container",
                        60,
                    );
                    r = r
                        .with_artifacts(vec![format!("Memory limit: unlimited")])
                        .with_mitre("T1613 - Container and Resource Discovery")
                        .with_recommendations(vec![
                            "Set memory limit: docker run -m 512m".into(),
                            "Configure cgroup resource constraints".into(),
                        ]);
                    findings.push(r);
                    break;
                }
            }
        }

        // Check PIDs limit
        if let Ok(pids_max) = fs::read_to_string("/sys/fs/cgroup/pids/pids.max") {
            if pids_max.trim() == "max" {
                let mut r = ScanResult::new(
                    "Container PID limit not set",
                    "Container can create unlimited processes. \
                     This allows process exhaustion attacks (fork bombs).",
                    Severity::Medium,
                    "Container",
                    65,
                );
                r = r
                    .with_artifacts(vec!["PIDs limit: unlimited".to_string()])
                    .with_mitre("T1613 - Container and Resource Discovery")
                    .with_recommendations(vec![
                        "Set PID limit: docker run --pids-limit 1024".into(),
                        "Configure process limit in systemd or cgroup".into(),
                    ]);
                findings.push(r);
            }
        }

        Ok(findings)
    }

    fn check_suid_binaries(&self) -> Result<Vec<ScanResult>> {
        let mut findings = Vec::new();

        let dangerous_suid_binaries = vec![
            "nsenter", "unshare", "newuidmap", "newgidmap", "capsh", "chroot",
        ];

        // Quick check in common locations
        let search_paths = vec!["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin"];

        for search_path in search_paths {
            if let Ok(entries) = fs::read_dir(search_path) {
                for entry in entries.flatten() {
                    if let Ok(name) = entry.file_name().into_string() {
                        if dangerous_suid_binaries.contains(&name.as_str()) {
                            if let Ok(metadata) = entry.metadata() {
                                let mode = metadata.permissions().mode();
                                if (mode & 0o4000) != 0 {
                                    // SUID bit is set
                                    let mut r = ScanResult::new(
                                        format!("Dangerous SUID binary in container: {}", name),
                                        format!(
                                            "Binary {} is SUID (mode {:o}) in the container. \
                                             This is a critical escape vector for privilege escalation.",
                                            name,
                                            mode & 0o777
                                        ),
                                        Severity::Critical,
                                        "Container",
                                        88,
                                    );
                                    r = r
                                        .with_artifacts(vec![
                                            format!("Binary: {}/{}", search_path, name),
                                            format!("Permissions: {:o}", mode & 0o777),
                                        ])
                                        .with_mitre("T1611 - Escape to Host")
                                        .with_recommendations(vec![
                                            format!("Remove SUID bit: chmod u-s {}/{}", search_path, name),
                                            "Or remove the binary entirely if not needed".into(),
                                            "Use capability restrictions instead of SUID".into(),
                                        ]);
                                    findings.push(r);
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(findings)
    }

    fn get_container_id(&self) -> Option<String> {
        // Try to read container ID from cgroup
        if let Ok(cgroup) = fs::read_to_string("/proc/self/cgroup") {
            for line in cgroup.lines() {
                if line.contains("docker") {
                    // Extract container ID from cgroup path
                    let parts: Vec<&str> = line.split('/').collect();
                    if let Some(container_segment) = parts.last() {
                        if container_segment.len() > 11 {
                            return Some(container_segment[0..12].to_string());
                        }
                    }
                }
            }
        }
        None
    }
}

// Helper trait to get file mode
trait FileMode {
    fn mode(&self) -> u32;
}

#[cfg(unix)]
impl FileMode for std::fs::Permissions {
    fn mode(&self) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        self.mode()
    }
}
