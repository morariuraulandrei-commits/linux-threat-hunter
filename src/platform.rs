/// Platform detection helpers for cross-environment compatibility
/// Supports: standard Linux, WSL1, WSL2, containers (Docker/Podman/LXC)

use std::fs;

/// Returns true if running inside Windows Subsystem for Linux (WSL1 or WSL2)
pub fn is_wsl() -> bool {
    // Check /proc/version for "Microsoft" or "WSL"
    if let Ok(version) = fs::read_to_string("/proc/version") {
        let v = version.to_lowercase();
        if v.contains("microsoft") || v.contains("wsl") {
            return true;
        }
    }
    // Check /proc/sys/kernel/osrelease
    if let Ok(osrelease) = fs::read_to_string("/proc/sys/kernel/osrelease") {
        let o = osrelease.to_lowercase();
        if o.contains("microsoft") || o.contains("wsl") {
            return true;
        }
    }
    false
}

/// Returns true if running inside a container (Docker, Podman, LXC, etc.)
pub fn is_container() -> bool {
    // Docker: /.dockerenv exists
    if std::path::Path::new("/.dockerenv").exists() {
        return true;
    }
    // Check cgroup for docker/lxc/podman
    if let Ok(cgroup) = fs::read_to_string("/proc/1/cgroup") {
        if cgroup.contains("docker") || cgroup.contains("lxc") || cgroup.contains("podman") {
            return true;
        }
    }
    false
}

/// Returns true if the current process has root privileges
pub fn is_root() -> bool {
    unsafe { libc::getuid() == 0 }
}

/// Check if a /proc/net/ file is accessible and non-empty (WSL may have limited /proc/net)
pub fn proc_net_available(name: &str) -> bool {
    let path = format!("/proc/net/{}", name);
    fs::metadata(&path)
        .map(|m| m.len() > 0)
        .unwrap_or(false)
}

/// Returns a human-readable environment description
pub fn describe_environment() -> String {
    if is_wsl() {
        "WSL (Windows Subsystem for Linux)".into()
    } else if is_container() {
        "Container (Docker/Podman/LXC)".into()
    } else {
        "Native Linux".into()
    }
}
