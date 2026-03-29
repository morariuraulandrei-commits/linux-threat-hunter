# ⚡ Linux Threat Hunting Framework (LTHF)

> **⚠️ Support / Errors?**
> If you encounter any issues, bugs, or compilation errors, please contact:
> **📧 contact@morariuandreiraul.com**
> I'll do my best to help you as quickly as possible.

<div align="center">
  <img src="https://media1.tenor.com/m/XKNjuLjL7W8AAAAd/naruto-thumbs-up.gif" alt="Naruto thumbs up" width="200"/>
</div>

---

<p align="center">
  <img src="https://img.shields.io/badge/language-Rust-orange?style=for-the-badge&logo=rust" alt="Rust">
  <img src="https://img.shields.io/badge/platform-Linux-blue?style=for-the-badge&logo=linux" alt="Linux">
  <img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge" alt="MIT License">
  <img src="https://img.shields.io/badge/MITRE-ATT%26CK-red?style=for-the-badge" alt="MITRE ATT&CK">
  <img src="https://img.shields.io/github/v/release/morariuraulandrei-commits/linux-threat-hunter?style=for-the-badge" alt="Release">
</p>

> [A high-performance, Rust-powered Linux threat hunting engine] detects malware, rootkits, reverse shells, brute force attacks, file tampering, and network-level threats in real-time.

---

## Features

### Process Scanner
- Detects fileless malware (memfd_create, anonymous mappings)
- Finds processes running from deleted executables
- Identifies LD_PRELOAD injection per-process
- Detects webshells (web server spawning shells)
- Finds processes being ptrace-traced (injection)
- Detects processes running from /tmp, /dev/shm with network connections
- PID gap analysis for kernel-level process hiding
- Cryptominer detection (high-CPU processes from temp dirs)
- Zombie process accumulation (fork bomb indicator)

### File Integrity Monitor
- SUID/SGID binary detection with whitelist
- World-writable files in sensitive directories
- Executable files in /tmp, /dev/shm (ELF detection via magic bytes)
- /etc/ld.so.preload rootkit detection with library hash
- Crontab analysis for suspicious entries (curl|bash, base64 decode, etc.)
- SSH authorized_keys audit for all users
- Kernel module analysis for rootkit names (Diamorphine, Reptile, etc.)
- Recently modified system binaries detection
- Kernel security parameter hardening check
- /etc/shadow permissions audit

### Log Analyzer
- SSH brute force detection by IP (configurable threshold)
- Password spray detection by username
- Root account brute force alerts
- Privilege escalation attempt tracking (su/sudo failures)
- Bash history forensic analysis (reverse shells, obfuscation, anti-forensics)
- Syslog analysis: OOM kills, segfaults, kernel panics, USB insertions
- Audit log analysis: syscall failures, privilege-change events
- Log tampering detection (truncated/empty log files)
- btmp analysis for failed login volume
- Active session monitoring (root logins, concurrent sessions)

### Network Hunter
- Scans for suspicious ports (4444, 31337, Metasploit defaults, Tor ports)
- Reverse shell detection (stdin/stdout/stderr redirected to sockets)
- ARP poisoning detection via multi-MAC and multi-IP analysis
- Tor connection detection
- Promiscuous interface detection (PROMISC flag)
- Port scanner detection (high SYN_SENT count)
- DNS tunneling via Shannon entropy analysis
- Raw packet socket monitoring
- Default route hijacking detection
- C2 connection matching against IOC list

---

## Installation

### Build from source
```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Clone and build
git clone https://github.com/morariuraulandrei-commits/linux-threat-hunter
cd linux-threat-hunter
cargo build --release
sudo cp target/release/lthf /usr/local/bin/
```

---

## Usage

```bash
# Full scan
sudo lthf scan --all --verbose

# Module-specific scans
sudo lthf scan --processes -v
sudo lthf scan --files -v
sudo lthf scan --logs -v
sudo lthf scan --network -v

# Export reports
sudo lthf scan --all --output report.html --format html
sudo lthf scan --all --output findings.json --format json

# Interactive TUI
sudo lthf watch
```

---

## Security Notes

- Requires root for full scan capabilities
- The binary has no network connections — 100% offline analysis
- All /proc reads are read-only — no system modifications

---

## License

MIT License © 2024 morariuraulandrei-commits
