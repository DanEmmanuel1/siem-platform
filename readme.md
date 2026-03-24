# SIEM Platform — Unified Security CLI

A unified command-line platform that controls 6 cybersecurity tools from a single entry point. One command to run any tool, launch the dashboard, schedule automated scans or check system status.

---

## 🎯 Why This Exists

Building 6 separate security tools is one thing. Tying them all together into a single platform is another. This CLI transforms a collection of scripts into a cohesive security operations platform — the same architecture used by enterprise security suites.

---

## 🚀 Commands
```
py siem.py --scan network [IP]         Audit network config & open ports
py siem.py --scan passwords            Analyze password strength & breaches
py siem.py --scan files                Monitor file integrity changes
py siem.py --scan logs                 Analyze Windows Event Log threats
py siem.py --scan vulnerabilities [IP] Scan target for vulnerabilities
py siem.py --scan all [IP]             Run all 5 tools sequentially
py siem.py --dashboard                 Launch SIEM web dashboard
py siem.py --schedule                  Start automated scheduled scans
py siem.py --status                    Show last scan results summary
py siem.py --help                      Show help menu
```

---

## 🔗 Tools Integrated

| Tool | Repo | What It Does |
|------|------|-------------|
| Network Config Auditor | [network-config-auditor](https://github.com/DanEmmanuel1/network-config-auditor) | Ports, firewall, SSH, DNS, interfaces |
| Password Strength Analyzer | [password-strength-analyzer](https://github.com/DanEmmanuel1/password-strength-analyzer) | Breach detection, strength scoring |
| File Integrity Monitor | [file-integrity-monitor](https://github.com/DanEmmanuel1/file-integrity-monitor) | SHA-256 file change detection |
| Log Analyzer | [log-analyzer](https://github.com/DanEmmanuel1/log-analyzer) | Windows Event Log threat detection |
| Vulnerability Scanner | [vulnerability-scanner](https://github.com/DanEmmanuel1/vulnerability-scanner) | Port-based CVE risk scoring |
| SIEM Dashboard | [siem-dashboard](https://github.com/DanEmmanuel1/siem-dashboard) | Live web dashboard for all tools |

---

## 🛠️ Built With

- Python 3.14
- [rich](https://pypi.org/project/rich/) — formatted CLI output
- [argparse](https://docs.python.org/3/library/argparse.html) — command line argument parsing
- subprocess — tool orchestration

---

## 🚀 Getting Started

### Requirements
- Windows 10/11
- Python 3.8+
- All 6 tools cloned and set up individually first
- Administrator privileges for port scanning and log reading

### Installation

1. Clone this repository:
```
git clone https://github.com/DanEmmanuel1/siem-platform.git
cd siem-platform
```

2. Create and activate a virtual environment:
```
python -m venv venv
.\venv\Scripts\activate
```

3. Install dependencies:
```
pip install -r requirements.txt
```

4. Update tool paths in `config.py`:
```python
TOOLS = {
    "network":        r"C:\your-path\network-config-auditor",
    "passwords":      r"C:\your-path\password-analyzer",
    "files":          r"C:\your-path\file-integrity-monitor",
    "logs":           r"C:\your-path\log-analyzer",
    "vulnerabilities": r"C:\your-path\vulnerability-scanner",
    "dashboard":      r"C:\your-path\siem-dashboard",
}
```

5. Run a full audit:
```
py siem.py --scan all
```

---

## 📁 Project Structure
```
siem-platform/
├── siem.py         # Main CLI entry point
├── config.py       # Tool paths and settings
├── reporter.py     # Status reporting
└── requirements.txt
```

---

## ⚠️ Disclaimer

This platform is intended for use on systems you own or have explicit permission to audit.

---

## 👤 Author

**DanEmmanuel1**
- GitHub: [@DanEmmanuel1](https://github.com/DanEmmanuel1)
- LinkedIn: [Emmanuel Dan](https://www.linkedin.com/in/emmanuel-dan-458877212)