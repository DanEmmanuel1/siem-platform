import os

# ============================================================
# SIEM PLATFORM CONFIGURATION
# Update these paths to match your machine
# ============================================================

TOOLS = {
    "network":        r"C:\network-auditor",
    "passwords":      r"C:\password-analyzer",
    "files":          r"C:\file-integrity-monitor",
    "logs":           r"C:\log-analyzer",
    "vulnerabilities": r"C:\vulnerability-scanner",
    "dashboard":      r"C:\siem-dashboard",
}

REPORTS = {
    "network":        r"C:\network-auditor\network_report.txt",
    "passwords":      r"C:\password-analyzer\password_report.txt",
    "files":          r"C:\file-integrity-monitor\integrity_report.txt",
    "logs":           r"C:\log-analyzer\threat_report.txt",
    "vulnerabilities": r"C:\vulnerability-scanner\vulnerability_report.txt",
}

DEFAULT_TARGET = "127.0.0.1"
SCAN_INTERVAL_HOURS = 6
EMAIL_ALERTS = True

VERSION = "1.0"
AUTHOR = "Emmanuel Dan"
GITHUB = "github.com/DanEmmanuel1"