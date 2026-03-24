import os
import re
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

# ============================================================
# CORRELATION RULES
# Each rule links events across multiple tools
# ============================================================

CORRELATION_RULES = [
    {
        "id": "CR001",
        "name": "Brute Force Attack on Open Port",
        "severity": "CRITICAL",
        "description": "Multiple failed logins detected while SMB or RDP port is open",
        "sources": ["logs", "network"],
        "logic": "failed_logins >= 5 AND (port_445_open OR port_3389_open)",
    },
    {
        "id": "CR002",
        "name": "Possible Malware Installation",
        "severity": "CRITICAL",
        "description": "New service installed AND new files detected in system directories",
        "sources": ["logs", "files"],
        "logic": "new_service_installed AND files_added > 0",
    },
    {
        "id": "CR003",
        "name": "Privilege Escalation Chain",
        "severity": "HIGH",
        "description": "Privilege escalation event followed by new account creation",
        "sources": ["logs"],
        "logic": "privilege_escalation AND new_account_created",
    },
    {
        "id": "CR004",
        "name": "Vulnerable Port with Active Exploitation Attempt",
        "severity": "CRITICAL",
        "description": "Critical vulnerability found AND brute force attempts detected",
        "sources": ["vulnerabilities", "logs"],
        "logic": "critical_vulnerability AND failed_logins >= 3",
    },
    {
        "id": "CR005",
        "name": "Audit Log Tampering",
        "severity": "CRITICAL",
        "description": "Audit log cleared AND files deleted from system directories",
        "sources": ["logs", "files"],
        "logic": "audit_log_cleared AND files_deleted > 0",
    },
    {
        "id": "CR006",
        "name": "Suspicious Outbound Connection from Vulnerable Host",
        "severity": "HIGH",
        "description": "Critical vulnerability exists AND unusual outbound connections detected",
        "sources": ["vulnerabilities", "network"],
        "logic": "critical_vulnerability AND open_ports >= 3",
    },
    {
        "id": "CR007",
        "name": "Ransomware Precursor",
        "severity": "CRITICAL",
        "description": "SMB port open AND files being modified at high rate AND privilege escalation",
        "sources": ["network", "files", "logs"],
        "logic": "port_445_open AND files_modified >= 5 AND privilege_escalation",
    },
    {
        "id": "CR008",
        "name": "Weak Password on Exposed Service",
        "severity": "HIGH",
        "description": "Breached password found AND SSH or RDP port is open",
        "sources": ["passwords", "network"],
        "logic": "breached_passwords > 0 AND (port_22_open OR port_3389_open)",
    },
]

def parse_network_report(path):
    data = {
        "port_445_open": False,
        "port_3389_open": False,
        "port_22_open": False,
        "port_135_open": False,
        "open_ports": 0,
    }
    if not os.path.exists(path):
        return data
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        if "445" in content and "open" in content.lower():
            data["port_445_open"] = True
            data["open_ports"] += 1
        if "3389" in content and "open" in content.lower():
            data["port_3389_open"] = True
            data["open_ports"] += 1
        if "22" in content and "open" in content.lower():
            data["port_22_open"] = True
            data["open_ports"] += 1
        if "135" in content and "open" in content.lower():
            data["port_135_open"] = True
            data["open_ports"] += 1
    except Exception as e:
        console.print(f"[yellow]Warning reading network report: {e}[/yellow]")
    return data

def parse_log_report(path):
    data = {
        "failed_logins": 0,
        "privilege_escalation": False,
        "new_service_installed": False,
        "new_account_created": False,
        "audit_log_cleared": False,
    }
    if not os.path.exists(path):
        return data
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        failed = re.findall(r'Failed Login|Brute Force|4625', content, re.IGNORECASE)
        data["failed_logins"] = len(failed)
        if re.search(r'Privilege Escalation|4672', content, re.IGNORECASE):
            data["privilege_escalation"] = True
        if re.search(r'New Service|7045|Service Installed', content, re.IGNORECASE):
            data["new_service_installed"] = True
        if re.search(r'New Account|4720|Account Created', content, re.IGNORECASE):
            data["new_account_created"] = True
        if re.search(r'Audit Log Cleared|1102', content, re.IGNORECASE):
            data["audit_log_cleared"] = True
    except Exception as e:
        console.print(f"[yellow]Warning reading log report: {e}[/yellow]")
    return data

def parse_file_report(path):
    data = {
        "files_modified": 0,
        "files_added": 0,
        "files_deleted": 0,
    }
    if not os.path.exists(path):
        return data
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        modified = re.findall(r'MODIFIED FILES:', content, re.IGNORECASE)
        added = re.findall(r'ADDED FILES:', content, re.IGNORECASE)
        deleted = re.findall(r'DELETED FILES:', content, re.IGNORECASE)
        data["files_modified"] = len(modified) * 2
        data["files_added"] = len(added) * 2
        data["files_deleted"] = len(deleted) * 2
        changes_match = re.findall(r'Changes:\s+(\d+)', content)
        if changes_match:
            total = sum(int(x) for x in changes_match)
            data["files_modified"] = max(data["files_modified"], total)
    except Exception as e:
        console.print(f"[yellow]Warning reading file report: {e}[/yellow]")
    return data

def parse_vulnerability_report(path):
    data = {
        "critical_vulnerability": False,
        "high_vulnerability": False,
        "total_vulns": 0,
    }
    if not os.path.exists(path):
        return data
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        if re.search(r'CRITICAL', content, re.IGNORECASE):
            data["critical_vulnerability"] = True
        if re.search(r'\bHIGH\b', content, re.IGNORECASE):
            data["high_vulnerability"] = True
        vulns = re.findall(r'\[(CRITICAL|HIGH|MEDIUM|LOW)\]', content, re.IGNORECASE)
        data["total_vulns"] = len(vulns)
    except Exception as e:
        console.print(f"[yellow]Warning reading vulnerability report: {e}[/yellow]")
    return data

def parse_password_report(path):
    data = {
        "breached_passwords": 0,
        "weak_passwords": 0,
    }
    if not os.path.exists(path):
        return data
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        breached = re.findall(r'Breached:\s+YES', content, re.IGNORECASE)
        data["breached_passwords"] = len(breached)
        weak = re.findall(r'Score:\s+[0-3]\d/100', content)
        data["weak_passwords"] = len(weak)
    except Exception as e:
        console.print(f"[yellow]Warning reading password report: {e}[/yellow]")
    return data

def evaluate_rule(rule, context):
    triggered = False
    logic = rule["logic"]

    checks = {
        "failed_logins >= 5": context.get("failed_logins", 0) >= 5,
        "failed_logins >= 3": context.get("failed_logins", 0) >= 3,
        "port_445_open": context.get("port_445_open", False),
        "port_3389_open": context.get("port_3389_open", False),
        "port_22_open": context.get("port_22_open", False),
        "new_service_installed": context.get("new_service_installed", False),
        "files_added > 0": context.get("files_added", 0) > 0,
        "privilege_escalation": context.get("privilege_escalation", False),
        "new_account_created": context.get("new_account_created", False),
        "critical_vulnerability": context.get("critical_vulnerability", False),
        "audit_log_cleared": context.get("audit_log_cleared", False),
        "files_deleted > 0": context.get("files_deleted", 0) > 0,
        "open_ports >= 3": context.get("open_ports", 0) >= 3,
        "files_modified >= 5": context.get("files_modified", 0) >= 5,
        "breached_passwords > 0": context.get("breached_passwords", 0) > 0,
    }

    result = logic
    for check, value in checks.items():
        result = result.replace(check, str(value))

    result = result.replace("AND", "and").replace("OR", "or")

    try:
        triggered = eval(result)
    except Exception:
        triggered = False

    return triggered

def run_correlation_engine():
    from config import REPORTS

    console.print(Panel.fit(
        "[bold cyan]Correlation Engine[/bold cyan]\n"
        "[yellow]Linking events across all security tools...[/yellow]",
        border_style="cyan"
    ))

    console.print("[yellow]Parsing all report files...[/yellow]\n")

    network = parse_network_report(REPORTS.get("network", ""))
    logs = parse_log_report(REPORTS.get("logs", ""))
    files = parse_file_report(REPORTS.get("files", ""))
    vulns = parse_vulnerability_report(REPORTS.get("vulnerabilities", ""))
    passwords = parse_password_report(REPORTS.get("passwords", ""))

    context = {**network, **logs, **files, **vulns, **passwords}

    console.print("[bold]Security Context:[/bold]")
    console.print(f"  Failed logins detected:     {context.get('failed_logins', 0)}")
    console.print(f"  Port 445 open:              {context.get('port_445_open', False)}")
    console.print(f"  Port 3389 open:             {context.get('port_3389_open', False)}")
    console.print(f"  Privilege escalation:       {context.get('privilege_escalation', False)}")
    console.print(f"  New service installed:      {context.get('new_service_installed', False)}")
    console.print(f"  Files modified:             {context.get('files_modified', 0)}")
    console.print(f"  Critical vulnerability:     {context.get('critical_vulnerability', False)}")
    console.print(f"  Breached passwords:         {context.get('breached_passwords', 0)}")
    console.print()

    triggered_rules = []
    for rule in CORRELATION_RULES:
        if evaluate_rule(rule, context):
            triggered_rules.append(rule)

    if not triggered_rules:
        console.print("[bold green]✔ No correlated threats detected — system looks clean[/bold green]")
        return []

    console.print(f"[bold red]⚠ {len(triggered_rules)} correlated threat(s) detected![/bold red]\n")

    table = Table(
        title="Correlated Incidents",
        show_header=True,
        header_style="bold magenta"
    )
    table.add_column("ID", style="cyan", width=8)
    table.add_column("Severity", style="red", width=12)
    table.add_column("Incident", style="white", width=35)
    table.add_column("Description", style="yellow", width=45)

    severity_colors = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "green"
    }

    for rule in triggered_rules:
        color = severity_colors.get(rule["severity"], "white")
        table.add_row(
            rule["id"],
            f"[{color}]{rule['severity']}[/{color}]",
            rule["name"],
            rule["description"]
        )

    console.print(table)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_lines = []
    report_lines.append("=" * 60)
    report_lines.append(f"Correlation Engine Report")
    report_lines.append(f"Generated: {now}")
    report_lines.append(f"Incidents: {len(triggered_rules)}")
    report_lines.append("=" * 60)
    for rule in triggered_rules:
        report_lines.append(f"\n[{rule['severity']}] {rule['id']} — {rule['name']}")
        report_lines.append(f"  {rule['description']}")
    report_lines.append("\n" + "=" * 60)

    with open("correlation_report.txt", "a", encoding="utf-8", errors="replace") as f:
        f.write("\n".join(report_lines) + "\n")

    console.print(f"\n[green]✔ Correlation report saved to correlation_report.txt[/green]")
    return triggered_rules