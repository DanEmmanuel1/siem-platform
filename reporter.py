import os
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

def generate_status_report():
    from config import REPORTS

    console.print(Panel.fit(
        "[bold cyan]SIEM Platform Status Report[/bold cyan]\n"
        f"[yellow]Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/yellow]",
        border_style="cyan"
    ))

    table = Table(
        title="Tool Status",
        show_header=True,
        header_style="bold magenta"
    )
    table.add_column("Tool", style="cyan", width=25)
    table.add_column("Report File", style="white", width=45)
    table.add_column("Last Updated", style="yellow", width=20)
    table.add_column("Status", style="green", width=12)

    tool_names = {
        "network": "Network Config Auditor",
        "passwords": "Password Analyzer",
        "files": "File Integrity Monitor",
        "logs": "Log Analyzer",
        "vulnerabilities": "Vulnerability Scanner",
    }

    for key, path in REPORTS.items():
        name = tool_names.get(key, key)
        if os.path.exists(path):
            modified = datetime.fromtimestamp(
                os.path.getmtime(path)
            ).strftime("%Y-%m-%d %H:%M")
            size = os.path.getsize(path)
            status = "[green]✔ Ready[/green]"
        else:
            modified = "Never"
            status = "[red]✘ No report[/red]"

        table.add_row(name, path, modified, status)

    console.print(table)
    console.print("\n[yellow]Tip: Run a scan first to generate report files[/yellow]\n")

def generate_summary():
    from config import REPORTS
    console.print("\n[bold cyan]═══ QUICK SUMMARY ═══[/bold cyan]\n")

    total_tools = len(REPORTS)
    ready_tools = sum(1 for p in REPORTS.values() if os.path.exists(p))

    console.print(f"[bold]Tools configured:[/bold] {total_tools}")
    console.print(f"[bold]Reports available:[/bold] [{'green' if ready_tools == total_tools else 'yellow'}]{ready_tools}/{total_tools}[/{'green' if ready_tools == total_tools else 'yellow'}]")

    if ready_tools < total_tools:
        console.print("\n[yellow]Run 'py siem.py --scan all' to generate all reports[/yellow]")
    else:
        console.print("\n[green]✔ All tools have been run and reports are ready[/green]")
        console.print("[green]✔ Open dashboard at http://127.0.0.1:5000[/green]")