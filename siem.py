import sys
import os
import subprocess
import argparse
import webbrowser
import time
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from config import TOOLS, VERSION, AUTHOR, GITHUB, DEFAULT_TARGET
from reporter import generate_status_report, generate_summary

console = Console()

def print_banner():
    console.print(Panel.fit(
        f"[bold cyan]SIEM PLATFORM[/bold cyan]\n"
        f"[yellow]Version {VERSION} — Unified Security CLI[/yellow]\n"
        f"[white]6 Tools. 1 Command. Complete Security Visibility.[/white]\n"
        f"[dim]By {AUTHOR} — {GITHUB}[/dim]",
        border_style="cyan"
    ))

def print_help():
    print_banner()

    table = Table(
        title="Available Commands",
        show_header=True,
        header_style="bold magenta"
    )
    table.add_column("Command", style="cyan", width=40)
    table.add_column("Description", style="white", width=45)

    commands = [
        ("py siem.py --scan network [IP]",      "Audit network config & open ports"),
        ("py siem.py --scan passwords",          "Analyze password strength & breaches"),
        ("py siem.py --scan files",              "Monitor file integrity changes"),
        ("py siem.py --scan logs",               "Analyze Windows Event Log threats"),
        ("py siem.py --scan vulnerabilities [IP]","Scan for vulnerabilities"),
        ("py siem.py --scan all [IP]",           "Run all 5 tools sequentially"),
        ("py siem.py --dashboard",               "Launch SIEM web dashboard"),
        ("py siem.py --schedule",                "Start automated scheduled scans"),
        ("py siem.py --status",                  "Show last scan results summary"),
        ("py siem.py --help",                    "Show this help menu"),
    ]

    for cmd, desc in commands:
        table.add_row(cmd, desc)

    console.print(table)
    console.print()

def run_tool(tool_name, args=[]):
    tool_path = TOOLS.get(tool_name)
    if not tool_path or not os.path.exists(tool_path):
        console.print(f"[red]✘ Tool path not found: {tool_path}[/red]")
        console.print(f"[yellow]Update config.py with the correct path[/yellow]")
        return False

    # Find the main script for each tool
    scripts = {
        "network":        "auditor.py",
        "passwords":      "analyzer.py",
        "files":          "monitor.py",
        "logs":           "analyzer.py",
        "vulnerabilities": "scanner.py",
        "dashboard":      "app.py",
        "schedule":       "scheduler.py",
    }

    script = scripts.get(tool_name)
    if not script:
        console.print(f"[red]✘ No script found for tool: {tool_name}[/red]")
        return False

    script_path = os.path.join(tool_path, script)
    if not os.path.exists(script_path):
        console.print(f"[red]✘ Script not found: {script_path}[/red]")
        return False

    venv_python = os.path.join(tool_path, "venv", "Scripts", "python.exe")
    python_cmd = venv_python if os.path.exists(venv_python) else sys.executable

    cmd = [python_cmd, script_path] + args

    console.print(f"\n[bold cyan]Starting {tool_name.upper()} tool...[/bold cyan]")
    console.print(f"[dim]Running: {' '.join(cmd)}[/dim]\n")

    try:
        result = subprocess.run(cmd, cwd=tool_path)
        return result.returncode == 0
    except Exception as e:
        console.print(f"[red]✘ Error running tool: {e}[/red]")
        return False

def run_all(target=None):
    console.print(Panel.fit(
        "[bold cyan]FULL SECURITY AUDIT[/bold cyan]\n"
        "[yellow]Running all 5 tools sequentially...[/yellow]",
        border_style="cyan"
    ))

    tools_to_run = ["network", "logs", "files", "vulnerabilities"]
    args_map = {
        "network": [target] if target else [],
        "vulnerabilities": [target] if target else [],
        "logs": [],
        "files": [],
    }

    results = {}
    for i, tool in enumerate(tools_to_run, 1):
        console.print(f"\n[bold yellow][{i}/{len(tools_to_run)}] Running {tool.upper()}...[/bold yellow]")
        success = run_tool(tool, args_map.get(tool, []))
        results[tool] = "✔ Complete" if success else "✘ Failed"
        console.print(f"[{'green' if success else 'red'}]{results[tool]}[/{'green' if success else 'red'}]")

    console.print("\n[bold cyan]═══ FULL AUDIT COMPLETE ═══[/bold cyan]\n")

    table = Table(title="Audit Results", show_header=True, header_style="bold magenta")
    table.add_column("Tool", style="cyan", width=25)
    table.add_column("Result", style="white", width=15)

    for tool, result in results.items():
        color = "green" if "Complete" in result else "red"
        table.add_row(tool.title(), f"[{color}]{result}[/{color}]")

    console.print(table)
    console.print("\n[yellow]Open dashboard: py siem.py --dashboard[/yellow]\n")

def launch_dashboard():
    console.print("[bold cyan]Launching SIEM Dashboard...[/bold cyan]")
    console.print("[yellow]Opening http://127.0.0.1:5000 in your browser...[/yellow]")

    def open_browser():
        time.sleep(2)
        webbrowser.open("http://127.0.0.1:5000")

    import threading
    threading.Thread(target=open_browser, daemon=True).start()
    run_tool("dashboard")

def main():
    parser = argparse.ArgumentParser(
        description="SIEM Platform — Unified Security CLI",
        add_help=False
    )
    parser.add_argument("--scan", nargs="+", metavar="TOOL",
        help="Tool to run: network, passwords, files, logs, vulnerabilities, all")
    parser.add_argument("--dashboard", action="store_true",
        help="Launch SIEM web dashboard")
    parser.add_argument("--schedule", action="store_true",
        help="Start automated scheduled scans")
    parser.add_argument("--status", action="store_true",
        help="Show last scan results")
    parser.add_argument("--help", action="store_true",
        help="Show help menu")

    args = parser.parse_args()

    print_banner()

    if args.help or len(sys.argv) == 1:
        print_help()

    elif args.status:
        generate_status_report()
        generate_summary()

    elif args.dashboard:
        launch_dashboard()

    elif args.schedule:
        run_tool("schedule")

    elif args.scan:
        tool = args.scan[0].lower()
        target = args.scan[1] if len(args.scan) > 1 else DEFAULT_TARGET

        if tool == "all":
            run_all(target)
        elif tool in TOOLS:
            tool_args = [target] if tool in ["network", "vulnerabilities"] else []
            run_tool(tool, tool_args)
        else:
            console.print(f"[red]✘ Unknown tool: {tool}[/red]")
            console.print("[yellow]Available tools: network, passwords, files, logs, vulnerabilities, all[/yellow]")

    else:
        print_help()

if __name__ == "__main__":
    main()