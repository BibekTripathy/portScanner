import sys
import json
import argparse
import os
from datetime import datetime
from rich.console import Console
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.table import Table
from modules.scanner import scan_listening_ports
from modules.mapper import processes_map
from modules.comparator import load_scan_from_file, compare_scans
from modules.monitor import start_monitor
from utils.logger import logger

console = Console()
last_scan_results = []


def render_table(data, detailed=False):
    if not data:
        console.print("[yellow]No listening ports found[/yellow]")
        return

    table = Table(title=" Listening Ports")

    table.add_column("Proto", style="cyan")
    table.add_column("Port", style="bold")
    table.add_column("Service", style="green")
    table.add_column("IP", style="green")
    table.add_column("Scope", style="blue")
    table.add_column("Process", style="magenta", width=20)
    table.add_column("User", style="yellow")

    if detailed:
        table.add_column("PID", style="dim")
        table.add_column("Exe", style="dim", width=30)
        table.add_column("Status", style="dim")

    for d in data:
        row_data = [
            d.get("protocol", "N/A"),
            str(d.get("port", "N/A")),
            d.get("service_guess", "Unknown"),
            d.get("ip", "N/A"),
            d.get("scope", "N/A"),
            d.get("process_name", d.get("process", "Unknown")),
            d.get("username", d.get("user", "Unknown")),
        ]

        if detailed:
            row_data.extend(
                [
                    str(d.get("pid", "N/A")),
                    d.get("exe_path", d.get("exe", "N/A")) or "N/A",
                    d.get("status", "N/A"),
                ]
            )

        # colour code according to scope
        scope = d.get("scope", "")
        if scope == "localhost":
            row_data[3] = f"[green]{scope}[/green]"
        else:
            row_data[3] = f"[red]{scope}[/red]"

        table.add_row(*row_data)

    console.print(table)
    console.print(f"[dim]Found {len(data)} listening port(s)[/dim]")


def print_diff_report(added, removed, changed):
    if not added and not removed and not changed:
        console.print(
            "[bold green]No changes detected compared to baseline.[/bold green]"
        )
        return

    table = Table(title="Scan Comparison Report")
    table.add_column("Type", style="bold")
    table.add_column("Port")
    table.add_column("Details")

    for p in added:
        table.add_row(
            "[green][+] New[/green]",
            f"{p['port']}/{p['protocol']}",
            f"Process: {p.get('process_name', 'N/A')}",
        )

    for p in removed:
        table.add_row(
            "[red][-] Closed[/red]",
            f"{p['port']}/{p['protocol']}",
            f"Was: {p.get('process_name', 'N/A')}",
        )

    for p in changed:
        table.add_row(
            "[yellow][~] Changed[/yellow]",
            f"{p['port']}/{p['protocol']}",
            f"{p['old_process']} -> {p['new_process']}",
        )

    console.print(table)


def export_to_json(data, filename=None, force=False):
    if not data:
        console.print(
            "[yellow]No scan data to export. Please run a scan first.[/yellow]"
        )
        return

    if not filename:
        default_filename = (
            f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        filename = Prompt.ask("Enter filename to save JSON", default=default_filename)

    if os.path.exists(filename) and not force:
        confirm = Confirm.ask(
            f"[yellow]File '{filename}' already exists. Overwrite?[/yellow]"
        )
        if not confirm:
            console.print("[blue]Export cancelled.[/blue]")
            return

    if os.path.exists(filename) and force:
        logger.info(f"File {filename} exists. Overwriting old data due to --force.")

    export_data = {
        "scan_time": datetime.now().isoformat(),
        "total_ports": len(data),
        "ports": data,
    }

    try:
        with open(filename, "w") as f:
            json.dump(export_data, f, indent=2, default=str)
        logger.info(f"Results exported to {filename}")
        console.print(f"[green]✓ Results successfully exported to {filename}[/green]")
    except Exception as e:
        logger.error(f"Failed to export to {filename}: {e}")
        console.print(f"[red]✗ Failed to export: {e}[/red]")


def run_scan(detailed=False, quiet=False):
    global last_scan_results
    if not quiet:
        console.print("[bold blue]Scanning for listening ports...[/bold blue]")
    try:
        ports = scan_listening_ports()
        if not ports:
            if not quiet:
                console.print("[yellow]No listening ports found[/yellow]")
            last_scan_results = []
            return []

        mapped = processes_map(ports)
        last_scan_results = mapped

        if not quiet:
            render_table(mapped, detailed=detailed)

        return mapped

    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=True)
        if not quiet:
            console.print(f"[red]Error during scan: {e}[/red]")
        return []


def print_menu():
    console.print("\n[bold green]Port Scanner Menu[/bold green]")
    console.print("1. Scan Ports (Basic)")
    console.print("2. Scan Ports (Detailed)")
    console.print("3. Export Last Scan to JSON")
    console.print("4. Watch Mode (Live Monitor)")
    console.print("5. Exit")


def interactive_mode():
    console.print("[bold]Port Scanner[/bold] - Interactive Mode")

    while True:
        print_menu()
        choice = IntPrompt.ask(
            "Select an option", choices=["1", "2", "3", "4", "5"], show_choices=False
        )

        if choice == 1:
            run_scan(detailed=False)
        elif choice == 2:
            run_scan(detailed=True)
        elif choice == 3:
            export_to_json(last_scan_results)
        elif choice == 4:
            start_monitor(console=console)
        elif choice == 5:
            console.print("[blue]Goodbye![/blue]")
            sys.exit(0)

        console.input("\n[dim]Press Enter to continue...[/dim]")


def main():
    parser = argparse.ArgumentParser(description="Port Scanner")
    parser.add_argument(
        "-s", "--scan", action="store_true", help="Run scan immediately"
    )
    parser.add_argument(
        "-d", "--detailed", action="store_true", help="Include detailed process info"
    )
    parser.add_argument("-j", "--json", help="Export results to specified JSON file")
    parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Overwrite existing files without asking",
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="Suppress console table output"
    )
    parser.add_argument(
        "-c", "--compare", help="Compare current scan with a baseline JSON file"
    )
    parser.add_argument(
        "-w", "--watch", action="store_true", help="Run in live monitor mode"
    )
    parser.add_argument(
        "-i", "--interval", type=int, default=2, help="Refresh interval for watch mode (seconds)"
    )

    args = parser.parse_args()

    if args.watch:
        start_monitor(interval=args.interval, console=console)

    elif args.compare:
        baseline = load_scan_from_file(args.compare)
        if baseline is None:
            sys.exit(1)

        current = run_scan(detailed=args.detailed, quiet=True)
        added, removed, changed = compare_scans(baseline, current)
        print_diff_report(added, removed, changed)
        if args.json:
            export_to_json(current, filename=args.json, force=args.force)

    elif args.scan or args.json:
        results = run_scan(detailed=args.detailed, quiet=args.quiet)
        if args.json:
            export_to_json(results, filename=args.json, force=args.force)
    else:
        interactive_mode()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[blue]Goodbye![/blue]")
        sys.exit(0)
