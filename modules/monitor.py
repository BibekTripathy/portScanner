import time
from datetime import datetime
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.console import Group
from rich import box

from modules.scanner import scan_listening_ports
from modules.mapper import processes_map
from modules.comparator import compare_scans
from utils.logger import logger


def generate_table(data):
    table = Table(title="Live Port Monitor", box=box.ROUNDED, expand=True)
    table.add_column("Proto", style="cyan", width=6)
    table.add_column("Port", style="bold", width=8)
    table.add_column("Service", style="green")
    table.add_column("IP", style="green")
    table.add_column("Scope", style="blue")
    table.add_column("Process", style="magenta")
    table.add_column("User", style="yellow")
    table.add_column("PID", style="dim")

    # Sort data by port for stability
    data.sort(key=lambda x: x.get("port", 0))

    for d in data:
        row_data = [
            d.get("protocol", "N/A"),
            str(d.get("port", "N/A")),
            d.get("service_guess", "Unknown"),
            d.get("ip", "N/A"),
            d.get("scope", "N/A"),
            d.get("process_name", d.get("process", "Unknown")),
            d.get("username", d.get("user", "Unknown")),
            str(d.get("pid", "N/A")),
        ]
        
        # Color code localhost vs external
        if d.get("scope") == "localhost":
             row_data[3] = f"[green]{row_data[3]}[/green]"
        else:
             row_data[3] = f"[red]{row_data[3]}[/red]"

        table.add_row(*row_data)

    return table


def start_monitor(interval=2, console=None):
    if not console:
        from rich.console import Console
        console = Console()

    event_log = []
    max_log_lines = 5
    
    # Initial scan
    console.print("[blue]Initializing monitor...[/blue]")
    raw_ports = scan_listening_ports()
    current_scan = processes_map(raw_ports)
    previous_scan = current_scan

    with Live(console=console, screen=True, auto_refresh=False) as live:
        while True:
            try:
                # 1. Perform Scan
                raw_ports = scan_listening_ports()
                current_scan = processes_map(raw_ports)

                # 2. Compare
                added, removed, changed = compare_scans(previous_scan, current_scan)
                
                timestamp = datetime.now().strftime("%H:%M:%S")

                for p in added:
                    msg = f"[{timestamp}] [green][+][/green] New port found: {p['port']}/{p['protocol']} ({p.get('process_name', 'unknown')})"
                    event_log.insert(0, msg)
                
                for p in removed:
                    msg = f"[{timestamp}] [red][-][/red] Port closed: {p['port']}/{p['protocol']} ({p.get('process_name', 'unknown')})"
                    event_log.insert(0, msg)
                
                for p in changed:
                    msg = f"[{timestamp}] [yellow][~][/yellow] Port {p['port']} changed: {p['old_process']} -> {p['new_process']}"
                    event_log.insert(0, msg)

                # Trim log
                if len(event_log) > max_log_lines:
                    event_log = event_log[:max_log_lines]

                # 3. Render
                table = generate_table(current_scan)
                
                log_content = "\n".join(event_log) if event_log else "[dim]No recent events[/dim]"
                log_panel = Panel(log_content, title="Activity Log", border_style="blue", height=max_log_lines + 2)

                render_group = Group(
                    table,
                    log_panel,
                    f"\n[dim]Refreshing every {interval}s. Press Ctrl+C to exit.[/dim]"
                )

                live.update(render_group, refresh=True)
                
                # Update state
                previous_scan = current_scan
                time.sleep(interval)

            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"Monitor error: {e}", exc_info=True)
                # Don't crash the UI immediately, maybe just log it
                time.sleep(interval)

    console.print("[blue]Monitor stopped.[/blue]")
