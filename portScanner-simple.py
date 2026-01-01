import sys
import json
from datetime import datetime
from rich.console import Console
from rich.prompt import Prompt, IntPrompt
from rich.table import Table
from modules.scanner import scan_listening_ports
from modules.mapper import processes_map
from utils.logger import logger

# Initialize Console with color system disabled
console = Console(no_color=True)
last_scan_results = []


def render_table(data, detailed=False):
    if not data:
        console.print("No listening ports found")
        return

    table = Table(title=" Listening Ports", show_header=True, header_style="")

    table.add_column("Proto")
    table.add_column("Port")
    table.add_column("Service")
    table.add_column("IP")
    table.add_column("Scope")
    table.add_column("Process", width=20)
    table.add_column("User")

    if detailed:
        table.add_column("PID")
        table.add_column("Exe", width=30)
        table.add_column("Status")

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

        table.add_row(*row_data)

    console.print(table)
    console.print(f"Found {len(data)} listening port(s)")


def export_to_json(data):
    if not data:
        console.print("No scan data to export. Please run a scan first.")
        return

    default_filename = f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    filename = Prompt.ask("Enter filename to save JSON", default=default_filename)

    export_data = {
        "scan_time": datetime.now().isoformat(),
        "total_ports": len(data),
        "ports": data,
    }

    try:
        with open(filename, "w") as f:
            json.dump(export_data, f, indent=2, default=str)
        logger.info(f"Results exported to {filename}")
        console.print(f"✓ Results successfully exported to {filename}")
    except Exception as e:
        logger.error(f"Failed to export to {filename}: {e}")
        console.print(f"✗ Failed to export: {e}")


def run_scan(detailed=False):
    global last_scan_results
    console.print("Scanning for listening ports...")
    try:
        ports = scan_listening_ports()
        if not ports:
            console.print("No listening ports found")
            last_scan_results = []
            return

        # Map processes to ports
        mapped = processes_map(ports)
        last_scan_results = mapped
        
        # Render results
        render_table(mapped, detailed=detailed)
        
    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=True)
        console.print(f"Error during scan: {e}")


def print_menu():
    console.print("\n=== Port Guardian Menu ===")
    console.print("1. Scan Ports (Basic)")
    console.print("2. Scan Ports (Detailed)")
    console.print("3. Export Last Scan to JSON")
    console.print("4. Exit")


def main():
    console.print("Port Guardian - Interactive Mode")
    
    while True:
        print_menu()
        choice = IntPrompt.ask("Select an option", choices=["1", "2", "3", "4"], show_choices=False)
        
        if choice == 1:
            run_scan(detailed=False)
        elif choice == 2:
            run_scan(detailed=True)
        elif choice == 3:
            export_to_json(last_scan_results)
        elif choice == 4:
            console.print("Goodbye!")
            sys.exit(0)
            
        console.input("\nPress Enter to continue...")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\nGoodbye!")
        sys.exit(0)
