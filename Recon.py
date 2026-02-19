from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
import subprocess
import re
import ipaddress
import shutil
import os
import time

console = Console()
LAST_IP_FILE = ".last_target"

# -----------------------------------
# Scan Definitions
# -----------------------------------

SCANS = {
    "1": {
        "name": "Host Discovery (Ping Scan)",
        "command": ["nmap", "-sn"],
        "description": "Checks which hosts are alive without scanning ports."
    },
    "2": {
        "name": "Quick Port Scan",
        "command": ["nmap"],
        "description": "Scans the most common 1000 TCP ports."
    },
    "3": {
        "name": "Full Port Scan",
        "command": ["nmap", "-p-"],
        "description": "Scans all 65535 TCP ports."
    },
    "4": {
        "name": "Service & Version Detection",
        "command": ["nmap", "-sV", "-sC"],
        "description": "Detects service versions and runs default scripts."
    },
    "5": {
        "name": "OS Detection",
        "command": ["nmap", "-O"],
        "description": "Attempts to identify the target operating system."
    },
    "6": {
        "name": "Stealth Mode (SYN Scan)",
        "command": ["nmap", "-sS", "-Pn"],
        "description": "Scans without completing TCP connections. (Usually requires sudo/root)"
    }
}

# -----------------------------------
# Utility Functions
# -----------------------------------

def load_last_ip():
    if os.path.exists(LAST_IP_FILE):
        with open(LAST_IP_FILE, "r") as f:
            return f.read().strip()
    return None

def save_last_ip(ip):
    with open(LAST_IP_FILE, "w") as f:
        f.write(ip)

def validate_ip(ip):
    try:
        if "/" in ip:
            ipaddress.ip_network(ip, strict=False)
        else:
            ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def check_nmap():
    if not shutil.which("nmap"):
        console.print("[bold red]Error:[/bold red] nmap is not installed.")
        return False
    return True

# -----------------------------------
# Run Scan (Enhanced Version)
# -----------------------------------

def run_scan(scan_command, target):
    # Log file for the user to keep results
    log_filename = f"scan_{target.replace('/', '_')}_{int(time.time())}.txt"
    
    # We add --stats-every to get progress updates from Nmap
    command = scan_command + ["--stats-every", "3s", target]

    console.print(f"\n[bold cyan]Targeting:[/bold cyan] [white]{target}[/white]")
    console.print(f"[bold cyan]Command:[/bold cyan] [dim]{' '.join(command)}[/dim]\n")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:

        task = progress.add_task("Scanning...", total=100)

        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        console.print("\n[bold yellow]--- Live Scan Results ---[/bold yellow]")
        
        with open(log_filename, "w") as log_file:
            for line in process.stdout:
                clean_line = line.strip()
                if not clean_line: continue
                
                # Write every line to the log file for later review
                log_file.write(clean_line + "\n")

                # 1. Handle Progress Updates (Don't print these to screen)
                match = re.search(r"(\d+\.\d+)% done", clean_line)
                if match:
                    percent = float(match.group(1))
                    progress.update(task, completed=percent)
                    continue

                # 2. Highlight Port Information (The part you needed!)
                # This matches lines like "80/tcp open  http"
                if re.match(r"^\d+/(tcp|udp)", clean_line):
                    console.print(f"[bold green]PORT FOUND: {clean_line}[/bold green]")
                
                # 3. Highlight OS and Service Details
                elif "OS details:" in clean_line or "Service Info:" in clean_line:
                    console.print(f"[bold magenta]➔ {clean_line}[/bold magenta]")
                
                # 4. Highlight Script Results (from Option 4)
                elif clean_line.startswith("|"):
                    console.print(f"  [cyan]{clean_line}[/cyan]")
                
                # 5. Print standard output in dim
                else:
                    # Filter out the boring "Stats" lines to keep terminal clean
                    if "Stats:" not in clean_line:
                        console.print(f"  [dim]{clean_line}[/dim]")

        process.wait()
        progress.update(task, completed=100)

    if process.returncode != 0:
        console.print(f"\n[bold red]Scan failed.[/bold red] Run as sudo/admin for advanced scans.")
    else:
        console.print(f"\n[bold green]Scan complete![/bold green]")
        console.print(f"Detailed report saved to: [bold white]{log_filename}[/bold white]\n")

# -----------------------------------
# Explanation & Menu UI
# -----------------------------------

def explain_scans():
    console.print("\n[bold blue]Scan Explanations[/bold blue]\n")
    for key, data in SCANS.items():
        console.print(f"[yellow]{key}. {data['name']}[/yellow]")
        console.print(f"   Command: {' '.join(data['command'])}")
        console.print(f"   What it does: {data['description']}\n")
    input("Press Enter to return to menu...")

def print_banner():
    banner = """
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗  ██╗
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝

=============================================
Simplified Nmap Interface for Beginners
=============================================
"""
    console.print(Panel(banner, border_style="bright_blue"))

def menu():
    console.clear()
    print_banner()

    for key, data in SCANS.items():
        console.print(f"[yellow]{key}.[/yellow] {data['name']}")

    console.print("[cyan]E.[/cyan] Explain Scan Types")
    console.print("[red]X.[/red] Exit")

    choice = Prompt.ask("\nSelect a scan option").strip().lower()

    if choice == 'x':
        console.print("[bold red]Exiting...[/bold red]")
        exit()
    if choice == 'e':
        explain_scans()
        return

    if choice in SCANS:
        last_ip = load_last_ip()
        prompt_msg = f"Enter target IP (or 'r' for {last_ip})" if last_ip else "Enter target IP"
        
        target_input = Prompt.ask(prompt_msg).strip()
        ip = last_ip if target_input.lower() == 'r' and last_ip else target_input

        if not validate_ip(ip):
            console.print("[bold red]Invalid IP format.[/bold red]")
            time.sleep(2)
            return
        
        save_last_ip(ip)
        if check_nmap():
            run_scan(SCANS[choice]["command"], ip)
            input("\nPress Enter to return to menu...")
    else:
        console.print("[bold red]Invalid selection.[/bold red]")
        time.sleep(1.5)

if __name__ == "__main__":
    while True:
        menu()
