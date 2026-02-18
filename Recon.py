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
        # Support both single IPs and CIDR notation (e.g., 192.168.1.0/24)
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
# Run Scan
# -----------------------------------

def run_scan(scan_command, target):
    # Combine the base command with the target and progress flags
    command = scan_command + ["--stats-every", "5s", target]

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

        for line in process.stdout:
            # Print live Nmap output
            console.print(f"  [dim]{line.strip()}[/dim]")

            # Extract progress percentage from nmap output
            match = re.search(r"(\d+\.\d+)% done", line)
            if match:
                percent = float(match.group(1))
                progress.update(task, completed=percent)

        process.wait()
        progress.update(task, completed=100)

    if process.returncode != 0:
        console.print("\n[bold red]Scan failed.[/bold red] You might need to run this as sudo for certain scans (like Stealth or OS Detection).")
    else:
        console.print("\n[bold green]Scan complete![/bold green]\n")

# -----------------------------------
# Explanation Mode
# -----------------------------------

def explain_scans():
    console.print("\n[bold blue]Scan Explanations[/bold blue]\n")
    for key, data in SCANS.items():
        console.print(f"[yellow]{key}. {data['name']}[/yellow]")
        console.print(f"   Command: {' '.join(data['command'])}")
        console.print(f"   What it does: {data['description']}\n")
    input("Press Enter to return to menu...")

# -----------------------------------
# Banner & Menu
# -----------------------------------

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

    if choice == "x":
        console.print("[bold red]Exiting...[/bold red]")
        exit()

    if choice == "e":
        explain_scans()
        return

    if choice in SCANS:
        last_ip = load_last_ip()
        
        # --- The 'r' to use Last IP Logic ---
        if last_ip:
            prompt_msg = f"Enter target IP or subnet (or press [bold magenta]'r'[/bold magenta] for {last_ip})"
        else:
            prompt_msg = "Enter target IP or subnet"

        target_input = Prompt.ask(prompt_msg).strip()

        if target_input.lower() == 'r' and last_ip:
            ip = last_ip
        else:
            ip = target_input
            if not validate_ip(ip):
                console.print("[bold red]Invalid IP or subnet format.[/bold red]")
                time.sleep(2)
                return
            save_last_ip(ip)

        if not check_nmap():
            time.sleep(2)
            return

        run_scan(SCANS[choice]["command"], ip)
        input("\nPress Enter to return to menu...")
    else:
        console.print("[bold red]Invalid selection.[/bold red]")
        time.sleep(1.5)

# -----------------------------------
# Entry
# -----------------------------------

if __name__ == "__main__":
    while True:
        menu()
