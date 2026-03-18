#!/usr/bin/env python3
"""WPX output formatting helpers — WPScan-style rich output."""

GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
CYAN = "\033[36m"
RESET = "\033[0m"
BOLD = "\033[1m"


def print_banner():
    print(f"""{BOLD}{GREEN}
         __      ______  _  __
        | | /\\ / /  _ \\| |/ /
        | |/  V /| |_) |   /
        |_|\\_/\\_/ |____/|_|\\_\\
{RESET}
    WordPress X-Ray Scanner | WAF/Cloudflare Bypass
""")


def print_finding(title, subitems=None):
    """[+] title, then | subitem lines."""
    print(f"{GREEN}[+]{RESET} {title}")
    if subitems:
        for item in subitems:
            print(f" | {item}")


def print_info(msg):
    """[i] informational message."""
    print(f"{CYAN}[i]{RESET} {msg}")


def print_warn(msg):
    """[!] warning message."""
    print(f"{YELLOW}[!]{RESET} {msg}")


def print_status(msg):
    """[*] status/progress message."""
    print(f"[*] {msg}")
