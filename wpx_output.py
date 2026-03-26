#!/usr/bin/env python3
"""WPX output formatting helpers — WPScan-style rich output."""

GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
CYAN = "\033[36m"
RESET = "\033[0m"
BOLD = "\033[1m"

_RAINBOW = [
    "\033[91m",   # bright red
    "\033[33m",   # yellow/orange
    "\033[93m",   # bright yellow
    "\033[92m",   # bright green
    "\033[36m",   # cyan
    "\033[94m",   # bright blue
    "\033[35m",   # magenta
    "\033[95m",   # bright magenta
]

_BANNER_LINES = [
    " █     █░ ██▓███     ▒██   ██▒ ██▀███   ▄▄▄     ▓██   ██▓",
    "▓█░ █ ░█░▓██░  ██▒   ▒▒ █ █ ▒░▓██ ▒ ██▒▒████▄    ▒██  ██▒",
    "▒█░ █ ░█ ▓██░ ██▓▒   ░░  █   ░▓██ ░▄█ ▒▒██  ▀█▄   ▒██ ██░",
    "░█░ █ ░█ ▒██▄█▓▒ ▒    ░ █ █ ▒ ▒██▀▀█▄  ░██▄▄▄▄██  ░ ▐██▓░",
    "░░██▒██▓ ▒██▒ ░  ░   ▒██▒ ▒██▒░██▓ ▒██▒ ▓█   ▓██▒ ░ ██▒▓░",
    "░ ▓░▒ ▒  ▒▓▒░ ░  ░   ▒▒ ░ ░▓ ░░ ▒▓ ░▒▓░ ▒▒   ▓▒█░  ██▒▒▒ ",
    "  ▒ ░ ░  ░▒ ░        ░░   ░▒ ░  ░▒ ░ ▒░  ▒   ▒▒ ░▓██ ░▒░ ",
    "  ░   ░  ░░           ░    ░    ░░   ░   ░   ▒   ▒ ▒ ░░  ",
    "    ░                 ░    ░     ░           ░  ░░ ░     ",
    "                                                 ░ ░     ",
]

# How many characters wide each color band is (diagonal step size)
_BAND = 8


def print_banner():
    """Print the banner with diagonal rainbow stripes (color determined by row+col)."""
    print()
    n = len(_RAINBOW)
    for row, line in enumerate(_BANNER_LINES):
        out = []
        current_color = None
        for col, ch in enumerate(line):
            color = _RAINBOW[(row + col // _BAND) % n]
            if color != current_color:
                out.append(f"{BOLD}{color}")
                current_color = color
            out.append(ch)
        out.append(RESET)
        print("".join(out))
    print(f"\n{CYAN}    WordPress X-Ray Scanner | WAF Bypass{RESET}\n")


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
