#!/usr/bin/env python3
"""WPX output formatting helpers — WPScan-style rich output."""

import re as _re

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

_ANSI_RE = _re.compile(r'\033\[[0-9;]*m')

_quiet = False
_output_file = None


def init_output(quiet=False, output_file=None):
    """Set output mode. Call once at startup before any output functions."""
    global _quiet, _output_file
    _quiet = quiet
    _output_file = output_file


def strip_ansi(text):
    """Remove ANSI escape codes from text."""
    return _ANSI_RE.sub('', text)


def _write(msg, end='\n'):
    """Print to terminal and mirror (ANSI-stripped) to output file if set."""
    print(msg, end=end)
    if _output_file:
        print(strip_ansi(msg), end=end, file=_output_file)


def print_banner():
    """Print the banner with diagonal rainbow stripes (color determined by row+col)."""
    if _quiet:
        return
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
    _write(f"{GREEN}[+]{RESET} {title}")
    if subitems:
        for item in subitems:
            _write(f" | {item}")


def print_info(msg):
    """[i] informational message."""
    if _quiet:
        return
    _write(f"{CYAN}[i]{RESET} {msg}")


def print_warn(msg):
    """[!] warning message."""
    _write(f"{YELLOW}[!]{RESET} {msg}")


def print_status(msg):
    """[*] status/progress message."""
    if _quiet:
        return
    _write(f"[*] {msg}")


def print_plain(msg=''):
    """Plain text line (separators, blank lines) — suppressed in quiet mode."""
    if _quiet:
        return
    _write(msg)


def print_progress(msg):
    """Inline progress bar — suppressed in quiet mode, never written to file."""
    if not _quiet:
        print(f"\r[*] {msg}", end="", flush=True)


def print_progress_done():
    """Newline to terminate a progress bar line."""
    if not _quiet:
        print()
