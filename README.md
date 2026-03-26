# █     █░ ██▓███     ▒██   ██▒ ██▀███   ▄▄▄     ▓██   ██▓
# ▓█░ █ ░█░▓██░  ██▒   ▒▒ █ █ ▒░▓██ ▒ ██▒▒████▄    ▒██  ██▒
# ▒█░ █ ░█ ▓██░ ██▓▒   ░░  █   ░▓██ ░▄█ ▒▒██  ▀█▄   ▒██ ██░
# ░█░ █ ░█ ▒██▄█▓▒ ▒    ░ █ █ ▒ ▒██▀▀█▄  ░██▄▄▄▄██  ░ ▐██▓░
# ░░██▒██▓ ▒██▒ ░  ░   ▒██▒ ▒██▒░██▓ ▒██▒ ▓█   ▓██▒ ░ ██▒▓░
# ░ ▓░▒ ▒  ▒▓▒░ ░  ░   ▒▒ ░ ░▓ ░░ ▒▓ ░▒▓░ ▒▒   ▓▒█░  ██▒▒▒ 
#   ▒ ░ ░  ░▒ ░        ░░   ░▒ ░  ░▒ ░ ▒░  ▒   ▒▒ ░▓██ ░▒░ 
#   ░   ░  ░░           ░    ░    ░░   ░   ░   ▒   ▒ ▒ ░░  
#     ░                 ░    ░     ░           ░  ░░ ░     
#                                                  ░ ░     

# WPX: WordPress X-Ray scanner with WAF bypass

WPX (WordPress X-Ray) is a security scanner that uses Camoufox to solve Cloudflare and WAF challenges. It mirrors those sessions to perform fast, asynchronous plugin and theme discovery.

**Note**: WPX downloads necessary scan metadata (fingerprints, detection rules) from `data.wpscan.org`.

## Features

*   **WAF bypass**: Uses Camoufox headless browser to solve challenges and extract session tokens.
*   **Asynchronous scanning**: Built with `asyncio` and `curl_cffi` for fast enumeration.
*   **Fingerprinting**: Mimics browser fingerprints and TLS handshakes to avoid detection.
*   **WPScan API**: Integrates with the WPScan Vulnerability Database for vulnerability lookups.
*   **Massive Plugin Catalog**: Tracks ~110,000 historical and ~55,000 current plugins.
*   **Plugin cataloging**: Includes a script to fetch and rank plugin slugs from WordPress.org.
*   **CLI output**: Structured terminal output similar to `wpscan`.
*   **Stealth mode**: High-fidelity browser impersonation and TLS session mirroring.

## Installation

### 1. Clone and Install
```bash
git clone https://github.com/wpscan/python.git wpx
cd wpx
pip install .
```

### 2. Setup Camoufox
```bash
python3 -m camoufox fetch
```

## Usage

### Basic scan
```bash
python3 wpx.py -u https://example.com
```

### Vulnerability scan (requires API key)
```bash
python3 wpx.py -u https://example.com --api-key YOUR_API_KEY
```

### Flexible plugin enumeration
Scan a specific number of top-ranked plugins (e.g., top 500):
```bash
python3 wpx.py -u https://example.com --plugins-limit 500
```

### Full plugin brute-force
Scan every plugin ever created. WPX can traverse the entire historical library of ~110,000 plugins (including ~55,000 currently active ones) to find every trace of software on the target.
**Warning**: This performs a massive number of requests and can take several hours to complete depending on your thread count and the target's responsiveness.
```bash
python3 wpx.py -u https://example.com --full-scan
```

### Silent output and logging
Run a scan silently and save results to a file without ANSI color codes:
```bash
python3 wpx.py -u https://example.com --quiet --output results.txt
```

### Refresh plugin data
To update the plugin lists and rank by popularity:
```bash
python3 data/wpx_fetch_plugins.py --sort-by score
```

Outputs `data/plugins_active.txt` (default top 5000) and `data/plugins_dead.txt` (default top 2500).
To change the limits:
```bash
python3 data/wpx_fetch_plugins.py --active-limit 10000 --dead-limit 5000
```

## Data management

The `data/` directory contains the processed plugin datasets and maintenance tools:

*   **`data/plugins_active.txt`**: Top active plugin slugs ranked by popularity score (geometric mean of installs × downloads).
*   **`data/plugins_dead.txt`**: Top closed/removed plugin slugs ranked by historical install count (sourced from previous catalog runs or Archive.org snapshots).
*   **`data/plugins_catalog.json`**: Cached metadata for active plugins.
*   **`data/plugins_dead.jsonl`**: Append-only cache of dead plugin metadata including last-known install counts. New entries override old ones on load (last-write-wins).
*   **`data/archive.org-cache/`**: Raw HTML snapshots from the Wayback Machine, used to recover historical install counts for plugins closed before the first catalog run.
*   **`data/wpx_fetch_plugins.py`**: Fetcher that combines the WordPress.org API, SVN repository, and Archive.org to build and enrich the plugin lists.

## Advanced Options

### Main Scanner (`wpx.py`)

| Flag | Description |
|------|-------------|
| `-u, --url` | Target WordPress URL (required). |
| `--api-key` | WPScan Vulnerability Database API Key. |
| `-t, --threads` | Concurrent threads for scanning (Default: 20). |
| `--plugins-limit` | Limit the number of plugins to scan (e.g. 500, 5000). |
| `--full-scan` | Scans all available plugin slugs (up to 50k+). |
| `--update` | Force update of WPScan metadata files. |
| `--no-browser` | Skip Camoufox WAF bypass and connect directly. |
| `--enum-users-disable` | Skip user enumeration. |
| `--users-limit N` | Number of author IDs to probe via ?author=N (default: 10). |
| `-q, --quiet` | Suppress banner, status, and progress — show findings only. |
| `-o, --output FILE`| Write output to FILE (plain text, no ANSI codes). |

### Plugin Fetcher (`data/wpx_fetch_plugins.py`)

| Flag | Description |
|------|-------------|
| `--sort-by` | How to rank active plugins: `score` (default), `active_installs`, `downloaded`. |
| `--active-limit N` | Number of active slugs to write to `plugins_active.txt` (default: 5000, 0 = all). |
| `--dead-limit N` | Number of dead slugs to write to `plugins_dead.txt` (default: 2500, 0 = all). |
| `--force` | Re-fetch everything even if catalog already exists. |
| `--fetch-limit N` | Stop after fetching N active plugins from API (0 = all). |
| `--max-age HOURS` | Skip API fetch if catalog is fresher than N hours (default: 24). |

## Disclaimer

This tool is for authorized security testing only. The developers are not responsible for misuse or damage.
