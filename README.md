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

# WPX: WordPress scanner with WAF bypass

WPX is a WordPress security scanner. It uses Camoufox to solve Cloudflare and WAF challenges, then mirrors those sessions to perform asynchronous plugin and theme discovery.

## Features

*   **WAF bypass**: Uses Camoufox headless browser to solve challenges and extract session tokens.
*   **Asynchronous scanning**: Built with `asyncio` and `curl_cffi` for fast enumeration.
*   **Fingerprinting**: Mimics browser fingerprints and TLS handshakes to avoid detection.
*   **WPScan API**: Integrates with the WPScan Vulnerability Database for vulnerability lookups.
*   **Plugin cataloging**: Includes a script to fetch and rank plugin slugs from WordPress.org.
*   **CLI output**: Structured terminal output similar to `wpscan`.

## Installation

### 1. Clone the repository
```bash
git clone https://github.com/wpscan/python.git wpx
cd wpx
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Setup Camoufox
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
Scan all available plugin slugs (up to 50,000+ if `plugins_full.txt` exists):
```bash
python3 wpx.py -u https://example.com --full-scan
```

### Refresh plugin data
To update the plugin list and rank by popularity:
```bash
python3 wpx_fetch_plugins.py --sort-by score
```

## Comparison with WPScan

WPX is a Python implementation focused on WAF evasion and speed.

| Feature | Original WPScan (Ruby) | WPX (Python) |
|---------|------------------------|--------------|
| **Engine** | Ruby / Typhoeus | Python / Asyncio / curl_cffi |
| **WAF bypass** | Manual | Automatic (Camoufox) |
| **Speed** | Multi-threaded | Asynchronous |
| **Stealth** | Standard | Browser fingerprinting |

## Advanced options

| Flag | Description |
|------|-------------|
| `-u, --url` | Target WordPress URL. |
| `--api-key` | WPScan API key. |
| `-e, --enumerate` | `p` for plugins, `vp` for vulnerable plugins. |
| `-t, --threads` | Concurrent threads for scanning (Default: 20). |
| `--plugins-limit` | Limit the number of plugins to scan (e.g. 500, 5000). |
| `--full-scan` | Scans all available plugin slugs. |

## Disclaimer

This tool is for authorized security testing only. The developers are not responsible for misuse or damage.
