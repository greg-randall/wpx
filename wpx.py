#!/usr/bin/env python3
import argparse
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

from wpx_data import WPXData
from wpx_core import WPXCore
from wpx_finder import WPXFinder
from wpx_vulnerability import WPXVulnerability
from wpx_output import (
    print_banner, print_finding, print_info, print_warn, print_status,
    GREEN, YELLOW, RED, RESET,
)


def _ver_status(plugin_info, api_result):
    """Return a human-readable version status string comparing detected vs latest."""
    version = plugin_info.get("version", "Unknown")
    if version == "Unknown":
        return version

    latest = None
    if api_result:
        latest = api_result.get("latest_version")

    if not latest:
        return version

    if version == latest:
        status = f"{GREEN}up to date{RESET}"
    else:
        status = f"{YELLOW}outdated, latest: {latest}{RESET}"
    return f"{version} ({status})"


def main():
    parser = argparse.ArgumentParser(description="WPX - WordPress X-Ray Scanner (Stealth & WAF-Bypass)")
    parser.add_argument("--url", "-u", required=True, help="Target WordPress URL")
    parser.add_argument("--api-key", help="WPScan Vulnerability Database API Key")
    parser.add_argument("--enumerate", "-e", choices=['p', 'vp'], default='p',
                        help="Enumeration type: 'p' (plugins), 'vp' (vulnerable plugins)")
    parser.add_argument("--threads", "-t", type=int, default=20,
                        help="Number of concurrent threads (default: 20)")
    parser.add_argument("--full-scan", action="store_true",
                        help="Scan all 1500+ plugin slugs instead of top 200")

    args = parser.parse_args()
    target_url = args.url
    start_time = time.time()

    print_banner()
    print_status(f"Scanning: {target_url}")
    print_status(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    # 1. Initialize Data
    data = WPXData()
    data.download_metadata()
    data.load_dynamic_finders()
    data.load_slugs()
    data.load_wp_metadata()

    # 2. Bypass Cloudflare / WAF
    core = WPXCore(target_url)
    if not core.bypass_cloudflare():
        print_warn("Could not bypass Cloudflare. Aborting.")
        sys.exit(1)

    if not core.setup_mirror_session():
        print_warn("Could not establish a mirrored session. Aborting.")
        sys.exit(1)

    # 3. Discovery Engine
    finder = WPXFinder(core, data)

    # Homepage
    homepage_res = core.session.get(target_url, impersonate="firefox")

    # Headers
    finder.check_headers(homepage_res)

    # WP version
    finder.detect_wp_version(homepage_res.text, target_url)

    # Core files (robots.txt, xmlrpc, wp-cron, readme)
    finder.check_core_files()

    # Passive plugin/theme discovery
    finder.find_passive_items(homepage_res.text)

    # Theme details
    finder.detect_theme_details()

    # Config backups
    if data.backups:
        finder.check_config_backups()

    # Active plugin brute-force
    if args.full_scan:
        # Check repo-bundled list first, then fall back to .wpx_data/
        for candidate in [Path("plugins_full.txt"), Path(".wpx_data/plugins_full.txt")]:
            if candidate.exists():
                full_list = candidate
                break
        else:
            full_list = None
        if full_list:
            with open(full_list) as f:
                slugs = [line.strip() for line in f if line.strip()]
            print_status(f"Full scan: {len(slugs):,} slugs from {full_list} (run wpx_fetch_plugins.py to update)")
        else:
            slugs = data.plugins
            print_status(f"Full scan: {len(slugs):,} slugs (run wpx_fetch_plugins.py to get all ~58k WP.org plugins)")
    else:
        slugs = data.plugins[:200]
    finder.scan_plugins(slugs, threads=args.threads)

    # Version detection
    finder.detect_versions()

    # 4. Vulnerability API
    vuln_api = WPXVulnerability(api_key=args.api_key)
    api_results = {}
    if args.api_key:
        for slug in finder.found_plugins:
            api_results[slug] = vuln_api.get_vulnerabilities("plugins", slug)

    # ------------------------------------------------------------------
    # 5. Rich output
    # ------------------------------------------------------------------
    print()
    print("=" * 60)
    print_status(f"WPX Scan Results for: {target_url}")
    print("=" * 60)
    print()

    # --- Headers ---
    if finder.headers_result and finder.headers_result["entries"]:
        hr = finder.headers_result
        subitems = ["Interesting Entries:"]
        for entry in hr["entries"]:
            subitems.append(f" - {entry}")
        subitems.append(f"Found By: {hr['found_by']}")
        subitems.append(f"Confidence: {hr['confidence']}%")
        print_finding("Headers", subitems)
        print()

    # --- robots.txt ---
    if "robots_txt" in finder.core_files:
        rt = finder.core_files["robots_txt"]
        subitems = []
        if rt["entries"]:
            subitems.append("Interesting Entries:")
            for e in rt["entries"]:
                subitems.append(f" - {e}")
        subitems.append(f"Found By: {rt['found_by']}")
        subitems.append(f"Confidence: {rt['confidence']}%")
        print_finding(f"robots.txt found: {rt['url']}", subitems)
        print()

    # --- XML-RPC ---
    if "xmlrpc" in finder.core_files:
        xi = finder.core_files["xmlrpc"]
        subitems = [f"Found By: {xi['found_by']}", f"Confidence: {xi['confidence']}%", "References:"]
        for ref in xi["references"]:
            subitems.append(f" - {ref}")
        print_finding(f"XML-RPC seems to be enabled: {xi['url']}", subitems)
        print()

    # --- WP-Cron ---
    if "wp_cron" in finder.core_files:
        wc = finder.core_files["wp_cron"]
        subitems = [f"Found By: {wc['found_by']}", f"Confidence: {wc['confidence']}%", "References:"]
        for ref in wc["references"]:
            subitems.append(f" - {ref}")
        print_finding(f"The external WP-Cron seems to be enabled: {wc['url']}", subitems)
        print()

    # --- WordPress readme.html ---
    if "readme" in finder.core_files:
        rd = finder.core_files["readme"]
        print_finding(
            f"WordPress readme found: {rd['url']}",
            [f"Found By: {rd['found_by']}", f"Confidence: {rd['confidence']}%"],
        )
        print()

    # --- WP Version ---
    if finder.wp_version:
        wv = finder.wp_version
        version = wv["version"]

        if wv.get("is_latest") is True:
            rd = wv.get("release_date")
            rd_str = f", released on {rd}" if rd else ""
            ver_label = f"{version} identified ({GREEN}Latest{rd_str}{RESET})"
        elif wv.get("is_latest") is False:
            latest = wv.get("latest_version", "?")
            ver_label = f"{version} identified ({YELLOW}Outdated, latest: {latest}{RESET})"
        else:
            ver_label = f"{version} identified"

        subitems = [
            f"Found By: {wv['found_by']}",
            f" - {wv['found_url']}, Match: '{wv['found_match']}'",
        ]
        if wv.get("confirmed_by"):
            cb = wv["confirmed_by"]
            subitems.append(f"Confirmed By: {cb['method']}")
            match_str = f", Match: '{cb['match']}'" if cb.get("match") else ""
            subitems.append(f" - {cb['url']}{match_str}")

        print_finding(f"WordPress version {ver_label}", subitems)
        print()

    # --- Theme ---
    if finder.theme and isinstance(finder.theme, dict):
        th = finder.theme
        subitems = [f"Location: {th['location']}"]
        if th.get("readme_url"):
            subitems.append(f"Readme: {th['readme_url']}")
        if th.get("style_url"):
            subitems.append(f"Style URL: {th['style_url']}")
        if th.get("name"):
            subitems.append(f"Style Name: {th['name']}")
        if th.get("description"):
            subitems.append(f"Description: {th['description']}")
        if th.get("author"):
            subitems.append(f"Author: {th['author']}")
        subitems.append(f"Found By: {th['found_by']}")
        if th.get("confirmed_by"):
            subitems.append(f"Confirmed By: {th['confirmed_by']}")
        if th.get("version"):
            subitems.append(f"Version: {th['version']} ({th.get('version_confidence', '?')}% confidence)")
            subitems.append(f"Found By: {th['version_found_by']}")
        print_finding(f"WordPress theme in use: {th['slug']}", subitems)
        print()

    # --- Config Backups ---
    if finder.config_backups:
        for bu in finder.config_backups:
            print_finding(f"A Config Backup file has been found: {bu}")
        print()

    # --- Plugins ---
    if not finder.found_plugins:
        print_info("No plugins detected.")
    else:
        for slug, info in finder.found_plugins.items():
            ar = api_results.get(slug)
            version = info.get("version", "Unknown")
            version_confidence = info.get("version_confidence", 0)
            version_found_by = info.get("version_found_by")
            version_url = info.get("version_url")

            subitems = [f"Location: {info.get('location', '')}"]

            # Latest version from API
            if ar and ar.get("latest_version"):
                latest = ar["latest_version"]
                if version != "Unknown" and version == latest:
                    status_str = f"{GREEN}up to date{RESET}"
                elif version != "Unknown":
                    status_str = f"{YELLOW}outdated{RESET}"
                else:
                    status_str = ""
                label = f"{latest} ({status_str})" if status_str else latest
                subitems.append(f"Latest Version: {label}")
            if ar and ar.get("last_updated"):
                subitems.append(f"Last Updated: {ar['last_updated']}")

            subitems.append(f"Found By: {info.get('found_by', 'Unknown')}")
            if info.get("confirmed_by"):
                subitems.append(f"Confirmed By: {info['confirmed_by']}")

            if version != "Unknown" and version_confidence:
                subitems.append(f"Version: {version} ({version_confidence}% confidence)")
                if version_found_by:
                    subitems.append(f"Found By: {version_found_by}")
                if version_url:
                    subitems.append(f" - {version_url}")
            elif version != "Unknown":
                subitems.append(f"Version: {version}")

            # Vulnerabilities
            if ar and ar.get("vulns"):
                vulns = ar["vulns"]
                title_str = f"{RED}[VULNERABLE]{RESET} {slug}"
                subitems.append(f"{len(vulns)} vulnerability/ies found:")
                for vuln in vulns:
                    subitems.append(f" | Title: {vuln['title']}")
                    subitems.append(f" | Fixed In: {vuln.get('fixed_in', 'N/A')}")
                    refs = vuln.get("references", {}).get("url", [])
                    if refs:
                        subitems.append(f" | References: {refs[0]}")
                print_finding(title_str, subitems)
            else:
                print_finding(slug, subitems)
            print()

    # ------------------------------------------------------------------
    # 6. Summary
    # ------------------------------------------------------------------
    elapsed = time.time() - start_time
    elapsed_str = str(timedelta(seconds=int(elapsed)))
    print("=" * 60)
    print_finding(f"Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print_finding(f"Elapsed time: {elapsed_str}")
    print()


if __name__ == "__main__":
    main()
