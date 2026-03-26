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
from packaging.version import Version, InvalidVersion
from wpx_output import (
    init_output,
    print_banner, print_finding, print_info, print_warn, print_status, print_plain,
    GREEN, YELLOW, RED, RESET,
)


def _is_version_affected(detected: str, fixed_in) -> bool:
    """Return True if the detected version is still affected by this vulnerability."""
    if not fixed_in or fixed_in == "N/A":
        return True  # unknown fix point — assume affected
    if not detected or detected == "Unknown":
        return True  # unknown installed version — assume affected
    try:
        return Version(detected) < Version(str(fixed_in))
    except InvalidVersion:
        return True  # unparseable version — assume affected


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
    parser = argparse.ArgumentParser(
        description="WPX - WordPress X-Ray Scanner (Stealth & WAF-Bypass)"
    )
    parser.add_argument("--url", "-u", required=True, help="Target WordPress URL")
    parser.add_argument("--api-key", help="WPScan Vulnerability Database API Key")
    parser.add_argument("--threads", "-t", type=int, default=20,
                        help="Number of concurrent threads (default: 20)")
    parser.add_argument("--plugins-limit", type=int,
                        help="Limit the number of plugins to scan (e.g. 500, 5000)")
    parser.add_argument("--full-scan", action="store_true",
                        help="Scan all available plugin slugs (up to 50k+ if fetched)")
    parser.add_argument("--update", action="store_true",
                        help="Force update of WPScan metadata files")
    parser.add_argument("--no-browser", action="store_true",
                        help="Skip Camoufox WAF bypass and connect directly (no stealth)")
    parser.add_argument("--enum-users-disable", action="store_true",
                        help="Skip user enumeration")
    parser.add_argument("--users-limit", type=int, default=10,
                        help="Number of author IDs to probe via ?author=N (default: 10)")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="Suppress banner, status, and progress — show findings only")
    parser.add_argument("--output", "-o", metavar="FILE",
                        help="Write output to FILE (plain text, no ANSI codes)")

    args = parser.parse_args()

    out_file = open(args.output, 'w', encoding='utf-8') if args.output else None
    try:
        init_output(quiet=args.quiet, output_file=out_file)
        _run(args)
    finally:
        if out_file:
            out_file.close()


def _run(args):
    if args.update:
        print_banner()
        data = WPXData(force_update=True)
        data.download_metadata()
        print_info("Metadata update complete.")
        print_info("To update the full plugin catalog, run: python3 wpx_fetch_plugins.py")
        sys.exit(0)

    target_url = args.url
    if "://" not in target_url:
        target_url = "https://" + target_url
    start_time = time.time()

    print_banner()
    print_status(f"Scanning: {target_url}")
    print_status(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print_plain()

    # 1. Initialize Data
    data = WPXData()
    stale = data.get_stale_files()
    if stale:
        print_warn(f"Some data files are older than 30 days or missing: {', '.join(stale[:3])}...")
        print_warn("It is recommended to run: python3 wpx.py --update")
        print_plain()

    data.download_metadata()
    data.load_dynamic_finders()
    data.load_slugs()
    data.load_wp_metadata()
    data.load_user_enum_techniques()

    # 2. WAF Bypass
    core = WPXCore(target_url)
    if args.no_browser:
        print_warn("--no-browser: skipping WAF bypass, using direct session.")
    else:
        bypassed = core.bypass_waf()
        if not bypassed:
            print_warn("WAF bypass failed. See diagnostic output above.")
            print_warn("  Skip bypass  : python3 wpx.py --no-browser -u " + target_url)
            sys.exit(1)

    if not core.setup_mirror_session():
        print_warn("Could not establish a session (WAF may be blocking). Aborting.")
        sys.exit(1)

    # 3. Discovery Engine
    finder = WPXFinder(core, data)

    try:
        # Homepage
        homepage_res = core.session.get(target_url, impersonate="firefox")

        # Headers
        finder.check_headers(homepage_res)

        # WP version
        finder.detect_wp_version(homepage_res.text, target_url)

        # Core files (robots.txt, xmlrpc, wp-cron, readme) + multisite
        finder.check_core_files()
        finder.detect_multisite()

        # Passive plugin/theme discovery
        finder.find_passive_items(homepage_res.text)

        # Theme details
        finder.detect_theme_details()

        # Config backups
        if data.backups:
            finder.check_config_backups()

        # 4. Active plugin brute-force selection
        best_source = None
        for candidate in [Path("data/plugins_full.txt"), Path("plugins_full.txt"), Path(".wpx_data/plugins_full.txt")]:
            if candidate.exists():
                best_source = candidate
                break

        if best_source:
            with open(best_source) as f:
                all_slugs = [line.strip() for line in f if line.strip()]
            source_name = str(best_source)
        else:
            all_slugs = data.plugins
            source_name = "WPScan default list"

        if not all_slugs:
            print_warn("No plugin slugs found. Skipping active enumeration.")
            slugs = []
        elif args.full_scan:
            slugs = all_slugs
            print_status(f"Full scan: {len(slugs):,} slugs from {source_name}")
        elif args.plugins_limit:
            slugs = all_slugs[:args.plugins_limit]
            print_status(
                f"Limited scan: {len(slugs):,} slugs (top {args.plugins_limit}) from {source_name}"
            )
        else:
            slugs = all_slugs[:200]
            print_status(f"Default scan: {len(slugs):,} slugs (top 200) from {source_name}")

        if slugs:
            finder.scan_plugins(slugs, threads=args.threads)

        # Version detection
        finder.detect_versions()

        # User enumeration
        if not args.enum_users_disable:
            finder.enumerate_users(
                techniques=data.user_enum_techniques,
                users_limit=args.users_limit,
            )

    except KeyboardInterrupt:
        print_plain()
        print_warn("Scan interrupted by user (Ctrl+C). Showing partial results...")

    # 5. Vulnerability API
    vuln_api = WPXVulnerability(api_key=args.api_key)
    api_results = {}
    if args.api_key:
        for slug in finder.found_plugins:
            api_results[slug] = vuln_api.get_vulnerabilities("plugins", slug)

    # ------------------------------------------------------------------
    # 5. Rich output
    # ------------------------------------------------------------------
    print_plain()
    print_plain("=" * 60)
    print_status(f"WPX Scan Results for: {target_url}")
    print_plain("=" * 60)
    print_plain()

    # --- Headers ---
    if finder.headers_result and finder.headers_result["entries"]:
        hr = finder.headers_result
        subitems = ["Interesting Entries:"]
        for entry in hr["entries"]:
            subitems.append(f" - {entry}")
        subitems.append(f"Found By: {hr['found_by']}")
        subitems.append(f"Confidence: {hr['confidence']}%")
        print_finding("Headers", subitems)
        print_plain()

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
        print_plain()

    # --- XML-RPC ---
    if "xmlrpc" in finder.core_files:
        xi = finder.core_files["xmlrpc"]
        subitems = [f"Found By: {xi['found_by']}", f"Confidence: {xi['confidence']}%", "References:"]
        for ref in xi["references"]:
            subitems.append(f" - {ref}")
        print_finding(f"XML-RPC seems to be enabled: {xi['url']}", subitems)
        print_plain()

    # --- WP-Cron ---
    if "wp_cron" in finder.core_files:
        wc = finder.core_files["wp_cron"]
        subitems = [f"Found By: {wc['found_by']}", f"Confidence: {wc['confidence']}%", "References:"]
        for ref in wc["references"]:
            subitems.append(f" - {ref}")
        print_finding(f"The external WP-Cron seems to be enabled: {wc['url']}", subitems)
        print_plain()

    # --- Multisite ---
    if finder.multisite:
        ms = finder.multisite
        subitems = [
            f"Found By: {ms['found_by']}",
            f"Confidence: {ms['confidence']}%",
            f"Reference: {ms['reference']}",
        ]
        if ms.get("confirmed_by"):
            cb = ms["confirmed_by"]
            subitems.append(f"Confirmed By: {cb['found_by']}")
            subitems.append(f" - {cb['url']}")
        print_finding(f"This site appears to be a WordPress Multisite: {ms['url']}", subitems)
        print_plain()

    # --- WordPress readme.html ---
    if "readme" in finder.core_files:
        rd = finder.core_files["readme"]
        print_finding(
            f"WordPress readme found: {rd['url']}",
            [f"Found By: {rd['found_by']}", f"Confidence: {rd['confidence']}%"],
        )
        print_plain()

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
            ver_label = (
                f"{version} identified ({YELLOW}Outdated, latest: {latest}{RESET})"
            )
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
        print_plain()

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
            ver = th.get("version")
            conf = th.get("version_confidence", "?")
            subitems.append(f"Version: {ver} ({conf}% confidence)")
            subitems.append(f"Found By: {th['version_found_by']}")
        print_finding(f"WordPress theme in use: {th['slug']}", subitems)
        print_plain()

    # --- Config Backups ---
    if finder.config_backups:
        for bu in finder.config_backups:
            print_finding(f"A Config Backup file has been found: {bu}")
        print_plain()

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
                label = f"Version: {version} ({version_confidence}% confidence)"
                subitems.append(label)
                if version_found_by:
                    subitems.append(f"Found By: {version_found_by}")
                if version_url:
                    subitems.append(f" - {version_url}")
            elif version != "Unknown":
                subitems.append(f"Version: {version}")

            # Vulnerabilities
            if ar and ar.get("vulns"):
                all_vulns = ar["vulns"]
                vulns = [v for v in all_vulns if _is_version_affected(version, v.get("fixed_in"))]
                skipped = len(all_vulns) - len(vulns)
                if vulns:
                    title_str = f"{RED}[VULNERABLE]{RESET} {slug}"
                    count_note = f"{len(vulns)} active vulnerability/ies found"
                    if skipped:
                        count_note += f" ({len(all_vulns)} total, {skipped} fixed in current version)"
                    subitems.append(count_note + ":")
                    for vuln in vulns:
                        subitems.append(f" | Title: {vuln['title']}")
                        subitems.append(f" | Fixed In: {vuln.get('fixed_in', 'N/A')}")
                        refs = vuln.get("references", {}).get("url", [])
                        if refs:
                            subitems.append(f" | References: {refs[0]}")
                    print_finding(title_str, subitems)
                else:
                    if skipped:
                        subitems.append(f"No active vulnerabilities ({skipped} historical, all fixed)")
                    print_finding(slug, subitems)
            else:
                print_finding(slug, subitems)
            print_plain()

    # --- Users ---
    if not args.enum_users_disable:
        found_users = finder.found_users
        blocked = finder.user_enum_blocked
        has_found = bool(found_users)
        has_blocked = bool(blocked)

        # Status
        if has_found and has_blocked:
            status = f"{YELLOW}Partially Protected{RESET}"
        elif has_found:
            status = f"{RED}Vulnerable{RESET}"
        elif has_blocked:
            status = f"{GREEN}Fully Protected{RESET}"
        else:
            status = "Unknown"

        # Risk level — based on which methods leaked users
        _high_risk = {"REST API User Enumeration", "Author Archive (?author=N)", "Passive HTML Scan"}
        _med_risk = {"oEmbed Author Leak"}
        if has_found:
            leaked_via = {u["found_by"] for u in found_users}
            if leaked_via & _high_risk:
                risk = f"{RED}High{RESET}"
            elif leaked_via & _med_risk:
                risk = f"{YELLOW}Medium{RESET}"
            else:
                risk = f"{YELLOW}Low{RESET}"
        else:
            risk = f"{GREEN}None{RESET}"

        subitems = [f"Status: {status}"]
        if has_found:
            subitems.append(f"{len(found_users)} user(s) found via leakage")
        else:
            subitems.append("No users found")

        if has_found:
            subitems.append("")
            subitems.append("Users Discovered:")
            for u in found_users:
                label = u.get("login") or u.get("name") or "unknown"
                uid_str = f" (ID: {u['id']})" if u.get("id") else ""
                subitems.append(f"  \u2022 {label}{uid_str}")
                subitems.append(f"    Found By: {u['found_by']}")
                subitems.append(f"    Confidence: {u['confidence']}%")

        if has_blocked:
            subitems.append("")
            subitems.append("Blocked Methods:")
            for m in blocked:
                subitems.append(f"  {GREEN}\u2713{RESET} {m:<42}(Good)")

        subitems.append("")
        subitems.append(f"Risk Level: {risk}")

        # Contextual recommendation
        if has_found:
            leaked_via = {u["found_by"] for u in found_users}
            recs = []
            if "REST API User Enumeration" in leaked_via:
                recs.append(
                    "Restrict the /wp/v2/users REST API endpoint to authenticated users only."
                )
            if leaked_via & {"Author Archive (?author=N)", "Passive HTML Scan"}:
                recs.append(
                    "Block ?author= redirects and disable author archive pages via your security plugin."
                )
            if "RSS Feed Author Leak" in leaked_via:
                recs.append(
                    "Apply the `the_author` and `the_content_feed` filters to hide author info from feeds."
                )
            if "oEmbed Author Leak" in leaked_via:
                recs.append("Restrict or disable the oEmbed endpoint.")
            if recs:
                subitems.append(f"Recommendation: {recs[0]}")
                for r in recs[1:]:
                    subitems.append(f"  {r}")

        print_finding("User Enumeration", subitems)
        print_plain()

    # ------------------------------------------------------------------
    # 6. Summary
    # ------------------------------------------------------------------
    elapsed = time.time() - start_time
    elapsed_str = str(timedelta(seconds=int(elapsed)))
    print_plain("=" * 60)
    print_finding(f"Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print_finding(f"Elapsed time: {elapsed_str}")
    print_plain()


if __name__ == "__main__":
    main()
