#!/usr/bin/env python3
import argparse
import sys
from wpx_data import WPXData
from wpx_core import WPXCore
from wpx_finder import WPXFinder
from wpx_vulnerability import WPXVulnerability

def main():
    parser = argparse.ArgumentParser(description="WPX - WordPress X-Ray Scanner (Stealth & WAF-Bypass)")
    parser.add_argument("--url", "-u", required=True, help="Target WordPress URL")
    parser.add_argument("--api-key", help="WPScan Vulnerability Database API Key")
    parser.add_argument("--enumerate", "-e", choices=['p', 'vp'], default='p', 
                        help="Enumeration type: 'p' (plugins), 'vp' (vulnerable plugins)")
    parser.add_argument("--threads", "-t", type=int, default=20, help="Number of concurrent threads (default: 20)")
    parser.add_argument("--full-scan", action="store_true", help="Scan all 1500+ plugin slugs instead of top 200")
    
    args = parser.parse_args()
    target_url = args.url

    # 1. Initialize Data
    data = WPXData()
    data.download_metadata()
    data.load_dynamic_finders()
    data.load_slugs()

    # 2. Bypass Cloudflare / WAF
    core = WPXCore(target_url)
    if not core.bypass_cloudflare():
        print("[!] Could not bypass Cloudflare. Aborting.")
        sys.exit(1)

    if not core.setup_mirror_session():
        print("[!] Could not establish a mirrored session. Aborting.")
        sys.exit(1)

    # 3. Discovery Engine
    finder = WPXFinder(core, data)
    
    # Get homepage content for passive detection
    homepage_res = core.session.get(target_url, impersonate="firefox")
    finder.detect_wp_version(homepage_res.text)
    finder.check_core_files()
    finder.find_passive_items(homepage_res.text)
    
    # Select plugin slugs for brute force
    slugs = data.plugins if args.full_scan else data.plugins[:200]
    
    finder.scan_plugins(slugs, threads=args.threads)
    finder.detect_versions()

    # 4. Vulnerability Reporting
    vuln_api = WPXVulnerability(api_key=args.api_key)
    
    print("\n" + "="*50)
    print(f"WPX SCAN RESULTS FOR: {target_url}")
    print("="*50)
    
    if not finder.found_plugins:
        print("[+] No plugins detected.")
    else:
        for slug, info in finder.found_plugins.items():
            version = info["version"]
            print(f"[*] {slug} ({version})")
            
            if args.api_key:
                vulns = vuln_api.get_vulnerabilities("plugins", slug)
                if vulns:
                    print(vuln_api.format_report(slug, vulns))

    print("\n[*] Scan complete.")

if __name__ == "__main__":
    main()
