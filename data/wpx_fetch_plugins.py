#!/usr/bin/env python3
"""
Fetch the full WordPress.org plugin catalog and save to .wpx_data/.

Outputs:
  .wpx_data/plugins_catalog.json  — slug → metadata (active_installs, downloads, rating…)
  plugins_dead.jsonl              — repo-bundled cache for dead plugin metadata
  plugins_full.txt                — all slugs (active sorted by popularity, dead by last_updated)

Usage:
  python3 wpx_fetch_plugins.py [--sort-by active_installs|downloaded|rating]
"""
import argparse
import asyncio
import json
import math
import re
import sys
import time
import urllib.request
from pathlib import Path
from datetime import datetime

DATA_DIR = Path(".wpx_data")
CATALOG_FILE = Path("data/plugins_catalog.json")
DEAD_CATALOG_FILE = Path("data/plugins_dead.jsonl")
SLUGS_FILE = Path("data/plugins_full.txt")

API_BASE = "https://api.wordpress.org/plugins/info/1.2/"
SVN_BASE = "https://plugins.svn.wordpress.org/"
PER_PAGE = 250
CHECKPOINT_EVERY = 25
POLITE_DELAY = 0.15

# Global adaptive rate limiting for SVN
svn_delay = 0.0
svn_backoff_active = False

SORT_KEYS = {
    "score": lambda p: math.sqrt(p.get("active_installs", 0) * p.get("downloaded", 0)),
    "active_installs": lambda p: p.get("active_installs", 0),
    "downloaded": lambda p: p.get("downloaded", 0),
}


def api_url(page):
    fields = "&".join([
        "request[fields][description]=0",
        "request[fields][sections]=0",
        "request[fields][banners]=0",
        "request[fields][icons]=0",
        "request[fields][tags]=0",
        "request[fields][donate_link]=0",
        "request[fields][homepage]=0",
        "request[fields][short_description]=0",
        "request[fields][downloaded]=1",
        "request[fields][active_installs]=1",
        "request[fields][rating]=1",
        "request[fields][num_ratings]=1",
        "request[fields][last_updated]=1",
        "request[fields][added]=1",
    ])
    return (
        f"{API_BASE}?action=query_plugins"
        f"&request[per_page]={PER_PAGE}"
        f"&request[page]={page}"
        f"&{fields}"
    )


def fetch_page(page, retries=3):
    req = urllib.request.Request(
        api_url(page),
        headers={"User-Agent": "WPX-Plugin-Fetcher/1.0"},
    )
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read())
        except Exception:
            if attempt == retries - 1:
                raise
            time.sleep(2 ** attempt)
    return None


def extract(plugin):
    return {
        "name":            plugin.get("name", ""),
        "active_installs": plugin.get("active_installs", 0),
        "downloaded":      plugin.get("downloaded", 0),
        "rating":          plugin.get("rating", 0),
        "num_ratings":     plugin.get("num_ratings", 0),
        "last_updated":    plugin.get("last_updated", ""),
        "added":           plugin.get("added", ""),
    }


def fetch_svn_slugs():
    """Scrape the SVN root for all ~150k plugin slugs."""
    print(f"[*] Scraping SVN root: {SVN_BASE}...")
    slugs = set()
    try:
        req = urllib.request.Request(SVN_BASE, headers={"User-Agent": "WPX-Plugin-Fetcher/1.0"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            # Stream the response to avoid huge memory usage
            for line in resp:
                line_str = line.decode('utf-8', errors='ignore')
                # Pattern for <a href="slug/">slug/</a>
                matches = re.findall(r'href="([^/"]+)/"', line_str)
                for slug in matches:
                    if slug != "..":
                        slugs.add(slug)
    except Exception as e:
        print(f"[!] Failed to scrape SVN root: {e}")
    return slugs


def load_dead_catalog():
    catalog = {}
    if DEAD_CATALOG_FILE.exists():
        with open(DEAD_CATALOG_FILE, "r") as f:
            for line in f:
                try:
                    data = json.loads(line.strip())
                    if "slug" in data and "last_updated" in data:
                        catalog[data["slug"]] = data["last_updated"]
                except Exception:
                    continue
    return catalog


async def fetch_dead_metadata(slugs_to_fetch):
    global svn_delay, svn_backoff_active
    from curl_cffi.requests import AsyncSession

    if not slugs_to_fetch:
        return

    print(f"[*] Fetching metadata for {len(slugs_to_fetch):,} new dead plugins...")
    sem = asyncio.Semaphore(10)
    total = len(slugs_to_fetch)
    completed = 0

    async def fetch_one(session, slug):
        global svn_delay, svn_backoff_active
        nonlocal completed
        url = f"{SVN_BASE}{slug}/"

        async with sem:
            while True:
                if svn_delay > 0:
                    await asyncio.sleep(svn_delay)

                try:
                    # Use HEAD to get Last-Modified without body
                    res = await session.head(url, timeout=15, impersonate="firefox")

                    if res.status_code == 200:
                        last_mod = res.headers.get("Last-Modified", "")
                        # Reduce delay slightly on success if we were backing off
                        if svn_backoff_active:
                            svn_delay = max(0.1, svn_delay * 0.9)
                        
                        completed += 1
                        if completed % 10 == 0 or completed == total:
                            pct = completed / total * 100
                            print(f"\r[*] Graveyard progress: {completed}/{total} ({pct:.1f}%) — delay: {svn_delay:.2f}s", end="", flush=True)

                        result = {"slug": slug, "last_updated": last_mod}
                        # Append to JSONL immediately
                        with open(DEAD_CATALOG_FILE, "a") as f:
                            f.write(json.dumps(result) + "\n")
                        return result

                    elif res.status_code in [429, 404, 403]:
                        # 404/403 often mean block on SVN
                        print(f"\n[!] Throttled ({res.status_code}) on {slug}. Cooling down 60s...")
                        svn_backoff_active = True
                        if svn_delay == 0:
                            svn_delay = 0.5
                        else:
                            svn_delay = min(30, svn_delay * 2)
                        await asyncio.sleep(60)
                        continue # Retry this slug

                    else:
                        completed += 1
                        return None

                except Exception as e:
                    # Network error, retry
                    await asyncio.sleep(5)
                    continue

    async with AsyncSession() as session:
        tasks = [fetch_one(session, slug) for slug in slugs_to_fetch]
        await asyncio.gather(*tasks)
    print()


def main():
    parser = argparse.ArgumentParser(description="Fetch WordPress.org plugin catalog for WPX")
    parser.add_argument(
        "--sort-by",
        choices=list(SORT_KEYS),
        default="score",
        help="How to rank active plugins (default: score)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Re-fetch everything even if catalog already exists",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        metavar="N",
        help="Stop after fetching N active plugins (0 = all)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print full metadata for each plugin",
    )
    args = parser.parse_args()

    DATA_DIR.mkdir(exist_ok=True)

    # 1. Load Active Catalog
    catalog = {}
    if CATALOG_FILE.exists() and not args.force:
        with open(CATALOG_FILE) as f:
            catalog = json.load(f)
        print(f"[*] Loaded active catalog: {len(catalog)} plugins.")

    # 2. Fetch Active Plugins from API
    print("[*] Fetching page 1...")
    try:
        first = fetch_page(1)
    except Exception as e:
        print(f"[!] Failed to reach WordPress.org API: {e}")
        sys.exit(1)

    total_pages = first["info"]["pages"]
    total_active_reported = first["info"]["results"]
    print(f"[*] API reports {total_active_reported:,} active plugins")

    for p in first["plugins"]:
        catalog[p["slug"]] = extract(p)

    def _limit_reached():
        return args.limit > 0 and len(catalog) >= args.limit

    for page in range(2, total_pages + 1):
        if _limit_reached():
            break
        print(f"\r[*] API Page {page}/{total_pages} — {len(catalog):,} plugins", end="", flush=True)
        try:
            data = fetch_page(page)
            for p in data.get("plugins", []):
                catalog[p["slug"]] = extract(p)
                if _limit_reached():
                    break
        except Exception as e:
            print(f"\n[!] Page {page} failed: {e}")

        if page % CHECKPOINT_EVERY == 0:
            with open(CATALOG_FILE, "w") as f:
                json.dump(catalog, f)
        time.sleep(POLITE_DELAY)
    print(f"\n[+] Active plugins fetched: {len(catalog):,}")

    with open(CATALOG_FILE, "w") as f:
        json.dump(catalog, f, indent=2)

    # 3. Fetch Master List from SVN
    svn_slugs = fetch_svn_slugs()
    print(f"[+] SVN reports {len(svn_slugs):,} total slugs ever created.")

    # 4. Process the Graveyard
    dead_catalog = load_dead_catalog()
    active_slugs = set(catalog.keys())
    dead_slugs_all = svn_slugs - active_slugs
    newly_dead = list(dead_slugs_all - set(dead_catalog.keys()))

    if newly_dead:
        asyncio.run(fetch_dead_metadata(newly_dead))
        # Reload to get the new results
        dead_catalog = load_dead_catalog()

    # 5. Build Final Sorted List
    print("[*] Sorting and building final slug list...")
    
    # Sort active by popularity
    sort_fn = SORT_KEYS[args.sort_by]
    sorted_active = sorted(catalog, key=lambda s: sort_fn(catalog[s]), reverse=True)
    
    # Sort dead by last updated (newest first)
    # Parse dates for sorting: "Wed, 03 Feb 2016 14:24:48 GMT"
    def parse_svn_date(date_str):
        if not date_str:
            return 0
        try:
            return datetime.strptime(date_str, "%a, %d %b %Y %H:%M:%S %Z").timestamp()
        except Exception:
            return 0

    sorted_dead = sorted(
        [s for s in dead_slugs_all if s in dead_catalog],
        key=lambda s: parse_svn_date(dead_catalog[s]),
        reverse=True
    )
    
    # Any dead plugins we failed to get dates for (alphabetical)
    undated_dead = sorted(list(dead_slugs_all - set(dead_catalog.keys())))

    final_list = sorted_active + sorted_dead + undated_dead
    
    with open(SLUGS_FILE, "w") as f:
        f.write("\n".join(final_list) + "\n")
    
    print(f"[+] Final list saved → {SLUGS_FILE}")
    print(f"    - {len(sorted_active):,} active (sorted by {args.sort_by})")
    print(f"    - {len(sorted_dead):,} closed/dead (sorted by last updated)")
    print(f"    - {len(undated_dead):,} undated dead")
    print(f"    - Total: {len(final_list):,} slugs")


if __name__ == "__main__":
    main()
