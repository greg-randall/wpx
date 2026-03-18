#!/usr/bin/env python3
"""
Fetch the full WordPress.org plugin catalog and save to .wpx_data/.

Outputs:
  .wpx_data/plugins_catalog.json  — slug → metadata (active_installs, downloads, rating…)
  .wpx_data/plugins_full.txt      — all slugs sorted by active_installs desc

Run once (takes ~5 min for ~58k plugins), then use --full-scan in wpx.py.
Resume-safe: skips pages already in the catalog file.

Usage:
  python3 wpx_fetch_plugins.py [--sort-by active_installs|downloaded|rating]
"""
import argparse
import json
import math
import sys
import time
import urllib.request
from pathlib import Path

DATA_DIR = Path(".wpx_data")
CATALOG_FILE = DATA_DIR / "plugins_catalog.json"
SLUGS_FILE = Path("plugins_full.txt")  # repo-bundled, not in .wpx_data/

API_BASE = "https://api.wordpress.org/plugins/info/1.2/"
PER_PAGE = 250
CHECKPOINT_EVERY = 25   # save catalog to disk every N pages
POLITE_DELAY = 0.15     # seconds between requests

SORT_KEYS = {
    "score": lambda p: math.sqrt(p["active_installs"] * p["downloaded"]),
    "active_installs": lambda p: p["active_installs"],
    "downloaded": lambda p: p["downloaded"],
}


def api_url(page):
    # Exclude heavy fields we don't need (description, sections, banners, icons, tags)
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


def main():
    parser = argparse.ArgumentParser(description="Fetch WordPress.org plugin catalog for WPX")
    parser.add_argument(
        "--sort-by",
        choices=list(SORT_KEYS),
        default="score",
        help="How to rank plugins in plugins_full.txt (default: score = sqrt(active_installs × downloaded))",
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
        help="Stop after fetching N plugins (0 = all, useful for testing)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print full metadata for each plugin in the final sorted list",
    )
    args = parser.parse_args()

    DATA_DIR.mkdir(exist_ok=True)

    # Load existing catalog for resuming
    catalog = {}
    if CATALOG_FILE.exists() and not args.force:
        with open(CATALOG_FILE) as f:
            catalog = json.load(f)
        print(f"[*] Loaded existing catalog: {len(catalog)} plugins. Resuming.")

    # Page 1 to get totals
    print("[*] Fetching page 1...")
    try:
        first = fetch_page(1)
    except Exception as e:
        print(f"[!] Failed to reach WordPress.org API: {e}")
        sys.exit(1)

    total_pages = first["info"]["pages"]
    total_plugins = first["info"]["results"]
    print(f"[*] WordPress.org reports {total_plugins:,} plugins across {total_pages:,} pages")

    for p in first["plugins"]:
        catalog[p["slug"]] = extract(p)

    def _limit_reached():
        return args.limit > 0 and len(catalog) >= args.limit

    # Fetch remaining pages
    failed_pages = []
    for page in range(2, total_pages + 1):
        if _limit_reached():
            print(f"\n[*] --limit {args.limit} reached, stopping early.")
            break
        pct = page / total_pages * 100
        print(
            f"\r[*] Page {page}/{total_pages} ({pct:.1f}%)  —  {len(catalog):,} plugins collected",
            end="", flush=True,
        )
        try:
            data = fetch_page(page)
            for p in data.get("plugins", []):
                catalog[p["slug"]] = extract(p)
                if _limit_reached():
                    break
        except Exception as e:
            print(f"\n[!] Page {page} failed: {e}")
            failed_pages.append(page)

        if page % CHECKPOINT_EVERY == 0:
            with open(CATALOG_FILE, "w") as f:
                json.dump(catalog, f)

        time.sleep(POLITE_DELAY)

    print(f"\n[+] Fetched {len(catalog):,} plugins ({len(failed_pages)} pages failed)")
    if failed_pages:
        print(f"[!] Failed pages: {failed_pages}")

    # Final save
    with open(CATALOG_FILE, "w") as f:
        json.dump(catalog, f, indent=2)
    print(f"[+] Catalog saved → {CATALOG_FILE}")

    # Sort and write slug list
    sort_fn = SORT_KEYS[args.sort_by]
    sorted_slugs = sorted(catalog, key=lambda s: sort_fn(catalog[s]), reverse=True)
    with open(SLUGS_FILE, "w") as f:
        f.write("\n".join(sorted_slugs) + "\n")
    print(f"[+] Slug list saved → {SLUGS_FILE}  (sorted by {args.sort_by})")

    if args.debug:
        print(f"\n[DEBUG] Full catalog ({len(sorted_slugs)} plugins, sorted by {args.sort_by}):")
        for slug in sorted_slugs:
            meta = catalog[slug]
            score = sort_fn(meta)
            print(
                f"  {slug:40s}  score={score:>14.0f}"
                f"  installs={meta['active_installs']:>10,}"
                f"  downloaded={meta['downloaded']:>12,}"
                f"  rating={meta['rating']:>5.1f}"
                f"  num_ratings={meta['num_ratings']:>6,}"
                f"  added={meta['added']}"
                f"  updated={meta['last_updated']}"
            )
    else:
        print(f"    Top 5 by {args.sort_by}:")
        for slug in sorted_slugs[:5]:
            meta = catalog[slug]
            print(f"      {slug:40s}  installs={meta['active_installs']:>10,}  rating={meta['rating']}")


if __name__ == "__main__":
    main()
