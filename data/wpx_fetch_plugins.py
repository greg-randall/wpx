#!/usr/bin/env python3
"""
Fetch the full WordPress.org plugin catalog and save to data/.

Outputs:
  data/plugins_catalog.json     — slug → metadata (active_installs, downloads, rating…)
  data/plugins_dead.jsonl       — cache for dead plugin metadata (append-only, last-write-wins)
  data/plugins_active.txt       — active slugs sorted by popularity (top --active-limit)
  data/plugins_dead.txt         — dead slugs sorted by install count (top --dead-limit)
  data/archive.org-cache/       — raw HTML snapshots used for dead plugin enrichment

Usage:
  python3 data/wpx_fetch_plugins.py [--sort-by active_installs|downloaded|score]
                                    [--active-limit N] [--dead-limit N]
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

from bs4 import BeautifulSoup

DATA_DIR = Path(__file__).parent
CATALOG_FILE = DATA_DIR / "plugins_catalog.json"
DEAD_CATALOG_FILE = DATA_DIR / "plugins_dead.jsonl"
ACTIVE_SLUGS_FILE = DATA_DIR / "plugins_active.txt"
DEAD_SLUGS_FILE = DATA_DIR / "plugins_dead.txt"
ARCHIVE_CACHE_DIR = DATA_DIR / "archive.org-cache"

API_BASE = "https://api.wordpress.org/plugins/info/1.2/"
SVN_BASE = "https://plugins.svn.wordpress.org/"
WAYBACK_AVAIL_API = "https://archive.org/wayback/available"
PER_PAGE = 250
CHECKPOINT_EVERY = 25
POLITE_DELAY = 0.15
ARCHIVE_DELAY = 0.5

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
            for line in resp:
                line_str = line.decode('utf-8', errors='ignore')
                matches = re.findall(r'href="([^/"]+)/"', line_str)
                for slug in matches:
                    if slug != "..":
                        slugs.add(slug)
    except Exception as e:
        print(f"[!] Failed to scrape SVN root: {e}")
    return slugs


def load_dead_catalog():
    """Load dead plugin records from JSONL. Last entry wins for duplicate slugs."""
    catalog = {}
    if DEAD_CATALOG_FILE.exists():
        with open(DEAD_CATALOG_FILE, "r") as f:
            for line in f:
                try:
                    data = json.loads(line.strip())
                    if "slug" in data:
                        existing = catalog.get(data["slug"], {})
                        catalog[data["slug"]] = {**existing, **data}
                except Exception:
                    continue
    return catalog


def seed_from_catalog(newly_dead, old_catalog):
    """
    Write dead JSONL entries for slugs we already have API data for.
    Returns the set of slugs that were seeded (no Archive.org needed for these).
    """
    seeded = set()
    for slug in newly_dead:
        if slug not in old_catalog:
            continue
        record = {
            "slug": slug,
            "last_updated": old_catalog[slug].get("last_updated", ""),
            "active_installs": old_catalog[slug].get("active_installs", 0),
        }
        with open(DEAD_CATALOG_FILE, "a") as f:
            f.write(json.dumps(record) + "\n")
        seeded.add(slug)
    return seeded


async def fetch_dead_metadata(slugs_to_fetch):
    global svn_delay, svn_backoff_active
    from curl_cffi.requests import AsyncSession

    if not slugs_to_fetch:
        return

    print(f"[*] Fetching SVN metadata for {len(slugs_to_fetch):,} new dead plugins...")
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
                    res = await session.head(url, timeout=15, impersonate="firefox")

                    if res.status_code == 200:
                        last_mod = res.headers.get("Last-Modified", "")
                        if svn_backoff_active:
                            svn_delay = max(0.1, svn_delay * 0.9)

                        completed += 1
                        if completed % 10 == 0 or completed == total:
                            pct = completed / total * 100
                            msg = f"\r[*] Graveyard: {completed}/{total} ({pct:.1f}%) — delay: {svn_delay:.2f}s"
                            print(msg, end="", flush=True)

                        result = {"slug": slug, "last_updated": last_mod}
                        with open(DEAD_CATALOG_FILE, "a") as f:
                            f.write(json.dumps(result) + "\n")
                        return result

                    elif res.status_code in [429, 404, 403]:
                        print(f"\n[!] Throttled ({res.status_code}) on {slug}. Cooling down 60s...")
                        svn_backoff_active = True
                        if svn_delay == 0:
                            svn_delay = 0.5
                        else:
                            svn_delay = min(30, svn_delay * 2)
                        await asyncio.sleep(60)
                        continue

                    else:
                        completed += 1
                        return None

                except Exception:
                    await asyncio.sleep(5)
                    continue

    async with AsyncSession() as session:
        tasks = [fetch_one(session, slug) for slug in slugs_to_fetch]
        await asyncio.gather(*tasks)
    print()


def parse_svn_date_to_cdx(date_str):
    """Convert 'Wed, 03 Feb 2016 14:24:48 GMT' to CDX timestamp '20160203142448'."""
    if not date_str:
        return None
    try:
        dt = datetime.strptime(date_str, "%a, %d %b %Y %H:%M:%S %Z")
        return dt.strftime("%Y%m%d%H%M%S")
    except Exception:
        return None


def parse_plugin_stats(html):
    """
    Extract popularity stats from a wordpress.org plugin page snapshot.

    Returns a dict with any of:
      active_installs — from the "X+ active installations" stat (modern pages)
      downloaded      — from the UserDownloads meta tag (older pages)
    Empty dict if nothing is found.
    """
    result = {}
    soup = BeautifulSoup(html, 'lxml')

    # Collapse all markup to plain text — handles every layout variant without
    # caring whether the number is before or after the label, or what tags wrap it.
    text = soup.get_text(' ', strip=True).lower()

    # "1 million+ active installations"
    m = re.search(r'([\d.]+)\s*million\+?\s*active\s*install', text)
    if m:
        result["active_installs"] = int(float(m.group(1)) * 1_000_000)

    # "fewer/less than 10 active installations"  OR  "active installations fewer than 10"
    if "active_installs" not in result:
        m = re.search(r'(?:fewer|less) than\s+[\d,]+\s*active\s*install', text)
        if m:
            result["active_installs"] = 0
    if "active_installs" not in result:
        m = re.search(r'active\s*installations?\s+(?:fewer|less) than', text)
        if m:
            result["active_installs"] = 0
    if "active_installs" not in result:
        # "Active Installs: Less than 10" — label then fewer/less
        m = re.search(r'active\s*install\w*:?\s*(?:fewer|less) than', text)
        if m:
            result["active_installs"] = 0
    if "active_installs" not in result:
        # "Active installations: N/A" or "Active installations N/A"
        m = re.search(r'active\s*install\w*:?\s*n/a', text)
        if m:
            result["active_installs"] = 0

    # "active installs: 5,000+"  /  "active installations: 4,000+"  /  "active installations 30+"
    if "active_installs" not in result:
        m = re.search(r'active\s*install\w*:?\s*(\d[\d,]*)', text)
        if m:
            val = m.group(1).replace(',', '')
            if val:
                result["active_installs"] = int(val)
    if "active_installs" not in result:
        m = re.search(r'(\d[\d,]*)\+?\s*active\s*install', text)
        if m:
            val = m.group(1).replace(',', '')
            if val:
                result["active_installs"] = int(val)

    # Fallback: UserDownloads meta tag (older pages that predate the installs stat)
    if "active_installs" not in result:
        meta = soup.find('meta', attrs={'itemprop': 'interactionCount'})
        if meta:
            m = re.match(r'UserDownloads:(\d+)', meta.get('content', ''))
            if m:
                result["downloaded"] = int(m.group(1))

    return result


async def enrich_dead_with_archive(slugs_to_enrich, dead_catalog):
    """
    Fetch historical active_installs from Archive.org for dead plugins.

    Uses the SVN Last-Modified date as a ceiling so we get the most recent
    snapshot while the plugin was still active in the directory. Caches raw
    HTML in ARCHIVE_CACHE_DIR so subsequent runs skip network requests.
    Enriched records are appended to DEAD_CATALOG_FILE (last-write-wins on load).
    """
    from curl_cffi.requests import AsyncSession

    if not slugs_to_enrich:
        return

    ARCHIVE_CACHE_DIR.mkdir(parents=True, exist_ok=True)

    total = len(slugs_to_enrich)
    completed = 0
    enriched = 0

    # Semaphore caps active workers; rate limiter ensures requests don't START
    # within ARCHIVE_DELAY of each other regardless of concurrency.
    sem = asyncio.Semaphore(5)
    _last_req = [0.0]
    _req_lock = asyncio.Lock()

    async def rate_limited_get(session, url):
        async with _req_lock:
            elapsed = time.time() - _last_req[0]
            if elapsed < ARCHIVE_DELAY:
                await asyncio.sleep(ARCHIVE_DELAY - elapsed)
            _last_req[0] = time.time()
        return await session.get(url, timeout=30, impersonate="firefox")

    async def enrich_one(session, slug):
        nonlocal completed, enriched

        async with sem:
            slug_data = dead_catalog.get(slug, {})
            last_updated = slug_data.get("last_updated", "") if isinstance(slug_data, dict) else ""
            cache_file = ARCHIVE_CACHE_DIR / f"{slug}.html"
            none_file = ARCHIVE_CACHE_DIR / f"{slug}.none"

            html = None

            if none_file.exists():
                completed += 1
                if completed % 25 == 0 or completed == total:
                    pct = completed / total * 100
                    print(f"\r[*] Archive: {completed}/{total} ({pct:.1f}%) — {enriched} enriched",
                          end="", flush=True)
                return
            elif cache_file.exists():
                html = cache_file.read_text(encoding='utf-8', errors='ignore')
            else:
                cdx_ts = parse_svn_date_to_cdx(last_updated)
                avail_url = (
                    f"{WAYBACK_AVAIL_API}"
                    f"?url=wordpress.org/plugins/{slug}/"
                    f"&timestamp={cdx_ts or ''}"
                )
                try:
                    resp = await rate_limited_get(session, avail_url)
                    if resp.status_code != 200:
                        completed += 1
                        return

                    data = resp.json()
                    closest = data.get("archived_snapshots", {}).get("closest", {})

                    if not closest.get("available") or closest.get("status") != "200":
                        none_file.touch()
                        completed += 1
                        if completed % 25 == 0 or completed == total:
                            pct = completed / total * 100
                            print(f"\r[*] Archive: {completed}/{total} ({pct:.1f}%) — {enriched} enriched",
                                  end="", flush=True)
                        return

                    resp2 = await rate_limited_get(session, closest["url"])
                    if resp2.status_code != 200:
                        completed += 1
                        return

                    html = resp2.text
                    cache_file.write_text(html, encoding='utf-8')

                except Exception:
                    completed += 1
                    return

            stats = parse_plugin_stats(html) if html else {}

            completed += 1
            if completed % 25 == 0 or completed == total:
                pct = completed / total * 100
                print(f"\r[*] Archive: {completed}/{total} ({pct:.1f}%) — {enriched} enriched",
                      end="", flush=True)

            if stats:
                enriched += 1
                record = {**slug_data, "slug": slug, **stats}
                with open(DEAD_CATALOG_FILE, "a") as f:
                    f.write(json.dumps(record) + "\n")

    async with AsyncSession() as session:
        await asyncio.gather(*[enrich_one(session, slug) for slug in slugs_to_enrich])

    print(f"\n[+] Archive enrichment complete: {enriched:,}/{total:,} plugins enriched")


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
        "--fetch-limit",
        type=int,
        default=0,
        metavar="N",
        help="Stop after fetching N active plugins from API (0 = all)",
    )
    parser.add_argument(
        "--active-limit",
        type=int,
        default=5000,
        metavar="N",
        help="How many active slugs to write to plugins_active.txt (0 = all, default: 5000)",
    )
    parser.add_argument(
        "--dead-limit",
        type=int,
        default=2500,
        metavar="N",
        help="How many dead slugs to write to plugins_dead.txt (0 = all, default: 2500)",
    )
    parser.add_argument(
        "--max-age",
        type=float,
        default=24.0,
        metavar="HOURS",
        help="Skip API fetch if catalog is fresher than this many hours (default: 24, 0 = always fetch)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print full metadata for each plugin",
    )
    args = parser.parse_args()

    # 1. Load previous catalog before overwriting — used to seed newly-dead plugins
    old_catalog = {}
    if CATALOG_FILE.exists():
        with open(CATALOG_FILE) as f:
            old_catalog = json.load(f)
        if not args.force:
            print(f"[*] Loaded previous catalog: {len(old_catalog):,} plugins.")

    # 2. Fetch Active Plugins from API (skip if catalog is fresh enough)
    catalog_age_h = None
    if CATALOG_FILE.exists():
        catalog_age_h = (time.time() - CATALOG_FILE.stat().st_mtime) / 3600

    skip_api = (
        not args.force
        and args.max_age > 0
        and catalog_age_h is not None
        and catalog_age_h < args.max_age
    )

    if skip_api:
        print(f"[*] Catalog is {catalog_age_h:.1f}h old (< {args.max_age}h), skipping API fetch.")
        catalog = dict(old_catalog)
    else:
        catalog = {} if args.force else dict(old_catalog)

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

        def _fetch_limit_reached():
            return args.fetch_limit > 0 and len(catalog) >= args.fetch_limit

        for page in range(2, total_pages + 1):
            if _fetch_limit_reached():
                break
            print(f"\r[*] API Page {page}/{total_pages} — {len(catalog):,} plugins", end="", flush=True)
            try:
                data = fetch_page(page)
                for p in data.get("plugins", []):
                    catalog[p["slug"]] = extract(p)
                    if _fetch_limit_reached():
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
        # Seed from previous catalog first — no network needed for recently-closed plugins
        seeded = seed_from_catalog(newly_dead, old_catalog)
        if seeded:
            print(f"[+] Seeded {len(seeded):,} newly-dead plugins from previous catalog")

        # Fetch SVN Last-Modified for the rest
        needs_svn = [s for s in newly_dead if s not in seeded]
        if needs_svn:
            asyncio.run(fetch_dead_metadata(needs_svn))

        dead_catalog = load_dead_catalog()

    # 5. Enrich with Archive.org — only for slugs missing both popularity metrics
    needs_enrichment = [
        s for s in dead_slugs_all
        if s in dead_catalog
        and dead_catalog[s].get("active_installs") is None
        and dead_catalog[s].get("downloaded") is None
    ]
    if needs_enrichment:
        cached_html = sum(1 for s in needs_enrichment if (ARCHIVE_CACHE_DIR / f"{s}.html").exists())
        cached_none = sum(1 for s in needs_enrichment if (ARCHIVE_CACHE_DIR / f"{s}.none").exists())
        needs_network = len(needs_enrichment) - cached_html - cached_none
        print(f"[*] {len(needs_enrichment):,} dead plugins need Archive.org enrichment")
        print(f"    - {cached_html:,} html  |  {cached_none:,} no-snapshot  |  {needs_network:,} need network")
        asyncio.run(enrich_dead_with_archive(needs_enrichment, dead_catalog))
        dead_catalog = load_dead_catalog()

    # 6. Build and write sorted lists
    print("[*] Sorting and building plugin lists...")

    sort_fn = SORT_KEYS[args.sort_by]
    sorted_active = sorted(catalog, key=lambda s: sort_fn(catalog[s]), reverse=True)

    def svn_date_ts(slug):
        date_str = dead_catalog.get(slug, {}).get("last_updated", "")
        if not date_str:
            return 0
        try:
            return datetime.strptime(date_str, "%a, %d %b %Y %H:%M:%S %Z").timestamp()
        except Exception:
            return 0

    dead_with_installs = sorted(
        [s for s in dead_slugs_all if dead_catalog.get(s, {}).get("active_installs") is not None],
        key=lambda s: dead_catalog[s]["active_installs"],
        reverse=True,
    )
    dead_with_downloads = sorted(
        [s for s in dead_slugs_all
         if dead_catalog.get(s, {}).get("active_installs") is None
         and dead_catalog.get(s, {}).get("downloaded") is not None],
        key=lambda s: dead_catalog[s]["downloaded"],
        reverse=True,
    )
    dead_without_installs = sorted(
        [s for s in dead_slugs_all
         if s in dead_catalog
         and dead_catalog[s].get("active_installs") is None
         and dead_catalog[s].get("downloaded") is None],
        key=svn_date_ts,
        reverse=True,
    )
    undated_dead = sorted(list(dead_slugs_all - set(dead_catalog.keys())))

    sorted_dead = dead_with_installs + dead_with_downloads + dead_without_installs + undated_dead

    active_out = sorted_active if args.active_limit == 0 else sorted_active[:args.active_limit]
    dead_out = sorted_dead if args.dead_limit == 0 else sorted_dead[:args.dead_limit]

    with open(ACTIVE_SLUGS_FILE, "w") as f:
        f.write("\n".join(active_out) + "\n")

    with open(DEAD_SLUGS_FILE, "w") as f:
        f.write("\n".join(dead_out) + "\n")

    # Stats
    dead_from_catalog = sum(1 for s in dead_out if dead_catalog.get(s, {}).get("active_installs") is not None)
    print(f"[+] {ACTIVE_SLUGS_FILE} — {len(active_out):,} active plugins (sorted by {args.sort_by})")
    print(f"[+] {DEAD_SLUGS_FILE} — {len(dead_out):,} dead plugins")
    print(f"    - {len(dead_with_installs):,} total with known installs "
          f"({dead_from_catalog:,} in output, sorted by popularity)")
    print(f"    - {len(dead_without_installs):,} installs unknown (sorted by last updated)")
    print(f"    - {len(undated_dead):,} no data at all")


if __name__ == "__main__":
    main()
