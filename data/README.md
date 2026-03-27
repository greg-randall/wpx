# WPX Plugin Catalog

This directory contains the plugin datasets used by WPX and the script that builds them.

## Files

| File | Description |
|------|-------------|
| `plugins_active.txt` | Active plugin slugs ranked by popularity (default top 5,000). |
| `plugins_dead.txt` | Closed/removed plugin slugs ranked by historical install count (default top 2,500). |
| `plugins_catalog.json` | Cached metadata for active plugins (installs, downloads, rating, dates). |
| `plugins_dead.jsonl` | Append-only cache of dead plugin metadata. Last entry wins on load. |
| `archive.org-cache/` | Raw HTML snapshots from the Wayback Machine used to recover install counts for plugins closed before the first catalog run. |
| `user_enum_techniques.yml` | Technique definitions for user enumeration (REST API, author archives, oEmbed, RSS). |

---

## wpx_fetch_plugins.py

Builds and maintains the plugin lists by combining three data sources:

1. **WordPress.org API** — fetches all currently active plugins with install counts, download counts, and ratings
2. **SVN repository** — scrapes the full list of ~150k slugs ever created to identify closed/removed plugins
3. **Archive.org** — recovers historical install counts for dead plugins that predate the first catalog run

### Basic usage

```bash
python3 data/wpx_fetch_plugins.py
```

Outputs `plugins_active.txt` (top 5,000 active) and `plugins_dead.txt` (top 2,500 dead).

### Sort active plugins by a different metric

```bash
python3 data/wpx_fetch_plugins.py --sort-by active_installs
python3 data/wpx_fetch_plugins.py --sort-by downloaded
python3 data/wpx_fetch_plugins.py --sort-by score   # default: geometric mean of installs × downloads
```

### Change output limits

```bash
# Top 10,000 active, top 5,000 dead
python3 data/wpx_fetch_plugins.py --active-limit 10000 --dead-limit 5000

# Write everything (no limit)
python3 data/wpx_fetch_plugins.py --active-limit 0 --dead-limit 0
```

### All flags

| Flag | Description |
|------|-------------|
| `--sort-by` | Rank active plugins by `score` (default), `active_installs`, or `downloaded`. |
| `--active-limit N` | Slugs to write to `plugins_active.txt` (default: 5,000, 0 = all). |
| `--dead-limit N` | Slugs to write to `plugins_dead.txt` (default: 2,500, 0 = all). |
| `--force` | Re-fetch everything even if the catalog is fresh. |
| `--fetch-limit N` | Stop after fetching N active plugins from the API (0 = all). Useful for testing. |
| `--max-age HOURS` | Skip the API fetch if the catalog is fresher than N hours (default: 24). |
| `--debug` | Print full metadata for each plugin as it is fetched. |

### How dead plugin ranking works

Dead plugins are ranked in priority order:

1. **Known install count** — sorted by `active_installs` descending (most used first)
2. **Known download count only** — sorted by `downloaded` descending
3. **No popularity data, but dated** — sorted by SVN `Last-Modified` descending (most recently active first)
4. **No data at all** — alphabetical

### Archive.org enrichment

For dead plugins with no install count in the catalog, the script queries the Wayback Machine for the most recent snapshot of the plugin's wordpress.org page taken before the plugin was removed, then parses the install count from that snapshot. Results are cached in `archive.org-cache/` so subsequent runs skip the network requests.

This step requires `beautifulsoup4`:

```bash
pip install ".[dev]"
```

### Note on runtime

A full run against all ~150k SVN slugs is slow. The API fetch alone takes several minutes. The SVN metadata fetch and Archive.org enrichment steps are only triggered for slugs not already in the dead catalog, so subsequent runs are much faster.
