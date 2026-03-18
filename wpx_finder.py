import asyncio
import re
from lxml import html

XMLRPC_REFERENCES = [
    "http://codex.wordpress.org/XML-RPC_Pingback_API",
    "https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/",
    "https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/",
]

WPCRON_REFERENCES = [
    "https://www.iplocation.net/defend-wordpress-from-ddos",
    "https://github.com/wpscanteam/wpscan/issues/1299",
]

INTERESTING_HEADERS = [
    "server", "x-powered-by", "referrer-policy", "via",
    "x-generator", "link", "x-pingback",
]


class WPXFinder:
    def __init__(self, core, data):
        self.core = core
        self.data = data
        self.found_plugins = {}
        self.wp_version = None       # structured dict
        self.theme = None            # slug string initially, then structured dict
        self.headers_result = None
        self.core_files = {}
        self.config_backups = []
        self.homepage_content = None

    # ------------------------------------------------------------------
    # Headers
    # ------------------------------------------------------------------

    def check_headers(self, response):
        """Examine response headers for interesting entries. Returns structured dict."""
        interesting = []
        for header in INTERESTING_HEADERS:
            val = response.headers.get(header)
            if val:
                interesting.append(f"{header}: {val}")

        result = {
            "found_by": "Headers (Passive Detection)",
            "entries": interesting,
            "confidence": 100,
        }
        self.headers_result = result
        return result

    # ------------------------------------------------------------------
    # Core files
    # ------------------------------------------------------------------

    def check_core_files(self):
        """Check for common WP files. Returns structured dict."""
        base = self.core.target_url.rstrip('/')
        result = {}

        for filename in ["xmlrpc.php", "readme.html", "wp-cron.php", "robots.txt"]:
            url = f"{base}/{filename}"
            try:
                res = self.core.session.get(url, impersonate="firefox", timeout=10)
                if res.status_code != 200:
                    continue

                if filename == "xmlrpc.php":
                    result["xmlrpc"] = {
                        "url": url,
                        "references": XMLRPC_REFERENCES,
                        "confidence": 100,
                        "found_by": "Direct Access (Aggressive Detection)",
                    }
                elif filename == "readme.html":
                    result["readme"] = {
                        "url": url,
                        "confidence": 100,
                        "found_by": "Direct Access (Aggressive Detection)",
                    }
                elif filename == "wp-cron.php":
                    result["wp_cron"] = {
                        "url": url,
                        "references": WPCRON_REFERENCES,
                        "confidence": 60,
                        "found_by": "Direct Access (Aggressive Detection)",
                    }
                elif filename == "robots.txt":
                    entries = [
                        line.strip()
                        for line in res.text.splitlines()
                        if line.strip().startswith("Disallow:") or line.strip().startswith("Allow:")
                    ]
                    result["robots_txt"] = {
                        "url": url,
                        "entries": entries,
                        "confidence": 100,
                        "found_by": "Robots Txt (Aggressive Detection)",
                    }
            except Exception:
                pass

        self.core_files = result
        return result

    # ------------------------------------------------------------------
    # WP version
    # ------------------------------------------------------------------

    def detect_wp_version(self, content, homepage_url=None):
        """Detect WP version from meta generator or RSS feed. Returns structured dict or None."""
        base = self.core.target_url.rstrip('/')

        # 1. Meta generator
        match = re.search(r'name="generator" content="WordPress ([\d.]+)"', content, re.IGNORECASE)
        if match:
            version = match.group(1)
            result = {
                "version": version,
                "found_by": "Meta Generator (Passive Detection)",
                "found_url": homepage_url or base + "/",
                "found_match": f"WordPress {version}",
                "confirmed_by": None,
            }
            # Try RSS for confirmation
            feed_url = f"{base}/feed/"
            try:
                res = self.core.session.get(feed_url, impersonate="firefox", timeout=10)
                rss_match = re.search(r'<generator>https://wordpress\.org/\?v=([\d.]+)', res.text)
                if rss_match and rss_match.group(1) == version:
                    result["confirmed_by"] = {
                        "method": "Rss Generator (Aggressive Detection)",
                        "url": feed_url,
                    }
            except Exception:
                pass
            result["is_latest"], result["latest_version"] = self._check_wp_latest(version)
            self.wp_version = result
            return result

        # 2. RSS feed only
        feed_url = f"{base}/feed/"
        try:
            res = self.core.session.get(feed_url, impersonate="firefox", timeout=10)
            match = re.search(r'<generator>https://wordpress\.org/\?v=([\d.]+)', res.text)
            if match:
                version = match.group(1)
                result = {
                    "version": version,
                    "found_by": "Rss Generator (Aggressive Detection)",
                    "found_url": feed_url,
                    "found_match": f"?v={version}",
                    "confirmed_by": None,
                }
                result["is_latest"], result["latest_version"] = self._check_wp_latest(version)
                self.wp_version = result
                return result
        except Exception:
            pass

        self.wp_version = None
        return None

    def _check_wp_latest(self, version):
        """Query api.wordpress.org. Returns (is_latest: bool|None, latest_version: str|None)."""
        try:
            res = self.core.session.get(
                "https://api.wordpress.org/core/version-check/1.7/",
                impersonate="firefox",
                timeout=10,
            )
            data = res.json()
            latest = data["offers"][0]["version"]
            return version == latest, latest
        except Exception:
            return None, None

    # ------------------------------------------------------------------
    # Theme details
    # ------------------------------------------------------------------

    def detect_theme_details(self):
        """Fetch theme style.css and parse metadata. Returns structured dict."""
        if not self.theme:
            return None

        slug = self.theme if isinstance(self.theme, str) else self.theme.get("slug")
        base = self.core.target_url.rstrip('/')
        location = f"{base}/wp-content/themes/{slug}/"
        style_url = f"{location}style.css"

        result = {
            "slug": slug,
            "location": location,
            "style_url": style_url,
            "found_by": "Urls In Homepage (Passive Detection)",
            "name": None,
            "description": None,
            "author": None,
            "version": None,
            "version_confidence": None,
            "version_found_by": None,
            "readme_url": None,
        }

        try:
            res = self.core.session.get(style_url, impersonate="firefox", timeout=10)
            if res.status_code == 200:
                for line in res.text.splitlines()[:30]:
                    line = line.strip()
                    lower = line.lower()
                    if lower.startswith("theme name:"):
                        result["name"] = line.split(":", 1)[1].strip()
                    elif lower.startswith("description:"):
                        result["description"] = line.split(":", 1)[1].strip()
                    elif lower.startswith("author:"):
                        result["author"] = line.split(":", 1)[1].strip()
                    elif lower.startswith("version:"):
                        result["version"] = line.split(":", 1)[1].strip()
                        result["version_confidence"] = 80
                        result["version_found_by"] = f"Style (Passive Detection) - {style_url}"
        except Exception:
            pass

        for readme_name in ["README.md", "readme.txt", "readme.md"]:
            try:
                res = self.core.session.get(f"{location}{readme_name}", impersonate="firefox", timeout=5)
                if res.status_code == 200:
                    result["readme_url"] = f"{location}{readme_name}"
                    break
            except Exception:
                pass

        self.theme = result
        return result

    # ------------------------------------------------------------------
    # Passive discovery
    # ------------------------------------------------------------------

    def find_passive_items(self, content):
        """Parse HTML for plugins/themes. Cross-checks with a 404 page."""
        base = self.core.target_url.rstrip('/')
        self.homepage_content = content

        # Fetch a known-404 to identify noise
        nf_content = ""
        try:
            nf_res = self.core.session.get(
                f"{base}/wp-content/plugins/this-plugin-does-not-exist-xyz123/",
                impersonate="firefox",
                timeout=10,
            )
            nf_content = nf_res.text
        except Exception:
            pass

        hp_plugins = set(re.findall(r'/wp-content/plugins/([^/\s"\'?]+)', content))
        nf_plugins = set(re.findall(r'/wp-content/plugins/([^/\s"\'?]+)', nf_content))

        for slug in hp_plugins:
            if slug == "this-plugin-does-not-exist-xyz123":
                continue
            if slug not in self.found_plugins:
                in_404 = slug in nf_plugins
                self.found_plugins[slug] = {
                    "status": "passive",
                    "version": "Unknown",
                    "version_confidence": 0,
                    "version_found_by": None,
                    "version_url": None,
                    "found_by": "Urls In Homepage (Passive Detection)",
                    "confirmed_by": "Urls In 404 Page (Passive Detection)" if in_404 else None,
                    "location": f"{base}/wp-content/plugins/{slug}/",
                }

        theme_match = re.search(r'/wp-content/themes/([^/\s"\'?]+)', content)
        if theme_match:
            self.theme = theme_match.group(1)

    # ------------------------------------------------------------------
    # Config backups
    # ------------------------------------------------------------------

    def check_config_backups(self):
        """Check for config backup files with inline progress. Returns list of found URLs."""
        base = self.core.target_url.rstrip('/')
        backups = self.data.backups
        total = len(backups)
        found = []

        for i, path in enumerate(backups):
            url = f"{base}/{path}"
            pct = (i + 1) / total * 100
            print(f"\r[*] Checking Config Backups - ({i + 1} / {total}) {pct:.2f}%", end="", flush=True)
            try:
                res = self.core.session.get(url, impersonate="firefox", timeout=10, allow_redirects=False)
                if res.status_code == 200:
                    found.append(url)
            except Exception:
                pass

        print()  # newline after progress bar
        self.config_backups = found
        return found

    # ------------------------------------------------------------------
    # Plugin brute-force
    # ------------------------------------------------------------------

    def scan_plugins(self, slugs, threads=20):
        print(f"[*] Brute-forcing {len(slugs)} plugins with {threads} threads...")
        results = asyncio.run(self._scan_plugins_async(slugs, threads))
        base = self.core.target_url.rstrip('/')
        for item in results:
            if item:
                slug, status = item
                if slug not in self.found_plugins:
                    self.found_plugins[slug] = {
                        "status": status,
                        "version": "Unknown",
                        "version_confidence": 0,
                        "version_found_by": None,
                        "version_url": None,
                        "found_by": "Known Locations (Aggressive Detection)",
                        "confirmed_by": None,
                        "location": f"{base}/wp-content/plugins/{slug}/",
                    }
        print(f"[+] Found {len(self.found_plugins)} plugins.")

    async def _scan_plugins_async(self, slugs, concurrency):
        from curl_cffi.requests import AsyncSession
        base_url = self.core.target_url.rstrip('/')
        headers = dict(self.core.session.headers)
        cookies = dict(self.core.cookies)
        sem = asyncio.Semaphore(concurrency)

        async def check_plugin(session, slug):
            plugin_url = f"{base_url}/wp-content/plugins/{slug}/"
            async with sem:
                try:
                    res = await session.get(
                        plugin_url,
                        headers=headers,
                        cookies=cookies,
                        impersonate="firefox",
                        timeout=10,
                        allow_redirects=False,
                    )
                    if res.status_code in [200, 403]:
                        return slug, res.status_code
                except Exception:
                    pass
            return None

        async with AsyncSession() as session:
            tasks = [check_plugin(session, slug) for slug in slugs]
            return await asyncio.gather(*tasks)

    # ------------------------------------------------------------------
    # Version detection
    # ------------------------------------------------------------------

    def find_version_from_content(self, content, headers, rules):
        """
        Apply dynamic finder rules. Returns (version, confidence, found_by, source_url).
        """
        # 1. HeaderPattern
        if "header_pattern" in rules:
            for finder_name, config in rules["header_pattern"].items():
                header_name = config["header_name"]
                if header_name in headers:
                    match = config["pattern"].search(headers[header_name])
                    if match:
                        return self._extract_version(match), 100, f"{finder_name} (Passive Detection)", None

        # 2. BodyPattern
        if "body_pattern" in rules:
            for finder_name, config in rules["body_pattern"].items():
                match = config["pattern"].search(content)
                if match:
                    return self._extract_version(match), 80, f"{finder_name} (Passive Detection)", None

        # 3. QueryParameter (needs HTML — try homepage content if available)
        if "query_parameter" in rules:
            html_content = self.homepage_content or content
            try:
                tree = html.fromstring(html_content)
            except Exception:
                tree = None
            if tree is not None:
                for finder_name, config in rules["query_parameter"].items():
                    param = config["parameter_name"]
                    xpath = (
                        f"//link[contains(@href, '{param}')] | "
                        f"//script[contains(@src, '{param}')]"
                    )
                    for el in tree.xpath(xpath):
                        url = el.get('href') or el.get('src')
                        if url and f"{param}=" in url:
                            version = url.split(f"{param}=")[-1].split('&')[0]
                            if version:
                                return version, 100, f"{finder_name} (Passive Detection)", url

        return "Unknown", 0, None, None

    def _extract_version(self, match):
        try:
            return match.group('v')
        except IndexError:
            return match.group(1) if match.groups() else match.group(0)

    def detect_versions(self):
        print("[*] Detecting plugin versions...")
        results = asyncio.run(self._detect_versions_async())
        for slug, version, confidence, found_by, source_url in results:
            self.found_plugins[slug]["version"] = version
            self.found_plugins[slug]["version_confidence"] = confidence
            self.found_plugins[slug]["version_found_by"] = found_by
            self.found_plugins[slug]["version_url"] = source_url

    async def _detect_versions_async(self):
        from curl_cffi.requests import AsyncSession
        base_url = self.core.target_url.rstrip('/')
        headers = dict(self.core.session.headers)
        cookies = dict(self.core.cookies)
        sem = asyncio.Semaphore(10)
        slugs = list(self.found_plugins.keys())

        async def process_version(session, slug):
            rules = self.data.get_plugin_rules(slug)
            if not rules:
                return slug, "Unknown", 0, None, None

            readme_url = f"{base_url}/wp-content/plugins/{slug}/readme.txt"
            async with sem:
                try:
                    res = await session.get(
                        readme_url,
                        headers=headers,
                        cookies=cookies,
                        impersonate="firefox",
                        timeout=10,
                    )
                    if res.status_code == 200:
                        version, confidence, found_by, source_url = self.find_version_from_content(
                            res.text, res.headers, rules
                        )
                        return slug, version, confidence, found_by, source_url or readme_url
                except Exception:
                    pass
            return slug, "Unknown", 0, None, None

        async with AsyncSession() as session:
            tasks = [process_version(session, slug) for slug in slugs]
            return await asyncio.gather(*tasks)


if __name__ == "__main__":
    from wpx_data import WPXData
    from wpx_core import WPXCore
    import sys

    url = sys.argv[1] if len(sys.argv) > 1 else "https://247defensivedriving.com"
    data = WPXData()
    data.load_dynamic_finders()
    data.load_slugs()

    core = WPXCore(url)
    if core.bypass_cloudflare():
        core.setup_mirror_session()
        finder = WPXFinder(core, data)
        test_slugs = ["contact-form-7", "elementor", "wp-rocket", "wordfence"]
        finder.scan_plugins(test_slugs)
        finder.detect_versions()
        print(finder.found_plugins)
