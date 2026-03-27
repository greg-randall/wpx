import asyncio
import concurrent.futures
import random
import re
import time
from lxml import html
from wpx_output import print_status, print_info, print_progress, print_progress_done


class ScanIdleTimeout(Exception):
    pass


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
    def __init__(self, core, data, stealth=None, idle_timeout=60, threads=20):
        self.core = core
        self.data = data
        self.threads = threads
        self.found_plugins = {}
        self.wp_version = None       # structured dict
        self.theme = None            # slug string initially, then structured dict
        self.headers_result = None
        self.core_files = {}
        self.config_backups = []
        self.homepage_content = None
        self.theme_in_404 = False
        self.multisite = None        # None = not detected, dict = found
        self.found_users = []
        self.user_enum_blocked = []
        self.user_enum_ran = False
        self.stealth = stealth             # float or None
        self.idle_timeout = idle_timeout   # seconds, 0 = disabled
        self.last_response_time = time.time()

    def _stealth_delay(self):
        if self.stealth is not None:
            time.sleep(random.uniform(1.0, self.stealth * 2))

    def _touch_response(self):
        self.last_response_time = time.time()

    def _check_idle(self):
        if self.idle_timeout and time.time() - self.last_response_time > self.idle_timeout:
            raise ScanIdleTimeout(
                f"No server response in {self.idle_timeout}s — server may be blocking us."
            )

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
                self._stealth_delay()
                res = self.core.session.get(url, impersonate="firefox", timeout=10)

                if filename == "xmlrpc.php":
                    # WordPress returns 405 for GET requests; both 200 and 405 confirm existence
                    if res.status_code in (200, 405):
                        result["xmlrpc"] = {
                            "url": url,
                            "references": XMLRPC_REFERENCES,
                            "confidence": 100,
                            "found_by": "Direct Access (Aggressive Detection)",
                        }
                    continue

                if res.status_code != 200:
                    continue

                if filename == "readme.html":
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
                    entries = []
                    for line in res.text.splitlines():
                        s = line.strip()
                        if s.startswith("Disallow:"):
                            path = s[len("Disallow:"):].strip()
                            if path:
                                entries.append(path)
                        elif s.startswith("Allow:"):
                            path = s[len("Allow:"):].strip()
                            if path:
                                entries.append(path)
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

    def detect_multisite(self):
        """Detect WordPress Multisite via wp-signup.php and wp-activate.php."""
        base = self.core.target_url.rstrip('/')
        _MULTISITE_KEYWORDS = ("create a new site", "signup", "register a new site", "wordpress sites")

        signup_url = f"{base}/wp-signup.php"
        try:
            self._stealth_delay()
            res = self.core.session.get(signup_url, impersonate="firefox", timeout=10)
        except Exception:
            return

        if res.status_code != 200:
            return
        body_lower = res.text.lower()
        if not any(kw in body_lower for kw in _MULTISITE_KEYWORDS):
            return

        # wp-signup.php confirmed — check wp-activate.php for secondary confirmation
        confidence = 90
        confirmed_by = None
        activate_url = f"{base}/wp-activate.php"
        try:
            self._stealth_delay()
            act = self.core.session.get(activate_url, impersonate="firefox", timeout=10)
            if act.status_code == 200:
                confidence = 100
                confirmed_by = {"url": activate_url, "found_by": "Direct Access (Aggressive Detection)"}
        except Exception:
            pass

        self.multisite = {
            "url": signup_url,
            "confidence": confidence,
            "found_by": "Direct Access (Aggressive Detection)",
            "confirmed_by": confirmed_by,
            "reference": "https://wordpress.org/documentation/article/create-a-network/",
        }

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
                self._stealth_delay()
                res = self.core.session.get(feed_url, impersonate="firefox", timeout=10)
                rss_match = re.search(
                    r'(<generator>https://wordpress\.org/\?v=([\d.]+)</generator>)', res.text
                )
                if rss_match and rss_match.group(2) == version:
                    result["confirmed_by"] = {
                        "method": "Rss Generator (Aggressive Detection)",
                        "url": feed_url,
                        "match": rss_match.group(1),
                    }
            except Exception:
                pass
            result["is_latest"], result["latest_version"], result["release_date"] = (
                self._check_wp_latest(version)
            )
            self.wp_version = result
            return result

        # 2. RSS feed only
        feed_url = f"{base}/feed/"
        try:
            self._stealth_delay()
            res = self.core.session.get(feed_url, impersonate="firefox", timeout=10)
            match = re.search(
                r'(<generator>https://wordpress\.org/\?v=([\d.]+)</generator>)', res.text
            )
            if match:
                version = match.group(2)
                result = {
                    "version": version,
                    "found_by": "Rss Generator (Aggressive Detection)",
                    "found_url": feed_url,
                    "found_match": match.group(1),
                    "confirmed_by": None,
                }
                result["is_latest"], result["latest_version"], result["release_date"] = (
                    self._check_wp_latest(version)
                )
                self.wp_version = result
                return result
        except Exception:
            pass

        self.wp_version = None
        return None

    def _check_wp_latest(self, version):
        """Query api.wordpress.org + local metadata. Returns (is_latest, latest_version, release_date)."""
        release_date = self.data.wp_metadata.get(version, {}).get("release_date")
        try:
            res = self.core.session.get(
                "https://api.wordpress.org/core/version-check/1.7/",
                impersonate="firefox",
                timeout=10,
            )
            data = res.json()
            latest = data["offers"][0]["version"]
            return version == latest, latest, release_date
        except Exception:
            return None, None, release_date

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
            "confirmed_by": "Urls In 404 Page (Passive Detection)" if self.theme_in_404 else None,
            "name": None,
            "description": None,
            "author": None,
            "version": None,
            "version_confidence": None,
            "version_found_by": None,
            "readme_url": None,
        }

        try:
            self._stealth_delay()
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
                self._stealth_delay()
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
            self._stealth_delay()
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
            # Filter out our canary and any obviously invalid slugs (globs, short strings)
            if slug == "this-plugin-does-not-exist-xyz123":
                continue
            if not re.match(r'^[a-z0-9][a-z0-9\-]{1,}$', slug):
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
            nf_theme = re.search(
                rf'/wp-content/themes/{re.escape(self.theme)}/', nf_content
            )
            self.theme_in_404 = bool(nf_theme)

    # ------------------------------------------------------------------
    # Config backups
    # ------------------------------------------------------------------

    def check_config_backups(self):
        """Check for config backup files concurrently. Returns list of found URLs."""
        base = self.core.target_url.rstrip('/')
        backups = self.data.backups

        # Fetch a known-nonexistent path (follow redirects) to detect soft-404 content length
        baseline_len = None
        try:
            self._stealth_delay()
            canary = self.core.session.get(
                f"{base}/wp-config-THIS-DOES-NOT-EXIST-xyz123.bak",
                impersonate="firefox", timeout=10, allow_redirects=True,
            )
            if canary.status_code == 200:
                baseline_len = len(canary.content)
        except Exception:
            pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            found = pool.submit(
                asyncio.run, self._check_config_backups_async(backups, base, baseline_len)
            ).result()

        self.config_backups = found
        return found

    async def _check_config_backups_async(self, backups, base, baseline_len):
        from curl_cffi.requests import AsyncSession
        headers = dict(self.core.session.headers)
        cookies = dict(self.core.cookies)
        sem = asyncio.Semaphore(self.threads)
        total = len(backups)
        completed = 0

        async def check_one(session, path):
            nonlocal completed
            self._check_idle()
            url = f"{base}/{path}"
            async with sem:
                try:
                    if self.stealth is not None:
                        await asyncio.sleep(random.uniform(1.0, self.stealth * 2))
                    res = await session.get(
                        url, headers=headers, cookies=cookies,
                        impersonate="firefox", timeout=10, allow_redirects=True,
                    )
                    self._touch_response()
                    completed += 1
                    pct = completed / total * 100
                    print_progress(f"Checking Config Backups - ({completed} / {total}) {pct:.2f}%")
                    if res.status_code == 200:
                        body = res.content
                        if not any(m in body for m in [b'<?php', b'DB_NAME', b'DB_PASSWORD']):
                            return None
                        if baseline_len is not None:
                            body_len = len(body)
                            if body_len > 0 and abs(body_len - baseline_len) / baseline_len < 0.05:
                                return None
                        return url
                except ScanIdleTimeout:
                    raise
                except Exception:
                    completed += 1
            return None

        async with AsyncSession() as session:
            results = await asyncio.gather(*[check_one(session, p) for p in backups])
            print_progress_done()
            return [r for r in results if r is not None]

    # ------------------------------------------------------------------
    # Plugin brute-force
    # ------------------------------------------------------------------

    def scan_plugins(self, slugs, threads=20):
        print_status(f"Brute-forcing {len(slugs)} plugins with {threads} threads...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            results = pool.submit(asyncio.run, self._scan_plugins_async(slugs, threads)).result()
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
        print_info(f"Found {len(self.found_plugins)} plugins.")

    async def _scan_plugins_async(self, slugs, concurrency):
        from curl_cffi.requests import AsyncSession
        base_url = self.core.target_url.rstrip('/')
        headers = dict(self.core.session.headers)
        cookies = dict(self.core.cookies)
        sem = asyncio.Semaphore(concurrency)
        total = len(slugs)
        completed = 0

        async def check_plugin(session, slug):
            nonlocal completed
            self._check_idle()
            plugin_url = f"{base_url}/wp-content/plugins/{slug}/"
            async with sem:
                try:
                    if self.stealth is not None:
                        await asyncio.sleep(random.uniform(1.0, self.stealth * 2))
                    res = await session.get(
                        plugin_url,
                        headers=headers,
                        cookies=cookies,
                        impersonate="firefox",
                        timeout=10,
                        allow_redirects=False,
                    )
                    self._touch_response()
                    completed += 1
                    pct = completed / total * 100
                    print_progress(f"Brute-forcing plugins - ({completed} / {total}) {pct:.2f}%")
                    if res.status_code in [200, 403]:
                        return slug, res.status_code
                except ScanIdleTimeout:
                    raise
                except Exception:
                    completed += 1
            return None

        async with AsyncSession() as session:
            tasks = [check_plugin(session, slug) for slug in slugs]
            results = await asyncio.gather(*tasks)
            print_progress_done()
            return results

    # ------------------------------------------------------------------
    # Version detection
    # ------------------------------------------------------------------

    def find_version_from_content(self, content, headers, rules, slug=None):
        """
        Apply dynamic finder rules. Returns (version, confidence, found_by, source_url).
        Handles HeaderPattern and QueryParameter rule types (CamelCase keys from YAML).
        Readme/Stable-tag detection is handled separately in _detect_versions_async.
        """
        # 1. HeaderPattern
        if "HeaderPattern" in rules:
            hp = rules["HeaderPattern"]
            # Two possible shapes in the YAML:
            #   flat:   {header: "X-Foo", pattern: <re>}
            #   nested: {finder_name: {header: "X-Foo", pattern: <re>}, ...}
            if isinstance(hp, dict) and "header" in hp:
                hp_configs = [("HeaderPattern", hp)]
            else:
                hp_configs = hp.items() if isinstance(hp, dict) else []
            for finder_name, config in hp_configs:
                if not isinstance(config, dict):
                    continue
                header_name = config.get("header", "")
                # Case-insensitive header lookup
                val = next((v for k, v in headers.items() if k.lower() == header_name.lower()), None)
                if val and "pattern" in config:
                    match = config["pattern"].search(val)
                    if match:
                        return self._extract_version(match), 100, f"{finder_name} (Passive Detection)", None

        # 2. QueryParameter — match asset files listed in the rule against homepage HTML
        if "QueryParameter" in rules and self.homepage_content:
            qp = rules["QueryParameter"]
            files = qp.get("files", []) if isinstance(qp, dict) else []
            try:
                tree = html.fromstring(self.homepage_content)
                for asset_path in files:
                    xpath = (
                        f"//link[contains(@href, '{asset_path}')] | "
                        f"//script[contains(@src, '{asset_path}')]"
                    )
                    for el in tree.xpath(xpath):
                        url = el.get('href') or el.get('src') or ''
                        # Require the URL to belong to this plugin's path
                        if slug and f"/plugins/{slug}/" not in url:
                            continue
                        if 'ver=' in url:
                            ver = url.split('ver=')[-1].split('&')[0].split('#')[0]
                            if ver and re.match(r'^[\d.]+$', ver):
                                return ver, 100, "QueryParameter (Passive Detection)", url
            except Exception:
                pass

        return "Unknown", 0, None, None

    def _extract_version(self, match):
        try:
            return match.group('v')
        except IndexError:
            return match.group(1) if match.groups() else match.group(0)

    def detect_versions(self):
        print_status("Detecting plugin versions...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            results = pool.submit(asyncio.run, self._detect_versions_async()).result()
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
        sem = asyncio.Semaphore(self.threads)
        slugs = list(self.found_plugins.keys())
        total = len(slugs)
        completed = 0

        async def process_version(session, slug):
            nonlocal completed
            self._check_idle()
            rules = self.data.get_plugin_rules(slug)
            if not rules:
                completed += 1
                return slug, "Unknown", 0, None, None

            base_plugin_url = f"{base_url}/wp-content/plugins/{slug}/"

            # 1. HeaderPattern + QueryParameter (no extra request needed)
            version, confidence, found_by, source_url = self.find_version_from_content(
                "", {}, rules, slug=slug
            )
            if version != "Unknown":
                completed += 1
                pct = completed / total * 100
                print_progress(f"Detecting versions - ({completed} / {total}) {pct:.2f}%")
                return slug, version, confidence, found_by, source_url

            # 2. Readme — fetch and extract "Stable tag:"
            if "Readme" in rules:
                readme_rule = rules["Readme"]
                readme_path = (
                    readme_rule.get("path", "readme.txt")
                    if isinstance(readme_rule, dict) else "readme.txt"
                )
                readme_url = f"{base_plugin_url}{readme_path}"
                async with sem:
                    try:
                        if self.stealth is not None:
                            await asyncio.sleep(random.uniform(1.0, self.stealth * 2))
                        res = await session.get(
                            readme_url,
                            headers=headers,
                            cookies=cookies,
                            impersonate="firefox",
                            timeout=10,
                        )
                        self._touch_response()
                        completed += 1
                        pct = completed / total * 100
                        print_progress(f"Detecting versions - ({completed} / {total}) {pct:.2f}%")
                        if res.status_code == 200:
                            stable = re.search(
                                r'Stable tag:\s*([\d.]+)', res.text, re.IGNORECASE
                            )
                            if stable:
                                return (slug, stable.group(1), 100,
                                        "Readme - Stable Tag (Aggressive Detection)", readme_url)
                    except ScanIdleTimeout:
                        raise
                    except Exception:
                        pass
            else:
                completed += 1
                pct = completed / total * 100
                print_progress(f"Detecting versions - ({completed} / {total}) {pct:.2f}%")

            return slug, "Unknown", 0, None, None

        async with AsyncSession() as session:
            tasks = [process_version(session, slug) for slug in slugs]
            results = await asyncio.gather(*tasks)
            print_progress_done()
            return results

    # ------------------------------------------------------------------
    # User enumeration
    # ------------------------------------------------------------------

    def enumerate_users(self, techniques, users_limit=10):
        self.user_enum_ran = True
        print_status("Enumerating users...")
        base = self.core.target_url.rstrip('/')
        seen_slugs = set()

        def _add_user(user_dict):
            slug = user_dict.get("login") or ""
            name = user_dict.get("name") or ""
            if slug:
                if slug in seen_slugs:
                    return
                seen_slugs.add(slug)
            elif name:
                if name in {u.get("name") for u in self.found_users}:
                    return
            else:
                return
            self.found_users.append(user_dict)

        # 1. Passive — scan already-fetched homepage HTML for /author/slug/ links
        if self.homepage_content:
            for slug in set(re.findall(r'/author/([^/?#"\'<>\s]+)/', self.homepage_content)):
                if slug not in seen_slugs:
                    seen_slugs.add(slug)
                    self.found_users.append({
                        "id": None,
                        "login": slug,
                        "name": None,
                        "found_by": "Passive HTML Scan",
                        "confidence": 70,
                        "source_url": base,
                    })

        # 2. REST API
        rest_tech = techniques.get("rest_api")
        if rest_tech:
            url = f"{base}{rest_tech['endpoint']}"
            print_status(f"Trying {rest_tech['name']}...")
            try:
                self._stealth_delay()
                res = self.core.session.get(url, impersonate="firefox", timeout=15)
                if res.status_code == 200:
                    users = res.json()
                    if isinstance(users, list) and users:
                        for u in users:
                            _add_user({
                                "id": u.get("id"),
                                "login": u.get("slug"),
                                "name": u.get("name"),
                                "found_by": rest_tech["name"],
                                "confidence": rest_tech["confidence"],
                                "source_url": url,
                            })
                    else:
                        self.user_enum_blocked.append(rest_tech["name"])
                else:
                    self.user_enum_blocked.append(rest_tech["name"])
            except Exception:
                pass

        # 3. Author archive (?author=N) — sync, typically only 1–10 requests
        author_tech = techniques.get("author_archive")
        if author_tech and users_limit > 0:
            self._probe_author_archives(author_tech, users_limit, base, seen_slugs)

        # 4. oEmbed — find a post URL in the homepage then query the endpoint
        oembed_tech = techniques.get("oembed")
        if oembed_tech and self.homepage_content:
            post_url = None
            for link in re.findall(
                r'href=["\'](' + re.escape(base) + r'/[^"\'<>]+)["\']',
                self.homepage_content,
            ):
                if not any(x in link for x in ['/wp-content/', '/wp-admin/', '/wp-json/', '#', '?']):
                    post_url = link
                    break
            if post_url:
                url = f"{base}{oembed_tech['endpoint']}?url={post_url}&format=json"
                try:
                    self._stealth_delay()
                    res = self.core.session.get(url, impersonate="firefox", timeout=10)
                    if res.status_code == 200:
                        author_name = res.json().get("author_name")
                        if author_name:
                            _add_user({
                                "id": None,
                                "login": None,
                                "name": author_name,
                                "found_by": oembed_tech["name"],
                                "confidence": oembed_tech["confidence"],
                                "source_url": url,
                            })
                except Exception:
                    pass

        # 5. RSS feed — parse dc:creator and author tags
        rss_tech = techniques.get("rss_feed")
        if rss_tech:
            url = f"{base}{rss_tech['endpoint']}"
            try:
                self._stealth_delay()
                res = self.core.session.get(url, impersonate="firefox", timeout=15)
                if res.status_code == 200:
                    creators = re.findall(
                        r'<dc:creator><!\[CDATA\[(.*?)\]\]></dc:creator>', res.text
                    )
                    authors = re.findall(r'<author>([^<]+)</author>', res.text)
                    for name in set(creators + authors):
                        name = name.strip()
                        if name:
                            _add_user({
                                "id": None,
                                "login": None,
                                "name": name,
                                "found_by": rss_tech["name"],
                                "confidence": rss_tech["confidence"],
                                "source_url": url,
                            })
                elif res.status_code in (401, 403):
                    self.user_enum_blocked.append(rss_tech["name"])
            except Exception:
                pass

    def _probe_author_archives(self, tech, users_limit, base, seen_slugs):
        found_any = False

        for i in range(1, users_limit + 1):
            self._check_idle()
            url = f"{base}/?author={i}"
            print_progress(f"Author archive - probing ID {i}/{users_limit}")
            try:
                # Don't follow redirects — WordPress puts the raw /author/slug/ path
                # in the Location header of the first redirect. Following all the way
                # to the final URL can lose the slug after site-level rewriting.
                res = self.core.session.get(
                    url, impersonate="firefox", timeout=10, allow_redirects=False
                )
                self._touch_response()
                slug = None
                if res.status_code in (301, 302, 303, 307, 308):
                    location = res.headers.get("Location") or res.headers.get("location", "")
                    m = re.search(r'/author/([^/?#\s]+)', location)
                    if m:
                        slug = m.group(1)
                elif res.status_code == 200:
                    # Some setups serve the author page directly without redirecting
                    m = re.search(r'/author/([^/?#"\'<>\s]+)/', res.text)
                    if m:
                        slug = m.group(1)
                if slug:
                    found_any = True
                    if slug not in seen_slugs:
                        seen_slugs.add(slug)
                        self.found_users.append({
                            "id": i,
                            "login": slug,
                            "name": None,
                            "found_by": tech["name"],
                            "confidence": tech["confidence"],
                            "source_url": url,
                        })
            except ScanIdleTimeout:
                raise
            except Exception:
                pass
            self._stealth_delay()

        print_progress_done()
        if not found_any:
            self.user_enum_blocked.append(tech["name"])


if __name__ == "__main__":
    from wpx_data import WPXData
    from wpx_core import WPXCore
    import sys

    url = sys.argv[1] if len(sys.argv) > 1 else "https://247defensivedriving.com"
    data = WPXData()
    data.load_dynamic_finders()
    data.load_slugs()

    core = WPXCore(url)
    if core.bypass_waf():
        core.setup_mirror_session()
        finder = WPXFinder(core, data)
        test_slugs = ["contact-form-7", "elementor", "wp-rocket", "wordfence"]
        finder.scan_plugins(test_slugs)
        finder.detect_versions()
