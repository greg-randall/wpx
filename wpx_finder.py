import re
from lxml import html
from concurrent.futures import ThreadPoolExecutor

class WPXFinder:
    def __init__(self, core, data):
        self.core = core
        self.data = data
        self.found_plugins = {}
        self.wp_version = None
        self.theme = None

    def find_version_from_content(self, content, headers, rules):
        """
        Applies WPScan dynamic finder rules to determine a plugin's version.
        """
        # 1. HeaderPattern
        if "header_pattern" in rules:
            for finder_name, config in rules["header_pattern"].items():
                header_name = config["header_name"]
                if header_name in headers:
                    match = config["pattern"].search(headers[header_name])
                    if match:
                        # Extract version from named group 'v' if it exists
                        return self._extract_version(match)

        # 2. BodyPattern
        if "body_pattern" in rules:
            for finder_name, config in rules["body_pattern"].items():
                match = config["pattern"].search(content)
                if match:
                    return self._extract_version(match)

        # 3. QueryParameter
        if "query_parameter" in rules:
            # This usually requires parsing the DOM for script/link tags
            tree = html.fromstring(content)
            for finder_name, config in rules["query_parameter"].items():
                xpath = f"//link[contains(@href, '{config['parameter_name']}')] | //script[contains(@src, '{config['parameter_name']}')]"
                elements = tree.xpath(xpath)
                for el in elements:
                    url = el.get('href') or el.get('src')
                    if url and f"{config['parameter_name']}=" in url:
                        # Extract value after parameter_name=
                        version = url.split(f"{config['parameter_name']}=")[-1].split('&')[0]
                        if version:
                            return version

        return "Unknown"

    def _extract_version(self, match):
        try:
            return match.group('v')
        except IndexError:
            return match.group(1) if match.groups() else match.group(0)

    def scan_plugins(self, slugs, threads=20):
        print(f"[*] Brute-forcing {len(slugs)} plugins with {threads} threads...")
        
        # Capture headers and cookies to pass to threads
        headers = dict(self.core.session.headers)
        cookies = dict(self.core.cookies)
        base_url = self.core.target_url.rstrip('/')

        def check_plugin(slug):
            plugin_url = f"{base_url}/wp-content/plugins/{slug}/"
            try:
                # Import requests here to ensure it's available in the thread
                from curl_cffi import requests as thread_requests
                # Use a standalone get() instead of sharing a session handle
                res = thread_requests.get(
                    plugin_url, 
                    headers=headers,
                    cookies=cookies,
                    impersonate="firefox", 
                    timeout=10,
                    allow_redirects=False # Direct check
                )
                if res.status_code in [200, 403]:
                    return slug, res.status_code
            except:
                pass
            return None

        with ThreadPoolExecutor(max_workers=threads) as executor:
            results = list(executor.map(check_plugin, slugs))
            
        for res in results:
            if res:
                slug, status = res
                self.found_plugins[slug] = {"status": status, "version": "Unknown"}
        
        print(f"[+] Found {len(self.found_plugins)} plugins.")

    def find_passive_items(self, content):
        """
        Parses HTML to find plugins and themes mentioned in links/scripts.
        """
        print("[*] Performing passive discovery from homepage HTML...")
        
        # Find plugins: /wp-content/plugins/slug/
        plugin_matches = re.findall(r'\/wp-content\/plugins\/([^\/\s"\'\?]+)', content)
        for slug in set(plugin_matches):
            if slug not in self.found_plugins:
                print(f"  [+] Found plugin via passive: {slug}")
                self.found_plugins[slug] = {"status": "passive", "version": "Unknown"}

        # Find theme: /wp-content/themes/slug/
        theme_match = re.search(r'\/wp-content\/themes\/([^\/\s"\'\?]+)', content)
        if theme_match:
            self.theme = theme_match.group(1)
            print(f"  [+] Found theme: {self.theme}")

    def check_core_files(self):
        """
        Checks for common WP files like xmlrpc.php, readme.html, etc.
        """
        print("[*] Checking for core WordPress files...")
        core_files = {
            "xmlrpc.php": "XML-RPC seems to be enabled",
            "readme.html": "WordPress readme found",
            "wp-cron.php": "External WP-Cron seems to be enabled",
            "robots.txt": "robots.txt found"
        }
        
        for filename, desc in core_files.items():
            url = f"{self.core.target_url.rstrip('/')}/{filename}"
            try:
                res = self.core.session.get(url, impersonate="firefox", timeout=10)
                if res.status_code == 200:
                    print(f"  [!] {desc}: {url}")
            except:
                pass

    def detect_versions(self):
        print("[*] Detecting plugin versions...")
        headers = dict(self.core.session.headers)
        cookies = dict(self.core.cookies)
        base_url = self.core.target_url.rstrip('/')

        def process_version(slug):
            rules = self.data.get_plugin_rules(slug)
            if not rules:
                return slug, "Unknown"
            
            # Fetch readme.txt
            readme_url = f"{base_url}/wp-content/plugins/{slug}/readme.txt"
            try:
                from curl_cffi import requests as thread_requests
                res = thread_requests.get(
                    readme_url, 
                    headers=headers,
                    cookies=cookies,
                    impersonate="firefox", 
                    timeout=10
                )
                if res.status_code == 200:
                    version = self.find_version_from_content(res.text, res.headers, rules)
                    return slug, version
            except:
                pass
            return slug, "Unknown"

        # Using a ThreadPool to speed up version detection too
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(process_version, self.found_plugins.keys()))

        for slug, version in results:
            self.found_plugins[slug]["version"] = version

    def detect_wp_version(self, content):
        """
        Detects WP version from meta generator or RSS feed.
        """
        # 1. Meta generator
        match = re.search(r'name="generator" content="WordPress ([\d\.]+)"', content)
        if match:
            self.wp_version = match.group(1)
            print(f"[+] WordPress version {self.wp_version} identified (via Meta Generator)")
            return

        # 2. RSS Feed
        feed_url = f"{self.core.target_url.rstrip('/')}/feed/"
        try:
            res = self.core.session.get(feed_url, impersonate="firefox", timeout=10)
            match = re.search(r'<generator>https:\/\/wordpress\.org\/\?v=([\d\.]+)', res.text)
            if match:
                self.wp_version = match.group(1)
                print(f"[+] WordPress version {self.wp_version} identified (via RSS Feed)")
        except:
            pass

if __name__ == "__main__":
    # Test finder
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
        # Scan a few common ones for test
        test_slugs = ["contact-form-7", "elementor", "wp-rocket", "wordfence"]
        finder.scan_plugins(test_slugs)
        finder.detect_versions()
        print(finder.found_plugins)
