from browserforge.fingerprints import Screen
from camoufox import Camoufox
from curl_cffi import requests
import importlib.metadata
import time
import traceback
from wpx_output import print_status, print_warn


class WPXCore:
    def __init__(self, target_url):
        self.target_url = target_url
        self.cookies = {}
        self.user_agent = ""
        self.session = None

    def bypass_waf(self):
        print_status(f"Launching Camoufox to bypass WAF for {self.target_url}...")
        try:
            # Pass a realistic screen size — WSL's virtual display is 640x480
            # which is below the minimum resolution in browserforge's training data,
            # causing fingerprint generation to fail. A standard 1920x1080 works.
            screen = Screen(min_width=1280, min_height=720, max_width=1920, max_height=1080)
            with Camoufox(headless=True, screen=screen) as browser:
                page = browser.new_page()

                # Navigate and solve challenge
                page.goto(self.target_url, wait_until="networkidle")

                # Allow extra time for WAF JS challenge redirect to complete
                time.sleep(5)

                print_status("Page loaded. Extracting session tokens...")

                # Extract cookies
                self.cookies = {c['name']: c['value'] for c in page.context.cookies()}

                # Extract the exact User-Agent used by Camoufox
                self.user_agent = page.evaluate("navigator.userAgent")

                print_status(f"Extracted User-Agent: {self.user_agent[:60]}...")
                print_status(f"Extracted {len(self.cookies)} cookies.")

                return True
        except Exception as e:
            print_warn("── Camoufox launch failed ─────────────────────────────────────")
            print_warn(f" Error type : {type(e).__name__}")
            print_warn(f" Message    : {e}")
            print_warn("")
            print_warn(" Traceback:")
            for line in traceback.format_exc().splitlines():
                print_warn(f"   {line}")
            print_warn("")
            print_warn(" Installed versions:")
            for pkg in ("camoufox", "browserforge", "playwright"):
                try:
                    ver = importlib.metadata.version(pkg)
                except importlib.metadata.PackageNotFoundError:
                    ver = "NOT INSTALLED"
                print_warn(f"   {pkg}: {ver}")
            if "No headers based on this input" in str(e):
                print_warn("")
                print_warn(" Diagnosis: browserforge could not find a fingerprint matching the")
                print_warn("            screen size detected by camoufox. This commonly happens")
                print_warn("            on WSL/headless Linux where the virtual display is very")
                print_warn("            small (e.g. 640x480), below the minimum in the training")
                print_warn("            data. WPX passes an explicit screen size to work around")
                print_warn("            this — if you see this error, please report it.")
            print_warn("──────────────────────────────────────────────────────────────")
            return False

    _DEFAULT_UA = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0"
    )

    def setup_mirror_session(self):
        bypassed = bool(self.user_agent)
        if bypassed:
            print_status("Initializing mirrored curl_cffi session (WAF bypass active)...")
        else:
            print_status("Initializing direct curl_cffi session (no WAF bypass)...")

        self.session = requests.Session()
        ua = self.user_agent or self._DEFAULT_UA

        # Mirror the browser headers precisely
        self.session.headers.update({
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
        })

        print_status("Testing session...")
        try:
            res = self.session.get(
                self.target_url,
                cookies=self.cookies,
                impersonate="firefox",
                timeout=30
            )
            print_status(f"Session test status: {res.status_code}")

            if res.status_code == 200:
                if bypassed:
                    print_status("Mirror session validated! We are through the WAF.")
                else:
                    print_status("Direct session OK (site does not appear to require WAF bypass).")
                return True
            else:
                if bypassed:
                    print_warn(f"Mirror session failed with status {res.status_code} — WAF may still be blocking.")
                else:
                    print_warn(f"Direct session returned status {res.status_code} — site may require WAF bypass.")
                return False
        except Exception as e:
            print_warn(f"Session test failed: {e}")
            return False


if __name__ == "__main__":
    # Test core bypass
    import sys
    url = sys.argv[1] if len(sys.argv) > 1 else "https://247defensivedriving.com"
    core = WPXCore(url)
    if core.bypass_waf():
        core.setup_mirror_session()
