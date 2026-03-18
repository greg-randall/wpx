from camoufox import Camoufox
from curl_cffi import requests
import time

class WPXCore:
    def __init__(self, target_url):
        self.target_url = target_url
        self.cookies = {}
        self.user_agent = ""
        self.session = None

    def bypass_cloudflare(self):
        print(f"[*] Launching Camoufox to bypass Cloudflare for {self.target_url}...")
        try:
            with Camoufox(headless=True) as browser:
                page = browser.new_page()
                
                # Navigate and solve challenge
                response = page.goto(self.target_url, wait_until="networkidle")
                
                # Sometimes Cloudflare needs a bit more time for the final redirect
                time.sleep(5)
                
                print("[+] Page loaded. Extracting session tokens...")
                
                # Extract cookies
                self.cookies = {c['name']: c['value'] for c in page.context.cookies()}
                
                # Extract the exact User-Agent used by Camoufox
                self.user_agent = page.evaluate("navigator.userAgent")
                
                print(f"[*] Extracted User-Agent: {self.user_agent[:60]}...")
                print(f"[*] Extracted {len(self.cookies)} cookies.")
                
                return True
        except Exception as e:
            print(f"[!] Camoufox bypass failed: {e}")
            return False

    def setup_mirror_session(self):
        print("[*] Initializing mirrored curl_cffi session...")
        self.session = requests.Session()
        
        # Mirror the browser headers precisely
        self.session.headers.update({
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
        })
        
        # Use Firefox impersonation to match Camoufox
        # Note: curl_cffi might have different firefox profiles, firefox120 is a good default
        
        print("[*] Testing mirrored session...")
        try:
            res = self.session.get(
                self.target_url, 
                cookies=self.cookies, 
                impersonate="firefox",
                timeout=30
            )
            print(f"[*] Mirror Test Status: {res.status_code}")
            
            if res.status_code == 200:
                print("[+] Mirror session validated! We are through the WAF.")
                return True
            else:
                print(f"[!] Mirror session failed with status {res.status_code}.")
                return False
        except Exception as e:
            print(f"[!] Mirror session test failed: {e}")
            return False

if __name__ == "__main__":
    # Test core bypass
    import sys
    url = sys.argv[1] if len(sys.argv) > 1 else "https://247defensivedriving.com"
    core = WPXCore(url)
    if core.bypass_cloudflare():
        core.setup_mirror_session()
