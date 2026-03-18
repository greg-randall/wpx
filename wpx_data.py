import json
import re
import urllib.request
import yaml
from pathlib import Path

DATA_DIR = Path(".wpx_data")
BASE_URL = "https://data.wpscan.org/"
FILES = [
    "dynamic_finders.yml",
    "plugins.txt",
    "themes.txt",
    "config_backups.txt",
    "db_exports.txt",
    "wp_fingerprints.json",
    "metadata.json",
]


class WPXData:
    def __init__(self, force_update=False):
        DATA_DIR.mkdir(exist_ok=True)
        self.force_update = force_update
        self.dynamic_finders = {}
        self.plugins = []
        self.backups = []
        self.wp_metadata = {}

        # Handle !ruby/regexp tag
        yaml.add_constructor('!ruby/regexp', self._ruby_regexp_constructor, Loader=yaml.SafeLoader)

    def _ruby_regexp_constructor(self, loader, node):
        value = loader.construct_scalar(node)
        # Ruby regexes often have flags at the end, e.g. /pattern/i
        if value.startswith('/') and value.count('/') >= 2:
            parts = value.split('/')
            pattern = parts[1]
            flags_str = parts[2]
            flags = 0
            if 'i' in flags_str:
                flags |= re.IGNORECASE
            if 'm' in flags_str:
                flags |= re.MULTILINE

            # Ruby uses (?<v>...) for named groups. Python uses (?P<v>...)
            pattern = pattern.replace('(?<', '(?P<')

            try:
                return re.compile(pattern, flags)
            except re.error:
                return re.compile("$^")

        try:
            return re.compile(value.replace('(?<', '(?P<'))
        except re.error:
            return re.compile("$^")

    def download_metadata(self):
        print("[*] Checking for WPScan metadata updates...")
        for filename in FILES:
            local_path = DATA_DIR / filename
            if not local_path.exists() or self.force_update:
                url = f"{BASE_URL}{filename}"
                print(f"  - Downloading {filename} from {BASE_URL}...")
                try:
                    urllib.request.urlretrieve(url, local_path)
                except Exception as e:
                    print(f"  [!] Failed to download {filename}: {e}")

    def load_dynamic_finders(self):
        df_file = DATA_DIR / "dynamic_finders.yml"
        if df_file.exists():
            print("[*] Loading dynamic finders...")
            with open(df_file, "r") as f:
                data = yaml.safe_load(f)
                self.dynamic_finders = data.get("plugins", {})
                print(f"  - Loaded {len(self.dynamic_finders)} plugin detection rules.")

    def load_slugs(self):
        plugin_file = DATA_DIR / "plugins.txt"
        if plugin_file.exists():
            with open(plugin_file, "r") as f:
                self.plugins = [line.strip() for line in f if line.strip()]
            print(f"  - Loaded {len(self.plugins)} plugin slugs.")

        backup_file = DATA_DIR / "config_backups.txt"
        if backup_file.exists():
            with open(backup_file, "r") as f:
                self.backups = [line.strip() for line in f if line.strip()]

    def load_wp_metadata(self):
        meta_file = DATA_DIR / "metadata.json"
        if meta_file.exists():
            try:
                with open(meta_file) as f:
                    data = json.load(f)
                self.wp_metadata = data.get("wordpress", {})
            except Exception:
                pass

    def get_plugin_rules(self, slug):
        return self.dynamic_finders.get(slug, {})


if __name__ == "__main__":
    data = WPXData(force_update=False)
    data.download_metadata()
    data.load_dynamic_finders()
    data.load_slugs()
