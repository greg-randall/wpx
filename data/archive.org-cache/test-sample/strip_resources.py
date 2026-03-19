#!/usr/bin/env python3
"""
Strip external resources from cached Archive.org HTML files so they
load instantly in a browser without timing out on dead archive.org URLs.

Run from inside the test-sample/ directory:
  python3 strip_resources.py
"""
from bs4 import BeautifulSoup, Comment
from pathlib import Path

for f in sorted(Path('.').glob('*.html')):
    soup = BeautifulSoup(f.read_text(encoding='utf-8', errors='ignore'), 'lxml')

    # Archive.org toolbar injected as an HTML comment block
    for node in soup.find_all(string=lambda t: isinstance(t, Comment)):
        if 'WAYBACK TOOLBAR' in t:
            node.extract()

    # External JS
    for tag in soup.find_all('script', src=True):
        tag.decompose()

    # CSS, fonts, prefetch hints
    for tag in soup.find_all('link'):
        tag.decompose()

    f.write_text(str(soup), encoding='utf-8')
    print(f"cleaned {f.name}")
