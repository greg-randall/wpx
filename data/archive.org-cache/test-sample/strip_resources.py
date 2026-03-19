#!/usr/bin/env python3
from bs4 import BeautifulSoup
from pathlib import Path

STRIP_EXTS = {'.js', '.css', '.woff', '.woff2', '.ttf', '.otf', '.eot', '.ico', '.png', '.gif'}

STRIP_SCRIPT_KEYWORDS = {'ga.js', 'quant.js', 'analytics.js', 'gtag/js', 'gtm.js',
                         'google-analytics.com', 'quantserve.com', 'googletagmanager.com'}

STRIP_LINK_DOMAINS = {'fonts.googleapis.com', 'fonts.gstatic.com',
                      'use.typekit.net', 'use.fontawesome.com'}

for f in sorted(Path('.').glob('*.html')):
    soup = BeautifulSoup(f.read_text(encoding='utf-8', errors='ignore'), 'lxml')

    for tag in soup.find_all('script'):
        src = tag.get('src', '')
        if src and Path(src.split('?')[0]).suffix.lower() == '.js':
            tag.decompose()
            continue
        content = tag.string or ''
        if any(kw in content for kw in STRIP_SCRIPT_KEYWORDS):
            tag.decompose()

    for tag in soup.find_all('link', href=True):
        href = tag['href']
        ext = Path(href.split('?')[0]).suffix.lower()
        if ext in STRIP_EXTS or any(d in href for d in STRIP_LINK_DOMAINS):
            tag.decompose()

    for tag in soup.find_all('style'):
        if tag.string and '@import' in tag.string:
            tag.decompose()

    for tag in soup.find_all('iframe'):
        tag.decompose()

    f.write_text(str(soup), encoding='utf-8')
    print(f"cleaned {f.name}")
