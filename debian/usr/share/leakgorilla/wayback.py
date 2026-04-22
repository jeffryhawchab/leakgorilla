"""Wayback Machine scanner for LeakGorilla"""

import requests
from .scanner_core import scan_content


def get_wayback_urls(domain):
    """Fetch all archived URLs for a domain from Wayback Machine CDX API"""
    print(f"\n[Wayback] Fetching archived URLs for {domain}...")
    try:
        api_url = (
            f"http://web.archive.org/cdx/search/cdx"
            f"?url={domain}/*"
            f"&output=text"
            f"&fl=original"
            f"&collapse=urlkey"
            f"&filter=statuscode:200"
            f"&filter=mimetype:text/html|application/javascript|text/css"
        )
        response = requests.get(api_url, timeout=30)
        if response.status_code == 200:
            urls = list(set(response.text.strip().split('\n')))
            print(f"[Wayback] Found {len(urls)} archived URLs")
            return urls
    except Exception as e:
        print(f"[Wayback] Error fetching URLs: {str(e)[:50]}")
    return []


def fetch_wayback_content(url, timeout=10):
    """Fetch content from Wayback Machine for a given URL"""
    wayback_url = f"https://web.archive.org/web/2024/{url}"
    try:
        response = requests.get(wayback_url, timeout=timeout)
        if response.status_code == 200:
            return response.text
    except:
        pass
    return None


def scan_wayback(domain, max_pages, timeout):
    """Scan archived versions of a website for secrets"""
    findings = []
    urls = get_wayback_urls(domain)

    if not urls:
        print("[Wayback] No archived URLs found")
        return findings

    scanned = 0
    for url in urls[:max_pages]:
        print(f"[Wayback] [{scanned+1}/{min(len(urls), max_pages)}] Scanning: {url}")
        content = fetch_wayback_content(url, timeout)
        if content:
            source_type = "Wayback JS" if url.endswith('.js') else "Wayback HTML"
            page_findings = scan_content(content, url, source_type)
            if page_findings:
                print(f"  ✓ Found {len(page_findings)} potential secret(s)")
            findings.extend(page_findings)
        scanned += 1

    print(f"[Wayback] Scan complete: {scanned} archived pages scanned")
    return findings
