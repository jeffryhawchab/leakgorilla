"""Web crawler for LeakGorilla"""

import time
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

from .scanner_core import scan_page
from .resume import save_state, load_state


def crawl_and_scan(start_url, max_pages, timeout, delay, proxy, verbose, resume_file=None):
    """Crawl website and scan for secrets"""
    findings = []
    resumed_findings = []

    # Load state if resuming
    if resume_file:
        visited, queue, resumed_findings_data = load_state(resume_file)
        if visited is None:
            visited = set()
            queue = [start_url]
        # We'll re-add findings from state at the end
    else:
        visited = set()
        queue = [start_url]

    base_domain = urlparse(start_url).netloc

    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })

    if proxy:
        session.proxies = {'http': proxy, 'https': proxy}
        if verbose:
            print(f"Using proxy: {proxy}")

    while queue and len(visited) < max_pages:
        url = queue.pop(0)
        if url in visited:
            continue

        if delay > 0 and len(visited) > 0:
            if verbose:
                print(f"  ⏱ Waiting {delay}s...")
            time.sleep(delay)

        try:
            print(f"[{len(visited)+1}/{max_pages}] Scanning: {url}")
            response = session.get(url, timeout=timeout, allow_redirects=True)
            if response.status_code == 200:
                visited.add(url)
                page_findings = scan_page(url, response.text, session)
                findings.extend(page_findings)

                if page_findings:
                    print(f"  ✓ Found {len(page_findings)} potential secret(s)")

                # Save state every 10 pages
                if resume_file and len(visited) % 10 == 0:
                    save_state(resume_file, visited, queue, findings)
                    if verbose:
                        print(f"  💾 State saved to {resume_file}")

                # Find new links to crawl
                soup = BeautifulSoup(response.text, 'html.parser')
                for link in soup.find_all('a', href=True):
                    absolute_url = urljoin(url, link['href'])
                    parsed = urlparse(absolute_url)

                    if parsed.netloc == base_domain and absolute_url not in visited and absolute_url not in queue:
                        if not any(ext in absolute_url.lower() for ext in ['.pdf', '.zip', '.jpg', '.png', '.gif']):
                            queue.append(absolute_url)

        except requests.RequestException as e:
            print(f"  ✗ Error: {str(e)[:50]}")

    # Save final state
    if resume_file:
        save_state(resume_file, visited, queue, findings)

    return findings, visited
