"""Web crawler for LeakGorilla

This crawler uses a thread pool to fetch pages concurrently, rotates proxies
and user-agents, and adds random delays between requests to reduce detection.
"""

import time
import requests
import random
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import deque
import threading

from .scanner_core import scan_page
from .utils import ProxyManager, get_random_user_agent
from .config import TIMEOUT, MAX_WORKERS, VERBOSE, DELAY_MIN, DELAY_MAX


def crawl_and_scan(start_url, max_pages, timeout=TIMEOUT, delay=None, proxy=None, verbose=False,
                   proxies_file=None, stream_proxies=False, validate_proxies=False, revalidate_minutes=0,
                   delay_min=None, delay_max=None, max_workers=None):
    """Crawl website and scan for secrets.

    Args are mostly backward-compatible. New args support proxy file and streaming.
    """
    visited = set()
    visited_lock = threading.Lock()
    queue = deque([start_url])
    queue_lock = threading.Lock()
    findings = []
    base_domain = urlparse(start_url).netloc

    timeout = timeout or TIMEOUT
    delay_min = delay_min if delay_min is not None else (delay if isinstance(delay, (int, float)) else DELAY_MIN)
    delay_max = delay_max if delay_max is not None else (delay if isinstance(delay, (int, float)) else DELAY_MAX)
    max_workers = max_workers or MAX_WORKERS

    proxy_manager = None
    if proxies_file:
        proxy_manager = ProxyManager(proxies_file, stream=stream_proxies, validate=validate_proxies, revalidate_minutes=revalidate_minutes)
        if validate_proxies and proxy_manager.proxies:
            if verbose:
                print(f"Validated {len(proxy_manager.proxies)} proxies from {proxies_file}")

    def worker_fetch(url_to_fetch):
        # Prepare session per request so headers/proxies don't leak between threads
        session = requests.Session()
        ua = get_random_user_agent()
        session.headers.update({'User-Agent': ua})

        chosen_proxy = None
        if proxy_manager:
            chosen_proxy = proxy_manager.get_proxy()
        elif proxy:
            chosen_proxy = proxy

        if chosen_proxy:
            session.proxies = {'http': chosen_proxy, 'https': chosen_proxy}

        try:
            if verbose:
                print(f"    → Fetching {url_to_fetch} via {chosen_proxy or 'direct'} UA:{ua[:30]}...")
            resp = session.get(url_to_fetch, timeout=timeout, allow_redirects=True)
            if resp.status_code != 200:
                # mark proxy failed if we were using one
                if chosen_proxy and proxy_manager:
                    proxy_manager.mark_failed(chosen_proxy)
                return url_to_fetch, None, []

            # scan page
            page_findings = scan_page(url_to_fetch, resp.text, session)

            # collect links
            links = []
            soup = BeautifulSoup(resp.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                absolute_url = urljoin(url_to_fetch, link['href'])
                parsed = urlparse(absolute_url)
                if parsed.netloc == base_domain:
                    # Filter out non-content
                    if not any(ext in absolute_url.lower() for ext in ['.pdf', '.zip', '.jpg', '.png', '.gif']):
                        links.append(absolute_url)

            return url_to_fetch, page_findings, links
        except requests.RequestException as e:
            if verbose:
                print(f"    ✗ Error fetching {url_to_fetch}: {e}")
            if chosen_proxy and proxy_manager:
                proxy_manager.mark_failed(chosen_proxy)
            return url_to_fetch, None, []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        in_progress = {}

        def submit_next():
            with queue_lock:
                if not queue or len(visited) + len(in_progress) >= max_pages:
                    return
                u = queue.popleft()
            if u in visited:
                return
            fut = executor.submit(worker_fetch, u)
            in_progress[fut] = u

        # seed initial tasks
        for _ in range(min(max_workers, max_pages)):
            submit_next()

        while in_progress:
            for future in as_completed(list(in_progress.keys())):
                url_fetched = in_progress.pop(future)
                try:
                    url_done, page_findings, links = future.result()
                except Exception as e:
                    if verbose:
                        print(f"  ✗ Worker exception: {e}")
                    page_findings = None
                    links = []

                if page_findings is not None:
                    with visited_lock:
                        visited.add(url_done)
                    if page_findings:
                        findings.extend(page_findings)
                        if verbose:
                            print(f"  ✓ Found {len(page_findings)} potential secret(s) on {url_done}")

                # add discovered links
                with queue_lock:
                    for l in links:
                        if l not in visited and l not in queue:
                            queue.append(l)

                # random delay
                sleep_for = random.uniform(delay_min, delay_max)
                if verbose:
                    print(f"  ⏱ Sleeping {sleep_for:.3f}s")
                time.sleep(sleep_for)

                # submit new tasks while we have capacity
                while len(in_progress) < max_workers and len(visited) + len(in_progress) < max_pages and queue:
                    submit_next()

    return findings, visited
    # stop background revalidator if running
    try:
        if proxy_manager:
            proxy_manager.stop_revalidator()
    except Exception:
        pass
