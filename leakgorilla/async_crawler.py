"""Async aiohttp-based crawler for LeakGorilla"""
import asyncio
import random
from urllib.parse import urljoin, urlparse
from collections import deque
import time

import aiohttp
from bs4 import BeautifulSoup

from .scanner_core import scan_page
from .utils import ProxyManager, get_random_user_agent
from .config import TIMEOUT, DELAY_MIN, DELAY_MAX


async def _fetch(session, url, proxy, timeout, verbose):
    try:
        headers = {'User-Agent': get_random_user_agent()}
        proxy_arg = proxy if proxy else None
        async with session.get(url, timeout=timeout, proxy=proxy_arg, headers=headers) as resp:
            if resp.status != 200:
                if verbose:
                    print(f"    ✗ HTTP {resp.status} for {url}")
                return None, None
            text = await resp.text()
            return resp.url.human_repr(), text
    except Exception as e:
        if verbose:
            print(f"    ✗ Error fetching {url}: {e}")
        return None, None


async def crawl_async(start_urls, max_pages=50, timeout=TIMEOUT, delay_min=DELAY_MIN, delay_max=DELAY_MAX,
                      proxies_file=None, stream_proxies=False, validate_proxies=False, revalidate_minutes=0,
                      max_workers=10, verbose=False):
    """Asynchronously crawl start_urls (single str or iterable) and scan pages."""
    if isinstance(start_urls, str):
        start_urls = [start_urls]

    visited = set()
    queue = deque(start_urls)
    findings = []

    proxy_manager = None
    if proxies_file:
        proxy_manager = ProxyManager(proxies_file, stream=stream_proxies, validate=validate_proxies, revalidate_minutes=revalidate_minutes)

    timeout_obj = aiohttp.ClientTimeout(total=timeout)
    connector = aiohttp.TCPConnector(limit_per_host=max_workers)

    async with aiohttp.ClientSession(timeout=timeout_obj, connector=connector) as session:
        sem = asyncio.Semaphore(max_workers)

        async def worker(url):
            async with sem:
                chosen_proxy = proxy_manager.get_proxy() if proxy_manager else None
                fetched_url, text = await _fetch(session, url, chosen_proxy, timeout, verbose)
                if fetched_url and text is not None:
                    # mark visited
                    visited.add(fetched_url)
                    page_findings = scan_page(fetched_url, text, session=None)
                    if page_findings:
                        findings.extend(page_findings)
                        if verbose:
                            print(f"  ✓ Found {len(page_findings)} potential secret(s) on {fetched_url}")

                    # discover links
                    soup = BeautifulSoup(text, 'html.parser')
                    base_domain = urlparse(fetched_url).netloc
                    for link in soup.find_all('a', href=True):
                        absolute_url = urljoin(fetched_url, link['href'])
                        parsed = urlparse(absolute_url)
                        if parsed.netloc == base_domain and absolute_url not in visited:
                            if not any(ext in absolute_url.lower() for ext in ['.pdf', '.zip', '.jpg', '.png', '.gif']):
                                queue.append(absolute_url)

        tasks = set()
        while queue and len(visited) < max_pages:
            while queue and len(tasks) < max_workers and len(visited) + len(tasks) < max_pages:
                u = queue.popleft()
                if u in visited:
                    continue
                t = asyncio.create_task(worker(u))
                tasks.add(t)

            if not tasks:
                break

            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            tasks = set(pending)

            # random delay between batches
            await asyncio.sleep(random.uniform(delay_min, delay_max))

    # stop proxy background thread
    try:
        if proxy_manager:
            proxy_manager.stop_revalidator()
    except Exception:
        pass

    return findings, visited
