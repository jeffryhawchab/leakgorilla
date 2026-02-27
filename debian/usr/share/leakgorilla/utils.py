"""Utilities: proxy manager and user-agent loader"""
import threading
import time
import requests
from pathlib import Path
import random

# Hard-coded user agents loaded once
_USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148',
    'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)'
]


def get_random_user_agent():
    return random.choice(_USER_AGENTS)


class ProxyManager:
    """Manage rotating proxies loaded from a file. Thread-safe round-robin.

    Supports streaming load for very large lists via `stream=True`.
    Validates proxies (best-effort) by issuing a small request.
    """

    def __init__(self, proxies_file=None, stream=False, validate=False, validate_timeout=3, revalidate_minutes=0):
        self.lock = threading.Lock()
        self.proxies = []
        self.index = 0
        self.last_validated = 0
        self.validate_timeout = validate_timeout
        self.stream = stream
        self.file = Path(proxies_file) if proxies_file else None
        self._revalidator = None
        self._stop_revalidator = threading.Event()
        if proxies_file:
            if stream:
                # don't read whole file now
                self._stream = True
            else:
                self._load_file()

        if validate and self.proxies:
            self.validate_all()

        # Start background revalidation thread if requested
        if revalidate_minutes and revalidate_minutes > 0:
            self._revalidator = threading.Thread(target=self._background_revalidate, args=(revalidate_minutes,), daemon=True)
            self._revalidator.start()

    def _load_file(self):
        if not self.file or not self.file.exists():
            return
        with self.file.open('r', encoding='utf-8', errors='ignore') as fh:
            for line in fh:
                p = line.strip()
                if p:
                    self.proxies.append(p)

    def stream_proxies(self):
        if not self.file:
            return
        with self.file.open('r', encoding='utf-8', errors='ignore') as fh:
            for line in fh:
                p = line.strip()
                if p:
                    yield p

    def validate_proxy(self, proxy):
        try:
            resp = requests.get('https://httpbin.org/ip', proxies={'http': proxy, 'https': proxy}, timeout=self.validate_timeout)
            return resp.status_code == 200
        except:
            return False

    def validate_all(self):
        if self.stream:
            valid = []
            for p in self.stream_proxies():
                if self.validate_proxy(p):
                    valid.append(p)
            with self.lock:
                self.proxies = valid
        else:
            valid = []
            for p in list(self.proxies):
                if self.validate_proxy(p):
                    valid.append(p)
            with self.lock:
                self.proxies = valid
        self.last_validated = time.time()

    def _background_revalidate(self, minutes):
        """Background thread that re-validates proxies every `minutes` minutes."""
        interval = max(1, minutes) * 60
        while not self._stop_revalidator.wait(interval):
            try:
                self.validate_all()
            except Exception:
                pass

    def stop_revalidator(self):
        if self._revalidator:
            self._stop_revalidator.set()
            self._revalidator.join(timeout=2)

    def get_proxy(self):
        with self.lock:
            if not self.proxies:
                return None
            p = self.proxies[self.index % len(self.proxies)]
            self.index += 1
            return p

    def mark_failed(self, proxy):
        with self.lock:
            try:
                self.proxies.remove(proxy)
            except ValueError:
                pass
