"""Core scanning logic for LeakGorilla"""

import re
import time
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed

from .config import PATTERNS, TIMEOUT, MAX_WORKERS, VERBOSE, DELAY_MIN, DELAY_MAX, WHITELIST
from .models import SecretFinding
from .utils import get_random_user_agent
import threading

# Compile patterns once for performance and more accurate matching
_compiled_lock = threading.Lock()
_COMPILED_PATTERNS = None
_COMPILED_WHITELIST = None


def _compile_patterns():
    global _COMPILED_PATTERNS
    with _compiled_lock:
        if _COMPILED_PATTERNS is None:
            cp = {}
            for k, pats in PATTERNS.items():
                cp[k] = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in pats]
            _COMPILED_PATTERNS = cp
    return _COMPILED_PATTERNS


def _compile_whitelist():
    global _COMPILED_WHITELIST
    with _compiled_lock:
        if _COMPILED_WHITELIST is None:
            _COMPILED_WHITELIST = [re.compile(p, re.IGNORECASE) for p in (WHITELIST or [])]
    return _COMPILED_WHITELIST


def get_context(text, match, context_length=50):
    """Extract context around a matched pattern"""
    start = max(0, match.start() - context_length)
    end = min(len(text), match.end() + context_length)
    return text[start:end].replace('\n', ' ').strip()


def scan_content(content, url, source_type):
    """Scan content for secrets using regex patterns"""
    findings = []
    compiled = _compile_patterns()
    whitelist = _compile_whitelist()
    for secret_type, patterns in compiled.items():
        for pattern in patterns:
            for match in pattern.finditer(content):
                m = match.group()
                if not m:
                    continue
                # Skip very short generic matches to reduce false positives
                if secret_type in ('Generic API Key', 'Generic Secret') and len(m) < 20:
                    continue

                # Apply whitelist filtering: if matched string looks like a benign blob, skip it
                skip = False
                for wl in whitelist:
                    try:
                        if wl.search(m):
                            skip = True
                            break
                    except Exception:
                        continue
                if skip:
                    continue
                context = get_context(content, match)
                findings.append(SecretFinding(
                    url=url,
                    source=source_type,
                    matched_string=m,
                    secret_type=secret_type,
                    context=context
                ))
    return findings


def scan_js_file(js_url, session):
    """Scan a JavaScript file for secrets"""
    try:
        if VERBOSE:
            print(f"    → Scanning JS: {js_url}")
        response = session.get(js_url, timeout=TIMEOUT)
        if response.status_code == 200:
            return scan_content(response.text, js_url, "JavaScript file")
    except:
        pass
    return []


def scan_css_file(css_url, session):
    """Scan a CSS file for secrets"""
    try:
        if VERBOSE:
            print(f"    → Scanning CSS: {css_url}")
        response = session.get(css_url, timeout=TIMEOUT)
        if response.status_code == 200:
            return scan_content(response.text, css_url, "CSS file")
    except:
        pass
    return []


def scan_page(url, html_content, session):
    """Scan an HTML page and its resources for secrets"""
    findings = []
    
    # Scan HTML content
    findings.extend(scan_content(html_content, url, "HTML content"))
    
    soup = BeautifulSoup(html_content, 'html.parser')
    js_urls = []
    
    # Collect JS files
    for script in soup.find_all('script'):
        if script.get('src'):
            js_url = urljoin(url, script['src'])
            js_urls.append(js_url)
        elif script.string:
            findings.extend(scan_content(script.string, url, "Inline JavaScript"))
    
    # Collect CSS files but intentionally do not scan CSS (high false positive rate)
    # if in future you want CSS scanning, re-enable below logic.

    # Scan JS files concurrently
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {}
        for js_url in js_urls:
            futures[executor.submit(scan_js_file, js_url, session)] = js_url
        
        for future in as_completed(futures):
            findings.extend(future.result())
    
    return findings
