"""Core scanning logic for LeakGorilla"""

import re
import time
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed

from .config import PATTERNS, TIMEOUT, MAX_WORKERS, DELAY, VERBOSE
from .models import SecretFinding


def get_context(text, match, context_length=50):
    """Extract context around a matched pattern"""
    start = max(0, match.start() - context_length)
    end = min(len(text), match.end() + context_length)
    return text[start:end].replace('\n', ' ').strip()


def scan_content(content, url, source_type):
    """Scan content for secrets using regex patterns"""
    findings = []
    for secret_type, patterns in PATTERNS.items():
        for pattern in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                if match.group():
                    context = get_context(content, match)
                    findings.append(SecretFinding(
                        url=url,
                        source=source_type,
                        matched_string=match.group(),
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
    css_urls = []
    
    # Collect JS files
    for script in soup.find_all('script'):
        if script.get('src'):
            js_url = urljoin(url, script['src'])
            js_urls.append(js_url)
        elif script.string:
            findings.extend(scan_content(script.string, url, "Inline JavaScript"))
    
    # Collect CSS files
    for link in soup.find_all('link', rel='stylesheet'):
        if link.get('href'):
            css_url = urljoin(url, link['href'])
            css_urls.append(css_url)
    
    # Scan JS and CSS files concurrently
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {}
        for js_url in js_urls:
            futures[executor.submit(scan_js_file, js_url, session)] = js_url
        for css_url in css_urls:
            futures[executor.submit(scan_css_file, css_url, session)] = css_url
        
        for future in as_completed(futures):
            findings.extend(future.result())
    
    return findings
