#!/usr/bin/env python3
import re
import requests
import argparse
import json
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

# Configuration
OUTPUT_FILE = "web_secrets.txt"
REDACT_LENGTH = 4
MAX_PAGES = 50
TIMEOUT = 10
MAX_WORKERS = 5
DELAY = 0
VERBOSE = False

# Severity levels
SEVERITY = {
    'OpenAI API Key': 'CRITICAL',
    'Anthropic Claude API Key': 'CRITICAL',
    'AWS Access Key': 'CRITICAL',
    'AWS Secret Key': 'CRITICAL',
    'Stripe API Key': 'CRITICAL',
    'Private Key': 'CRITICAL',
    'Groq API Key': 'HIGH',
    'Google API Key': 'HIGH',
    'Meta AI/Facebook API Key': 'HIGH',
    'GitHub Token': 'HIGH',
    'Database Connection String': 'HIGH',
    'Slack Token': 'MEDIUM',
    # 'Twilio API Key': 'MEDIUM',
    'SendGrid API Key': 'MEDIUM',
    'Mailgun API Key': 'MEDIUM',
    'JWT Token': 'MEDIUM',
    'OAuth Token': 'MEDIUM',
    'Google Cloud Service Account': 'HIGH',
    'Generic API Key': 'LOW',
    'Generic Secret': 'LOW'
}

# Advanced patterns for web secrets with categorization
PATTERNS = {
    'OpenAI API Key': [
        r'sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}',
        r'sk-proj-[a-zA-Z0-9_-]{43,}',
        r'sk-[a-zA-Z0-9]{48}'
    ],
    'Anthropic Claude API Key': [
        r'sk-ant-api03-[a-zA-Z0-9_-]{95}',
        r'sk-ant-[a-zA-Z0-9_-]{95,}'
    ],
    'Groq API Key': [
        r'gsk_[a-zA-Z0-9]{52}'
    ],
    'Google API Key': [
        r'AIza[0-9A-Za-z\-_]{35}'
    ],
    'Google Cloud Service Account': [
        r'"type":\s*"service_account"',
        r'"private_key":\s*"-----BEGIN PRIVATE KEY-----'
    ],
    'Meta AI/Facebook API Key': [
        r'EAA[a-zA-Z0-9]{100,}',
        r'\b[0-9]{15,16}\|[a-zA-Z0-9_-]{27,}\b'
    ],
    'AWS Access Key': [
        r'\b(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b'
    ],
    'AWS Secret Key': [
        r'(?i)aws[_\-]?secret[_\-]?access[_\-]?key[\s:=]+[\'"\`]?([a-zA-Z0-9/+=]{40})[\'"\`]?'
    ],
    'GitHub Token': [
        r'ghp_[a-zA-Z0-9]{36}',
        r'gho_[a-zA-Z0-9]{36}',
        r'ghu_[a-zA-Z0-9]{36}',
        r'ghs_[a-zA-Z0-9]{36}',
        r'ghr_[a-zA-Z0-9]{36}'
    ],
    'Stripe API Key': [
        r'sk_live_[0-9a-zA-Z]{24,}',
        r'sk_test_[0-9a-zA-Z]{24,}',
        r'pk_live_[0-9a-zA-Z]{24,}',
        r'pk_test_[0-9a-zA-Z]{24,}'
    ],
    'Slack Token': [
        r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}'
    ],
    # 'Twilio API Key': [
    #     r'SK[a-z0-9]{32}'
    # ],
    'SendGrid API Key': [
        r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}'
    ],
    'Mailgun API Key': [
        r'key-[a-zA-Z0-9]{32}'
    ],
    'JWT Token': [
        r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}'
    ],
    'OAuth Token': [
        r'\bya29\.[a-zA-Z0-9\-_]{100,}\b'
    ],
    'Database Connection String': [
        r'(mongodb|postgres|mysql|redis)://[^\s:]+:[^\s@]+@[a-z0-9\-\.]+:[0-9]+',
        r'Server=[^;]+;Database=[^;]+;User Id=[^;]+;Password=[^;]+'
    ],
    'Private Key': [
        r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----',
        r'-----BEGIN OPENSSH PRIVATE KEY-----'
    ],
    'Generic API Key': [
        r'(?i)(api|access)[_\-]?key[\s:=]+[\'"\`]([a-zA-Z0-9_\-]{20,50})[\'"\`]',
        r'(?i)bearer [a-zA-Z0-9_\-\.=]{20,}'
    ],
    'Generic Secret': [
        r'(?i)(secret|password|passwd|pwd)[\s:=]+[\'"\`]([^\s\'"\`]{8,50})[\'"\`]'
    ]
}

class SecretFinding:
    def __init__(self, url, source, matched_string, secret_type, context=''):
        self.url = url
        self.source = source
        self.matched_string = matched_string
        self.secret_type = secret_type
        self.context = context
        self.timestamp = datetime.now()
        self.severity = SEVERITY.get(secret_type, 'LOW')

def get_context(text, match, context_length=50):
    start = max(0, match.start() - context_length)
    end = min(len(text), match.end() + context_length)
    return text[start:end].replace('\n', ' ').strip()

def scan_content(content, url, source_type):
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

def crawl_and_scan(start_url, max_pages, timeout, delay, proxy, verbose):
    global TIMEOUT, MAX_PAGES, DELAY, VERBOSE
    TIMEOUT = timeout
    MAX_PAGES = max_pages
    DELAY = delay
    VERBOSE = verbose
    
    visited = set()
    queue = [start_url]
    findings = []
    base_domain = urlparse(start_url).netloc
    
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })
    
    if proxy:
        session.proxies = {'http': proxy, 'https': proxy}
        if VERBOSE:
            print(f"Using proxy: {proxy}")
    
    while queue and len(visited) < MAX_PAGES:
        url = queue.pop(0)
        if url in visited:
            continue
        
        if DELAY > 0 and len(visited) > 0:
            if VERBOSE:
                print(f"  ⏱ Waiting {DELAY}s...")
            import time
            time.sleep(DELAY)
            
        try:
            print(f"[{len(visited)+1}/{MAX_PAGES}] Scanning: {url}")
            response = session.get(url, timeout=TIMEOUT, allow_redirects=True)
            if response.status_code == 200:
                visited.add(url)
                page_findings = scan_page(url, response.text, session)
                findings.extend(page_findings)
                
                if page_findings:
                    print(f"  ✓ Found {len(page_findings)} potential secret(s)")
                
                # Find new links to crawl
                soup = BeautifulSoup(response.text, 'html.parser')
                for link in soup.find_all('a', href=True):
                    absolute_url = urljoin(url, link['href'])
                    parsed = urlparse(absolute_url)
                    
                    # Stay within same domain
                    if parsed.netloc == base_domain and absolute_url not in visited and absolute_url not in queue:
                        # Filter out common non-content URLs
                        if not any(ext in absolute_url.lower() for ext in ['.pdf', '.zip', '.jpg', '.png', '.gif']):
                            queue.append(absolute_url)
                        
        except requests.RequestException as e:
            print(f"  ✗ Error: {str(e)[:50]}")
    
    return findings, visited

def save_findings(findings, output_file, output_format='txt'):
    if output_format == 'json':
        data = [{
            'url': f.url,
            'source': f.source,
            'type': f.secret_type,
            'severity': f.severity,
            'secret': f.matched_string,
            'context': f.context,
            'timestamp': f.timestamp.isoformat()
        } for f in findings]
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
    else:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"Web Secret Scan Results - {datetime.now()}\n")
            f.write("="*80 + "\n\n")
            
            # Group by severity then type
            by_severity = {'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': []}
            for finding in findings:
                by_severity[finding.severity].append(finding)
            
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                items = by_severity[severity]
                if not items:
                    continue
                    
                f.write(f"\n{'='*80}\n")
                f.write(f"{severity} SEVERITY ({len(items)} found)\n")
                f.write(f"{'='*80}\n\n")
                
                by_type = defaultdict(list)
                for finding in items:
                    by_type[finding.secret_type].append(finding)
                
                for secret_type, type_items in sorted(by_type.items()):
                    f.write(f"\n[{secret_type}] - {len(type_items)} found\n")
                    f.write("-"*80 + "\n")
                    
                    for finding in type_items:
                        f.write(f"URL: {finding.url}\n")
                        f.write(f"Source: {finding.source}\n")
                        f.write(f"Secret: {finding.matched_string}\n")
                        f.write(f"Context: ...{finding.context}...\n")
                        f.write("-"*80 + "\n")

def print_findings(findings):
    print(f"\n{'='*80}")
    print(f"SCAN SUMMARY")
    print(f"{'='*80}")
    print(f"Total secrets found: {len(findings)}\n")
    
    # Group by severity
    by_severity = {'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': []}
    for finding in findings:
        by_severity[finding.severity].append(finding)
    
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        items = by_severity[severity]
        if not items:
            continue
            
        print(f"\n{'='*80}")
        print(f"{severity} SEVERITY - {len(items)} found")
        print(f"{'='*80}")
        
        by_type = defaultdict(list)
        for finding in items:
            by_type[finding.secret_type].append(finding)
        
        for secret_type, type_items in sorted(by_type.items()):
            print(f"\n[{secret_type}] - {len(type_items)} found")
            print("-"*80)
            
            for finding in type_items[:2]:  # Show first 2 of each type
                secret = finding.matched_string
                if len(secret) > REDACT_LENGTH * 2:
                    redacted = secret[:REDACT_LENGTH] + "..." + secret[-REDACT_LENGTH:]
                else:
                    redacted = "***REDACTED***"
                
                print(f"  URL: {finding.url}")
                print(f"  Source: {finding.source}")
                print(f"  Value: {redacted}")
                print()
            
            if len(type_items) > 2:
                print(f"  ... and {len(type_items) - 2} more\n")

def main():
    parser = argparse.ArgumentParser(
        description='LeakGorilla - Advanced Web Secret Scanner\nDetect API keys, tokens, and credentials in web applications',
        epilog='Author: Jeffrey Hawchab | GitHub: https://github.com/jeffryhawchab/leakgorilla',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('--max-pages', type=int, default=50, help='Maximum pages to scan (default: 50)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('--delay', type=float, default=0, help='Delay between requests in seconds (default: 0)')
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--output', default='web_secrets.txt', help='Output file (default: web_secrets.txt)')
    parser.add_argument('--format', choices=['txt', 'json'], default='txt', help='Output format (default: txt)')
    
    args = parser.parse_args()
    
    start_url = args.url
    if not start_url.startswith(('http://', 'https://')):
        start_url = 'https://' + start_url
    
    print(f"\n{'='*80}")
    print(f"LeakGorilla - Advanced Web Secret Scanner")
    print(f"{'='*80}")
    print(f"Target: {start_url}")
    print(f"Max Pages: {args.max_pages}")
    print(f"Timeout: {args.timeout}s")
    if args.delay:
        print(f"Delay: {args.delay}s")
    if args.proxy:
        print(f"Proxy: {args.proxy}")
    if args.verbose:
        print(f"Verbose: Enabled")
    print(f"{'='*80}\n")
    
    findings, visited = crawl_and_scan(start_url, args.max_pages, args.timeout, args.delay, args.proxy, args.verbose)
    
    print(f"\n{'='*80}")
    print(f"Scan completed: {len(visited)} pages scanned")
    print(f"{'='*80}")
    
    if findings:
        save_findings(findings, args.output, args.format)
        print_findings(findings)
        print(f"\n✓ Full results saved to {args.output}")
    else:
        print("\n✓ No secrets found")

if __name__ == "__main__":
    main()
