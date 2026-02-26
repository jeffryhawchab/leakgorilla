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
    'Twilio API Key': [
        r'SK[a-z0-9]{32}'
    ],
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
        response = session.get(js_url, timeout=TIMEOUT)
        if response.status_code == 200:
            return scan_content(response.text, js_url, "JavaScript file")
    except:
        pass
    return []

def scan_page(url, html_content, session):
    findings = []
    
    # Scan HTML content
    findings.extend(scan_content(html_content, url, "HTML content"))
    
    # Scan JavaScript files
    soup = BeautifulSoup(html_content, 'html.parser')
    js_urls = []
    
    for script in soup.find_all('script'):
        if script.get('src'):
            js_url = urljoin(url, script['src'])
            js_urls.append(js_url)
        elif script.string:
            findings.extend(scan_content(script.string, url, "Inline JavaScript"))
    
    # Scan JS files concurrently
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(scan_js_file, js_url, session): js_url for js_url in js_urls}
        for future in as_completed(futures):
            findings.extend(future.result())
    
    return findings

def crawl_and_scan(start_url, max_pages, timeout):
    global TIMEOUT, MAX_PAGES
    TIMEOUT = timeout
    MAX_PAGES = max_pages
    
    visited = set()
    queue = [start_url]
    findings = []
    base_domain = urlparse(start_url).netloc
    
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })
    
    while queue and len(visited) < MAX_PAGES:
        url = queue.pop(0)
        if url in visited:
            continue
            
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
            
            # Group by type
            by_type = defaultdict(list)
            for finding in findings:
                by_type[finding.secret_type].append(finding)
            
            for secret_type, items in sorted(by_type.items()):
                f.write(f"\n{'='*80}\n")
                f.write(f"{secret_type} ({len(items)} found)\n")
                f.write(f"{'='*80}\n\n")
                
                for finding in items:
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
    
    # Group by type
    by_type = defaultdict(list)
    for finding in findings:
        by_type[finding.secret_type].append(finding)
    
    for secret_type, items in sorted(by_type.items()):
        print(f"\n[{secret_type}] - {len(items)} found")
        print("-"*80)
        
        for finding in items[:3]:  # Show first 3 of each type
            secret = finding.matched_string
            if len(secret) > REDACT_LENGTH * 2:
                redacted = secret[:REDACT_LENGTH] + "..." + secret[-REDACT_LENGTH:]
            else:
                redacted = "***REDACTED***"
            
            print(f"  URL: {finding.url}")
            print(f"  Source: {finding.source}")
            print(f"  Value: {redacted}")
            print()
        
        if len(items) > 3:
            print(f"  ... and {len(items) - 3} more\n")

def main():
    parser = argparse.ArgumentParser(
        description='Advanced Web Secret Scanner - Detect API keys, tokens, and credentials',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('--max-pages', type=int, default=50, help='Maximum pages to scan (default: 50)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
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
    print(f"{'='*80}\n")
    
    findings, visited = crawl_and_scan(start_url, args.max_pages, args.timeout)
    
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
