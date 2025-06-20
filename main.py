#!/usr/bin/env python3
import re
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from datetime import datetime

# Configuration
OUTPUT_FILE = "web_secrets.txt"
REDACT_LENGTH = 4  # Show first/last N chars of secrets
MAX_PAGES = 50  # Maximum pages to scan
TIMEOUT = 10  # Request timeout in seconds

# Enhanced patterns for web secrets
PATTERNS = [
    # API keys
    r'(?i)\b(api|access)[_\-]?(key|token)\b[\s:=]+[\'"`]?([a-z0-9]{20,50})[\'"`]?',
    
    # OAuth tokens
    r'\bya29\.[a-z0-9\-_]{100,}\b',
    
    # Database credentials
    r'\b(mongodb|postgres|mysql)://\w+:\w+@[a-z0-9\-\.]+:\d+\/\w+\b',
    
    # AWS keys
    r'\b(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b',
    
    # Google API keys
    r'\bAIza[0-9A-Za-z\-_]{35}\b',
    
    # Stripe keys
    r'\b(sk|pk)_(test|live)_[0-9a-z]{24}\b',
    
    # Encryption keys
    r'\b(enc|dec)ryption_?key\b[\s:=]+[\'"`]?([a-z0-9]{20,50})[\'"`]?',
    
    # General secrets
    r'\b(secret|private|confidential)[_\-]?(key|token|pass)\b[\s:=]+[\'"`]?([a-z0-9]{20,50})[\'"`]?'
]

class SecretFinding:
    def __init__(self, url, source, matched_string, pattern):
        self.url = url
        self.source = source  # URL or page content where found
        self.matched_string = matched_string
        self.pattern = pattern

def scan_page(url, html_content):
    findings = []
    
    # Scan HTML content
    for pattern in PATTERNS:
        for match in re.finditer(pattern, html_content, re.IGNORECASE):
            if match.group():
                findings.append(SecretFinding(
                    url=url,
                    source="HTML content",
                    matched_string=match.group(),
                    pattern=pattern
                ))
    
    # Scan JavaScript files
    soup = BeautifulSoup(html_content, 'html.parser')
    for script in soup.find_all('script'):
        if script.get('src'):
            try:
                js_url = urljoin(url, script['src'])
                js_response = requests.get(js_url, timeout=TIMEOUT)
                if js_response.status_code == 200:
                    for pattern in PATTERNS:
                        for match in re.finditer(pattern, js_response.text, re.IGNORECASE):
                            if match.group():
                                findings.append(SecretFinding(
                                    url=js_url,
                                    source="JavaScript file",
                                    matched_string=match.group(),
                                    pattern=pattern
                                ))
            except requests.RequestException:
                continue
        else:
            # Inline scripts
            for pattern in PATTERNS:
                for match in re.finditer(pattern, script.string or '', re.IGNORECASE):
                    if match.group():
                        findings.append(SecretFinding(
                            url=url,
                            source="Inline JavaScript",
                            matched_string=match.group(),
                            pattern=pattern
                        ))
    
    return findings

def crawl_and_scan(start_url):
    visited = set()
    queue = [start_url]
    findings = []
    
    while queue and len(visited) < MAX_PAGES:
        url = queue.pop(0)
        if url in visited:
            continue
            
        try:
            print(f"Scanning: {url}")
            response = requests.get(url, timeout=TIMEOUT)
            if response.status_code == 200:
                visited.add(url)
                findings.extend(scan_page(url, response.text))
                
                # Find new links to crawl
                soup = BeautifulSoup(response.text, 'html.parser')
                for link in soup.find_all('a', href=True):
                    absolute_url = urljoin(url, link['href'])
                    if absolute_url.startswith(start_url) and absolute_url not in visited:
                        queue.append(absolute_url)
                        
        except requests.RequestException as e:
            print(f"Error scanning {url}: {str(e)}")
    
    return findings

def save_findings(findings):
    with open(OUTPUT_FILE, 'w') as f:
        f.write(f"Web Secret Scan Results - {datetime.now()}\n")
        f.write("="*80 + "\n")
        for finding in findings:
            f.write(f"URL: {finding.url}\n")
            f.write(f"Source: {finding.source}\n")
            f.write(f"Type: {finding.pattern}\n")
            f.write(f"Secret: {finding.matched_string}\n")
            f.write("-"*80 + "\n")

def print_findings(findings):
    print(f"\nFound {len(findings)} potential secrets:")
    print("="*80)
    for finding in findings:
        secret = finding.matched_string
        redacted = (secret[:REDACT_LENGTH] + 
                   "..." + 
                   secret[-REDACT_LENGTH:] if len(secret) > REDACT_LENGTH*2 
                   else "***REDACTED***")
        print(f"URL: {finding.url}")
        print(f"Source: {finding.source}")
        print(f"Type: {finding.pattern}")
        print(f"Value: {redacted}\n")

def main():
    if len(sys.argv) != 2:
        print("Usage: python web_secret_scanner.py <starting_url>")
        sys.exit(1)

    start_url = sys.argv[1]
    if not start_url.startswith(('http://', 'https://')):
        start_url = 'https://' + start_url

    print(f"Starting scan of {start_url}...")
    findings = crawl_and_scan(start_url)

    if findings:
        save_findings(findings)
        print_findings(findings)
        print(f"\nResults saved to {OUTPUT_FILE}")
    else:
        print("No secrets found")

if __name__ == "__main__":
    import sys
    main()