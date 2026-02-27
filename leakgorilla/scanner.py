#!/usr/bin/env python3
"""
LeakGorilla - Advanced Web Secret Scanner
Author: Jeffrey Hawchab
GitHub: https://github.com/jeffryhawchab/leakgorilla
"""

import argparse
from leakgorilla.crawler import crawl_and_scan
from leakgorilla.reporter import save_findings, print_findings


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
