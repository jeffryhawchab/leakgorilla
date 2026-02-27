#!/usr/bin/env python3
"""
LeakGorilla - Advanced Web Secret Scanner
Author: Jeffrey Hawchab
GitHub: https://github.com/jeffryhawchab/leakgorilla
"""

import argparse
import asyncio
from leakgorilla.crawler import crawl_and_scan
from leakgorilla import search
from leakgorilla.async_crawler import crawl_async
from leakgorilla.reporter import save_findings, print_findings


def main():
    parser = argparse.ArgumentParser(
        description='LeakGorilla - Advanced Web Secret Scanner\nDetect API keys, tokens, and credentials in web applications',
        epilog='Author: Jeffrey Hawchab | GitHub: https://github.com/jeffryhawchab/leakgorilla',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    epilog = (
        'Author: Jeffrey Hawchab | GitHub: https://github.com/jeffryhawchab/leakgorilla\n'
        '\nExamples:\n'
        '  python3 leakgorilla/scanner.py https://example.com --max-pages 100 --timeout 8\n'
        '  python3 leakgorilla/scanner.py https://example.com --proxies-file proxies.txt --stream-proxies --validate-proxies\n'
        '  python3 leakgorilla/scanner.py https://example.com --use-search --dorks-file dorks.conf --async\n'
    )

    parser.epilog = epilog

    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('--max-pages', type=int, default=50, help='Maximum pages to scan (default: 50)')
    parser.add_argument('--timeout', type=int, default=4, help='Request timeout in seconds (default: 4)')
    parser.add_argument('--delay-min', type=float, default=0.15, help='Minimum delay between requests in seconds (default: 0.15)')
    parser.add_argument('--delay-max', type=float, default=0.3, help='Maximum delay between requests in seconds (default: 0.3)')
    parser.add_argument('--proxy', help='Single proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--proxies-file', help='Path to a file with proxies (one per line)')
    parser.add_argument('--stream-proxies', action='store_true', help='Load proxies line-by-line to avoid large memory usage')
    parser.add_argument('--validate-proxies', action='store_true', help='Validate proxies before use')
    parser.add_argument('--max-workers', type=int, default=10, help='Max concurrent workers (default: 10)')
    parser.add_argument('--use-search', action='store_true', help='Seed crawl using search engines and dorks')
    parser.add_argument('--dorks-file', default='dorks.conf', help='Dorks config file to use for search seeding')
    parser.add_argument('--async', dest='use_async', action='store_true', help='Use async aiohttp crawler for better performance')
    parser.add_argument('--revalidate-minutes', type=int, default=0, help='Background proxy re-validation interval in minutes (0 to disable)')
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
    print(f"Delay range: {args.delay_min}-{args.delay_max}s")
    if args.proxy:
        print(f"Proxy: {args.proxy}")
    if args.proxies_file:
        print(f"Proxy list: {args.proxies_file} (stream={args.stream_proxies})")
    if args.revalidate_minutes:
        print(f"Proxy revalidation: every {args.revalidate_minutes} minute(s)")
    if args.verbose:
        print(f"Verbose: Enabled")
    print(f"{'='*80}\n")
    
    seed = None
    if args.use_search:
        print("Seeding URLs from search engines using dorks...")
        seed = search.seed_urls_from_search(args.dorks_file)
        print(f"  → Collected {len(seed)} seed URLs from search engines")

    if args.use_async:
        print("Using async aiohttp crawler...")
        findings, visited = asyncio.run(crawl_async(
            seed if seed else start_url,
            max_pages=args.max_pages,
            timeout=args.timeout,
            delay_min=args.delay_min,
            delay_max=args.delay_max,
            proxies_file=args.proxies_file,
            stream_proxies=args.stream_proxies,
            validate_proxies=args.validate_proxies,
            revalidate_minutes=args.revalidate_minutes,
            max_workers=args.max_workers,
            verbose=args.verbose
        ))
    else:
        findings, visited = crawl_and_scan(
            seed if seed else start_url,
            args.max_pages,
            timeout=args.timeout,
            proxy=args.proxy,
            verbose=args.verbose,
            proxies_file=args.proxies_file,
            stream_proxies=args.stream_proxies,
            validate_proxies=args.validate_proxies,
            revalidate_minutes=args.revalidate_minutes,
            delay_min=args.delay_min,
            delay_max=args.delay_max,
            max_workers=args.max_workers
        )
    
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
