"""Output and reporting for LeakGorilla"""

import json
from datetime import datetime
from collections import defaultdict

from .config import REDACT_LENGTH


def save_findings(findings, output_file, output_format='txt'):
    """Save findings to file in specified format"""
    if output_format == 'json':
        data = [f.to_dict() for f in findings]
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
    else:
        _save_text_format(findings, output_file)


def _save_text_format(findings, output_file):
    """Save findings in text format"""
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
    """Print findings summary to console"""
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
