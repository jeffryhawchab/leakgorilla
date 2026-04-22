"""Custom patterns loader for LeakGorilla"""

import json
from .config import PATTERNS, SEVERITY


def load_custom_patterns(patterns_file):
    """Load custom regex patterns from a JSON file and merge with defaults"""
    try:
        with open(patterns_file, 'r') as f:
            custom = json.load(f)

        patterns = dict(PATTERNS)
        severity = dict(SEVERITY)

        for name, data in custom.items():
            patterns[name] = data.get('patterns', [])
            severity[name] = data.get('severity', 'LOW')

        print(f"[+] Loaded {len(custom)} custom pattern(s) from {patterns_file}")
        return patterns, severity

    except FileNotFoundError:
        print(f"[!] Patterns file not found: {patterns_file}")
    except json.JSONDecodeError:
        print(f"[!] Invalid JSON in patterns file: {patterns_file}")

    return PATTERNS, SEVERITY


def create_example_patterns_file(output_file='custom_patterns.json'):
    """Create an example custom patterns file"""
    example = {
        "My Custom API Key": {
            "patterns": [
                "myapp-[a-zA-Z0-9]{32}"
            ],
            "severity": "HIGH"
        },
        "Internal Token": {
            "patterns": [
                "tok_[a-zA-Z0-9]{40}"
            ],
            "severity": "CRITICAL"
        }
    }
    with open(output_file, 'w') as f:
        json.dump(example, f, indent=2)
    print(f"[+] Example patterns file created: {output_file}")
