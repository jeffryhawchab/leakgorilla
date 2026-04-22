"""Resume scan functionality for LeakGorilla"""

import json
import os
from datetime import datetime


def save_state(state_file, visited, queue, findings):
    """Save current scan state to file"""
    state = {
        'timestamp': datetime.now().isoformat(),
        'visited': list(visited),
        'queue': list(queue),
        'findings': [f.to_dict() for f in findings]
    }
    with open(state_file, 'w') as f:
        json.dump(state, f, indent=2)


def load_state(state_file):
    """Load previous scan state from file"""
    if not os.path.exists(state_file):
        print(f"[!] State file not found: {state_file}")
        return None, None, None

    try:
        with open(state_file, 'r') as f:
            state = json.load(f)

        visited = set(state.get('visited', []))
        queue = state.get('queue', [])
        findings_data = state.get('findings', [])

        print(f"[+] Resuming scan from {state['timestamp']}")
        print(f"[+] Already visited: {len(visited)} pages")
        print(f"[+] Remaining in queue: {len(queue)} pages")
        print(f"[+] Findings so far: {len(findings_data)}")

        return visited, queue, findings_data

    except Exception as e:
        print(f"[!] Error loading state: {str(e)}")
        return None, None, None


def clear_state(state_file):
    """Delete saved scan state"""
    if os.path.exists(state_file):
        os.remove(state_file)
        print(f"[+] State file cleared: {state_file}")
