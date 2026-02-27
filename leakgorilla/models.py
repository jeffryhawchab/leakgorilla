"""Data models for LeakGorilla"""

from datetime import datetime
from .config import SEVERITY


class SecretFinding:
    """Represents a discovered secret in scanned content"""
    
    def __init__(self, url, source, matched_string, secret_type, context=''):
        self.url = url
        self.source = source
        self.matched_string = matched_string
        self.secret_type = secret_type
        self.context = context
        self.timestamp = datetime.now()
        self.severity = SEVERITY.get(secret_type, 'LOW')
    
    def to_dict(self):
        """Convert finding to dictionary for JSON export"""
        return {
            'url': self.url,
            'source': self.source,
            'type': self.secret_type,
            'severity': self.severity,
            'secret': self.matched_string,
            'context': self.context,
            'timestamp': self.timestamp.isoformat()
        }
