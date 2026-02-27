"""Configuration and patterns for LeakGorilla scanner"""

# Scanner Configuration
OUTPUT_FILE = "web_secrets.txt"
REDACT_LENGTH = 4
MAX_PAGES = 50
TIMEOUT = 4
MAX_WORKERS = 10
# Delay is a range in seconds (min, max). Default 150-300ms
DELAY_MIN = 0.15
DELAY_MAX = 0.3
VERBOSE = False

# Severity levels for different secret types
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
    'Twilio API Key': 'MEDIUM',
    'SendGrid API Key': 'MEDIUM',
    'Mailgun API Key': 'MEDIUM',
    'JWT Token': 'MEDIUM',
    'OAuth Token': 'MEDIUM',
    'Google Cloud Service Account': 'HIGH',
    'Generic API Key': 'LOW',
    'Generic Secret': 'LOW'
}

# Regex patterns for detecting secrets
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
        r'EAA[a-zA-Z]{1}[0-9a-zA-Z]{8,}'
    ],
    'AWS Access Key': [
        r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'
    ],
    'AWS Secret Key': [
        r'(?i)aws[_\-]?secret[_\-]?access[_\-]?key[\s:=]+[\'"`]?([a-zA-Z0-9/+=]{40})[\'"`]?'
    ],
    'GitHub Token': [
        r'ghp_[a-zA-Z0-9]{36}',
        r'gho_[a-zA-Z0-9]{36}',
        r'ghu_[a-zA-Z0-9]{36}',
        r'ghs_[a-zA-Z0-9]{36}',
        r'ghr_[a-zA-Z0-9]{36}'
    ],
    'Stripe API Key': [
        r'(?:r|s)k_(?:live|test)_[0-9a-zA-Z]{24,}',
        r'pk_(?:live|test)_[0-9a-zA-Z]{24,}'
    ],
    'Slack Token': [
        r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}'
    ],
    'Twilio API Key': [
        r'SK[0-9a-fA-F]{32}'
    ],
    'SendGrid API Key': [
        r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}'
    ],
    'Mailgun API Key': [
        r'key-[0-9a-zA-Z]{32}'
    ],
    'JWT Token': [
        r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}'
    ],
    'OAuth Token': [
        r'\bya29\.[a-zA-Z0-9\-_]{100,}\b'
    ],
    'Database Connection String': [
        r'(?:mongodb|postgres|mysql|redis)://[^\s:]+:[^\s@]+@[a-z0-9\-\.]+:[0-9]+',
        r'Server=[^;]+;Database=[^;]+;User Id=[^;]+;Password=[^;]+'
    ],
    'Private Key': [
        r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'
    ],
    'Generic API Key': [
        r'(?i)(?:api|access)[_\-]?key[\s:=]+[\'"`]([a-zA-Z0-9_\-]{32,})[\'"`]',
        r'(?i)bearer\s+[a-zA-Z0-9_\-\.=]{32,}'
    ],
    'Generic Secret': [
        r'(?i)(?:secret|password|passwd|pwd)[\s:=]+[\'"`]([^\s\'"\`]{16,})[\'"`]'
    ]
}

# Whitelist patterns to reduce false positives (if a match fits a whitelist, ignore it)
WHITELIST = [
    r'^[A-Za-z0-9+/=]{40,}$',  # long base64 blobs (likely assets)
    r'^[0-9a-f]{32,}$',         # hex blobs often not secrets
    r'\.(jpg|jpeg|png|gif|svg)$',
    r'^data:image/.+',
]
