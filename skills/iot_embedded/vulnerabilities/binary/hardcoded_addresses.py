from ...models import VulnType, Severity

PATTERNS = [
    {
        'pattern': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
        'description': 'Hardcoded IPv4 address detected (potential C2 or fixed endpoint).',
        'severity': Severity.MEDIUM,
        'confidence': 0.6
    },
    {
        'pattern': r'(https?://[a-zA-Z0-9-._\+/~#?=&]+)',
        'description': 'Hardcoded URL endpoint found.',
        'severity': Severity.MEDIUM,
        'confidence': 0.8
    }
]
