from ...models import VulnType, Severity

PATTERNS = [
    {
        'pattern': r'%[spnx]',
        'description': 'Potential format string vulnerability (user-controlled format specifiers).',
        'severity': Severity.CRITICAL,
        'confidence': 0.6
    },
    {
        'pattern': r'%[0-9]*[xXpPsS]',
        'description': 'Repeated or numerically qualified format specifiers (exploitation indicator).',
        'severity': Severity.HIGH,
        'confidence': 0.75
    }
]
