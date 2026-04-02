from ...models import VulnType, Severity

PATTERNS = [
    {
        'pattern': r'(strcpy|strcat|sprintf|vsprintf|gets|system|exec[lvep]|popen|mktemp|mkstemp|scanf|sscanf|memcpy|memset)',
        'description': 'Use of inherently unsafe C library functions (prone to overflows or injection).',
        'severity': Severity.HIGH,
        'confidence': 0.7
    },
    {
        'pattern': r'bcopy|bzero',
        'description': 'Older, deprecated memory manipulation functions suspected of misuse.',
        'severity': Severity.MEDIUM,
        'confidence': 0.6
    }
]
