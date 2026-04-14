from ...models import VulnType, Severity

PATTERNS = [
    {
        'pattern': r'(?i)(password|passwd|pass|pwd|secret|key|api_key|token)\s*[=:]\s*[\'\"]?([a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};\':\"\\\\|,.<>\\/?]{8,64})[\'\"]?',
        'description': 'Potential plaintext password or API key found in configuration or code.',
        'severity': Severity.CRITICAL,
        'confidence': 0.85
    },
    {
        'pattern': r'-----BEGIN (RSA|OPENSSH|EC) PRIVATE KEY-----',
        'description': 'Hardcoded private cryptographic key found.',
        'severity': Severity.CRITICAL,
        'confidence': 1.0
    },
    {
        'pattern': r'(?i)(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AZURE_CLIENT_SECRET|GOOGLE_API_KEY|STRIPE_API_KEY)\s*=\s*[\'\"]?([a-zA-Z0-9\/\+=]{20,})[\'\"]?',
        'description': 'Hardcoded cloud service credentials detected.',
        'severity': Severity.CRITICAL,
        'confidence': 0.95
    }
]
