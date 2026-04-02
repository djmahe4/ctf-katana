from ...models import VulnType, Severity

PATTERNS = [
    {
        'pattern': r'(?i)(MD5|SHA1|DES|RC4|ECB|Blowfish|SHA-1)',
        'description': 'Use of deprecated or weak cryptographic algorithms.',
        'severity': Severity.HIGH,
        'confidence': 0.7
    },
    {
        'pattern': r'(md5_init|md5_update|md5_final|sha1_init|sha1_update|sha1_final)',
        'description': 'MD5/SHA1 hashing initialization detected.',
        'severity': Severity.HIGH,
        'confidence': 0.9
    }
]
