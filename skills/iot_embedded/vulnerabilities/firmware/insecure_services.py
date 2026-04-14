from ...models import VulnType, Severity

PATTERNS = [
    {
        'pattern': r'(?i)(enable_telnet|telnetd_enable|start_telnet)\s*=\s*(true|1)',
        'description': 'Telnet service enabled by default (unencrypted management).',
        'severity': Severity.HIGH,
        'confidence': 0.9
    },
    {
        'pattern': r'(?i)(enable_ftp|ftpd_enable|start_ftp)\s*=\s*(true|1)',
        'description': 'FTP service enabled by default (unencrypted file transfer).',
        'severity': Severity.HIGH,
        'confidence': 0.9
    },
    {
        'pattern': r'(?i)listen\s*(port)?\s*(21|23|8080|80)',
        'description': 'Potential insecure or unauthenticated service listing on common ports.',
        'severity': Severity.MEDIUM,
        'confidence': 0.6
    }
]
