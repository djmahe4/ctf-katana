import logging
import random
import time
from typing import Dict, List, Any, Optional, Generator
from urllib.parse import urlparse, urlencode, parse_qs
from pathlib import Path
from datetime import datetime

from skills.fuzzing.models import FuzzRunResult, FuzzCategory, FuzzFinding, FuzzerSeverity
from skills.fuzzing.base import FuzzerHandlerBase

logger = logging.getLogger(__name__)

# Constants migrated from run.py
PAYLOADS = {
    "generic": ["admin", "login", "dashboard", "api", "config", "backup", "uploads", ".git", ".env", "robots.txt"],
    "sqli": ["' OR 1=1--", "' UNION SELECT NULL--", "admin'--"],
    "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
    "lfi": ["../etc/passwd", "/proc/self/environ", "php://filter/convert.base64-encode/resource=index.php"],
    "rce": ["; id", "| id", "$(id)", "{{7*7}}"],
    "ssti": ["{{7*7}}", "${7*7}", "{{config}}"]
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
]

class WebHandler(FuzzerHandlerBase):
    """Handler for intelligent Web Fuzzing."""

    def analyze(self, target: str, **kwargs) -> FuzzRunResult:
        return self.fuzz(target, **kwargs)

    def fuzz(self, target: str, **kwargs) -> FuzzRunResult:
        mode = kwargs.get('mode', 'directory')
        payload_type = kwargs.get('payload_type', 'generic')
        wordlist = kwargs.get('wordlist')
        max_requests = kwargs.get('max_requests', 100)
        rate_limit = kwargs.get('rate_limit', 0.0)
        timeout = kwargs.get('timeout', 10)

        result = self.create_empty_result(FuzzCategory.WEB, target)
        session = self._get_requests_session()
        
        payload_gen = self._get_payloads(payload_type, wordlist)
        baseline = None
        
        count = 0
        for payload in payload_gen:
            if count >= max_requests:
                break
            
            try:
                url = self._build_url(target, payload, mode)
                headers = {'User-Agent': random.choice(USER_AGENTS)}
                
                start_time = time.time()
                response = session.get(url, headers=headers, timeout=timeout, allow_redirects=False)
                elapsed = time.time() - start_time
                
                if baseline is None:
                    baseline = {'status_code': response.status_code, 'content_length': len(response.text)}

                analysis = self._analyze_response(response, payload, elapsed, baseline)
                if analysis:
                    result.findings.append(analysis)
                
                count += 1
                if rate_limit > 0:
                    time.sleep(rate_limit)

            except Exception as e:
                logger.debug(f"Request error for {payload}: {e}")
            
        result.statistics = {
            "total_requests": count,
            "findings_count": len(result.findings)
        }
        result.summary = f"Web fuzzing complete. Probed {count} paths, found {len(result.findings)} interesting responses."
        return result

    def _get_payloads(self, payload_type: str, wordlist: Optional[str]) -> Generator[str, None, None]:
        if wordlist and Path(wordlist).exists():
            with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if line.strip() and not line.startswith('#'):
                        yield line.strip()
        else:
            for p in PAYLOADS.get(payload_type, PAYLOADS['generic']):
                yield p

    def _build_url(self, target: str, payload: str, mode: str) -> str:
        if 'FUZZ' in target:
            return target.replace('FUZZ', payload)
        if mode == 'directory':
            return f"{target.rstrip('/')}/{payload}"
        elif mode == 'parameter':
            parsed = urlparse(target)
            params = parse_qs(parsed.query)
            if params:
                first_key = list(params.keys())[0]
                params[first_key] = [payload]
                return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"
        return f"{target.rstrip('/')}/{payload}"

    def _analyze_response(self, response, payload: str, elapsed: float, baseline: Dict[str, Any]) -> Optional[FuzzFinding]:
        interesting = False
        reasons = []
        
        if response.status_code != baseline['status_code'] and response.status_code in [200, 201, 301, 302, 403]:
            interesting = True
            reasons.append(f"Status changed to {response.status_code}")
            
        size_diff = abs(len(response.text) - baseline['content_length'])
        if size_diff > 100:
            interesting = True
            reasons.append(f"Size diff: {size_diff}")
            
        if payload in response.text:
            interesting = True
            reasons.append("Payload reflected")

        if elapsed > 5:
            interesting = True
            reasons.append(f"Slow response: {elapsed:.2f}s")

        if interesting:
            return FuzzFinding(
                vulnerability_id="web_discovery",
                description=f"Interesting response for payload: {payload}",
                severity=FuzzerSeverity.MEDIUM if response.status_code == 200 else FuzzerSeverity.INFO,
                payload=payload,
                evidence=f"Status: {response.status_code}, Length: {len(response.text)}, Logic: {'; '.join(reasons)}",
                metadata={"url": str(response.url), "reasons": reasons}
            )
        return None
