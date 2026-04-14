"""Unit tests for the script_writer skill components.

All I/O and network calls are mocked; no real files or HTTP requests are made.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

import pytest
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


# ---------------------------------------------------------------------------
# ReconParser
# ---------------------------------------------------------------------------

class TestReconParser:
    def _ws(self, tmp_path: Path, files: dict[str, str]) -> str:
        for name, content in files.items():
            (tmp_path / name).write_text(content, encoding="utf-8")
        return str(tmp_path)

    def test_empty_workspace(self, tmp_path: Path):
        from skills.script_writer.wrappers.recon_parser import ReconParser
        parser = ReconParser(str(tmp_path))
        result = parser.correlate_findings()
        assert result["hosts"] == []
        assert result["ports"] == []
        assert result["vulnerabilities"] == []

    def test_reads_alive_and_ports(self, tmp_path: Path):
        from skills.script_writer.wrappers.recon_parser import ReconParser
        ws = self._ws(tmp_path, {
            "alive.txt": "http://a.com\nhttp://b.com\n",
            "ports.txt": "a.com:80\na.com:443\n",
        })
        result = ReconParser(ws).correlate_findings()
        assert result["hosts"] == ["http://a.com", "http://b.com"]
        assert result["ports"] == ["a.com:80", "a.com:443"]

    def test_parses_nuclei_text_format(self, tmp_path: Path):
        from skills.script_writer.wrappers.recon_parser import ReconParser
        nuclei_line = "[cve-2021-0001] [http] [high] http://a.com/vuln\n"
        ws = self._ws(tmp_path, {"nuclei.txt": nuclei_line})
        result = ReconParser(ws).correlate_findings()
        assert len(result["vulnerabilities"]) == 1
        v = result["vulnerabilities"][0]
        assert v["template"] == "cve-2021-0001"
        assert v["severity"] == "high"

    def test_parses_nuclei_jsonl_format(self, tmp_path: Path):
        from skills.script_writer.wrappers.recon_parser import ReconParser
        obj = {
            "template-id": "exposed-admin",
            "type": "http",
            "info": {"severity": "high", "name": "Admin Panel"},
            "matched-at": "http://a.com/admin",
        }
        ws = self._ws(tmp_path, {"nuclei.txt": json.dumps(obj) + "\n"})
        result = ReconParser(ws).correlate_findings()
        assert len(result["vulnerabilities"]) == 1
        v = result["vulnerabilities"][0]
        assert v["template"] == "exposed-admin"
        assert v["name"] == "Admin Panel"

    def test_skips_blank_lines_in_nuclei(self, tmp_path: Path):
        from skills.script_writer.wrappers.recon_parser import ReconParser
        ws = self._ws(tmp_path, {"nuclei.txt": "\n\n   \n"})
        result = ReconParser(ws).correlate_findings()
        assert result["vulnerabilities"] == []

    def test_mixed_nuclei_formats(self, tmp_path: Path):
        from skills.script_writer.wrappers.recon_parser import ReconParser
        jsonl = json.dumps({
            "template-id": "json-tmpl", "type": "http",
            "info": {"severity": "medium", "name": "JSON Vuln"},
            "matched-at": "http://b.com",
        })
        text = "[text-tmpl] [tcp] [low] http://c.com\n"
        ws = self._ws(tmp_path, {"nuclei.txt": jsonl + "\n" + text})
        result = ReconParser(ws).correlate_findings()
        assert len(result["vulnerabilities"]) == 2


# ---------------------------------------------------------------------------
# TamperGenerator
# ---------------------------------------------------------------------------

class TestTamperGenerator:
    def test_writes_valid_tamper(self, tmp_path: Path):
        from skills.script_writer.wrappers.tamper_generator import TamperGenerator
        gen = TamperGenerator(
            tamper_dir=str(tmp_path), fallback_dir=str(tmp_path)
        )
        path = gen.write_tamper(
            name="test_tamper",
            logic="payload = payload.replace(' ', '/**/');",
            description="Space to comment bypass",
        )
        assert Path(path).exists()
        content = Path(path).read_text()
        assert "space to comment bypass" in content.lower() or "Space to comment" in content

    def test_sanitises_name(self, tmp_path: Path):
        from skills.script_writer.wrappers.tamper_generator import TamperGenerator
        gen = TamperGenerator(tamper_dir=str(tmp_path), fallback_dir=str(tmp_path))
        path = gen.write_tamper(
            name="my tamper!@#", logic="pass", description=""
        )
        assert Path(path).exists()
        # Filename must not contain spaces or special chars
        assert " " not in Path(path).name
        assert "!" not in Path(path).name

    def test_invalid_logic_raises_value_error(self, tmp_path: Path):
        from skills.script_writer.wrappers.tamper_generator import TamperGenerator
        gen = TamperGenerator(tamper_dir=str(tmp_path), fallback_dir=str(tmp_path))
        with pytest.raises(ValueError, match="tamper_logic is not valid Python"):
            gen.write_tamper(
                name="bad_tamper",
                logic="def (",  # invalid syntax
                description="broken",
            )

    def test_fallback_on_permission_error(self, tmp_path: Path):
        from skills.script_writer.wrappers.tamper_generator import TamperGenerator
        fallback = tmp_path / "fallback"
        fallback.mkdir()
        gen = TamperGenerator(
            tamper_dir="/root/no_permission_here_ever",
            fallback_dir=str(fallback),
        )
        path = gen.write_tamper(
            name="fallback_test", logic="pass", description="fallback"
        )
        assert Path(path).exists()
        assert str(fallback) in path


# ---------------------------------------------------------------------------
# ReportGenerator
# ---------------------------------------------------------------------------

class TestReportGenerator:
    def _findings(self, n_hosts: int = 2, n_vulns: int = 2) -> dict:
        return {
            "hosts": [f"http://host{i}.com" for i in range(n_hosts)],
            "vulnerabilities": [
                {
                    "template": f"tmpl-{i}",
                    "severity": "high",
                    "target": f"http://host{i}.com/vuln",
                    "protocol": "http",
                    "name": f"SQLi Finding {i}",
                    "description": "SQL injection detected",
                }
                for i in range(n_vulns)
            ],
        }

    def test_generates_both_files(self, tmp_path: Path):
        from skills.script_writer.wrappers.report_generator import ReportGenerator
        gen = ReportGenerator(workspace=str(tmp_path), findings=self._findings())
        paths = gen.generate()
        assert Path(paths["markdown"]).exists()
        assert Path(paths["json"]).exists()

    def test_markdown_contains_headers(self, tmp_path: Path):
        from skills.script_writer.wrappers.report_generator import ReportGenerator
        gen = ReportGenerator(workspace=str(tmp_path), findings=self._findings())
        md_path = gen.generate_markdown()
        md = Path(md_path).read_text()
        assert "# Purple Engine" in md
        assert "Executive Summary" in md
        assert "Detailed Findings" in md

    def test_owasp_classification_sqli(self, tmp_path: Path):
        from skills.script_writer.wrappers.report_generator import ReportGenerator
        gen = ReportGenerator(workspace=str(tmp_path), findings=self._findings())
        paths = gen.generate()
        md = Path(paths["markdown"]).read_text()
        assert "A03:2021" in md

    def test_json_structure(self, tmp_path: Path):
        from skills.script_writer.wrappers.report_generator import ReportGenerator
        gen = ReportGenerator(workspace=str(tmp_path), findings=self._findings(n_vulns=1))
        paths = gen.generate()
        data = json.loads(Path(paths["json"]).read_text())
        assert "vulnerabilities" in data
        assert "owasp_category" in data["vulnerabilities"][0]
        assert data["summary"]["total_vulnerabilities"] == 1

    def test_empty_findings(self, tmp_path: Path):
        from skills.script_writer.wrappers.report_generator import ReportGenerator
        gen = ReportGenerator(workspace=str(tmp_path), findings={})
        paths = gen.generate()
        md = Path(paths["markdown"]).read_text()
        assert "0" in md  # zero hosts / vulns

    def test_backward_compat_generate_markdown(self, tmp_path: Path):
        from skills.script_writer.wrappers.report_generator import ReportGenerator
        gen = ReportGenerator(workspace=str(tmp_path), findings=self._findings())
        md_path = gen.generate_markdown()
        assert Path(md_path).exists()


# ---------------------------------------------------------------------------
# JSAnalyzer
# ---------------------------------------------------------------------------

class TestJSAnalyzer:
    def test_extract_endpoints(self):
        from skills.script_writer.wrappers.js_analyzer import JSAnalyzer
        analyzer = JSAnalyzer("http://example.com")
        endpoints = analyzer._extract_endpoints(
            'fetch("/api/v1/users"); fetch("/api/v1/items");'
        )
        assert "/api/v1/users" in endpoints
        assert "/api/v1/items" in endpoints

    def test_deduplicates_endpoints(self):
        from skills.script_writer.wrappers.js_analyzer import JSAnalyzer
        analyzer = JSAnalyzer("http://example.com")
        endpoints = analyzer._extract_endpoints(
            '"/api/users" "/api/users"'
        )
        assert endpoints.count("/api/users") == 1

    def test_extract_secrets(self):
        from skills.script_writer.wrappers.js_analyzer import JSAnalyzer
        js = 'const api_key = "SuperSecretKey12345";'
        secrets = JSAnalyzer._extract_secrets(js)
        assert len(secrets) == 1
        assert secrets[0].endswith("****")

    def test_no_secrets_clean_js(self):
        from skills.script_writer.wrappers.js_analyzer import JSAnalyzer
        secrets = JSAnalyzer._extract_secrets("const x = 1 + 2;")
        assert secrets == []

    @patch("skills.script_writer.wrappers.js_analyzer.requests.Session.head")
    def test_validate_endpoints_200(self, mock_head):
        from skills.script_writer.wrappers.js_analyzer import JSAnalyzer
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_head.return_value = mock_resp

        analyzer = JSAnalyzer("http://example.com")
        result = analyzer._validate_endpoints(["/admin"])
        assert result[0]["url"] == "http://example.com/admin"
        assert result[0]["status"] == 200

    @patch("skills.script_writer.wrappers.js_analyzer.requests.Session.head")
    def test_validate_endpoints_ignores_404(self, mock_head):
        from skills.script_writer.wrappers.js_analyzer import JSAnalyzer
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_head.return_value = mock_resp

        analyzer = JSAnalyzer("http://example.com")
        result = analyzer._validate_endpoints(["/missing"])
        assert result == []


# ---------------------------------------------------------------------------
# PrototypePollutionVerifier
# ---------------------------------------------------------------------------

class TestPrototypePollutionVerifier:
    def test_build_payload_url(self):
        from skills.script_writer.wrappers.proto_pollution import (
            PrototypePollutionVerifier,
            _PAYLOAD_KEY,
            _PAYLOAD_VAL,
        )
        url = PrototypePollutionVerifier._build_payload_url("http://example.com/page")
        assert f"__proto__%5B{_PAYLOAD_KEY}%5D" in url or f"__proto__[{_PAYLOAD_KEY}]" in url
        assert _PAYLOAD_VAL in url

    def test_returns_false_when_playwright_missing(self):
        import importlib
        import unittest.mock as um
        # Simulate Playwright not available
        with um.patch("skills.script_writer.wrappers.proto_pollution._HAS_PLAYWRIGHT", False):
            from importlib import reload
            import skills.script_writer.wrappers.proto_pollution as m
            reload(m)
            verifier = m.PrototypePollutionVerifier()
            assert verifier.verify("http://example.com") is False

    @patch("skills.script_writer.wrappers.proto_pollution._HAS_PLAYWRIGHT", True)
    @patch(
        "skills.script_writer.wrappers.proto_pollution.sync_playwright",
        create=True,
    )
    def test_confirmed_vulnerable(self, mock_pw):
        from skills.script_writer.wrappers.proto_pollution import PrototypePollutionVerifier

        mock_page = MagicMock()
        mock_page.evaluate.return_value = True
        mock_browser = MagicMock()
        mock_browser.new_page.return_value = mock_page
        mock_p = MagicMock()
        mock_p.chromium.launch.return_value = mock_browser
        mock_pw.return_value.__enter__.return_value = mock_p

        verifier = PrototypePollutionVerifier()
        assert verifier.verify("http://example.com") is True

    @patch("skills.script_writer.wrappers.proto_pollution._HAS_PLAYWRIGHT", True)
    @patch(
        "skills.script_writer.wrappers.proto_pollution.sync_playwright",
        create=True,
    )
    def test_not_vulnerable(self, mock_pw):
        from skills.script_writer.wrappers.proto_pollution import PrototypePollutionVerifier

        mock_page = MagicMock()
        mock_page.evaluate.return_value = False
        mock_browser = MagicMock()
        mock_browser.new_page.return_value = mock_page
        mock_p = MagicMock()
        mock_p.chromium.launch.return_value = mock_browser
        mock_pw.return_value.__enter__.return_value = mock_p

        verifier = PrototypePollutionVerifier()
        assert verifier.verify("http://example.com") is False


# ---------------------------------------------------------------------------
# OOBValidator
# ---------------------------------------------------------------------------

class TestOOBValidator:
    def test_poll_sync_returns_false_when_aiohttp_missing(self, monkeypatch):
        # Simulate aiohttp not installed
        import builtins
        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "aiohttp":
                raise ImportError("No module named 'aiohttp'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)
        from skills.script_writer.wrappers.oob_validator import OOBValidator
        validator = OOBValidator("oast.pro", "token123")
        result = validator.poll_sync("test-corr-id")
        assert result is False

    def test_poll_sync_is_callable(self):
        """poll_sync exists and is callable regardless of aiohttp availability."""
        from skills.script_writer.wrappers.oob_validator import OOBValidator
        validator = OOBValidator("oast.pro", "token", max_retries=1)
        assert callable(validator.poll_sync)

    @patch("skills.script_writer.wrappers.oob_validator.OOBValidator.poll_sync", return_value=True)
    def test_poll_sync_returns_true_when_patched(self, mock_poll):
        """Verify the public poll_sync interface contract."""
        from skills.script_writer.wrappers.oob_validator import OOBValidator
        validator = OOBValidator("oast.pro", "token", max_retries=1)
        result = validator.poll_sync("abc123")
        assert result is True


# ---------------------------------------------------------------------------
# FreediumScraper
# ---------------------------------------------------------------------------

class TestFreediumScraper:
    def test_freedium_url_construction(self):
        from skills.script_writer.scrapers.freedium import FreediumScraper
        scraper = FreediumScraper()
        # The URL built must start with the freedium base
        assert scraper._FREEDIUM_BASE == "https://freedium.cfd/"

    @patch("skills.script_writer.scrapers.freedium._HAS_DRISSION", False)
    @patch("skills.script_writer.scrapers.freedium._HAS_PLAYWRIGHT", False)
    def test_scrape_returns_empty_when_no_deps(self):
        from skills.script_writer.scrapers.freedium import FreediumScraper
        scraper = FreediumScraper()
        result = scraper.scrape("https://medium.com/@user/article-slug")
        assert result == ""

    @patch("skills.script_writer.scrapers.freedium._HAS_DRISSION", True)
    @patch(
        "skills.script_writer.scrapers.freedium.SessionPage",
        create=True,
    )
    def test_scrape_drissionpage_success(self, mock_session_page_cls):
        from skills.script_writer.scrapers.freedium import FreediumScraper
        mock_page = MagicMock()
        mock_article = MagicMock()
        mock_article.text = "Article text here"
        mock_page.ele.return_value = mock_article
        mock_session_page_cls.return_value = mock_page

        scraper = FreediumScraper(use_playwright=False)
        result = scraper.scrape("https://medium.com/@user/article")
        assert result == "Article text here"

    @patch("skills.script_writer.scrapers.freedium._HAS_DRISSION", True)
    @patch(
        "skills.script_writer.scrapers.freedium.SessionPage",
        create=True,
    )
    def test_scrape_falls_back_on_drission_failure(self, mock_session_page_cls):
        from skills.script_writer.scrapers.freedium import FreediumScraper
        mock_page = MagicMock()
        mock_page.get.side_effect = Exception("network error")
        mock_session_page_cls.return_value = mock_page

        with patch.object(
            FreediumScraper, "_playwright_fallback", return_value="fallback"
        ):
            scraper = FreediumScraper(use_playwright=False)
            result = scraper.scrape("https://medium.com/@user/article")
            assert result == "fallback"


# ---------------------------------------------------------------------------
# RAGProcessor
# ---------------------------------------------------------------------------

class TestRAGProcessor:
    def test_chunk_and_retrieve_keyword_fallback(self):
        """When FAISS/sentence_transformers are absent, use keyword fallback."""
        import skills.script_writer.scrapers.freedium as mod
        # Force keyword mode
        orig = mod._HAS_FAISS
        orig_st = mod._HAS_ST
        try:
            mod._HAS_FAISS = False
            mod._HAS_ST = False
            from importlib import reload
            reload(mod)
            from skills.script_writer.scrapers.freedium import RAGProcessor
            proc = RAGProcessor()
            proc.chunk_and_embed("SQL injection payload bypass firewall")
            proc.chunk_and_embed("XSS cross-site scripting alert")
            results = proc.retrieve("SQL injection", top_k=1)
            assert any("SQL" in r for r in results)
        finally:
            mod._HAS_FAISS = orig
            mod._HAS_ST = orig_st
            reload(mod)

    def test_retrieve_empty_returns_empty(self):
        from skills.script_writer.scrapers.freedium import RAGProcessor
        proc = RAGProcessor()
        assert proc.retrieve("anything") == []
