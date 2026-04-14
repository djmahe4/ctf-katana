"""Integration tests for the script_writer skill (end-to-end pipeline).

All file I/O happens in temporary directories; all HTTP and browser calls are
mocked.  No real network traffic is generated.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from skills.script_writer.run import run


# ---------------------------------------------------------------------------
# Helpers / Fixtures
# ---------------------------------------------------------------------------

def _nuclei_line(**kwargs) -> str:
    """Return a nuclei JSONL line."""
    default = {
        "template-id": "exposed-admin",
        "type": "http",
        "info": {"severity": "high", "name": "Exposed Admin Panel", "description": ""},
        "matched-at": "http://target.com/admin",
    }
    default.update(kwargs)
    return json.dumps(default)


def _make_workspace(tmp_path: Path, *, include_nuclei: bool = True) -> str:
    (tmp_path / "alive.txt").write_text("http://target.com\nhttp://api.target.com\n")
    (tmp_path / "ports.txt").write_text("target.com:80\ntarget.com:443\n")
    if include_nuclei:
        (tmp_path / "nuclei.txt").write_text(
            _nuclei_line() + "\n"
            + "[sqli-error] [http] [critical] http://target.com/login\n"
        )
    return str(tmp_path)


# ---------------------------------------------------------------------------
# parse_recon action
# ---------------------------------------------------------------------------

class TestParseRecon:
    def test_parses_workspace(self, tmp_path: Path):
        ws = _make_workspace(tmp_path)
        result = run({"action": "parse_recon", "workspace": ws})
        assert result["status"] is True
        data = result["result"]["findings"]
        assert len(data["hosts"]) == 2
        assert len(data["vulnerabilities"]) == 2

    def test_empty_workspace(self, tmp_path: Path):
        result = run({"action": "parse_recon", "workspace": str(tmp_path)})
        assert result["status"] is True
        assert result["result"]["findings"]["hosts"] == []

    def test_missing_workspace(self):
        result = run({"action": "parse_recon", "workspace": "/nonexistent/path/xyz"})
        # Should still return status True with empty findings (no files = no data)
        assert result["status"] is True


# ---------------------------------------------------------------------------
# generate_report action
# ---------------------------------------------------------------------------

class TestGenerateReport:
    def test_generates_both_report_files(self, tmp_path: Path):
        ws = _make_workspace(tmp_path)
        reports_dir = str(tmp_path / "reports")
        result = run({
            "action": "generate_report",
            "workspace": ws,
            "reports_dir": reports_dir,
        })
        assert result["status"] is True
        paths = result["result"]["report_paths"]
        assert Path(paths["markdown"]).exists()
        assert Path(paths["json"]).exists()

    def test_report_with_supplied_findings(self, tmp_path: Path):
        findings = {
            "hosts": ["http://h1.com"],
            "vulnerabilities": [
                {"template": "lfi-test", "severity": "high",
                 "target": "http://h1.com/view?file=x",
                 "protocol": "http", "name": "LFI", "description": ""}
            ],
        }
        result = run({
            "action": "generate_report",
            "workspace": str(tmp_path),
            "reports_dir": str(tmp_path / "reports"),
            "findings": findings,
        })
        assert result["status"] is True
        md = Path(result["result"]["report_paths"]["markdown"]).read_text()
        assert "LFI" in md
        assert "A01:2021" in md

    def test_report_with_zero_findings(self, tmp_path: Path):
        result = run({
            "action": "generate_report",
            "workspace": str(tmp_path),
            "reports_dir": str(tmp_path / "reports"),
            "findings": {"hosts": [], "vulnerabilities": []},
        })
        assert result["status"] is True
        assert result["result"]["findings_count"] == 0

    def test_report_owasp_ssrf_classified(self, tmp_path: Path):
        findings = {
            "hosts": [],
            "vulnerabilities": [
                {"template": "ssrf", "severity": "high",
                 "target": "http://h.com/?url=x",
                 "protocol": "http", "name": "SSRF", "description": ""}
            ],
        }
        result = run({
            "action": "generate_report",
            "workspace": str(tmp_path),
            "reports_dir": str(tmp_path / "reports"),
            "findings": findings,
        })
        md = Path(result["result"]["report_paths"]["markdown"]).read_text()
        assert "A10:2021" in md


# ---------------------------------------------------------------------------
# write_tamper action
# ---------------------------------------------------------------------------

class TestWriteTamper:
    def test_writes_tamper_script(self, tmp_path: Path):
        result = run({
            "action": "write_tamper",
            "tamper_name": "space2hash",
            "tamper_logic": "payload = payload.replace(' ', '#')",
            "tamper_description": "Replace space with hash",
            "tamper_dir": str(tmp_path),
            "tamper_fallback_dir": str(tmp_path),
        })
        assert result["status"] is True
        assert Path(result["result"]["tamper_path"]).exists()

    def test_missing_tamper_name(self):
        result = run({
            "action": "write_tamper",
            "tamper_logic": "pass",
        })
        assert result["status"] is False
        assert "tamper_name" in result["summary"]

    def test_missing_tamper_logic(self):
        result = run({
            "action": "write_tamper",
            "tamper_name": "test",
        })
        assert result["status"] is False
        assert "tamper_logic" in result["summary"]

    def test_invalid_tamper_logic(self, tmp_path: Path):
        result = run({
            "action": "write_tamper",
            "tamper_name": "invalid",
            "tamper_logic": "def (",  # syntax error
            "tamper_dir": str(tmp_path),
            "tamper_fallback_dir": str(tmp_path),
        })
        assert result["status"] is False
        assert "tamper_logic" in result["summary"].lower()

    def test_tamper_content_includes_description(self, tmp_path: Path):
        result = run({
            "action": "write_tamper",
            "tamper_name": "my_bypass",
            "tamper_logic": "pass",
            "tamper_description": "Custom Cloudflare bypass",
            "tamper_dir": str(tmp_path),
            "tamper_fallback_dir": str(tmp_path),
        })
        content = Path(result["result"]["tamper_path"]).read_text()
        assert "Cloudflare" in content


# ---------------------------------------------------------------------------
# analyze_js action
# ---------------------------------------------------------------------------

class TestAnalyzeJs:
    def test_missing_target_returns_error(self):
        result = run({"action": "analyze_js", "js_content": "const x = 1;"})
        assert result["status"] is False
        assert "target" in result["summary"]

    def test_missing_js_content_returns_error(self):
        result = run({"action": "analyze_js", "target": "http://example.com"})
        assert result["status"] is False
        assert "js_content" in result["summary"]

    @patch("skills.script_writer.wrappers.js_analyzer.requests.Session.head")
    def test_finds_endpoints_and_secrets(self, mock_head):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_head.return_value = mock_resp

        js = 'fetch("/api/v1/data"); const api_key = "SuperSecretKey123";'
        result = run({
            "action": "analyze_js",
            "target": "http://example.com",
            "js_content": js,
        })
        assert result["status"] is True
        endpoints = result["result"]["endpoints"]
        assert any("/api/v1/data" in ep["url"] for ep in endpoints)
        secrets = result["result"]["secrets"]
        assert len(secrets) == 1

    @patch("skills.script_writer.wrappers.js_analyzer.requests.Session.head")
    def test_empty_js_content(self, mock_head):
        result = run({
            "action": "analyze_js",
            "target": "http://example.com",
            "js_content": "  ",  # whitespace only
        })
        assert result["status"] is False


# ---------------------------------------------------------------------------
# validate_oob action
# ---------------------------------------------------------------------------

class TestValidateOob:
    def test_missing_params_returns_error(self):
        result = run({"action": "validate_oob"})
        assert result["status"] is False
        assert "interactsh_url" in result["summary"]

    def test_partially_missing_params(self):
        result = run({
            "action": "validate_oob",
            "interactsh_url": "oast.pro",
            # missing token and correlation_id
        })
        assert result["status"] is False

    @patch("skills.script_writer.wrappers.oob_validator.OOBValidator.poll_sync", return_value=True)
    def test_ssrf_confirmed(self, mock_poll):
        result = run({
            "action": "validate_oob",
            "interactsh_url": "oast.pro",
            "interactsh_token": "mytoken",
            "correlation_id": "abc123",
        })
        assert result["status"] is True
        assert result["result"]["ssrf_confirmed"] is True
        assert "confirmed" in result["summary"].lower()

    @patch("skills.script_writer.wrappers.oob_validator.OOBValidator.poll_sync", return_value=False)
    def test_ssrf_not_confirmed(self, mock_poll):
        result = run({
            "action": "validate_oob",
            "interactsh_url": "oast.pro",
            "interactsh_token": "mytoken",
            "correlation_id": "abc123",
        })
        assert result["status"] is True
        assert result["result"]["ssrf_confirmed"] is False


# ---------------------------------------------------------------------------
# full_pipeline action
# ---------------------------------------------------------------------------

class TestFullPipeline:
    def test_full_pipeline(self, tmp_path: Path):
        ws = _make_workspace(tmp_path)
        reports_dir = str(tmp_path / "reports")
        result = run({
            "action": "full_pipeline",
            "workspace": ws,
            "reports_dir": reports_dir,
        })
        assert result["status"] is True
        assert "pipeline_log" in result["result"]
        assert len(result["result"]["pipeline_log"]) >= 2
        paths = result["result"].get("report_paths", {})
        assert Path(paths.get("markdown", "/nonexistent")).exists()

    def test_full_pipeline_empty_workspace(self, tmp_path: Path):
        result = run({
            "action": "full_pipeline",
            "workspace": str(tmp_path),
            "reports_dir": str(tmp_path / "reports"),
        })
        assert result["status"] is True


# ---------------------------------------------------------------------------
# run() entry-point edge cases
# ---------------------------------------------------------------------------

class TestRunEntryPoint:
    def test_unknown_action(self):
        result = run({"action": "nonexistent_action"})
        assert result["status"] is False
        assert "available_actions" in result["result"]

    def test_default_action_is_generate_report(self, tmp_path: Path):
        result = run({
            "workspace": str(tmp_path),
            "reports_dir": str(tmp_path / "reports"),
        })
        assert result["status"] is True

    def test_exception_in_action_handled(self, tmp_path: Path):
        with patch(
            "skills.script_writer.run._action_generate_report",
            side_effect=RuntimeError("unexpected failure"),
        ):
            result = run({
                "action": "generate_report",
                "workspace": str(tmp_path),
            })
        assert result["status"] is False
        assert "unexpected failure" in result["summary"]
