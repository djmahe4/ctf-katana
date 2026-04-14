"""Unit tests for the bug_hunting skill (skills/bug_hunting/run.py).

All subprocess calls and KnowledgeBase interactions are mocked so that these
tests run offline without any external tools installed.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure the project root is on sys.path regardless of how pytest is invoked.
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from skills.bug_hunting.run import (
    BugHuntingSkill,
    Finding,
    HuntResult,
    Severity,
    _VULN_META,
    run,
    step_analyze,
    step_interpret,
    step_report,
    step_search_kb,
    step_subdomain_enum,
    step_url_collect,
    step_vuln_scan,
)


# ---------------------------------------------------------------------------
# step_analyze
# ---------------------------------------------------------------------------

class TestStepAnalyze:
    def test_bare_domain(self):
        result = step_analyze("example.com")
        assert result["domain"] == "example.com"
        assert result["is_url"] is False

    def test_https_url(self):
        result = step_analyze("https://sub.example.com/path?q=1")
        assert result["domain"] == "sub.example.com"
        assert result["is_url"] is True

    def test_http_url(self):
        result = step_analyze("http://target.local:8080")
        assert result["domain"] == "target.local"
        assert result["is_url"] is True
        assert result["has_explicit_port"] is True

    def test_raw_target_preserved(self):
        target = "ctf-box.hack.me"
        result = step_analyze(target)
        assert result["raw_target"] == target


# ---------------------------------------------------------------------------
# step_search_kb
# ---------------------------------------------------------------------------

class TestStepSearchKb:
    def test_returns_empty_when_no_kb(self):
        """Should return an empty list if KnowledgeBase cannot be initialised."""
        snippets = step_search_kb("example.com", kb=None)
        assert isinstance(snippets, list)

    def test_returns_snippets_from_mock_kb(self):
        mock_result = MagicMock()
        mock_result.content = "Some relevant KB snippet"
        mock_kb = MagicMock()
        mock_kb.search.return_value = [mock_result]

        snippets = step_search_kb("example.com", kb=mock_kb)
        assert snippets == ["Some relevant KB snippet"]
        mock_kb.search.assert_called_once_with("example.com", top_k=3)

    def test_returns_empty_on_kb_exception(self):
        mock_kb = MagicMock()
        mock_kb.search.side_effect = RuntimeError("KB offline")
        snippets = step_search_kb("example.com", kb=mock_kb)
        assert snippets == []


# ---------------------------------------------------------------------------
# step_subdomain_enum
# ---------------------------------------------------------------------------

class TestStepSubdomainEnum:
    @patch("skills.bug_hunting.run._run_cmd")
    def test_returns_subfinder_output(self, mock_run):
        mock_run.return_value = (0, "api.example.com\ndev.example.com\n", "")
        subs = step_subdomain_enum("example.com")
        assert set(subs) == {"api.example.com", "dev.example.com"}

    @patch("skills.bug_hunting.run._run_cmd")
    def test_falls_back_to_domain_when_empty(self, mock_run):
        mock_run.return_value = (0, "", "")
        subs = step_subdomain_enum("example.com")
        assert subs == ["example.com"]

    @patch("skills.bug_hunting.run._run_cmd")
    def test_subfinder_not_installed(self, mock_run):
        mock_run.side_effect = FileNotFoundError("subfinder not found")
        subs = step_subdomain_enum("example.com")
        assert subs == ["example.com"]

    @patch("skills.bug_hunting.run._run_cmd")
    def test_deep_depth_adds_all_flag(self, mock_run):
        mock_run.return_value = (0, "a.example.com\n", "")
        step_subdomain_enum("example.com", depth="deep")
        cmd = mock_run.call_args[0][0]
        assert "-all" in cmd


# ---------------------------------------------------------------------------
# step_url_collect
# ---------------------------------------------------------------------------

class TestStepUrlCollect:
    @patch("skills.bug_hunting.run._run_cmd")
    def test_returns_katana_urls(self, mock_run):
        mock_run.return_value = (
            0,
            "http://example.com/login\nhttp://example.com/api/v1/users\n",
            "",
        )
        urls = step_url_collect(["http://example.com"])
        assert "http://example.com/login" in urls

    @patch("skills.bug_hunting.run._run_cmd")
    def test_deduplicates_urls(self, mock_run):
        mock_run.return_value = (
            0,
            "http://example.com/page\nhttp://example.com/page\n",
            "",
        )
        urls = step_url_collect(["http://example.com"])
        assert urls.count("http://example.com/page") == 1

    @patch("skills.bug_hunting.run._run_cmd")
    def test_katana_not_installed_falls_back(self, mock_run):
        mock_run.side_effect = FileNotFoundError("katana not found")
        urls = step_url_collect(["http://example.com"])
        assert urls == ["http://example.com"]


# ---------------------------------------------------------------------------
# step_vuln_scan (heuristic URL analysis)
# ---------------------------------------------------------------------------

class TestStepVulnScan:
    @patch("skills.bug_hunting.run._run_cmd")
    def test_lfi_param_detected(self, mock_run):
        mock_run.side_effect = FileNotFoundError("nuclei")
        urls = ["http://target.com/view?file=/etc/passwd"]
        findings = step_vuln_scan(urls, ["http://target.com"])
        ids = [f.vuln_id for f in findings]
        assert "lfi-param-detected" in ids

    @patch("skills.bug_hunting.run._run_cmd")
    def test_open_redirect_param_detected(self, mock_run):
        mock_run.side_effect = FileNotFoundError("nuclei")
        urls = ["http://target.com/go?redirect=http://evil.com"]
        findings = step_vuln_scan(urls, ["http://target.com"])
        ids = [f.vuln_id for f in findings]
        assert "open-redirect-param-detected" in ids

    @patch("skills.bug_hunting.run._run_cmd")
    def test_clean_url_no_findings(self, mock_run):
        mock_run.side_effect = FileNotFoundError("nuclei")
        urls = ["http://target.com/about", "http://target.com/contact"]
        findings = step_vuln_scan(urls, ["http://target.com"])
        assert findings == []

    @patch("skills.bug_hunting.run._run_cmd")
    def test_nuclei_json_parsed(self, mock_run):
        nuclei_line = json.dumps({
            "template-id": "cve-2021-0001",
            "info": {
                "name": "Test Vuln",
                "severity": "high",
                "description": "A test CVE",
                "classification": {"cwe-id": ["CWE-79"]},
            },
            "matched-at": "http://target.com/vuln",
            "extracted-results": ["payload"],
        })
        mock_run.return_value = (0, nuclei_line + "\n", "")
        findings = step_vuln_scan([], ["http://target.com"])
        assert any(f.vuln_id == "cve-2021-0001" for f in findings)


# ---------------------------------------------------------------------------
# step_interpret
# ---------------------------------------------------------------------------

class TestStepInterpret:
    def test_sqli_error_detected(self):
        raw = "You have an error in your SQL syntax; check the manual"
        findings = step_interpret(raw)
        ids = [f.vuln_id for f in findings]
        assert "sqli-error-based" in ids

    def test_xss_reflected_detected(self):
        raw = "Response body: <img src=x onerror=alert(1)>"
        findings = step_interpret(raw)
        ids = [f.vuln_id for f in findings]
        assert "xss-reflected" in ids

    def test_oracle_error_detected(self):
        raw = "ORA-00904: invalid identifier"
        findings = step_interpret(raw)
        ids = [f.vuln_id for f in findings]
        assert "sqli-error-based" in ids

    def test_clean_response_no_findings(self):
        findings = step_interpret("Welcome to the homepage!")
        assert findings == []


# ---------------------------------------------------------------------------
# step_report
# ---------------------------------------------------------------------------

class TestStepReport:
    def _make_result(self, **kwargs) -> HuntResult:
        defaults = dict(
            target="example.com",
            status=True,
            findings=[],
            subdomains=["example.com"],
            alive_hosts=["http://example.com"],
            urls=["http://example.com/"],
            pipeline_log=["[step] done"],
            summary="",
        )
        defaults.update(kwargs)
        return HuntResult(**defaults)

    def test_report_structure(self):
        result = step_report(self._make_result())
        assert "status" in result
        assert "summary" in result
        assert "result" in result

    def test_severity_counts_present(self):
        finding = Finding(
            vuln_id="test",
            title="Test",
            severity=Severity.HIGH,
            description="desc",
        )
        result = step_report(self._make_result(findings=[finding]))
        assert result["result"]["severity_counts"]["HIGH"] == 1

    def test_findings_serialised(self):
        finding = Finding(
            vuln_id="xss-test",
            title="XSS",
            severity=Severity.HIGH,
            description="reflected xss",
            affected_url="http://example.com/?q=1",
        )
        result = step_report(self._make_result(findings=[finding]))
        serialised = result["result"]["findings"]
        assert isinstance(serialised, list)
        assert serialised[0]["vuln_id"] == "xss-test"

    def test_default_summary_when_empty(self):
        result = step_report(self._make_result(summary=""))
        assert "0 finding(s)" in result["summary"]


# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------

class TestFindingModel:
    def test_defaults(self):
        f = Finding(vuln_id="test", title="T", severity=Severity.INFO, description="d")
        assert f.affected_url == ""
        assert f.cwe == ""

    def test_asdict_serialisable(self):
        f = Finding(
            vuln_id="sqli",
            title="SQL Injection",
            severity=Severity.CRITICAL,
            description="desc",
        )
        d = asdict(f)
        assert d["severity"] == Severity.CRITICAL

    def test_severity_enum_values(self):
        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.MEDIUM.value == "MEDIUM"


# ---------------------------------------------------------------------------
# run() entry-point
# ---------------------------------------------------------------------------

class TestRunEntryPoint:
    def test_missing_target_returns_error(self):
        result = run({})
        assert result["status"] is False
        assert "target" in result["summary"].lower()

    def test_empty_target_returns_error(self):
        result = run({"target": "  "})
        assert result["status"] is False

    def test_unknown_action(self):
        result = run({"target": "example.com", "action": "nonexistent"})
        assert result["status"] is False
        assert "available_actions" in result["result"]

    @patch("skills.bug_hunting.run._run_cmd")
    def test_subdomain_enum_action(self, mock_run):
        mock_run.return_value = (0, "sub.example.com\n", "")
        result = run({"target": "example.com", "action": "subdomain_enum"})
        assert result["status"] is True
        assert "subdomains" in result["result"]

    @patch("skills.bug_hunting.run._run_cmd")
    def test_url_collect_action(self, mock_run):
        mock_run.return_value = (0, "http://example.com/path\n", "")
        result = run({"target": "http://example.com", "action": "url_collect"})
        assert result["status"] is True
        assert "urls" in result["result"]

    def test_report_action_requires_raw_output(self):
        result = run({"target": "example.com", "action": "report"})
        assert result["status"] is False
        assert "raw_output" in result["summary"]

    def test_report_action_with_sqli_raw_output(self):
        result = run({
            "target": "example.com",
            "action": "report",
            "raw_output": "SQL syntax error near SELECT",
        })
        assert result["status"] is True
        ids = [f["vuln_id"] for f in result["result"]["findings"]]
        assert "sqli-error-based" in ids

    @patch("skills.bug_hunting.run._run_cmd")
    def test_vuln_scan_action(self, mock_run):
        mock_run.side_effect = FileNotFoundError("nuclei")
        result = run({
            "target": "http://target.com/view?file=x",
            "action": "vuln_scan",
        })
        assert result["status"] is True
        assert "findings" in result["result"]

    @patch("skills.bug_hunting.run.BugHuntingSkill.run")
    def test_full_pipeline_delegates_to_skill(self, mock_skill_run):
        mock_skill_run.return_value = {
            "status": True,
            "summary": "done",
            "result": {},
        }
        result = run({"target": "example.com", "action": "full_pipeline"})
        assert result["status"] is True
        mock_skill_run.assert_called_once()


# ---------------------------------------------------------------------------
# BugHuntingSkill class
# ---------------------------------------------------------------------------

class TestBugHuntingSkill:
    @patch("skills.bug_hunting.run.step_subdomain_enum", return_value=["example.com"])
    @patch("skills.bug_hunting.run.step_resolve_hosts", return_value=["example.com"])
    @patch("skills.bug_hunting.run.step_port_scan", return_value=["http://example.com"])
    @patch("skills.bug_hunting.run.step_url_collect", return_value=["http://example.com/"])
    @patch("skills.bug_hunting.run.step_vuln_scan", return_value=[])
    def test_run_returns_completed_status(self, *mocks):
        skill = BugHuntingSkill()
        result = skill.run("example.com")
        assert result["status"] is True

    @patch("skills.bug_hunting.run.step_subdomain_enum", return_value=["example.com"])
    @patch("skills.bug_hunting.run.step_resolve_hosts", return_value=["example.com"])
    @patch("skills.bug_hunting.run.step_port_scan", return_value=["http://example.com"])
    @patch("skills.bug_hunting.run.step_url_collect", return_value=["http://example.com/"])
    @patch("skills.bug_hunting.run.step_vuln_scan", return_value=[])
    def test_run_includes_pipeline_log(self, *mocks):
        skill = BugHuntingSkill()
        result = skill.run("example.com")
        assert len(result["result"]["pipeline_log"]) > 0

    @patch("skills.bug_hunting.run.step_subdomain_enum", return_value=["example.com"])
    @patch("skills.bug_hunting.run.step_resolve_hosts", return_value=["example.com"])
    @patch("skills.bug_hunting.run.step_port_scan", return_value=["http://example.com"])
    @patch("skills.bug_hunting.run.step_url_collect", return_value=["http://example.com/"])
    @patch("skills.bug_hunting.run.step_vuln_scan")
    def test_run_with_findings(self, mock_vuln_scan, *mocks):
        finding = Finding(
            vuln_id="lfi-param-detected",
            title="LFI",
            severity=Severity.HIGH,
            description="desc",
        )
        mock_vuln_scan.return_value = [finding]
        skill = BugHuntingSkill()
        result = skill.run("example.com")
        assert result["result"]["severity_counts"]["HIGH"] == 1
