"""Integration tests for the bug_hunting skill (end-to-end pipeline).

All subprocess calls (subfinder, dnsx, naabu, httpx, katana, nuclei) and
KnowledgeBase interactions are mocked.  No real network traffic is generated.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from skills.bug_hunting.run import (
    BugHuntingSkill,
    Finding,
    Severity,
    run,
)


# ---------------------------------------------------------------------------
# Helpers / Fixtures
# ---------------------------------------------------------------------------

NUCLEI_HIT = json.dumps({
    "template-id": "exposed-admin-panel",
    "info": {
        "name": "Exposed Admin Panel",
        "severity": "high",
        "description": "Admin panel is publicly accessible.",
        "classification": {"cwe-id": ["CWE-284"]},
    },
    "matched-at": "http://ctf-target.local/admin",
    "extracted-results": ["/admin"],
})


def _make_run_cmd_side_effect(tool_outputs: dict):
    """Return a side_effect function that dispatches mock output by tool name."""

    def side_effect(cmd, **kwargs):
        tool = cmd[0] if cmd else ""
        if tool in tool_outputs:
            output = tool_outputs[tool]
            if isinstance(output, Exception):
                raise output
            return (0, output, "")
        return (0, "", "")

    return side_effect


# ---------------------------------------------------------------------------
# Full pipeline integration tests
# ---------------------------------------------------------------------------

class TestFullPipeline:
    """Test the complete 6-step Purple Engine loop end-to-end."""

    @patch("skills.bug_hunting.run._run_cmd")
    @patch("skills.bug_hunting.run.step_search_kb", return_value=["KB context snippet"])
    def test_pipeline_completes_successfully(self, mock_kb, mock_run):
        mock_run.side_effect = _make_run_cmd_side_effect({
            "subfinder": "api.ctf-target.local\n",
            "dnsx": "api.ctf-target.local\n",
            "naabu": "api.ctf-target.local:80\n",
            "httpx": "http://api.ctf-target.local\n",
            "katana": "http://api.ctf-target.local/login\n",
            "nuclei": NUCLEI_HIT + "\n",
        })

        result = run({"target": "ctf-target.local", "action": "full_pipeline"})

        assert result["status"] is True
        assert "ctf-target.local" in result["summary"]
        data = result["result"]
        assert "findings" in data
        assert "alive_hosts" in data
        assert "subdomains" in data

    @patch("skills.bug_hunting.run._run_cmd")
    @patch("skills.bug_hunting.run.step_search_kb", return_value=[])
    def test_pipeline_with_lfi_url(self, mock_kb, mock_run):
        """LFI parameter in crawled URL should produce a finding."""
        mock_run.side_effect = _make_run_cmd_side_effect({
            "subfinder": "ctf-target.local\n",
            "dnsx": "ctf-target.local\n",
            "naabu": "ctf-target.local:80\n",
            "httpx": "http://ctf-target.local\n",
            "katana": "http://ctf-target.local/page?file=index.php\n",
            "nuclei": FileNotFoundError("nuclei"),
        })

        result = run({"target": "ctf-target.local"})

        assert result["status"] is True
        finding_ids = [f["vuln_id"] for f in result["result"]["findings"]]
        assert "lfi-param-detected" in finding_ids

    @patch("skills.bug_hunting.run._run_cmd")
    @patch("skills.bug_hunting.run.step_search_kb", return_value=[])
    def test_pipeline_tools_all_missing(self, mock_kb, mock_run):
        """Pipeline should still succeed with graceful fallbacks when no tools are installed."""
        mock_run.side_effect = FileNotFoundError("tool not found")

        result = run({"target": "ctf-target.local"})

        assert result["status"] is True
        # At minimum the domain itself should appear as a subdomain/alive host
        data = result["result"]
        assert len(data["subdomains"]) >= 1
        assert len(data["alive_hosts"]) >= 1

    @patch("skills.bug_hunting.run._run_cmd")
    @patch("skills.bug_hunting.run.step_search_kb", return_value=[])
    def test_pipeline_nuclei_findings_parsed(self, mock_kb, mock_run):
        """nuclei JSONL output should be parsed into Finding objects."""
        mock_run.side_effect = _make_run_cmd_side_effect({
            "subfinder": "ctf-target.local\n",
            "dnsx": "ctf-target.local\n",
            "naabu": "ctf-target.local:80\n",
            "httpx": "http://ctf-target.local\n",
            "katana": "http://ctf-target.local/\n",
            "nuclei": NUCLEI_HIT + "\n",
        })

        result = run({"target": "ctf-target.local"})

        assert result["status"] is True
        finding_ids = [f["vuln_id"] for f in result["result"]["findings"]]
        assert "exposed-admin-panel" in finding_ids

    @patch("skills.bug_hunting.run._run_cmd")
    @patch("skills.bug_hunting.run.step_search_kb", return_value=[])
    def test_pipeline_deep_depth(self, mock_kb, mock_run):
        """``depth=deep`` should be forwarded through the pipeline."""
        mock_run.side_effect = _make_run_cmd_side_effect({
            "subfinder": "a.ctf-target.local\nb.ctf-target.local\n",
            "dnsx": "a.ctf-target.local\nb.ctf-target.local\n",
            "naabu": "a.ctf-target.local:443\n",
            "httpx": "https://a.ctf-target.local\n",
            "katana": "https://a.ctf-target.local/secret\n",
            "nuclei": "",
        })

        result = run({
            "target": "ctf-target.local",
            "action": "full_pipeline",
            "depth": "deep",
        })

        assert result["status"] is True
        # deep scan uses -all flag; verify subfinder was called with it
        subfinder_calls = [
            c for c in mock_run.call_args_list if c[0][0][0] == "subfinder"
        ]
        if subfinder_calls:
            cmd = subfinder_calls[0][0][0]
            assert "-all" in cmd


# ---------------------------------------------------------------------------
# Individual action integration tests
# ---------------------------------------------------------------------------

class TestSubdomainEnumAction:
    @patch("skills.bug_hunting.run._run_cmd")
    def test_action_returns_subdomain_list(self, mock_run):
        mock_run.return_value = (0, "mail.example.com\nwww.example.com\n", "")
        result = run({"target": "example.com", "action": "subdomain_enum"})
        assert result["status"] is True
        assert "mail.example.com" in result["result"]["subdomains"]

    @patch("skills.bug_hunting.run._run_cmd")
    def test_action_falls_back_to_domain(self, mock_run):
        mock_run.side_effect = FileNotFoundError("subfinder")
        result = run({"target": "example.com", "action": "subdomain_enum"})
        assert result["status"] is True
        assert "example.com" in result["result"]["subdomains"]


class TestPortScanAction:
    @patch("skills.bug_hunting.run._run_cmd")
    def test_action_returns_alive_hosts(self, mock_run):
        mock_run.side_effect = _make_run_cmd_side_effect({
            "naabu": "example.com:80\nexample.com:443\n",
            "httpx": "http://example.com\nhttps://example.com\n",
        })
        result = run({"target": "example.com", "action": "port_scan"})
        assert result["status"] is True
        assert len(result["result"]["alive_hosts"]) >= 1

    @patch("skills.bug_hunting.run._run_cmd")
    def test_action_no_tools_still_succeeds(self, mock_run):
        mock_run.side_effect = FileNotFoundError("naabu")
        result = run({"target": "example.com", "action": "port_scan"})
        assert result["status"] is True


class TestUrlCollectAction:
    @patch("skills.bug_hunting.run._run_cmd")
    def test_action_deduplicates(self, mock_run):
        mock_run.return_value = (
            0,
            "http://example.com/a\nhttp://example.com/a\nhttp://example.com/b\n",
            "",
        )
        result = run({"target": "http://example.com", "action": "url_collect"})
        assert result["status"] is True
        urls = result["result"]["urls"]
        assert urls.count("http://example.com/a") == 1


class TestVulnScanAction:
    @patch("skills.bug_hunting.run._run_cmd")
    def test_lfi_found(self, mock_run):
        mock_run.side_effect = FileNotFoundError("nuclei")
        result = run({
            "target": "http://target.com/load?page=home",
            "action": "vuln_scan",
        })
        assert result["status"] is True
        ids = [f["vuln_id"] for f in result["result"]["findings"]]
        assert "lfi-param-detected" in ids

    @patch("skills.bug_hunting.run._run_cmd")
    def test_open_redirect_found(self, mock_run):
        mock_run.side_effect = FileNotFoundError("nuclei")
        result = run({
            "target": "http://target.com/go?next=http://evil.com",
            "action": "vuln_scan",
        })
        assert result["status"] is True
        ids = [f["vuln_id"] for f in result["result"]["findings"]]
        assert "open-redirect-param-detected" in ids


class TestReportAction:
    def test_sqli_in_raw_output(self):
        result = run({
            "target": "example.com",
            "action": "report",
            "raw_output": "mysql_fetch_array() expects parameter 1 to be resource",
        })
        assert result["status"] is True
        ids = [f["vuln_id"] for f in result["result"]["findings"]]
        assert "sqli-error-based" in ids

    def test_xss_in_raw_output(self):
        result = run({
            "target": "example.com",
            "action": "report",
            "raw_output": "Hello <img src=x onerror=alert(1)> world",
        })
        assert result["status"] is True
        ids = [f["vuln_id"] for f in result["result"]["findings"]]
        assert "xss-reflected" in ids

    def test_clean_raw_output(self):
        result = run({
            "target": "example.com",
            "action": "report",
            "raw_output": "Everything looks fine here.",
        })
        assert result["status"] is True
        assert result["result"]["findings"] == []

    def test_missing_raw_output_returns_error(self):
        result = run({"target": "example.com", "action": "report"})
        assert result["status"] is False


# ---------------------------------------------------------------------------
# BugHuntingSkill – constructor and edge cases
# ---------------------------------------------------------------------------

class TestBugHuntingSkillIntegration:
    def test_accepts_custom_kb(self):
        mock_kb = MagicMock()
        mock_kb.search.return_value = []
        skill = BugHuntingSkill(kb=mock_kb)
        assert skill._kb is mock_kb

    @patch("skills.bug_hunting.run._run_cmd")
    def test_run_result_is_registry_compatible(self, mock_run):
        """Result dict must have status (bool), summary (str), result (dict)."""
        mock_run.side_effect = FileNotFoundError("all tools missing")
        skill = BugHuntingSkill()
        result = skill.run("example.com")
        assert isinstance(result["status"], bool)
        assert isinstance(result["summary"], str)
        assert isinstance(result["result"], dict)

    @patch("skills.bug_hunting.run._run_cmd")
    def test_pipeline_log_all_six_steps_present(self, mock_run):
        mock_run.side_effect = FileNotFoundError("tools")
        skill = BugHuntingSkill()
        result = skill.run("example.com")
        log = " ".join(result["result"]["pipeline_log"])
        for step in ("analyze", "kb", "plan", "execute", "interpret", "report"):
            # Each step prefix should appear at least once in the log
            assert step in log or step.replace("execute", "execute") in log

    @patch("skills.bug_hunting.run._run_cmd")
    def test_exception_in_pipeline_handled_by_run_entry(self, mock_run):
        """If an unexpected exception escapes a step, run() must still return a dict."""
        mock_run.side_effect = Exception("unexpected catastrophic failure")
        # step_subdomain_enum is the first _run_cmd caller; let everything else
        # fall back gracefully
        result = run({"target": "example.com"})
        assert "status" in result
        assert "summary" in result
