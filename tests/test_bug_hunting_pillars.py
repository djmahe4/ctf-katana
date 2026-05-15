"""Unit tests for the new 5-pillar bug bounty methodology.
All external calls are mocked.
"""

from __future__ import annotations
import pytest
from unittest.mock import MagicMock, patch
from pathlib import Path
import sys

# Ensure project root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from skills.bug_hunting.run import (
    run,
    step_learning_loop,
    step_categorise_subdomains,
    step_feature_map,
    step_request_analysis,
    step_js_review,
    step_report_assist,
    step_feedback_loop,
    HitList
)

class TestPillar2:
    def test_learning_loop(self):
        writeup = "Found an IDOR by changing the id parameter in /api/user/123 to 124."
        result = step_learning_loop(writeup)
        assert "ai_tutor_prompts" in result
        assert any("IDOR" in p for p in result["ai_tutor_prompts"])

class TestPillar3:
    def test_categorise_subdomains(self):
        subs = [
            "auth.example.com",
            "admin-portal.example.com",
            "api-v2.example.com",
            "internal-git.example.com",
            "marketing.example.com",
            "blog.example.com"
        ]
        hit_list = step_categorise_subdomains(subs)
        assert "auth.example.com" in hit_list.auth_subdomains
        assert "admin-portal.example.com" in hit_list.admin_subdomains
        assert "api-v2.example.com" in hit_list.api_subdomains
        assert "internal-git.example.com" in hit_list.internal_subdomains
        
    def test_hitlist_prioritisation(self):
        hit_list = HitList(
            auth_subdomains=["auth.ex.com"],
            api_subdomains=["api.ex.com"],
            marketing_subdomains=["mkt.ex.com"]
        )
        prio = hit_list.prioritised()
        # Auth and API should come before Marketing
        assert prio.index("auth.ex.com") < prio.index("mkt.ex.com")
        assert prio.index("api.ex.com") < prio.index("mkt.ex.com")

class TestPillar4:
    def test_feature_map(self):
        features = "A user dashboard with profile editing and a billing section."
        result = step_feature_map(features)
        assert "prioritised_bug_classes" in result
        assert any("IDOR" in bc for bc in result["prioritised_bug_classes"])

    def test_request_analysis(self):
        req = "GET /api/v1/profile?uid=1001 HTTP/1.1\nAuthorization: Bearer xyz"
        result = step_request_analysis(req)
        assert any("uid=1001" in t for t in result["tamper_targets"])

    def test_js_review(self):
        js = "fetch('/api/secret/data');"
        result = step_js_review(js)
        assert any("/api/secret/data" in e for e in result["api_endpoints_found"])

class TestPillar5:
    def test_report_assist(self):
        result = step_report_assist("IDOR", "Accessed private invoices")
        assert "impact_statement" in result
        assert "report_critique_checklist" in result

    def test_feedback_loop(self):
        summary = "Found 2 IDORs and 1 XSS during the hunt on example.com"
        result = step_feedback_loop(summary)
        assert "reflection_questions" in result

class TestDispatcherPillars:
    def test_run_learning_loop(self):
        res = run({"action": "learning_loop", "writeup": "test"})
        assert res["status"] is True
        assert "Pillar 2" in res["summary"]

    def test_run_feature_map(self):
        res = run({"action": "feature_map", "features": "test"})
        assert res["status"] is True
        assert "Pillar 4" in res["summary"]

    def test_run_report_assist(self):
        res = run({"action": "report_assist", "bug_class": "xss"})
        assert res["status"] is True
        assert "Pillar 5" in res["summary"]
