"""Unit + integration tests for skills/bug_hunting/platform_scanner.py.

All network and browser calls are mocked — no real browsers or HTTP
traffic are used.  Tests are organised by component:

* TestFetchDynamicHtml  – DrissionPage engine edge cases
* TestFetchFallback     – Playwright engine edge cases
* TestFetchPage         – wrapper fallback logic
* TestParsePrograms     – HTML parsing, dedup, base-URL resolution
* TestScoreProgram      – scoring dimensions and penalties
* TestApplyCriteria     – min_score + tag filtering
* TestFetchAll          – per-platform orchestration and dedup
* TestPlatformScanner   – Purple Engine wrapper (run())
* TestRunPlatformScan   – module-level adapter
* TestRunEntryPlatform  – integration through run.py run()
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from skills.bug_hunting.platform_scanner import (
    PLATFORM_CONFIG,
    PlatformScanner,
    ProgramEntry,
    _MIN_HTML_BYTES,
    _apply_criteria,
    fetch_all,
    fetch_page,
    parse_programs,
    run_platform_scan,
    score_program,
)
from skills.bug_hunting.run import run


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_LARGE_HTML = "<html><body>" + ("x" * (_MIN_HTML_BYTES + 500)) + "</body></html>"

_PROGRAM_HTML = """
<html><body>
  <div class="card"><a href="/programs/alpha-corp">Alpha Corp</a></div>
  <div class="card"><a href="/programs/beta-finance">Beta Finance</a></div>
  <div class="card"><a href="/programs/beta-finance">Beta Finance</a></div>
  <article><a href="https://other.com/bounty/gamma">Gamma Bounty</a></article>
  <a href="#anchor">Skip nav</a>
  <a href="javascript:void(0)">JS link</a>
  <a href="">Empty href</a>
  <a href="/programs/valid">  </a>
</body></html>
"""

_WEB3_HTML = """
<html><body>
  <div class="card"><a href="/programs/defi-vault">DeFi Vault Protocol</a></div>
  <div class="card"><a href="/programs/iot-firmware">IoT Firmware Scanner</a></div>
</body></html>
"""


# ---------------------------------------------------------------------------
# TestFetchDynamicHtml
# ---------------------------------------------------------------------------

class TestFetchDynamicHtml:
    """Edge cases for the DrissionPage fetch path."""

    def test_drissionpage_not_installed_raises(self):
        """ImportError propagates when DrissionPage is not importable."""
        from skills.bug_hunting.platform_scanner import fetch_dynamic_html
        with patch.dict("sys.modules", {"DrissionPage": None}):
            with pytest.raises(ImportError, match="DrissionPage"):
                fetch_dynamic_html("https://example.com")

    def test_browser_crash_returns_empty(self):
        """If page.get() raises, an empty string is returned (not re-raised)."""
        from skills.bug_hunting.platform_scanner import fetch_dynamic_html
        mock_page = MagicMock()
        mock_page.get.side_effect = RuntimeError("browser crashed")
        mock_page.quit = MagicMock()
        with patch("skills.bug_hunting.platform_scanner.ChromiumPage", return_value=mock_page):
            result = fetch_dynamic_html("https://example.com", scrolls=1)
        assert result == ""
        mock_page.quit.assert_called_once()

    def test_quit_called_even_on_success(self):
        """page.quit() must be called in the finally block."""
        from skills.bug_hunting.platform_scanner import fetch_dynamic_html
        mock_page = MagicMock()
        mock_page.html = _LARGE_HTML
        mock_page.quit = MagicMock()
        mock_scroll = MagicMock()
        mock_page.scroll = mock_scroll
        with patch("skills.bug_hunting.platform_scanner.ChromiumPage", return_value=mock_page):
            with patch("skills.bug_hunting.platform_scanner.time") as mock_time:
                mock_time.sleep = MagicMock()
                result = fetch_dynamic_html("https://example.com", scrolls=2)
        mock_page.quit.assert_called_once()
        assert result == _LARGE_HTML

    def test_scroll_called_n_times(self):
        """scroll.to_bottom() must be called exactly ``scrolls`` times."""
        from skills.bug_hunting.platform_scanner import fetch_dynamic_html
        mock_page = MagicMock()
        mock_page.html = _LARGE_HTML
        mock_scroll = MagicMock()
        mock_page.scroll = mock_scroll
        with patch("skills.bug_hunting.platform_scanner.ChromiumPage", return_value=mock_page):
            with patch("skills.bug_hunting.platform_scanner.time"):
                fetch_dynamic_html("https://example.com", scrolls=4)
        assert mock_scroll.to_bottom.call_count == 4

    def test_empty_html_attribute_returns_empty(self):
        """When page.html returns empty/None, an empty string is returned."""
        from skills.bug_hunting.platform_scanner import fetch_dynamic_html
        mock_page = MagicMock()
        mock_page.html = ""
        mock_page.scroll = MagicMock()
        with patch("skills.bug_hunting.platform_scanner.ChromiumPage", return_value=mock_page):
            with patch("skills.bug_hunting.platform_scanner.time"):
                result = fetch_dynamic_html("https://example.com", scrolls=1)
        assert result == ""
        mock_page.quit.assert_called_once()


# ---------------------------------------------------------------------------
# TestFetchFallback
# ---------------------------------------------------------------------------

class TestFetchFallback:
    """Edge cases for the Playwright fallback path."""

    def test_playwright_not_installed_raises(self):
        from skills.bug_hunting.platform_scanner import fetch_fallback
        with patch.dict("sys.modules", {"playwright": None, "playwright.sync_api": None}):
            with pytest.raises(ImportError, match="Playwright"):
                fetch_fallback("https://example.com")

    def test_page_goto_timeout_returns_empty(self):
        from skills.bug_hunting.platform_scanner import fetch_fallback
        mock_browser = MagicMock()
        mock_page = MagicMock()
        mock_page.goto.side_effect = Exception("Timeout 120000ms exceeded")
        mock_page.content.return_value = ""
        mock_browser.new_page.return_value = mock_page
        mock_playwright = MagicMock()
        mock_playwright.__enter__ = MagicMock(return_value=mock_playwright)
        mock_playwright.__exit__ = MagicMock(return_value=False)
        mock_playwright.chromium.launch.return_value = mock_browser
        with patch(
            "skills.bug_hunting.platform_scanner.sync_playwright",
            return_value=mock_playwright,
        ):
            result = fetch_fallback("https://example.com")
        assert result == ""

    def test_browser_close_called(self):
        from skills.bug_hunting.platform_scanner import fetch_fallback
        mock_browser = MagicMock()
        mock_page = MagicMock()
        mock_page.content.return_value = _LARGE_HTML
        mock_browser.new_page.return_value = mock_page
        mock_playwright = MagicMock()
        mock_playwright.__enter__ = MagicMock(return_value=mock_playwright)
        mock_playwright.__exit__ = MagicMock(return_value=False)
        mock_playwright.chromium.launch.return_value = mock_browser
        with patch(
            "skills.bug_hunting.platform_scanner.sync_playwright",
            return_value=mock_playwright,
        ):
            result = fetch_fallback("https://example.com")
        mock_browser.close.assert_called_once()
        assert result == _LARGE_HTML


# ---------------------------------------------------------------------------
# TestFetchPage
# ---------------------------------------------------------------------------

class TestFetchPage:
    """Wrapper: DrissionPage first, Playwright on insufficient HTML."""

    def test_drissionpage_success_skips_playwright(self):
        with patch("skills.bug_hunting.platform_scanner.fetch_dynamic_html", return_value=_LARGE_HTML) as mock_dp:
            with patch("skills.bug_hunting.platform_scanner.fetch_fallback") as mock_pw:
                result = fetch_page("https://example.com", scrolls=3)
        assert result == _LARGE_HTML
        mock_dp.assert_called_once()
        mock_pw.assert_not_called()

    def test_drissionpage_too_small_falls_to_playwright(self):
        small_html = "<html><body>tiny</body></html>"
        with patch("skills.bug_hunting.platform_scanner.fetch_dynamic_html", return_value=small_html):
            with patch(
                "skills.bug_hunting.platform_scanner.fetch_fallback",
                return_value=_LARGE_HTML,
            ) as mock_pw:
                result = fetch_page("https://example.com")
        assert result == _LARGE_HTML
        mock_pw.assert_called_once()

    def test_drissionpage_unavailable_falls_to_playwright(self):
        with patch(
            "skills.bug_hunting.platform_scanner.fetch_dynamic_html",
            side_effect=ImportError("DrissionPage"),
        ):
            with patch(
                "skills.bug_hunting.platform_scanner.fetch_fallback",
                return_value=_LARGE_HTML,
            ) as mock_pw:
                result = fetch_page("https://example.com")
        assert result == _LARGE_HTML
        mock_pw.assert_called_once()

    def test_both_engines_fail_returns_empty(self):
        with patch(
            "skills.bug_hunting.platform_scanner.fetch_dynamic_html",
            side_effect=ImportError("DrissionPage"),
        ):
            with patch(
                "skills.bug_hunting.platform_scanner.fetch_fallback",
                side_effect=ImportError("playwright"),
            ):
                result = fetch_page("https://example.com")
        assert result == ""

    def test_drissionpage_empty_falls_to_playwright(self):
        with patch("skills.bug_hunting.platform_scanner.fetch_dynamic_html", return_value=""):
            with patch(
                "skills.bug_hunting.platform_scanner.fetch_fallback",
                return_value=_LARGE_HTML,
            ) as mock_pw:
                result = fetch_page("https://example.com")
        assert result == _LARGE_HTML
        mock_pw.assert_called_once()

    def test_playwright_also_returns_empty(self):
        with patch("skills.bug_hunting.platform_scanner.fetch_dynamic_html", return_value=""):
            with patch("skills.bug_hunting.platform_scanner.fetch_fallback", return_value=""):
                result = fetch_page("https://example.com")
        assert result == ""


# ---------------------------------------------------------------------------
# TestParsePrograms
# ---------------------------------------------------------------------------

class TestParsePrograms:
    """HTML parsing edge cases."""

    def test_empty_html_returns_empty(self):
        result = parse_programs("", "https://example.com", "test")
        assert result == []

    def test_whitespace_only_html_returns_empty(self):
        result = parse_programs("   \n  ", "https://example.com", "test")
        assert result == []

    def test_parses_card_links(self):
        programs = parse_programs(_PROGRAM_HTML, "https://hackerone.com", "hackerone")
        names = [p.name for p in programs]
        assert "Alpha Corp" in names
        assert "Beta Finance" in names

    def test_deduplicates_same_url(self):
        programs = parse_programs(_PROGRAM_HTML, "https://hackerone.com", "hackerone")
        urls = [p.url for p in programs]
        assert urls.count("https://hackerone.com/programs/beta-finance") == 1

    def test_resolves_relative_href(self):
        programs = parse_programs(_PROGRAM_HTML, "https://hackerone.com", "hackerone")
        urls = [p.url for p in programs]
        assert "https://hackerone.com/programs/alpha-corp" in urls

    def test_absolute_url_preserved(self):
        programs = parse_programs(_PROGRAM_HTML, "https://hackerone.com", "hackerone")
        urls = [p.url for p in programs]
        assert "https://other.com/bounty/gamma" in urls

    def test_anchor_href_skipped(self):
        programs = parse_programs(_PROGRAM_HTML, "https://hackerone.com", "hackerone")
        urls = [p.url for p in programs]
        assert not any("#anchor" in u for u in urls)

    def test_javascript_href_skipped(self):
        programs = parse_programs(_PROGRAM_HTML, "https://hackerone.com", "hackerone")
        urls = [p.url for p in programs]
        assert not any("javascript" in u for u in urls)

    def test_empty_name_skipped(self):
        """Entry with whitespace-only name and valid href must be skipped."""
        programs = parse_programs(_PROGRAM_HTML, "https://hackerone.com", "hackerone")
        names = [p.name for p in programs]
        assert "" not in names
        assert not any(n.strip() == "" for n in names)

    def test_platform_set_on_entries(self):
        programs = parse_programs(_PROGRAM_HTML, "https://hackerone.com", "hackerone")
        assert all(p.platform == "hackerone" for p in programs)

    def test_cap_at_max_programs(self):
        # Build HTML with > 100 unique links
        links = "".join(
            f'<div class="card"><a href="/programs/prog-{i}">Program {i}</a></div>'
            for i in range(150)
        )
        html = f"<html><body>{links}</body></html>"
        programs = parse_programs(html, "https://h1.com", "h1")
        assert len(programs) == 100

    def test_base_url_trailing_slash_normalised(self):
        """base URL with trailing slash must not produce double-slash paths."""
        html = '<html><body><div class="card"><a href="/programs/x">X</a></div></body></html>'
        programs = parse_programs(html, "https://example.com/", "test")
        assert not any("//programs" in p.url for p in programs)


# ---------------------------------------------------------------------------
# TestScoreProgram
# ---------------------------------------------------------------------------

class TestScoreProgram:
    def _entry(self, name: str, url: str, platform: str = "test") -> ProgramEntry:
        return ProgramEntry(name=name, url=url, platform=platform)

    def test_web3_boost(self):
        e = score_program(self._entry("DeFi Vault Protocol", "https://example.io/programs/defi"))
        assert e.score >= 3.0
        assert "web3" in e.tags

    def test_iot_boost(self):
        e = score_program(self._entry("IoT Firmware Security", "https://example.com/programs/iot"))
        assert e.score >= 2.0
        assert "iot" in e.tags

    def test_new_program_boost(self):
        e = score_program(self._entry("Just Added: New Bounty", "https://example.com/programs/new-prog"))
        assert e.score >= 2.0
        assert "new" in e.tags

    def test_deep_scope_boost(self):
        e = score_program(self._entry("Deep Scope", "https://example.com/programs/a/b/c/d"))
        assert "deep-scope" in e.tags

    def test_niche_tld_boost(self):
        e = score_program(self._entry("Finance Protocol", "https://project.finance/programs/x"))
        assert "niche-tld" in e.tags

    def test_short_name_penalty(self):
        e = score_program(self._entry("Hi", "https://example.com/programs/hi"))
        assert e.score < 0

    def test_nav_fragment_penalty(self):
        e = score_program(self._entry("Login Page", "https://example.com/login"))
        assert e.score < 0

    def test_patch_gap_penalty_no_bounty_keyword(self):
        e = score_program(self._entry("SomeCorp", "https://somecorp.com/security"))
        # No "bounty" / "program" / "bug-bounty" in name or URL → -0.5
        assert e.score < 0

    def test_score_is_float(self):
        e = score_program(self._entry("Test Program", "https://example.com/programs/test"))
        assert isinstance(e.score, float)

    def test_tags_is_list(self):
        e = score_program(self._entry("Test", "https://example.com/programs/test"))
        assert isinstance(e.tags, list)

    def test_combined_web3_iot(self):
        e = score_program(
            self._entry("Web3 IoT Bridge", "https://web3.io/programs/iot-defi")
        )
        assert "web3" in e.tags
        assert "iot" in e.tags
        assert e.score >= 5.0  # 3 (web3) + 2 (iot)


# ---------------------------------------------------------------------------
# TestApplyCriteria
# ---------------------------------------------------------------------------

class TestApplyCriteria:
    def _entries(self) -> list:
        e1 = ProgramEntry("A", "https://a.com/programs/a", "h1", score=5.0, tags=["web3"])
        e2 = ProgramEntry("B", "https://b.com/programs/b", "bc", score=1.0, tags=["iot"])
        e3 = ProgramEntry("C", "https://c.com/programs/c", "ig", score=0.0, tags=[])
        return [e1, e2, e3]

    def test_no_filter_returns_all(self):
        assert len(_apply_criteria(self._entries(), 0.0, [])) == 3

    def test_min_score_filters(self):
        result = _apply_criteria(self._entries(), 1.5, [])
        assert len(result) == 1
        assert result[0].name == "A"

    def test_tag_filter(self):
        result = _apply_criteria(self._entries(), 0.0, ["iot"])
        assert len(result) == 1
        assert result[0].name == "B"

    def test_tag_filter_and_min_score(self):
        result = _apply_criteria(self._entries(), 0.5, ["iot"])
        assert len(result) == 1

    def test_empty_list_returns_empty(self):
        assert _apply_criteria([], 0.0, []) == []

    def test_no_match_returns_empty(self):
        result = _apply_criteria(self._entries(), 10.0, [])
        assert result == []


# ---------------------------------------------------------------------------
# TestFetchAll
# ---------------------------------------------------------------------------

class TestFetchAll:
    def test_empty_platforms_returns_empty(self):
        result = fetch_all({})
        assert result == []

    def test_fetch_error_skips_platform(self):
        platforms = {
            "bad": {"url": "https://bad.com", "base": "https://bad.com", "scrolls": 1},
        }
        with patch(
            "skills.bug_hunting.platform_scanner.fetch_page",
            side_effect=RuntimeError("network error"),
        ):
            result = fetch_all(platforms)
        assert result == []

    def test_small_html_skips_platform(self):
        platforms = {
            "tiny": {"url": "https://tiny.com", "base": "https://tiny.com", "scrolls": 1},
        }
        with patch("skills.bug_hunting.platform_scanner.fetch_page", return_value="<html>hi</html>"):
            result = fetch_all(platforms)
        assert result == []

    def test_cross_platform_dedup(self):
        """Same URL appearing on two platforms should only produce one entry."""
        platforms = {
            "p1": {"url": "https://p1.com", "base": "https://p1.com", "scrolls": 1},
            "p2": {"url": "https://p2.com", "base": "https://p2.com", "scrolls": 1},
        }
        shared_html = (
            "<html><body>"
            '<div class="card"><a href="https://shared.com/programs/dup">Shared Program</a></div>'
            "</body></html>"
            + "x" * _MIN_HTML_BYTES
        )
        with patch("skills.bug_hunting.platform_scanner.fetch_page", return_value=shared_html):
            result = fetch_all(platforms)
        urls = [p.url for p in result]
        assert urls.count("https://shared.com/programs/dup") == 1

    def test_results_sorted_by_score_descending(self):
        platforms = {
            "h1": {"url": "https://h1.com", "base": "https://h1.com", "scrolls": 1},
        }
        html = (
            "<html><body>"
            '<div class="card"><a href="/programs/iot-firmware">IoT Firmware</a></div>'
            '<div class="card"><a href="/programs/plain">Plain Program</a></div>'
            "</body></html>"
            + "x" * _MIN_HTML_BYTES
        )
        with patch("skills.bug_hunting.platform_scanner.fetch_page", return_value=html):
            result = fetch_all(platforms)
        if len(result) >= 2:
            assert result[0].score >= result[1].score

    def test_parse_error_skips_platform(self):
        platforms = {
            "bad": {"url": "https://bad.com", "base": "https://bad.com", "scrolls": 1},
        }
        with patch("skills.bug_hunting.platform_scanner.fetch_page", return_value=_LARGE_HTML):
            with patch(
                "skills.bug_hunting.platform_scanner.parse_programs",
                side_effect=RuntimeError("parse failed"),
            ):
                result = fetch_all(platforms)
        assert result == []


# ---------------------------------------------------------------------------
# TestPlatformScanner
# ---------------------------------------------------------------------------

class TestPlatformScanner:
    def _platforms(self):
        return {
            "mock": {
                "url": "https://mock.com",
                "base": "https://mock.com",
                "scrolls": 1,
            }
        }

    def test_run_returns_status_true_on_success(self):
        scanner = PlatformScanner()
        with patch("skills.bug_hunting.platform_scanner.fetch_all", return_value=[]):
            result = scanner.run(platforms=self._platforms())
        assert result["status"] is True

    def test_run_returns_programs_list(self):
        scanner = PlatformScanner()
        program = ProgramEntry("Test", "https://mock.com/programs/test", "mock", score=2.0, tags=["web3"])
        with patch("skills.bug_hunting.platform_scanner.fetch_all", return_value=[program]):
            result = scanner.run(platforms=self._platforms())
        assert result["result"]["total"] == 1
        assert result["result"]["programs"][0]["name"] == "Test"

    def test_run_applies_min_score_criteria(self):
        scanner = PlatformScanner()
        programs = [
            ProgramEntry("High", "https://h.com/programs/h", "mock", score=5.0),
            ProgramEntry("Low", "https://l.com/programs/l", "mock", score=0.5),
        ]
        with patch("skills.bug_hunting.platform_scanner.fetch_all", return_value=programs):
            result = scanner.run(criteria={"min_score": 2.0}, platforms=self._platforms())
        assert result["result"]["total"] == 1
        assert result["result"]["programs"][0]["name"] == "High"

    def test_run_applies_tag_filter(self):
        scanner = PlatformScanner()
        programs = [
            ProgramEntry("Web3 One", "https://a.com/programs/a", "mock", score=3.0, tags=["web3"]),
            ProgramEntry("IoT One", "https://b.com/programs/b", "mock", score=2.0, tags=["iot"]),
        ]
        with patch("skills.bug_hunting.platform_scanner.fetch_all", return_value=programs):
            result = scanner.run(criteria={"tags": ["iot"]}, platforms=self._platforms())
        names = [p["name"] for p in result["result"]["programs"]]
        assert "IoT One" in names
        assert "Web3 One" not in names

    def test_unknown_platform_filter_returns_error(self):
        scanner = PlatformScanner()
        result = scanner.run(criteria={"platform": "nonexistent"})
        assert result["status"] is False
        assert "nonexistent" in result["summary"]

    def test_fetch_all_exception_returns_error(self):
        scanner = PlatformScanner()
        with patch(
            "skills.bug_hunting.platform_scanner.fetch_all",
            side_effect=RuntimeError("fatal error"),
        ):
            result = scanner.run(platforms=self._platforms())
        assert result["status"] is False

    def test_engine_hooks_called(self):
        mock_engine = MagicMock()
        scanner = PlatformScanner(engine=mock_engine)
        with patch("skills.bug_hunting.platform_scanner.fetch_all", return_value=[]):
            scanner.run(platforms=self._platforms())
        mock_engine.analyze.assert_called_once()
        mock_engine.interpret.assert_called_once()
        mock_engine.report.assert_called_once()

    def test_engine_hook_exceptions_do_not_abort_scan(self):
        mock_engine = MagicMock()
        mock_engine.analyze.side_effect = RuntimeError("engine down")
        scanner = PlatformScanner(engine=mock_engine)
        with patch("skills.bug_hunting.platform_scanner.fetch_all", return_value=[]):
            result = scanner.run(platforms=self._platforms())
        assert result["status"] is True

    def test_pipeline_log_in_result(self):
        scanner = PlatformScanner()
        with patch("skills.bug_hunting.platform_scanner.fetch_all", return_value=[]):
            result = scanner.run(platforms=self._platforms())
        assert "pipeline_log" in result["result"]
        assert len(result["result"]["pipeline_log"]) >= 3

    def test_platforms_scanned_in_result(self):
        scanner = PlatformScanner()
        with patch("skills.bug_hunting.platform_scanner.fetch_all", return_value=[]):
            result = scanner.run(platforms=self._platforms())
        assert "mock" in result["result"]["platforms_scanned"]

    def test_summary_contains_count(self):
        scanner = PlatformScanner()
        p = ProgramEntry("X", "https://x.com/programs/x", "mock", score=1.0)
        with patch("skills.bug_hunting.platform_scanner.fetch_all", return_value=[p]):
            result = scanner.run(platforms=self._platforms())
        assert "1" in result["summary"]

    def test_platform_criteria_shortcut(self):
        scanner = PlatformScanner()
        with patch("skills.bug_hunting.platform_scanner.fetch_all", return_value=[]) as mock_fa:
            result = scanner.run(criteria={"platform": "hackerone"})
        # hackerone is a real platform — no error
        assert result["status"] is True
        mock_fa.assert_called_once()
        called_cfg = mock_fa.call_args[0][0]
        assert list(called_cfg.keys()) == ["hackerone"]


# ---------------------------------------------------------------------------
# TestRunPlatformScan
# ---------------------------------------------------------------------------

class TestRunPlatformScan:
    def _platforms(self):
        return {"mock": {"url": "https://mock.com", "base": "https://mock.com", "scrolls": 1}}

    def test_basic_call(self):
        with patch("skills.bug_hunting.platform_scanner.fetch_all", return_value=[]):
            result = run_platform_scan({"platforms": self._platforms()})
        assert result["status"] is True

    def test_criteria_forwarded(self):
        with patch(
            "skills.bug_hunting.platform_scanner.fetch_all", return_value=[]
        ) as mock_fa:
            run_platform_scan(
                {
                    "criteria": {"min_score": 3.0},
                    "tags": ["web3"],
                    "platform": "hackerone",
                }
            )
        # platform override means only hackerone is passed to fetch_all
        assert mock_fa.call_count == 1

    def test_min_score_shortcut(self):
        programs = [
            ProgramEntry("High", "https://h.com/programs/h", "mock", score=5.0),
            ProgramEntry("Low", "https://l.com/programs/l", "mock", score=0.1),
        ]
        with patch("skills.bug_hunting.platform_scanner.fetch_all", return_value=programs):
            result = run_platform_scan({"min_score": 3.0})
        assert result["result"]["total"] == 1


# ---------------------------------------------------------------------------
# TestRunEntryPlatform  (integration via run.py)
# ---------------------------------------------------------------------------

class TestRunEntryPlatform:
    """Test the platform_scan action through the public run() entry-point."""

    def test_platform_scan_action_routed(self):
        with patch("skills.bug_hunting.run._PLATFORM_SCANNER_AVAILABLE", True):
            with patch("skills.bug_hunting.run.run_platform_scan", return_value={
                "status": True,
                "summary": "Scan complete. 2 program(s).",
                "result": {"programs": [], "total": 2},
            }) as mock_scan:
                result = run({"target": "example.com", "action": "platform_scan"})
        assert result["status"] is True
        mock_scan.assert_called_once()

    def test_platform_scan_unavailable_returns_error(self):
        with patch("skills.bug_hunting.run._PLATFORM_SCANNER_AVAILABLE", False):
            result = run({"target": "example.com", "action": "platform_scan"})
        assert result["status"] is False
        assert "unavailable" in result["summary"].lower()

    def test_platform_scan_in_available_actions(self):
        result = run({"target": "example.com", "action": "nonexistent"})
        assert "platform_scan" in result["result"]["available_actions"]

    def test_existing_actions_still_present(self):
        result = run({"target": "example.com", "action": "nonexistent"})
        expected = ["full_pipeline", "subdomain_enum", "port_scan", "url_collect", "vuln_scan", "report"]
        for action in expected:
            assert action in result["result"]["available_actions"]
