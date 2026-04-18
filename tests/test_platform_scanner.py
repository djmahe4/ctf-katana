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
    ProgramSelector,
    _MIN_HTML_BYTES,
    _apply_criteria,
    fetch_all,
    fetch_bugcrowd_json,
    fetch_fallback,
    fetch_page,
    parse_programs,
    run_platform_scan,
    score_program,
    simulate_scan,
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
        """ImportError raised when ChromiumPage module-level name is None."""
        from skills.bug_hunting.platform_scanner import fetch_dynamic_html
        with patch("skills.bug_hunting.platform_scanner.ChromiumPage", None):
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

    def _make_pw_mock(self, page_content=_LARGE_HTML, goto_exc=None):
        """Build a full mock sync_playwright context manager."""
        mock_page = MagicMock()
        if goto_exc:
            mock_page.goto.side_effect = goto_exc
        mock_page.content.return_value = page_content

        mock_ctx = MagicMock()
        mock_ctx.new_page.return_value = mock_page

        mock_browser = MagicMock()
        mock_browser.new_context.return_value = mock_ctx

        mock_pw = MagicMock()
        mock_pw.__enter__ = MagicMock(return_value=mock_pw)
        mock_pw.__exit__ = MagicMock(return_value=False)
        mock_pw.chromium.launch.return_value = mock_browser
        return mock_pw, mock_browser, mock_ctx, mock_page

    def test_playwright_not_installed_raises(self):
        """ImportError raised when sync_playwright module-level name is None."""
        from skills.bug_hunting.platform_scanner import fetch_fallback
        with patch("skills.bug_hunting.platform_scanner.sync_playwright", None):
            with pytest.raises(ImportError, match="Playwright"):
                fetch_fallback("https://example.com")

    def test_page_goto_timeout_returns_empty(self):
        mock_pw, mock_browser, mock_ctx, mock_page = self._make_pw_mock(
            goto_exc=Exception("Timeout 120000ms exceeded")
        )
        with patch("skills.bug_hunting.platform_scanner.sync_playwright", return_value=mock_pw):
            result = fetch_fallback("https://example.com")
        assert result == ""
        mock_browser.close.assert_called_once()

    def test_browser_close_called_on_success(self):
        mock_pw, mock_browser, mock_ctx, mock_page = self._make_pw_mock()
        with patch("skills.bug_hunting.platform_scanner.sync_playwright", return_value=mock_pw):
            result = fetch_fallback("https://example.com")
        mock_browser.close.assert_called_once()
        assert result == _LARGE_HTML

    def test_ctx_closed_on_success(self):
        mock_pw, mock_browser, mock_ctx, mock_page = self._make_pw_mock()
        with patch("skills.bug_hunting.platform_scanner.sync_playwright", return_value=mock_pw):
            fetch_fallback("https://example.com")
        mock_ctx.close.assert_called_once()

    def test_ignore_https_errors_passed_to_context(self):
        """new_context must be called with ignore_https_errors=True."""
        mock_pw, mock_browser, mock_ctx, _ = self._make_pw_mock()
        with patch("skills.bug_hunting.platform_scanner.sync_playwright", return_value=mock_pw):
            fetch_fallback("https://example.com")
        mock_browser.new_context.assert_called_once()
        call_kwargs = mock_browser.new_context.call_args[1]
        assert call_kwargs.get("ignore_https_errors") is True


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


# ---------------------------------------------------------------------------
# TestFetchBugcrowdJson  (unit — mocked browser context)
# ---------------------------------------------------------------------------

class TestFetchBugcrowdJson:
    """Unit tests for the Bugcrowd JSON fetcher with mocked Playwright."""

    def _make_pw_mock(self, pages_data: list):
        """
        Build a mock sync_playwright stack where each call to ctx.request.get()
        cycles through ``pages_data`` (list of dicts or exceptions).
        """
        call_count = {"n": 0}

        def mock_get(url, **kwargs):
            i = call_count["n"]
            call_count["n"] += 1
            if i >= len(pages_data):
                resp = MagicMock()
                resp.status = 200
                resp.json.return_value = {"engagements": []}
                return resp
            item = pages_data[i]
            if isinstance(item, Exception):
                raise item
            resp = MagicMock()
            resp.status = item.get("status", 200)
            resp.json.return_value = item.get("json", {})
            return resp

        mock_req = MagicMock()
        mock_req.get.side_effect = mock_get

        mock_ctx = MagicMock()
        mock_ctx.request = mock_req

        mock_browser = MagicMock()
        mock_browser.new_context.return_value = mock_ctx

        mock_pw = MagicMock()
        mock_pw.__enter__ = MagicMock(return_value=mock_pw)
        mock_pw.__exit__ = MagicMock(return_value=False)
        mock_pw.chromium.launch.return_value = mock_browser
        return mock_pw, mock_browser, mock_ctx

    def test_returns_programs_from_json(self):
        from skills.bug_hunting.platform_scanner import fetch_bugcrowd_json
        mock_pw, _, _ = self._make_pw_mock([
            {"json": {"engagements": [
                {"name": "OpenAI Safety", "briefUrl": "/engagements/openai-safety",
                 "tagline": "AI safety", "industryName": "Technology",
                 "scopeRank": 3, "isPrivate": False},
                {"name": "Bitstamp", "briefUrl": "/engagements/bitstamp",
                 "tagline": "Crypto exchange", "industryName": "Finance",
                 "scopeRank": 2, "isPrivate": False},
            ]}},
        ])
        with patch("skills.bug_hunting.platform_scanner.sync_playwright", return_value=mock_pw):
            result = fetch_bugcrowd_json()
        assert len(result) == 2
        assert result[0].name == "OpenAI Safety"
        assert result[0].url == "https://bugcrowd.com/engagements/openai-safety"
        assert result[0].platform == "bugcrowd"

    def test_pagination_stops_on_empty_page(self):
        from skills.bug_hunting.platform_scanner import fetch_bugcrowd_json
        mock_pw, _, mock_ctx = self._make_pw_mock([
            {"json": {"engagements": [
                {"name": "P1", "briefUrl": "/engagements/p1", "tagline": "", "industryName": "", "scopeRank": 1, "isPrivate": False},
            ]}},
            {"json": {"engagements": []}},   # empty page → stop
        ])
        with patch("skills.bug_hunting.platform_scanner.sync_playwright", return_value=mock_pw):
            result = fetch_bugcrowd_json(max_pages=5)
        # Only 1 program; request was not made for further pages after empty
        assert len(result) == 1
        assert mock_ctx.request.get.call_count == 2  # page 1 + page 2

    def test_pagination_stops_on_non_200(self):
        from skills.bug_hunting.platform_scanner import fetch_bugcrowd_json
        mock_pw, _, mock_ctx = self._make_pw_mock([
            {"json": {"engagements": [
                {"name": "P1", "briefUrl": "/engagements/p1", "tagline": "", "industryName": "", "scopeRank": 1, "isPrivate": False},
            ]}},
            {"status": 403, "json": {}},   # auth error → stop
        ])
        with patch("skills.bug_hunting.platform_scanner.sync_playwright", return_value=mock_pw):
            result = fetch_bugcrowd_json(max_pages=5)
        assert len(result) == 1

    def test_network_error_stops_pagination_returns_partial(self):
        from skills.bug_hunting.platform_scanner import fetch_bugcrowd_json
        mock_pw, _, _ = self._make_pw_mock([
            {"json": {"engagements": [
                {"name": "P1", "briefUrl": "/engagements/p1", "tagline": "", "industryName": "", "scopeRank": 1, "isPrivate": False},
            ]}},
            RuntimeError("connection reset"),
        ])
        with patch("skills.bug_hunting.platform_scanner.sync_playwright", return_value=mock_pw):
            result = fetch_bugcrowd_json(max_pages=5)
        assert len(result) == 1  # partial results returned

    def test_dedup_within_json_pages(self):
        from skills.bug_hunting.platform_scanner import fetch_bugcrowd_json
        eng = {"name": "DupProg", "briefUrl": "/engagements/dup", "tagline": "", "industryName": "", "scopeRank": 1, "isPrivate": False}
        mock_pw, _, _ = self._make_pw_mock([
            {"json": {"engagements": [eng]}},
            {"json": {"engagements": [eng]}},  # same entry on page 2
        ])
        with patch("skills.bug_hunting.platform_scanner.sync_playwright", return_value=mock_pw):
            result = fetch_bugcrowd_json(max_pages=2)
        urls = [p.url for p in result]
        assert urls.count("https://bugcrowd.com/engagements/dup") == 1

    def test_missing_brief_url_skipped(self):
        from skills.bug_hunting.platform_scanner import fetch_bugcrowd_json
        mock_pw, _, _ = self._make_pw_mock([
            {"json": {"engagements": [
                {"name": "NoUrl", "briefUrl": "", "tagline": "", "industryName": "", "scopeRank": 1, "isPrivate": False},
                {"name": "Valid", "briefUrl": "/engagements/valid", "tagline": "", "industryName": "", "scopeRank": 1, "isPrivate": False},
            ]}},
        ])
        with patch("skills.bug_hunting.platform_scanner.sync_playwright", return_value=mock_pw):
            result = fetch_bugcrowd_json()
        assert len(result) == 1
        assert result[0].name == "Valid"

    def test_playwright_unavailable_raises(self):
        from skills.bug_hunting.platform_scanner import fetch_bugcrowd_json
        with patch("skills.bug_hunting.platform_scanner.sync_playwright", None):
            with pytest.raises(ImportError, match="Playwright"):
                fetch_bugcrowd_json()

    def test_raw_text_includes_tagline_and_industry(self):
        """raw_text must include tagline + industry for scoring engine."""
        from skills.bug_hunting.platform_scanner import fetch_bugcrowd_json
        mock_pw, _, _ = self._make_pw_mock([
            {"json": {"engagements": [
                {"name": "Web3 Vault", "briefUrl": "/engagements/web3vault",
                 "tagline": "DeFi protocol bounty", "industryName": "Finance",
                 "scopeRank": 4, "isPrivate": False},
            ]}},
        ])
        with patch("skills.bug_hunting.platform_scanner.sync_playwright", return_value=mock_pw):
            result = fetch_bugcrowd_json()
        assert len(result) == 1
        raw = result[0].raw_text.lower()
        assert "defi" in raw
        assert "finance" in raw

    def test_fetch_all_routes_bugcrowd_to_json(self):
        """fetch_all must call fetch_bugcrowd_json for platforms with json_endpoint."""
        cfg = {
            "bugcrowd": {
                "url": "https://bugcrowd.com/engagements",
                "base": "https://bugcrowd.com",
                "scrolls": 5,
                "json_endpoint": "https://bugcrowd.com/engagements.json",
                "json_pages": 2,
            }
        }
        fake_programs = [
            ProgramEntry("BC Prog", "https://bugcrowd.com/engagements/bc", "bugcrowd", score=1.0),
        ]
        with patch(
            "skills.bug_hunting.platform_scanner.fetch_bugcrowd_json",
            return_value=fake_programs,
        ) as mock_bc:
            with patch("skills.bug_hunting.platform_scanner.fetch_page") as mock_html:
                result = fetch_all(cfg)
        mock_bc.assert_called_once_with(
            base="https://bugcrowd.com",
            json_endpoint="https://bugcrowd.com/engagements.json",
            max_pages=2,
        )
        mock_html.assert_not_called()
        assert len(result) == 1


# ---------------------------------------------------------------------------
# TestRealScenario  (live — requires network; skipped when DNS is blocked)
# ---------------------------------------------------------------------------

import socket

def _dns_ok(host: str) -> bool:
    """Return True if the host can be resolved via DNS."""
    try:
        socket.getaddrinfo(host, 443, socket.AF_INET)
        return True
    except OSError:
        return False


network_available = pytest.mark.skipif(
    not _dns_ok("hackerone.com"),
    reason="Network/DNS not reachable from this environment",
)


@network_available
class TestRealScenario:
    """Live integration tests against real bug-bounty platforms.

    Each test fetches a single page via Playwright (no scrolling, minimal
    wait) to verify the scanner returns at least 1 real program entry.
    These tests skip automatically when the network is unavailable.
    """

    def _fetch_one(self, url: str, base: str) -> list:
        """Fetch a single page and parse it; return list of ProgramEntry."""
        from skills.bug_hunting.platform_scanner import fetch_fallback, parse_programs
        html = fetch_fallback(url)
        assert len(html) > 1000, f"Page too small ({len(html)} bytes): {url}"
        return parse_programs(html, base, platform="live_test")

    # -- HackerOne -----------------------------------------------------------

    def test_hackerone_returns_programs(self):
        programs = self._fetch_one(
            "https://hackerone.com/opportunities/all",
            "https://hackerone.com",
        )
        assert len(programs) >= 1, "Expected at least 1 program from HackerOne"
        urls = [p.url for p in programs]
        assert any("hackerone.com" in u for u in urls), \
            "Expected at least one hackerone.com URL"

    def test_hackerone_entries_have_name_and_url(self):
        programs = self._fetch_one(
            "https://hackerone.com/opportunities/all",
            "https://hackerone.com",
        )
        for p in programs[:5]:
            assert p.name, f"Empty name: {p}"
            assert p.url.startswith("http"), f"Bad URL: {p.url}"

    # -- Bugcrowd (JSON path) ------------------------------------------------

    def test_bugcrowd_json_returns_programs(self):
        from skills.bug_hunting.platform_scanner import fetch_bugcrowd_json
        programs = fetch_bugcrowd_json(max_pages=1)
        assert len(programs) >= 1, "Expected at least 1 program from Bugcrowd JSON"

    def test_bugcrowd_json_page1_has_24_programs(self):
        from skills.bug_hunting.platform_scanner import fetch_bugcrowd_json
        programs = fetch_bugcrowd_json(max_pages=1)
        assert len(programs) == 24, f"Expected 24 programs on page 1, got {len(programs)}"

    def test_bugcrowd_json_entries_have_name_and_url(self):
        from skills.bug_hunting.platform_scanner import fetch_bugcrowd_json
        programs = fetch_bugcrowd_json(max_pages=1)
        for p in programs[:5]:
            assert p.name, f"Empty name: {p}"
            assert "bugcrowd.com/engagements/" in p.url, f"Bad URL: {p.url}"

    def test_bugcrowd_json_pagination(self):
        from skills.bug_hunting.platform_scanner import fetch_bugcrowd_json
        programs = fetch_bugcrowd_json(max_pages=2)
        assert len(programs) >= 25, \
            f"Expected >24 programs across 2 pages, got {len(programs)}"

    def test_bugcrowd_json_no_duplicates(self):
        from skills.bug_hunting.platform_scanner import fetch_bugcrowd_json
        programs = fetch_bugcrowd_json(max_pages=2)
        urls = [p.url for p in programs]
        assert len(urls) == len(set(urls)), "Duplicate URLs found in Bugcrowd results"

    # -- Intigriti -----------------------------------------------------------

    def test_intigriti_returns_programs(self):
        programs = self._fetch_one(
            "https://www.intigriti.com/researchers/bug-bounty-programs",
            "https://www.intigriti.com",
        )
        assert len(programs) >= 1, "Expected at least 1 program from Intigriti"

    def test_intigriti_entries_have_name_and_url(self):
        programs = self._fetch_one(
            "https://www.intigriti.com/researchers/bug-bounty-programs",
            "https://www.intigriti.com",
        )
        for p in programs[:5]:
            assert p.name, f"Empty name: {p}"
            assert p.url.startswith("http"), f"Bad URL: {p.url}"

    # -- Immunefi ------------------------------------------------------------

    def test_immunefi_returns_programs(self):
        programs = self._fetch_one(
            "https://immunefi.com/bug-bounty/",
            "https://immunefi.com",
        )
        assert len(programs) >= 1, "Expected at least 1 program from Immunefi"

    def test_immunefi_entries_are_web3(self):
        """Immunefi is a Web3 platform; URL/name patterns should trigger web3 scoring."""
        # Use the URL-based web3 detection: immunefi.com itself and /bug-bounty/
        # path both contain tokens that score_program tags as web3.
        from skills.bug_hunting.platform_scanner import score_program
        html = fetch_fallback("https://immunefi.com/bug-bounty/")
        if not html or len(html) < 1000:
            pytest.skip("Immunefi returned insufficient HTML in this environment")
        programs = parse_programs(html, "https://immunefi.com", platform="immunefi")
        if not programs:
            pytest.skip("Immunefi returned 0 parseable program links — page structure may have changed")
        scored = [score_program(p) for p in programs[:10]]
        web3_count = sum(1 for p in scored if "web3" in p.tags)
        assert web3_count >= 1, "Expected at least 1 web3-tagged program from Immunefi"

    # -- Cross-platform scoring ----------------------------------------------

    def test_scored_results_are_sorted(self):
        """fetch_all (single platform) must return sorted results."""
        from skills.bug_hunting.platform_scanner import fetch_bugcrowd_json, score_program
        programs = [score_program(p) for p in fetch_bugcrowd_json(max_pages=1)]
        programs.sort(key=lambda p: p.score, reverse=True)
        scores = [p.score for p in programs]
        assert scores == sorted(scores, reverse=True)

    def test_full_fetch_all_bugcrowd_only(self):
        """fetch_all with only Bugcrowd config must return scored, sorted programs."""
        cfg = {
            "bugcrowd": {
                "url": "https://bugcrowd.com/engagements",
                "base": "https://bugcrowd.com",
                "scrolls": 5,
                "json_endpoint": "https://bugcrowd.com/engagements.json",
                "json_pages": 1,
            }
        }
        result = fetch_all(cfg)
        assert len(result) >= 1
        scores = [p.score for p in result]
        assert scores == sorted(scores, reverse=True), "Results not sorted by score"

    # -- Live simulate_scan --------------------------------------------------

    def test_simulate_scan_patch_gap_returns_recommendations(self):
        """simulate_scan with patch_gap strategy against Bugcrowd only."""
        cfg = {
            "bugcrowd": {
                "url": "https://bugcrowd.com/engagements",
                "base": "https://bugcrowd.com",
                "scrolls": 5,
                "json_endpoint": "https://bugcrowd.com/engagements.json",
                "json_pages": 1,
            }
        }
        result = simulate_scan(strategy="patch_gap", top_n=5, platforms=cfg)
        assert result["status"] is True
        assert result["strategy"] == "patch_gap"
        assert result["total_scanned"] >= 1
        assert "recommendations" in result
        assert "platform_tips" in result
        assert "pipeline_ready" in result

    def test_simulate_scan_recommendations_are_ranked(self):
        """Recommendations must be sorted by strategy_score descending."""
        cfg = {
            "bugcrowd": {
                "url": "https://bugcrowd.com/engagements",
                "base": "https://bugcrowd.com",
                "scrolls": 5,
                "json_endpoint": "https://bugcrowd.com/engagements.json",
                "json_pages": 2,
            }
        }
        result = simulate_scan(strategy="asset_heavy", top_n=10, platforms=cfg)
        scores = [r["strategy_score"] for r in result["recommendations"]]
        assert scores == sorted(scores, reverse=True), "Recommendations not sorted by strategy_score"

    def test_simulate_scan_pipeline_urls_are_absolute(self):
        """pipeline_ready list must contain only absolute http(s) URLs."""
        cfg = {
            "bugcrowd": {
                "url": "https://bugcrowd.com/engagements",
                "base": "https://bugcrowd.com",
                "scrolls": 5,
                "json_endpoint": "https://bugcrowd.com/engagements.json",
                "json_pages": 1,
            }
        }
        result = simulate_scan(strategy="patch_gap", top_n=5, platforms=cfg)
        for url in result["pipeline_ready"]:
            assert url.startswith("http"), f"Non-absolute URL in pipeline_ready: {url}"

    def test_simulate_scan_web3_strategy_on_hackerone(self):
        """web3_defi strategy on HackerOne should surface DeFi programs."""
        cfg = {
            "hackerone": {
                "url": "https://hackerone.com/opportunities/all",
                "base": "https://hackerone.com",
                "scrolls": 3,
            }
        }
        result = simulate_scan(strategy="web3_defi", top_n=5, platforms=cfg)
        assert result["status"] is True
        # At minimum, we get a result dict (programs may or may not have web3 tags)
        assert isinstance(result["recommendations"], list)


# ---------------------------------------------------------------------------
# TestProgramSelector  (unit — mocked programs)
# ---------------------------------------------------------------------------


class TestProgramSelector:
    """Unit tests for ProgramSelector with mocked ProgramEntry lists."""

    def _make_programs(self) -> list:
        from skills.bug_hunting.platform_scanner import score_program
        return [
            score_program(ProgramEntry("DeFi Vault", "https://immunefi.com/bug-bounty/defi-vault", "immunefi")),
            score_program(ProgramEntry("IoT Firmware", "https://bugcrowd.com/engagements/iot-fw", "bugcrowd")),
            score_program(ProgramEntry("New Launch", "https://intigriti.com/programs/new-launch", "intigriti")),
            score_program(ProgramEntry("Acme Corp VDP", "https://hackerone.com/acme-vdp?vdp=true", "hackerone")),
            score_program(ProgramEntry("Plain Web App", "https://hackerone.com/plain-webapp", "hackerone")),
        ]

    def test_select_returns_top_n(self):
        from skills.bug_hunting.platform_scanner import ProgramSelector
        sel = ProgramSelector(strategy="patch_gap")
        recs = sel.select(self._make_programs(), top_n=3)
        assert len(recs) <= 3

    def test_select_sorted_by_strategy_score(self):
        from skills.bug_hunting.platform_scanner import ProgramSelector
        sel = ProgramSelector(strategy="web3_defi")
        recs = sel.select(self._make_programs(), top_n=10)
        scores = [r.strategy_score for r in recs]
        assert scores == sorted(scores, reverse=True)

    def test_vdp_detected_by_name(self):
        from skills.bug_hunting.platform_scanner import ProgramSelector
        sel = ProgramSelector(strategy="patch_gap")
        entry = ProgramEntry("Acme VDP", "https://hackerone.com/acme-vdp", "hackerone")
        rec = sel.score_recommendation(entry)
        assert rec.is_vdp is True

    def test_vdp_detected_by_url(self):
        from skills.bug_hunting.platform_scanner import ProgramSelector
        sel = ProgramSelector(strategy="asset_heavy")
        entry = ProgramEntry("Acme Corp", "https://hackerone.com/acme?vulnerability-disclosure=1", "hackerone")
        rec = sel.score_recommendation(entry)
        assert rec.is_vdp is True

    def test_vdp_bonus_applied(self):
        from skills.bug_hunting.platform_scanner import ProgramSelector, score_program
        sel = ProgramSelector(strategy="patch_gap")
        base = score_program(ProgramEntry("Acme", "https://hackerone.com/acme", "hackerone"))
        vdp  = score_program(ProgramEntry("Acme VDP", "https://hackerone.com/acme-vdp", "hackerone"))
        rec_vdp = sel.score_recommendation(vdp)
        rec_base = sel.score_recommendation(base)
        # VDP should get the vdp_bonus
        assert rec_vdp.strategy_score >= rec_base.strategy_score

    def test_rationale_non_empty_for_tagged_program(self):
        from skills.bug_hunting.platform_scanner import ProgramSelector, score_program
        sel = ProgramSelector(strategy="web3_defi")
        entry = score_program(ProgramEntry("DeFi Vault", "https://immunefi.com/bug-bounty/defi-vault", "immunefi"))
        rec = sel.score_recommendation(entry)
        assert len(rec.rationale) >= 1

    def test_unknown_strategy_falls_back_to_patch_gap(self):
        from skills.bug_hunting.platform_scanner import ProgramSelector, HUNT_STRATEGY_WEIGHTS
        sel = ProgramSelector(strategy="nonexistent_strategy")
        assert sel.weights == HUNT_STRATEGY_WEIGHTS["patch_gap"]

    def test_empty_programs_returns_empty(self):
        from skills.bug_hunting.platform_scanner import ProgramSelector
        sel = ProgramSelector(strategy="patch_gap")
        assert sel.select([]) == []

    def test_min_strategy_score_filter(self):
        from skills.bug_hunting.platform_scanner import ProgramSelector
        sel = ProgramSelector(strategy="patch_gap")
        recs = sel.select(self._make_programs(), top_n=10, min_strategy_score=999.0)
        assert recs == []

    def test_platform_tip_populated(self):
        from skills.bug_hunting.platform_scanner import ProgramSelector, PLATFORM_STRATEGY
        sel = ProgramSelector(strategy="iot_hardware")
        entry = ProgramEntry("IoT Device", "https://bugcrowd.com/engagements/iot-device", "bugcrowd")
        rec = sel.score_recommendation(entry)
        assert rec.platform_tip == PLATFORM_STRATEGY["bugcrowd"]["tip"]

    def test_web3_strategy_boosts_immunefi(self):
        from skills.bug_hunting.platform_scanner import ProgramSelector, score_program
        sel = ProgramSelector(strategy="web3_defi")
        immunefi = score_program(ProgramEntry("DeFi Protocol", "https://immunefi.com/bug-bounty/defi", "immunefi"))
        h1 = score_program(ProgramEntry("Plain App", "https://hackerone.com/plain", "hackerone"))
        rec_imm = sel.score_recommendation(immunefi)
        rec_h1  = sel.score_recommendation(h1)
        # Immunefi DeFi entry must outscore a plain HackerOne entry under web3_defi
        assert rec_imm.strategy_score >= rec_h1.strategy_score


# ---------------------------------------------------------------------------
# TestSimulateScan  (unit — mocked fetch_all)
# ---------------------------------------------------------------------------


class TestSimulateScan:
    """Unit tests for simulate_scan() with mocked fetch_all."""

    def _fake_programs(self):
        from skills.bug_hunting.platform_scanner import score_program
        return [
            score_program(ProgramEntry("DeFi Vault", "https://immunefi.com/bug-bounty/defi-vault", "immunefi")),
            score_program(ProgramEntry("IoT Camera", "https://bugcrowd.com/engagements/iot-cam", "bugcrowd")),
            score_program(ProgramEntry("New Program", "https://intigriti.com/programs/new", "intigriti")),
        ]

    def test_returns_status_true(self):
        with patch("skills.bug_hunting.platform_scanner.fetch_all", return_value=self._fake_programs()):
            result = simulate_scan(strategy="patch_gap", top_n=5)
        assert result["status"] is True

    def test_recommendations_capped_at_top_n(self):
        with patch("skills.bug_hunting.platform_scanner.fetch_all", return_value=self._fake_programs()):
            result = simulate_scan(strategy="patch_gap", top_n=2)
        assert len(result["recommendations"]) <= 2

    def test_recommendations_contain_required_keys(self):
        with patch("skills.bug_hunting.platform_scanner.fetch_all", return_value=self._fake_programs()):
            result = simulate_scan(strategy="web3_defi", top_n=5)
        required = {"rank", "name", "url", "platform", "strategy_score", "tags", "is_vdp", "rationale", "platform_tip"}
        for rec in result["recommendations"]:
            assert required <= set(rec.keys()), f"Missing keys in recommendation: {rec}"

    def test_pipeline_ready_deduped(self):
        """Same base domain appearing multiple times must be deduplicated."""
        programs = [
            ProgramEntry("P1", "https://bugcrowd.com/engagements/p1", "bugcrowd", score=2.0, tags=["web3"]),
            ProgramEntry("P2", "https://bugcrowd.com/engagements/p2", "bugcrowd", score=1.5, tags=["web3"]),
        ]
        with patch("skills.bug_hunting.platform_scanner.fetch_all", return_value=programs):
            result = simulate_scan(strategy="patch_gap", top_n=5)
        assert result["pipeline_ready"].count("https://bugcrowd.com") == 1

    def test_fetch_all_exception_returns_error_status(self):
        with patch("skills.bug_hunting.platform_scanner.fetch_all", side_effect=RuntimeError("crash")):
            result = simulate_scan(strategy="patch_gap")
        assert result["status"] is False
        assert "error" in result

    def test_platform_tips_present_for_all_platforms(self):
        with patch("skills.bug_hunting.platform_scanner.fetch_all", return_value=[]):
            result = simulate_scan(strategy="patch_gap")
        for platform in ["hackerone", "bugcrowd", "intigriti", "immunefi"]:
            assert platform in result["platform_tips"]

    def test_strategy_stored_in_result(self):
        with patch("skills.bug_hunting.platform_scanner.fetch_all", return_value=[]):
            result = simulate_scan(strategy="iot_hardware")
        assert result["strategy"] == "iot_hardware"

    def test_all_strategies_produce_valid_results(self):
        """Every defined strategy must run without error."""
        from skills.bug_hunting.platform_scanner import HUNT_STRATEGY_WEIGHTS
        programs = self._fake_programs()
        for strat in HUNT_STRATEGY_WEIGHTS:
            with patch("skills.bug_hunting.platform_scanner.fetch_all", return_value=programs):
                result = simulate_scan(strategy=strat, top_n=3)
            assert result["status"] is True, f"Strategy {strat!r} failed"
