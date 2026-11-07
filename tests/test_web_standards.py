"""CIS / OWASP IoT references per finding and the AI blocked-answer count (#66)."""

import json
from pathlib import Path

from fastapi.testclient import TestClient

from tool.ai.explain import Explainer
from tool.content import finding_text, standards_line
from tool.content.texts import FINDINGS
from tool.content.ui import UI
from tool.web.app import create_app
from tool.web.view import device_list, home_view

FIXTURES = Path(__file__).parent / "fixtures" / "contract"
SCAN = json.loads((FIXTURES / "example_scan.json").read_text(encoding="utf-8"))


class SilentProvider:
    """Never answers, so every AI call falls back. Only used to make AI "available"."""

    name = "fake:silent"

    def complete(self, system, prompt, timeout):
        return "not json"


# --- references ---------------------------------------------------------------------------


def test_every_catalog_code_has_a_cis_and_an_owasp_reference():
    assert len(FINDINGS) == 15
    for code in FINDINGS:
        text = finding_text(code, "en")
        assert text.cis, code
        assert text.owasp_iot, code


def test_standards_line_lists_both_frameworks_in_both_languages():
    for lang in ("ro", "en"):
        line = standards_line("TELNET_OPEN", lang)
        assert line.startswith(UI["standards"][lang])
        assert "CIS Controls v8: 4.8, 3.10" in line
        assert "OWASP IoT Top 10: I2, I7" in line


def test_unknown_code_has_no_standards_line():
    assert standards_line("NOT_A_CODE", "en") is None


def test_each_finding_item_carries_its_references():
    risky, _ = device_list(SCAN, "en")
    for device in risky:
        for finding in device.findings:
            assert finding.standards == standards_line(finding.code, "en")
            assert finding.standards


def test_page_shows_the_references_in_both_languages():
    for lang in ("ro", "en"):
        html = TestClient(create_app(lambda: SCAN)).get("/", params={"lang": lang}).text
        assert UI["standards"][lang] in html
        assert "OWASP IoT Top 10:" in html


# --- blocked-answer count -----------------------------------------------------------------


def test_rejection_count_reads_the_log(tmp_path):
    log = tmp_path / "ai_rejections.jsonl"
    log.write_text('{"time": 1, "reason": "unknown_port"}\n\n{"time": 2, "reason": "x"}\n')
    assert Explainer(SilentProvider(), rejection_log=log).rejection_count() == 2


def test_rejection_count_is_zero_without_a_log(tmp_path):
    missing = tmp_path / "missing.jsonl"
    assert Explainer(SilentProvider(), rejection_log=missing).rejection_count() == 0
    assert Explainer(SilentProvider()).rejection_count() == 0


def test_rejection_count_is_zero_when_the_log_is_unreadable(tmp_path):
    folder = tmp_path / "a_folder_not_a_file"
    folder.mkdir()
    assert Explainer(SilentProvider(), rejection_log=folder).rejection_count() == 0


def test_blocked_count_only_with_ai_on(tmp_path):
    log = tmp_path / "ai_rejections.jsonl"
    log.write_text('{"time": 1, "reason": "unknown_port"}\n' * 3)
    explainer = Explainer(SilentProvider(), rejection_log=log)
    assert home_view(SCAN, "en", explainer, ai_on=False).ai_blocked is None
    # Turning AI on calls the silent provider, whose non-JSON replies are rejections too.
    on = home_view(SCAN, "en", explainer, ai_on=True)
    assert on.ai_blocked is not None and on.ai_blocked >= 3


def test_page_shows_the_blocked_count_with_ai_on(tmp_path):
    log = tmp_path / "ai_rejections.jsonl"
    explainer = Explainer(SilentProvider(), rejection_log=log)
    app = TestClient(create_app(lambda: SCAN, explainer=explainer))
    off = app.get("/", params={"lang": "en", "ai": "0"}).text
    assert UI["ai_blocked"]["en"].split("{n}")[0] not in off
    for lang in ("ro", "en"):
        on = app.get("/", params={"lang": lang, "ai": "1"}).text
        count = explainer.rejection_count()
        assert UI["ai_blocked"][lang].replace("{n}", str(count)) in on
