"""Cache warm-up tests (MASTERPLAN §5.2). Fake providers only: no network, no real LLM."""

import io
import json
import shutil
from pathlib import Path

from tool.ai import warm as warm_module
from tool.ai.explain import Explainer
from tool.ai.provider import ProviderUnavailable
from tool.ai.warm import main, result_files, warm

SCAN = Path(__file__).parent / "fixtures" / "contract" / "example_scan.json"
ERROR = Path(__file__).parent / "fixtures" / "contract" / "example_error.json"
FINDINGS = len(json.loads(SCAN.read_text(encoding="utf-8"))["findings"])


class CitingProvider:
    """Answers every task with a short grounded text that cites the asked-for finding."""

    name = "fake:warm"

    def __init__(self, reply_for=None, error=None):
        self.reply_for, self.error = reply_for, error
        self.calls = 0

    def complete(self, system, prompt, timeout):
        self.calls += 1
        if self.error:
            raise self.error
        eid = json.loads(prompt)["finding"]
        if self.reply_for:
            return self.reply_for(eid)
        return json.dumps(
            {
                "en": "This device has a risky service turned on.",
                "ro": "Acest dispozitiv are pornit un serviciu riscant.",
                "cites": [eid],
            }
        )


def run(paths, explainer):
    out = io.StringIO()
    counts = warm(paths, explainer, out=out)
    return counts, out.getvalue().splitlines()


def test_first_run_fills_cache_second_run_uses_it(tmp_path):
    first = CitingProvider()
    counts, lines = run([SCAN], Explainer(first, cache_dir=tmp_path / "cache"))
    assert counts == {"ai": FINDINGS}
    assert first.calls == FINDINGS
    assert len(list((tmp_path / "cache").glob("*.json"))) == FINDINGS
    assert lines[0].startswith("example_scan.json E1 ")

    second = CitingProvider(error=ProviderUnavailable("must not be called"))
    counts, lines = run([SCAN], Explainer(second, cache_dir=tmp_path / "cache"))
    assert counts == {"cache": FINDINGS}
    assert second.calls == 0
    assert all(line.endswith(": cache") for line in lines)


def test_rejected_answer_is_not_cached(tmp_path):
    # Invents a number that isn't in the evidence, so the grounding checker rejects it.
    def invented(eid):
        en = "Port 31337 is open on this device."
        ro = "Portul 31337 este deschis pe acest dispozitiv."
        return json.dumps({"en": en, "ro": ro, "cites": [eid]})

    log = tmp_path / "rejections.jsonl"
    explainer = Explainer(
        CitingProvider(reply_for=invented), cache_dir=tmp_path / "cache", rejection_log=log
    )
    counts, lines = run([SCAN], explainer)
    assert counts == {"template": FINDINGS}
    assert all(": template:rejected:" in line for line in lines)
    assert not (tmp_path / "cache").exists() or not list((tmp_path / "cache").iterdir())
    assert explainer.rejection_count() == FINDINGS


def test_unavailable_provider_falls_back_and_continues(tmp_path):
    explainer = Explainer(CitingProvider(error=ProviderUnavailable("down")), cache_dir=tmp_path)
    counts, lines = run([SCAN], explainer)
    assert counts == {"template": FINDINGS}
    assert len(lines) == FINDINGS


def test_unreadable_and_error_files_are_skipped(tmp_path):
    bad = tmp_path / "broken.json"
    bad.write_text("{not json", encoding="utf-8")
    counts, lines = run([bad, ERROR, SCAN], Explainer(CitingProvider(), cache_dir=tmp_path / "c"))
    assert counts == {"skipped": 2, "ai": FINDINGS}
    assert lines[0] == "broken.json: skipped (not a readable ScanResult)"


def test_folder_input_reads_json_files_in_name_order(tmp_path):
    shutil.copy(SCAN, tmp_path / "b.json")
    shutil.copy(SCAN, tmp_path / "a.json")
    (tmp_path / "notes.txt").write_text("ignored", encoding="utf-8")
    assert [p.name for p in result_files([tmp_path])] == ["a.json", "b.json"]


def test_output_carries_no_device_details(tmp_path):
    data = json.loads(SCAN.read_text(encoding="utf-8"))
    secrets = {d["ip"] for d in data["devices"]}
    secrets |= {d["hostname"] for d in data["devices"] if d.get("hostname")}
    secrets |= {d["mac_masked"] for d in data["devices"] if d.get("mac_masked")}
    _, lines = run([SCAN], Explainer(CitingProvider(), cache_dir=tmp_path))
    text = "\n".join(lines)
    assert not any(s in text for s in secrets)
    assert "risky service" not in text  # the AI text itself is not printed


def test_main_with_ai_off_writes_nothing(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("TOOL_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("LLM_PROVIDER", "none")
    assert main([str(SCAN)]) == 0
    assert "AI is off" in capsys.readouterr().out
    assert not (tmp_path / "data").exists()


def test_main_uses_the_serve_cache_location(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("TOOL_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(warm_module, "provider_from_env", lambda: CitingProvider())
    assert main([str(SCAN)]) == 0
    assert len(list((tmp_path / "data" / "ai_cache").glob("*.json"))) == FINDINGS
    assert f"ai={FINDINGS}" in capsys.readouterr().out


def test_main_refuses_root(monkeypatch):
    monkeypatch.setattr(warm_module.os, "geteuid", lambda: 0, raising=False)
    assert main([str(SCAN)]) == 2
