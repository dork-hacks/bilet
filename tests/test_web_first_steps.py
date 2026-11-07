"""Local guidance agrees across surfaces without entering cloud evidence."""

import copy
import json
from pathlib import Path

import pytest

from tool.ai.evidence import build_evidence
from tool.ai.explain import SOURCE_TEMPLATE, Explainer, summary_steps
from tool.ai.provider import ProviderUnavailable
from tool.content import finding_text
from tool.content.device_steps import FIX_PREFIXES
from tool.engine.result import analyze_file
from tool.web.report import report_view
from tool.web.view import answer_question, device_fix_steps, home_view, network_plan

FIXTURES = Path(__file__).parent / "fixtures" / "validation"


@pytest.mark.parametrize("lang", ["ro", "en"])
@pytest.mark.parametrize("filename", ["V4_legacy.xml", "V6a_before.xml"])
def test_local_surfaces_share_the_device_fixing_action(filename, lang):
    result = analyze_file(FIXTURES / filename, salt=b"test").to_dict()
    before = copy.deepcopy(result)
    view = home_view(result, lang)
    report = report_view(result, lang)
    reply = answer_question(result, "What should I fix first?", lang, None)
    devices = {d["device_key"]: d for d in result["devices"]}
    findings = sorted(result["findings"], key=lambda f: -f["points"])[:3]
    for finding, plan_step, report_item in zip(
        findings, view.plan.steps, report["findings"], strict=True
    ):
        steps = device_fix_steps(devices[finding["device_key"]], finding["code"], lang, finding)
        expected = next(
            (s.removeprefix(FIX_PREFIXES[lang]) for s in steps if s.startswith(FIX_PREFIXES[lang])),
            steps[0],
        )
        assert expected in plan_step
        assert report_item["step"] == expected
        assert expected in reply.text
    assert view.first.step == report["findings"][0]["step"]
    assert reply.source == SOURCE_TEMPLATE
    assert result == before


@pytest.mark.parametrize("lang", ["ro", "en"])
def test_unavailable_ai_plan_keeps_local_actions_and_prompt_stays_generic(lang):
    result = analyze_file(FIXTURES / "V4_legacy.xml", salt=b"test").to_dict()

    class UnavailableProvider:
        name = "fake:unavailable"

        def complete(self, system, prompt, timeout):
            self.prompt = prompt
            raise ProviderUnavailable("offline")

    provider = UnavailableProvider()
    expected = network_plan(result, lang, None)
    assert network_plan(result, lang, Explainer(provider)) == expected
    sent = json.loads(provider.prompt)
    assert sent["evidence"] == build_evidence(result).payload
    for device in result["devices"]:
        assert device["ip"] not in provider.prompt
        if device.get("hostname"):
            assert device["hostname"] not in provider.prompt
    # The AI's own fallback/reference text remains generic, with no local addresses.
    for step in summary_steps(build_evidence(result), lang):
        assert all(device["ip"] not in step for device in result["devices"])


@pytest.mark.parametrize("lang", ["ro", "en"])
def test_report_without_device_context_uses_generic_step(lang):
    result = analyze_file(FIXTURES / "V4_legacy.xml", salt=b"test").to_dict()
    result["devices"] = []
    report = report_view(result, lang)
    finding = max(result["findings"], key=lambda f: f["points"])
    assert report["findings"][0]["step"] == finding_text(finding["code"], lang).steps[0]
