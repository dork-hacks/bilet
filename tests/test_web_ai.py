"""The AI layer on the home screen: opt-in toggle, data note, label, fallback (#30)."""

import json
from pathlib import Path

from fastapi.testclient import TestClient

from tool.ai.explain import Explainer
from tool.ai.provider import ProviderUnavailable
from tool.content import finding_text
from tool.content.ui import UI
from tool.web.app import create_app
from tool.web.view import home_view, most_dangerous

FIXTURES = Path(__file__).parent / "fixtures" / "contract"
SCAN = json.loads((FIXTURES / "example_scan.json").read_text(encoding="utf-8"))

AI_EN = "This device lets people on your Wi-Fi in too easily."
AI_RO = "Acest dispozitiv îi lasă prea ușor pe cei din rețeaua dumneavoastră să intre."


class CitingProvider:
    """Answers with a grounded reply that cites the finding it was asked about."""

    name = "fake:citing"

    def __init__(self, en=AI_EN, ro=AI_RO, error=None):
        self.en, self.ro, self.error = en, ro, error
        self.prompts: list[str] = []

    def complete(self, system, prompt, timeout):
        self.prompts.append(prompt)
        if self.error:
            raise self.error
        eid = json.loads(prompt)["finding"]
        return json.dumps({"en": self.en, "ro": self.ro, "cites": [eid]})


def top_template(lang):
    _, finding = most_dangerous(SCAN)
    return finding_text(finding["code"], lang).explanation


def get(explainer, **params):
    return TestClient(create_app(lambda: SCAN, explainer=explainer)).get("/", params=params)


# --- view ---------------------------------------------------------------------------------


def test_ai_is_off_by_default_and_the_provider_is_never_called():
    provider = CitingProvider()
    view = home_view(SCAN, "en", Explainer(provider))
    assert view.ai_available and not view.ai_on
    assert view.first.explanation == top_template("en")
    assert view.first.explanation_source == "template"
    assert provider.prompts == []


def test_ai_on_shows_the_grounded_answer():
    view = home_view(SCAN, "ro", Explainer(CitingProvider()), ai_on=True)
    assert view.first.explanation == AI_RO
    assert view.first.explanation_source == "ai"


def test_ai_on_but_unavailable_falls_back_to_the_template():
    explainer = Explainer(CitingProvider(error=ProviderUnavailable("down")))
    view = home_view(SCAN, "en", explainer, ai_on=True)
    assert view.first.explanation == top_template("en")
    assert view.first.explanation_source == "template"


def test_rejected_answer_falls_back_to_the_template():
    # 8080 is not in the evidence, so the grounding checker rejects it.
    explainer = Explainer(CitingProvider(en="Port 8080 is open too."))
    view = home_view(SCAN, "en", explainer, ai_on=True)
    assert view.first.explanation == top_template("en")
    assert view.first.explanation_source == "template"


def test_no_provider_means_ai_is_not_available():
    view = home_view(SCAN, "en", Explainer(None), ai_on=True)
    assert not view.ai_available
    assert view.first.explanation_source == "template"


def test_no_hostname_or_ip_reaches_the_provider():
    provider = CitingProvider()
    home_view(SCAN, "en", Explainer(provider), ai_on=True)
    (prompt,) = provider.prompts
    for device in SCAN["devices"]:
        assert device["ip"] not in prompt
        if device.get("hostname"):
            assert device["hostname"] not in prompt
        if device.get("mac_masked"):
            assert device["mac_masked"] not in prompt


# --- page ---------------------------------------------------------------------------------


def test_page_offers_the_opt_in_and_says_what_leaves_the_device():
    page = get(Explainer(CitingProvider()), lang="en").text
    assert UI["ai_off_state"]["en"] in page
    assert UI["ai_turn_on"]["en"] in page
    assert UI["ai_data_note"]["en"].split(".")[0] in page
    assert UI["standard_explanation"]["en"] in page
    assert "ai=1" in page


def test_page_with_ai_on_shows_the_ai_label_and_keeps_it_across_language_links():
    page = get(Explainer(CitingProvider()), lang="en", ai="1").text
    assert UI["explained_by_ai"]["en"] in page
    assert UI["ai_turn_off"]["en"] in page
    assert "?lang=ro&amp;ai=1" in page


def test_only_ai_1_turns_it_on():
    provider = CitingProvider()
    for value in ("true", "yes", "0", ""):
        get(Explainer(provider), ai=value)
    assert provider.prompts == []


def test_page_without_a_provider_says_ai_is_not_set_up():
    page = get(None, lang="ro", ai="1").text
    assert UI["ai_not_set_up"]["ro"] in page
    assert UI["standard_explanation"]["ro"] in page


def test_ai_text_is_escaped():
    # Markup that passes the grounding check is still shown as text, never as HTML.
    hostile = Explainer(CitingProvider(en="Your <b>device</b> is open to anyone."))
    assert home_view(SCAN, "en", hostile, ai_on=True).first.explanation_source == "ai"
    page = get(hostile, ai="1", lang="en").text
    assert "Your &lt;b&gt;device&lt;/b&gt; is open to anyone." in page
    assert "<b>device</b>" not in page
