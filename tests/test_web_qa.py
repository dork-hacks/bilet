"""The plan and the question form on the home screen (#50). Fake providers only."""

import json
from pathlib import Path

from fastapi.testclient import TestClient
from markupsafe import escape  # what Jinja's autoescape uses

from tool.ai.evidence import build_evidence, ranked_ids
from tool.ai.explain import Explainer
from tool.content.ui import UI
from tool.web.app import MAX_FORM_BYTES, create_app
from tool.web.view import home_view, local_plan_steps

FIXTURES = Path(__file__).parent / "fixtures" / "contract"
SCAN = json.loads((FIXTURES / "example_scan.json").read_text(encoding="utf-8"))
EVIDENCE = build_evidence(SCAN)
TOP = ranked_ids(EVIDENCE)[0]

PLAN_EN = "First close the risky service on Device A."
PLAN_RO = "Mai întâi închide serviciul riscant de pe Dispozitivul A."
ANSWER_EN = "Yes, that device has a risky service open."
ANSWER_RO = "Da, acel dispozitiv are un serviciu riscant deschis."


class TaskProvider:
    """Replies per task: a grounded plan that cites the top finding, and a set answer."""

    name = "fake:task"

    def __init__(self, answer=None, plan_cites=None):
        self.answer = answer or {"en": ANSWER_EN, "ro": ANSWER_RO, "cites": [TOP]}
        self.plan_cites = plan_cites or [TOP]
        self.prompts: list[dict] = []

    def complete(self, system, prompt, timeout):
        task = json.loads(prompt)
        self.prompts.append(task)
        if task["task"] == "summarise":
            return json.dumps({"en": PLAN_EN, "ro": PLAN_RO, "cites": self.plan_cites})
        if task["task"] == "answer":
            return json.dumps(self.answer)
        return json.dumps({"en": "x", "ro": "y", "cites": [task["finding"]]})

    def tasks(self, name):
        return [p for p in self.prompts if p["task"] == name]


def client(explainer):
    return TestClient(create_app(lambda: SCAN, explainer=explainer))


def ask(provider, **form):
    return client(Explainer(provider)).post("/ask", data=form)


# --- plan ---------------------------------------------------------------------------------


def test_plan_without_ai_is_the_built_in_list_in_the_rules_order():
    view = home_view(SCAN, "en", Explainer(TaskProvider()))
    assert view.plan.source == "template"
    assert view.plan.steps == tuple(local_plan_steps(SCAN, "en"))
    assert view.plan.text is None


def test_plan_with_ai_on_is_the_grounded_paragraph():
    view = home_view(SCAN, "ro", Explainer(TaskProvider()), ai_on=True)
    assert view.plan.source == "ai"
    assert view.plan.text == PLAN_RO


def test_plan_that_skips_the_top_finding_falls_back_to_the_list():
    later = ranked_ids(EVIDENCE)[1:2] or ["E99"]
    view = home_view(SCAN, "en", Explainer(TaskProvider(plan_cites=later)), ai_on=True)
    assert view.plan.source == "template"
    assert view.plan.steps


def test_no_plan_when_nothing_scores_points():
    clean = {**SCAN, "score": 100, "findings": [], "devices": []}
    assert home_view(clean, "en").plan is None


def test_page_shows_the_plan_with_its_label():
    page = client(Explainer(TaskProvider())).get("/", params={"lang": "en"}).text
    assert UI["plan_heading"]["en"] in page
    assert escape(local_plan_steps(SCAN, "en")[0]) in page


# --- question form ------------------------------------------------------------------------


def test_question_form_also_works_with_ai_off():
    app = client(Explainer(TaskProvider()))
    assert 'action="/ask"' in app.get("/", params={"ai": "0"}).text
    assert 'action="/ask"' in app.get("/", params={"ai": "1"}).text


def test_ask_shows_the_grounded_answer_and_the_question_escaped():
    provider = TaskProvider()
    question = "Is it <b>safe</b>?"
    page = ask(provider, lang="en", ai="1", q=question).text
    assert ANSWER_EN in page
    assert UI["explained_by_ai"]["en"] in page
    assert "Is it &lt;b&gt;safe&lt;/b&gt;?" in page
    assert "<b>safe</b>" not in page
    (asked,) = provider.tasks("answer")
    assert asked["untrusted_question"] == question


def test_invented_port_in_the_answer_gives_cant_tell():
    answer = {"en": "Port 31337 is open.", "ro": "Portul 31337 e deschis.", "cites": [TOP]}
    page = ask(TaskProvider(answer=answer), lang="en", ai="1", q="Anything else open?").text
    assert "31337" not in page
    assert escape(UI["ai_cant_tell"]["en"]) in page


def test_ask_with_ai_off_never_calls_the_provider():
    provider = TaskProvider()
    page = ask(provider, lang="en", ai="0", q="Is my camera safe?").text
    assert provider.prompts == []
    assert 'action="/ask"' in page
    assert UI["chat_off"]["en"] in page
    assert escape(local_plan_steps(SCAN, "en")[0]) in page


def test_empty_question_shows_no_answer_and_no_call():
    provider = TaskProvider()
    ask(provider, lang="en", ai="1", q="   ")
    assert provider.tasks("answer") == []


def test_oversized_form_is_refused_without_calling_the_provider():
    provider = TaskProvider()
    response = ask(provider, lang="en", ai="1", q="a" * (MAX_FORM_BYTES + 1))
    assert response.status_code == 413
    assert provider.prompts == []


def test_language_links_on_the_answer_page_go_back_home():
    page = ask(TaskProvider(), lang="ro", ai="1", q="E sigur?").text
    assert 'href="/?lang=en&amp;ai=1"' in page


def test_get_on_ask_is_not_allowed():
    provider = TaskProvider()
    response = client(Explainer(provider)).get("/ask", params={"ai": "1", "q": "hi"})
    assert response.status_code == 405
    assert provider.tasks("answer") == []


def test_cross_origin_question_never_calls_provider():
    provider = TaskProvider()
    response = client(Explainer(provider)).post(
        "/ask",
        data={"ai": "1", "q": "Is this safe?"},
        headers={"Origin": "https://other.example"},
    )
    assert response.status_code == 403
    assert provider.prompts == []


def test_chat_without_provider_shows_standard_answer():
    response = client(None).post("/ask", data={"lang": "ro", "q": "Ce repar?"})
    assert response.status_code == 200
    assert UI["chat_off"]["ro"] in response.text
    assert local_plan_steps(SCAN, "ro")[0] in response.text
    assert 'class="chat-message assistant chat-answer"' in response.text
