"""Turns one ScanResult dict (docs/contracts/data-model.md) into what the home screen shows.

Pure functions, no web framework, so the logic is tested without a server. Every text
comes from tool.content. RAW scan fields are passed through as data and escaped by the
template (Jinja autoescape), never here.
"""

from dataclasses import dataclass

from tool.ai.evidence import build_evidence
from tool.ai.explain import SOURCE_TEMPLATE, Explainer
from tool.content import DEFAULT_LANG, LANGS, device_type_label, file_error_message, finding_text
from tool.content.ui import SCORE_BANDS, UI

GOOD_FROM = 80  # score >= 80: green
WARN_FROM = 50  # score >= 50: amber, below: red


@dataclass(frozen=True)
class Band:
    key: str  # good | warn | bad: also the CSS class
    icon: str
    label: str


@dataclass(frozen=True)
class FirstStep:
    device: str  # "Camera at 192.168.1.40"
    hostname: str | None  # RAW, escaped by the template
    risk_points: int
    finding_title: str
    step: str
    explanation: str
    explanation_source: str = SOURCE_TEMPLATE  # "ai" | "template": the UI label


@dataclass(frozen=True)
class HomeView:
    lang: str
    kind: str  # "ok" | "error" | "empty"
    file: str | None = None
    score: int | None = None
    band: Band | None = None
    first: FirstStep | None = None
    error_message: str | None = None
    ai_on: bool = False  # the user opted in (MASTERPLAN §5.4: AI is opt-in)
    ai_available: bool = False  # a provider is configured (LLM_PROVIDER)


def explain_first(
    result: dict, finding: dict, lang: str, explainer: Explainer | None
) -> tuple[str, str]:
    """(text, source) for the top finding. The built-in text unless AI is on and grounded."""
    template = finding_text(finding["code"], lang).explanation
    if explainer is None:
        return template, SOURCE_TEMPLATE
    evidence = build_evidence(result)
    eid = next((e for e, f in evidence.finding_refs.items() if f == finding.get("id")), None)
    if eid is None:
        return template, SOURCE_TEMPLATE
    answer = explainer.explain_finding(evidence, eid)
    return answer.text(lang), answer.source


def pick_lang(lang: str | None) -> str:
    return lang if lang in LANGS else DEFAULT_LANG


def t(key: str, lang: str) -> str:
    return UI[key][lang]


def score_band(score: int, lang: str) -> Band:
    key = "good" if score >= GOOD_FROM else "warn" if score >= WARN_FROM else "bad"
    band = SCORE_BANDS[key]
    return Band(key, band["icon"], band[lang])


def most_dangerous(result: dict) -> tuple[dict, dict] | None:
    """The device with the most risk points and its highest-point finding.

    Ties go to the first device and the first finding in contract order (IP, port,
    code), so the answer is the same on every run. None when nothing scores points.
    """
    findings = {f["id"]: f for f in result.get("findings", [])}
    best_device, best_finding = None, None
    for device in result.get("devices", []):
        if device.get("risk_points", 0) <= 0:
            continue
        if best_device is not None and device["risk_points"] <= best_device["risk_points"]:
            continue
        own = [findings[i] for i in device.get("finding_ids", []) if i in findings]
        top = max(own, key=lambda f: f.get("points", 0), default=None)
        if top is not None and top.get("points", 0) > 0:
            best_device, best_finding = device, top
    return (best_device, best_finding) if best_device else None


def home_view(
    result: dict | None,
    lang: str | None = DEFAULT_LANG,
    explainer: Explainer | None = None,
    ai_on: bool = False,
) -> HomeView:
    """The home screen. `explainer` is used only when the user opted in (`ai_on`)."""
    lang = pick_lang(lang)
    ai_available = explainer is not None and explainer.provider is not None
    ai = {"ai_on": ai_on, "ai_available": ai_available}
    if result is None:
        return HomeView(lang=lang, kind="empty", **ai)
    file = result.get("file")
    if result.get("status") != "ok":
        code = (result.get("error") or {}).get("code", "")
        message = file_error_message(code, lang)
        return HomeView(lang=lang, kind="error", file=file, error_message=message, **ai)

    score = int(result.get("score") or 0)
    first = None
    pick = most_dangerous(result)
    if pick is not None:
        device, finding = pick
        text = finding_text(finding["code"], lang)
        label = device_type_label(device.get("device_type_guess", "unknown"), lang)
        explanation, source = explain_first(
            result, finding, lang, explainer if ai_on and ai_available else None
        )
        first = FirstStep(
            device=t("device_at", lang).replace("{device}", label).replace("{ip}", device["ip"]),
            hostname=device.get("hostname"),
            risk_points=device["risk_points"],
            finding_title=text.title,
            step=text.steps[0] if text.steps else text.explanation,
            explanation=explanation,
            explanation_source=source,
        )
    return HomeView(
        lang=lang,
        kind="ok",
        file=file,
        score=score,
        band=score_band(score, lang),
        first=first,
        **ai,
    )
