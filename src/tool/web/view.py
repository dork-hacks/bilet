"""Turns one ScanResult dict (docs/contracts/data-model.md) into what the home screen shows.

Pure functions, no web framework, so the logic is tested without a server. Every text
comes from tool.content. RAW scan fields are passed through as data and escaped by the
template (Jinja autoescape), never here.
"""

from collections.abc import Iterable
from dataclasses import dataclass

from tool.ai.evidence import build_evidence, ranked_items
from tool.ai.explain import SOURCE_TEMPLATE, SUMMARY_ITEMS, Explainer, clean_question
from tool.content import (
    DEFAULT_LANG,
    LANGS,
    alert_message,
    device_type_label,
    file_error_message,
    finding_text,
    fix_steps,
    severity_label,
    standards_line,
)
from tool.content.device_steps import FIX_PREFIXES
from tool.content.ui import SCORE_BANDS, UI
from tool.history import Alert

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
class FindingItem:
    code: str
    title: str
    severity: str  # high | medium | low | info: also the CSS class
    severity_label: str  # always shown as text, so colour is never the only signal
    points: int
    port_label: str | None  # "554/tcp", None for UNKNOWN_DEVICE
    explanation: str
    steps: tuple[str, ...]
    standards: str | None = None  # "Security standards: CIS Controls v8: … · OWASP IoT …"


@dataclass(frozen=True)
class DeviceItem:
    anchor: str  # "device-192-168-1-40": a stable id for links and tests
    label: str  # the device type, e.g. "Camera"
    ip: str
    mac_masked: str | None
    hostname: str | None  # RAW, escaped by the template
    risk_points: int
    findings: tuple[FindingItem, ...] = ()
    device_type: str = "unknown"  # the rules' guess, picks the small icon (#162)


@dataclass(frozen=True)
class Plan:
    """The "what to do, in order" plan under "Do this first" (#50).

    Built-in: `steps` is a list in the rules' order. AI: `text` is one short paragraph
    that the grounding checker accepted, and it cites the findings in the same order.
    """

    steps: tuple[str, ...] = ()
    text: str | None = None
    source: str = SOURCE_TEMPLATE


@dataclass(frozen=True)
class QuestionReply:
    question: str  # what the owner typed, cleaned; escaped by the template
    text: str
    source: str  # "ai" | "template"


@dataclass(frozen=True)
class HomeView:
    lang: str
    kind: str  # "ok" | "error" | "empty"
    file: str | None = None
    score: int | None = None
    band: Band | None = None
    first: FirstStep | None = None
    error_message: str | None = None
    devices: tuple[DeviceItem, ...] = ()  # devices with findings, most dangerous first
    safe_devices: tuple[DeviceItem, ...] = ()  # devices with no findings, in scan order
    ai_on: bool = False  # the user opted in (MASTERPLAN §5.4: AI is opt-in)
    ai_available: bool = False  # a provider is configured (LLM_PROVIDER)
    plan: Plan | None = None  # None when nothing scores points
    reply: QuestionReply | None = None  # the answer to the owner's question, if they asked
    ai_blocked: int | None = None  # AI answers the safety check replaced; None with AI off
    alerts: tuple[str, ...] = ()  # what appeared since the previous check (FR-13), as text


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


def local_plan_steps(result: dict, lang: str) -> tuple[str, ...]:
    """Device-specific actions for local display, in the evidence's stable rules order.

    Keep these separate from AI summary text: device addresses must never enter prompts.
    """
    evidence = build_evidence(result)
    devices = {device.get("device_key"): device for device in result.get("devices", [])}
    findings = {finding.get("id"): finding for finding in result.get("findings", [])}
    pairs = [(d, f) for d, f in ranked_items(evidence) if (f.get("points") or 0) > 0]
    steps = []
    for device_ref, item in pairs[:SUMMARY_ITEMS]:
        device = devices[evidence.device_refs[device_ref["device"]]]
        finding = findings[evidence.finding_refs[item["id"]]]
        text = finding_text(finding.get("code", ""), lang)
        label = device_type_label(device.get("device_type_guess") or "unknown", lang)
        steps.append(f"{text.title} ({label}): {first_fix_step(device, finding, lang)}")
    return tuple(steps)


def network_plan(result: dict, lang: str, explainer: Explainer | None) -> Plan | None:
    """The plan for the whole network. The AI paragraph only if AI is on and grounded."""
    evidence = build_evidence(result)
    steps = local_plan_steps(result, lang)
    if not steps:
        return None
    if explainer is not None:
        summary = explainer.summarise(evidence)
        if summary.source != SOURCE_TEMPLATE:
            return Plan(text=summary.text(lang), source=summary.source)
    return Plan(steps=steps)


def answer_question(
    result: dict, question: str, lang: str, explainer: Explainer | None
) -> QuestionReply | None:
    """One grounded answer (FR-12). None for an empty question, so nothing is shown."""
    question = clean_question(question)
    if not question:
        return None
    if explainer is None:
        steps = local_plan_steps(result, lang)
        text = " ".join(steps) if steps else t("ai_summary_nothing", lang)
        return QuestionReply(question, text, SOURCE_TEMPLATE)
    reply = explainer.answer(build_evidence(result), question)
    return QuestionReply(question, reply.text(lang), reply.source)


def pick_lang(lang: str | None) -> str:
    return lang if lang in LANGS else DEFAULT_LANG


def t(key: str, lang: str) -> str:
    return UI[key][lang]


def score_band(score: int, lang: str) -> Band:
    key = "good" if score >= GOOD_FROM else "warn" if score >= WARN_FROM else "bad"
    band = SCORE_BANDS[key]
    return Band(key, band["icon"], band[lang])


def ranked_devices(result: dict) -> list[dict]:
    """Most total points first, then highest single finding, then contract IP order."""
    findings = {f["id"]: f for f in result.get("findings", [])}

    def priority(device: dict) -> tuple[int, int]:
        peak = max(
            (
                int(findings[i].get("points", 0))
                for i in device.get("finding_ids", [])
                if i in findings
            ),
            default=0,
        )
        return -int(device.get("risk_points", 0)), -peak

    return sorted(result.get("devices", []), key=priority)


def most_dangerous(result: dict) -> tuple[dict, dict] | None:
    """The device with the most risk points and its highest-point finding.

    Equal device totals go to the highest single finding, then contract IP order.
    Finding ties keep port/code order. None when nothing scores points.
    """
    findings = {f["id"]: f for f in result.get("findings", [])}
    for device in ranked_devices(result):
        if device.get("risk_points", 0) <= 0:
            continue
        own = [findings[i] for i in device.get("finding_ids", []) if i in findings]
        top = max(own, key=lambda f: f.get("points", 0), default=None)
        if top is not None and top.get("points", 0) > 0:
            return device, top
    return None


def device_anchor(ip: str) -> str:
    """The id of a device's card, such as "device-192-168-1-40", for links and the map."""
    return "device-" + ip.replace(".", "-").replace(":", "-")


def _web_port(device: dict) -> int | None:
    """The lowest TCP port with a plain http page, when the scan saw one (the steps' URL)."""
    web = [p["port"] for p in device.get("open_ports", []) if _plain_http(p)]
    return min(web) if web else None


def _plain_http(port: dict) -> bool:
    tcp = port.get("protocol") == "tcp"
    return tcp and port.get("service_name") == "http" and port.get("tunnel") != "ssl"


def device_fix_steps(
    device: dict, code: str, lang: str, finding: dict | None = None
) -> tuple[str, ...]:
    """The fix steps for one finding on this device: they name its type and IP (#152).

    Only the rules' device-type guess, the IP and a port number are used, all from the
    scan file. tool.content fills them in as text and the template escapes them.
    """
    device_type, ip = device.get("device_type_guess"), device.get("ip")
    if code == "OUTDATED_SERVICE" and device_type == "camera" and finding:
        # Match the affected service, not a product name or an unrelated FTP port.
        if any(
            port.get("port") == finding.get("port")
            and port.get("protocol") == finding.get("protocol")
            and port.get("service_name") == "ftp"
            for port in device.get("open_ports", [])
        ):
            code = "FTP_CLEARTEXT"
    return fix_steps(code, lang, device_type, ip, _web_port(device))


def first_fix_step(device: dict, finding: dict, lang: str) -> str:
    """Show the fixing action first, with the first instruction as a fallback."""
    text = finding_text(finding["code"], lang)
    steps = device_fix_steps(device, finding["code"], lang, finding)
    prefix = FIX_PREFIXES[lang]
    return next(
        (step.removeprefix(prefix) for step in steps if step.startswith(prefix)),
        steps[0] if steps else text.explanation,
    )


def _finding_item(finding: dict, lang: str, device: dict | None = None) -> FindingItem:
    text = finding_text(finding["code"], lang)
    steps = device_fix_steps(device, finding["code"], lang, finding) if device else text.steps
    port, protocol = finding.get("port"), finding.get("protocol")
    severity = finding.get("severity", "info")
    return FindingItem(
        code=finding["code"],
        title=text.title,
        severity=severity,
        severity_label=severity_label(severity, lang),
        points=int(finding.get("points", 0)),
        port_label=f"{port}/{protocol}" if port is not None else None,
        explanation=text.explanation,
        steps=steps,
        standards=standards_line(finding["code"], lang),
    )


def device_list(result: dict, lang: str) -> tuple[tuple[DeviceItem, ...], tuple[DeviceItem, ...]]:
    """Devices with findings (most risk points first) and devices without any.

    Equal totals use the highest single finding, then contract IP order, matching
    the home recommendation and report. All points come from the rules.
    """
    findings = {f["id"]: f for f in result.get("findings", [])}
    risky, safe = [], []
    for device in ranked_devices(result):
        own = [findings[i] for i in device.get("finding_ids", []) if i in findings]
        own.sort(key=lambda f: -int(f.get("points", 0)))
        item = DeviceItem(
            anchor=device_anchor(device["ip"]),
            label=device_type_label(device.get("device_type_guess", "unknown"), lang),
            ip=device["ip"],
            mac_masked=device.get("mac_masked"),
            hostname=device.get("hostname"),
            risk_points=int(device.get("risk_points", 0)),
            findings=tuple(_finding_item(f, lang, device) for f in own),
            device_type=device.get("device_type_guess", "unknown"),
        )
        (risky if item.findings else safe).append(item)
    return tuple(risky), tuple(safe)


def alert_texts(alerts: Iterable[Alert], lang: str) -> tuple[str, ...]:
    """The RO/EN sentence for each change alert. Only the IP, port and protocol are used:
    never the device key, a MAC or a hostname."""
    return tuple(
        alert_message(a.code, a.ip, port=a.port, protocol=a.protocol, lang=lang) for a in alerts
    )


def home_view(
    result: dict | None,
    lang: str | None = DEFAULT_LANG,
    explainer: Explainer | None = None,
    ai_on: bool = False,
    question: str | None = None,
    alerts: Iterable[Alert] = (),
) -> HomeView:
    """The home screen. `explainer` is used only when the user opted in (`ai_on`).

    `question` is the owner's typed question (untrusted); it is answered only with AI on.
    `alerts` are the history's change alerts for this scan (#78), shown only for a readable
    scan. Their values come from scan files: the text is built by tool.content and the
    template escapes it.
    """
    lang = pick_lang(lang)
    ai_available = explainer is not None and explainer.provider is not None
    active = explainer if ai_on and ai_available else None
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
        explanation, source = explain_first(result, finding, lang, active)
        first = FirstStep(
            device=t("device_at", lang).replace("{device}", label).replace("{ip}", device["ip"]),
            hostname=device.get("hostname"),
            risk_points=device["risk_points"],
            finding_title=text.title,
            step=first_fix_step(device, finding, lang),
            explanation=explanation,
            explanation_source=source,
        )
    devices, safe_devices = device_list(result, lang)
    plan = network_plan(result, lang, active)
    reply = answer_question(result, question, lang, active) if question else None
    return HomeView(
        lang=lang,
        kind="ok",
        file=file,
        score=score,
        band=score_band(score, lang),
        first=first,
        devices=devices,
        safe_devices=safe_devices,
        plan=plan,
        reply=reply,
        # Counted after this page's AI calls, so the number includes them.
        ai_blocked=active.rejection_count() if active is not None else None,
        alerts=alert_texts(alerts, lang),
        **ai,
    )
