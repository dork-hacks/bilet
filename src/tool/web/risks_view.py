"""What the "every risk explained" page shows (#83): all catalog codes with their texts.

It reads only the catalog and tool.content, never a scan, so it works with no history.
Every text is hand-written: no LLM is involved. The order is fixed (points, then code),
so the page is identical on every request.
"""

from dataclasses import dataclass

from tool.content import finding_text, severity_label, standards_line
from tool.engine.catalog import CATALOG
from tool.web.view import pick_lang


@dataclass(frozen=True)
class RiskItem:
    code: str  # also the anchor: /risks#TELNET_OPEN
    title: str
    severity: str  # high | medium | low | info: also the CSS class
    severity_label: str  # always shown as text, so colour is never the only signal
    points: int
    explanation: str
    steps: tuple[str, ...]
    standards: str | None


@dataclass(frozen=True)
class RisksView:
    lang: str
    risks: tuple[RiskItem, ...]


def risks_view(lang: str | None) -> RisksView:
    lang = pick_lang(lang)
    entries = sorted(CATALOG.values(), key=lambda entry: (-entry.points, entry.code))
    risks = []
    for entry in entries:
        text = finding_text(entry.code, lang)
        risks.append(
            RiskItem(
                code=entry.code,
                title=text.title,
                severity=entry.severity,
                severity_label=severity_label(entry.severity, lang),
                points=entry.points,
                explanation=text.explanation,
                steps=text.steps,
                standards=standards_line(entry.code, lang),
            )
        )
    return RisksView(lang=lang, risks=tuple(risks))
