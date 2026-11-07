"""Grounding checker (NFR-06, MASTERPLAN §5.3).

An AI answer is shown only if every fact in it comes from the evidence. Any IP, CVE,
URL, e-mail, phone number or other number that isn't in the evidence rejects the whole
answer, and the built-in template text is shown instead. The checker is deliberately
strict: a false rejection costs a friendlier sentence, a false pass costs trust.
"""

import re
from dataclasses import dataclass

from tool.ai.evidence import Evidence

MAX_SENTENCES = 2
MAX_CHARS = 400

# Jargon a parent shouldn't have to look up. Matched as whole words, case-insensitive.
BANNED_TERMS = (
    "exploit",
    "exploits",
    "payload",
    "rce",
    "rootkit",
    "zero-day",
    "0-day",
    "botnet",
    "brute-force",
    "privilege escalation",
    "lateral movement",
    "buffer overflow",
    "shellcode",
    "metasploit",
)

_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_IPV6 = re.compile(r"\b[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,7}\b", re.IGNORECASE)
_CVE = re.compile(r"\bCVE-\d{4}-\d+\b", re.IGNORECASE)
_URL = re.compile(
    r"https?://|\bwww\.|\b[a-z0-9-]+\.(?:com|net|org|ro|io|eu|info|biz|co|ly)\b",
    re.IGNORECASE,
)
_EMAIL = re.compile(r"\b\S+@\S+\.\w+\b")
_PHONE = re.compile(r"\+?\d[\d ()\-]{6,}\d")
_NUMBER = re.compile(r"\d+(?:[.,]\d+)*")
_SENTENCE_END = re.compile(r"[.!?]+(?:\s+|$)")
_BANNED = re.compile(
    r"(?<![\w-])(?:" + "|".join(re.escape(t) for t in BANNED_TERMS) + r")(?![\w-])",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Verdict:
    ok: bool
    reason: str  # "ok" or a short machine-readable reason, logged locally


def allowed_numbers(evidence: Evidence) -> set[str]:
    """Every number the AI may mention: ports, the score and product/version numbers."""
    allowed: set[str] = set()
    score = evidence.payload.get("score")
    if isinstance(score, int):
        allowed.add(str(score))
    for device in evidence.payload.get("devices", []):
        for item in device.get("findings", []):
            if isinstance(item.get("port"), int):
                allowed.add(str(item["port"]))
            for key in ("untrusted_product", "untrusted_version"):
                for token in _NUMBER.findall(item.get(key) or ""):
                    allowed.add(token)
                    allowed.update(re.split(r"[.,]", token))
    return allowed


def evidence_ids(evidence: Evidence) -> set[str]:
    return {
        item["id"]
        for device in evidence.payload.get("devices", [])
        for item in device.get("findings", [])
    }


def count_sentences(text: str) -> int:
    parts = [p for p in _SENTENCE_END.split(text.strip()) if p.strip()]
    return len(parts)


def check_text(text: str, allowed: set[str]) -> Verdict:
    if not isinstance(text, str) or not text.strip():
        return Verdict(False, "empty")
    if len(text) > MAX_CHARS:
        return Verdict(False, "too_long")
    for name, pattern in (
        ("ip", _IP),
        ("ipv6", _IPV6),
        ("cve", _CVE),
        ("url", _URL),
        ("email", _EMAIL),
        ("phone", _PHONE),
    ):
        if pattern.search(text):
            return Verdict(False, name)
    for token in _NUMBER.findall(text):
        if token not in allowed:
            return Verdict(False, "number")
    if _BANNED.search(text):
        return Verdict(False, "jargon")
    if count_sentences(text) > MAX_SENTENCES:
        return Verdict(False, "too_many_sentences")
    return Verdict(True, "ok")


def check(answer: object, evidence: Evidence) -> Verdict:
    """Check one AI answer shaped {"en": str, "ro": str, "cites": [evidence ids]}."""
    if not isinstance(answer, dict):
        return Verdict(False, "not_an_object")
    cites = answer.get("cites")
    if not isinstance(cites, list) or not cites:
        return Verdict(False, "no_citation")
    known = evidence_ids(evidence)
    if any(cite not in known for cite in cites):
        return Verdict(False, "unknown_citation")
    allowed = allowed_numbers(evidence)
    for lang in ("en", "ro"):
        verdict = check_text(answer.get(lang), allowed)
        if not verdict.ok:
            return Verdict(False, f"{lang}:{verdict.reason}")
    return Verdict(True, "ok")
