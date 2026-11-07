"""Grounding checker (NFR-06, MASTERPLAN §5.3).

An AI answer is shown only if every fact in it comes from the evidence. Any IP, CVE,
URL, e-mail, phone number or other number that isn't in the evidence rejects the whole
answer, and the built-in template text is shown instead. The checker is deliberately
strict: a false rejection costs a friendlier sentence, a false pass costs trust.

Numbers are scoped to the findings the answer cites (#218): a port or version that
belongs to another device in the same scan is rejected. A "Device X" that isn't one of
the evidence pseudonyms is rejected, and so is a product-like word (capitalised inside a
sentence, mixed case such as "OpenSSH", or letters mixed with digits) that appears
neither in the evidence, in our own hand-written texts nor in a small plain-word list.
Lower-case words and the first word of a sentence are not product-checked: the check
targets brand and model names, not ordinary vocabulary.
"""

import re
from collections.abc import Iterable
from dataclasses import dataclass

from tool.ai.evidence import Evidence
from tool.content.texts import DEVICE_TYPES, FINDINGS, GENERIC_FINDING, SEVERITIES

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
# "Device C" (EN) or "Dispozitivul C" / "dispozitivului C" (RO).
_DEVICE_REF = re.compile(r"\b(?:[Dd]evice|[Dd]ispozitiv\w*)\s+([A-Z]{1,2})\b")
_WORD = re.compile(r"[^\W\d_](?:[\w]|[-'’](?=\w))*")
_SENTENCE_START = re.compile(r"(?:^|[.!?:;]\s+|[\"“„«(]\s*)$")
# Plain words that may be capitalised inside a sentence without being in any of our texts.
PLAIN_WORDS = frozenset(
    {"i", "ai", "ok", "wi-fi", "wifi", "internet", "web", "pin", "romania", "românia"}
)
_BANNED = re.compile(
    r"(?<![\w-])(?:" + "|".join(re.escape(t) for t in BANNED_TERMS) + r")(?![\w-])",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Verdict:
    ok: bool
    reason: str  # "ok" or a short machine-readable reason, logged locally


def _numbers(text: str) -> set[str]:
    out: set[str] = set()
    for token in _NUMBER.findall(text or ""):
        out.add(token)
        out.update(re.split(r"[.,]", token))
    return out


def allowed_numbers(evidence: Evidence, cites: Iterable[str] | None = None) -> set[str]:
    """Every number the AI may mention: the score, plus ports and product/version numbers.

    With `cites`, only the cited findings' ports and versions count (#218), so a port of
    another device in the same scan is rejected. Without it, every finding counts.
    """
    allowed: set[str] = set()
    score = evidence.payload.get("score")
    if isinstance(score, int):
        allowed.add(str(score))
    cited = None if cites is None else set(cites)
    for device in evidence.payload.get("devices", []):
        for item in device.get("findings", []):
            if cited is not None and item.get("id") not in cited:
                continue
            if isinstance(item.get("port"), int):
                allowed.add(str(item["port"]))
            for key in ("untrusted_product", "untrusted_version"):
                allowed |= _numbers(item.get(key) or "")
    return allowed


def evidence_pseudonyms(evidence: Evidence) -> set[str]:
    """The pseudonym letters in the evidence: {"A", "B"} for Device A and Device B."""
    out = set()
    for device in evidence.payload.get("devices", []):
        name = device.get("device")
        if isinstance(name, str) and name.startswith("Device "):
            out.add(name.removeprefix("Device "))
    return out


def _strings_in(value: object) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings_in(item)
    elif isinstance(value, list | tuple):
        for item in value:
            yield from _strings_in(item)


def _words(texts: Iterable[str]) -> set[str]:
    return {word.lower() for text in texts for word in _WORD.findall(text)}


# Every word in our own hand-written texts. Fixed at import, the same on every run.
_OWN_WORDS = frozenset(_words(_strings_in((FINDINGS, GENERIC_FINDING, DEVICE_TYPES, SEVERITIES))))


def allowed_words(evidence: Evidence, trusted_texts: Iterable[str] = ()) -> set[str]:
    """Lower-case words a product-like word may be: evidence fields, our texts, plain words."""
    evidence_texts: list[str] = []
    for device in evidence.payload.get("devices", []):
        evidence_texts.append(str(device.get("type_guess") or ""))
        for item in device.get("findings", []):
            evidence_texts.append(str(item.get("code") or "").replace("_", " "))
            for key in ("service_name", "untrusted_product", "untrusted_version", "protocol"):
                evidence_texts.append(str(item.get(key) or ""))
    return set(_OWN_WORDS | PLAIN_WORDS) | _words(evidence_texts) | _words(trusted_texts)


def _product_like(word: str, sentence_start: bool) -> bool:
    if any(ch.isdigit() for ch in word):
        return True
    if any(ch.isupper() for ch in word[1:]):
        return True  # mixed case or all caps: "OpenSSH", "vsFTPd", "TP-Link", "QNAP"
    return word[0].isupper() and not sentence_start


def check_devices(text: str, pseudonyms: set[str]) -> bool:
    """False if the text names a "Device X" that isn't in the evidence."""
    return all(match.group(1) in pseudonyms for match in _DEVICE_REF.finditer(text))


def check_products(text: str, words: set[str]) -> bool:
    """False if the text has a product-like word that isn't in `words`."""
    text = _DEVICE_REF.sub(lambda m: m.group(0)[: m.start(1) - m.start(0)] + "x", text)
    for match in _WORD.finditer(text):
        word = match.group(0)
        start = bool(_SENTENCE_START.search(text[: match.start()]))
        if _product_like(word, start) and word.lower() not in words:
            return False
    return True


def evidence_ids(evidence: Evidence) -> set[str]:
    return {
        item["id"]
        for device in evidence.payload.get("devices", [])
        for item in device.get("findings", [])
    }


def count_sentences(text: str) -> int:
    parts = [p for p in _SENTENCE_END.split(text.strip()) if p.strip()]
    return len(parts)


def check_text(
    text: str,
    allowed: set[str],
    max_sentences: int = MAX_SENTENCES,
    max_chars: int = MAX_CHARS,
    pseudonyms: set[str] | None = None,
    words: set[str] | None = None,
) -> Verdict:
    if not isinstance(text, str) or not text.strip():
        return Verdict(False, "empty")
    if len(text) > max_chars:
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
    if pseudonyms is not None and not check_devices(text, pseudonyms):
        return Verdict(False, "device")
    if words is not None and not check_products(text, words):
        return Verdict(False, "product")
    if _BANNED.search(text):
        return Verdict(False, "jargon")
    if count_sentences(text) > max_sentences:
        return Verdict(False, "too_many_sentences")
    return Verdict(True, "ok")


def check(
    answer: object,
    evidence: Evidence,
    max_sentences: int = MAX_SENTENCES,
    max_chars: int = MAX_CHARS,
    trusted_texts: Iterable[str] = (),
) -> Verdict:
    """Check one AI answer shaped {"en": str, "ro": str, "cites": [evidence ids]}.

    Explanations use the defaults (2 sentences). The network summary and Q&A answers
    may be a little longer, but every other rule is the same.

    `trusted_texts` are our own hand-written texts that were sent with the evidence
    (Q&A, #150). Numbers and words in them count as evidence too. Nothing else is relaxed.

    Numbers count only for the cited findings, and device names and product-like words
    must come from the evidence (#218).
    """
    if not isinstance(answer, dict):
        return Verdict(False, "not_an_object")
    cites = answer.get("cites")
    if not isinstance(cites, list) or not cites:
        return Verdict(False, "no_citation")
    known = evidence_ids(evidence)
    if any(cite not in known for cite in cites):
        return Verdict(False, "unknown_citation")
    trusted_texts = tuple(trusted_texts)
    allowed = allowed_numbers(evidence, cites)
    for text in trusted_texts:
        allowed |= _numbers(text)
    pseudonyms = evidence_pseudonyms(evidence)
    words = allowed_words(evidence, trusted_texts)
    for lang in ("en", "ro"):
        verdict = check_text(answer.get(lang), allowed, max_sentences, max_chars, pseudonyms, words)
        if not verdict.ok:
            return Verdict(False, f"{lang}:{verdict.reason}")
    return Verdict(True, "ok")
