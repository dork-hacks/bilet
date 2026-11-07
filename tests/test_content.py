import re

import pytest

from tool.content import (
    LANGS,
    device_type_label,
    file_error_message,
    finding_text,
    refusal_message,
    severity_label,
)
from tool.content.texts import (
    DEVICE_TYPES,
    FILE_ERRORS,
    FINDINGS,
    GENERIC_FINDING,
    REFUSALS,
    SEVERITIES,
)

# The 15 catalog codes from the brief (Part B).
CATALOG_CODES = {
    "TELNET_OPEN",
    "RDP_EXPOSED",
    "VNC_EXPOSED",
    "DB_EXPOSED",
    "CAMERA_STREAM_EXPOSED",
    "OUTDATED_SERVICE",
    "FTP_CLEARTEXT",
    "HTTP_ADMIN_CLEARTEXT",
    "SMB_EXPOSED",
    "MQTT_EXPOSED",
    "UPNP_EXPOSED",
    "SNMP_EXPOSED",
    "PRINTER_RAW_EXPOSED",
    "UNKNOWN_DEVICE",
    "SSH_OPEN",
}
# docs/contracts/data-model.md
DEVICE_TYPE_ENUM = {
    "router",
    "camera",
    "printer",
    "pc",
    "phone",
    "tv",
    "iot_hub",
    "nas",
    "server",
    "unknown",
}
ERROR_CODES = {"EMPTY_FILE", "TOO_LARGE", "NOT_XML", "UNSAFE_XML", "NOT_NMAP"}
OWASP_IOT = {f"I{n}" for n in range(1, 11)}

# Jargon a non-technical reader wouldn't know. Use plain words instead.
BANNED = [
    "exploit",
    "payload",
    "CVE",
    "daemon",
    "nmap",
    "firmware",
    "brute",
    "protocol",
    "port",
    "cleartext",
    "IP",
    "netcat",
    "shell",
]
BANNED_RE = re.compile(r"\b(" + "|".join(BANNED) + r")\b", re.IGNORECASE)
CEDILLA = re.compile("[şţŞŢ]")
RO_DIACRITIC = re.compile("[ăâîșțĂÂÎȘȚ]")
SENTENCE_END = re.compile(r"[.!?](\s|$)")


def all_entries():
    return [*FINDINGS.items(), ("GENERIC", GENERIC_FINDING)]


def all_texts(entry):
    for lang in LANGS:
        yield lang, entry["title"][lang]
        yield lang, entry["explanation"][lang]
        for step in entry["steps"][lang]:
            yield lang, step


def test_every_catalog_code_has_an_entry():
    assert set(FINDINGS) == CATALOG_CODES


def test_codes_match_the_engine_catalog_when_it_exists():
    catalog = pytest.importorskip("tool.engine.catalog")
    assert set(FINDINGS) == set(catalog.CATALOG)


@pytest.mark.parametrize(("code", "entry"), all_entries())
def test_both_languages_are_present_and_non_empty(code, entry):
    for field in ("title", "explanation", "steps"):
        assert set(entry[field]) == set(LANGS), (code, field)
    for lang, text in all_texts(entry):
        assert text.strip() == text and text, (code, lang)


@pytest.mark.parametrize(("code", "entry"), all_entries())
def test_explanation_is_at_most_two_sentences(code, entry):
    for lang in LANGS:
        text = entry["explanation"][lang]
        assert text[-1] in ".!?", (code, lang)
        assert 1 <= len(SENTENCE_END.findall(text)) <= 2, (code, lang)


@pytest.mark.parametrize(("code", "entry"), all_entries())
def test_one_to_five_steps_with_the_same_count_in_both_languages(code, entry):
    ro, en = entry["steps"]["ro"], entry["steps"]["en"]
    assert 1 <= len(ro) <= 5, code
    assert len(ro) == len(en), code


@pytest.mark.parametrize(("code", "entry"), all_entries())
def test_no_unexplained_jargon_or_links(code, entry):
    for lang, text in all_texts(entry):
        assert not BANNED_RE.search(text), (code, lang, text)
        assert "://" not in text and "www." not in text, (code, lang, text)


@pytest.mark.parametrize(("code", "entry"), all_entries())
def test_romanian_uses_comma_below_diacritics(code, entry):
    for lang, text in all_texts(entry):
        if lang == "ro":
            assert not CEDILLA.search(text), (code, text)
    assert RO_DIACRITIC.search(entry["explanation"]["ro"]), code


@pytest.mark.parametrize(("code", "entry"), FINDINGS.items())
def test_standards_mapping(code, entry):
    assert entry["cis"], code
    assert all(re.fullmatch(r"\d{1,2}\.\d{1,2}", c) for c in entry["cis"]), code
    assert entry["owasp_iot"] and set(entry["owasp_iot"]) <= OWASP_IOT, code


def test_lookup_returns_the_entry():
    text = finding_text("TELNET_OPEN", "en")
    assert text.title == FINDINGS["TELNET_OPEN"]["title"]["en"]
    assert text.steps == tuple(FINDINGS["TELNET_OPEN"]["steps"]["en"])
    assert not text.is_generic


def test_unknown_code_or_language_falls_back_without_crashing():
    text = finding_text("NOT_A_CODE", "de")
    assert text.is_generic
    assert text.lang == "ro"
    assert text.title == GENERIC_FINDING["title"]["ro"]


def test_labels_cover_the_contract_enums():
    assert set(DEVICE_TYPES) == DEVICE_TYPE_ENUM
    assert set(FILE_ERRORS) == ERROR_CODES
    assert set(SEVERITIES) == {"high", "medium", "low", "info"}
    for table in (DEVICE_TYPES, FILE_ERRORS, SEVERITIES, REFUSALS):
        for code, texts in table.items():
            assert set(texts) == set(LANGS), code
    assert device_type_label("toaster", "en") == "Unknown device"
    assert file_error_message("NOT_XML", "en") == FILE_ERRORS["NOT_XML"]["en"]
    assert file_error_message("SOMETHING_ELSE", "en") == "This file can't be read."
    assert severity_label("high", "ro") == "Risc ridicat"


def test_refusal_messages_fill_in_the_target():
    for code, texts in REFUSALS.items():
        for lang in LANGS:
            message = refusal_message(code, "8.8.8.8", lang)
            assert "{target}" not in message, (code, lang)
            if "{target}" in texts[lang]:
                assert "8.8.8.8" in message, (code, lang)
    assert "8.8.8.8" in refusal_message("SOME_NEW_CODE", "8.8.8.8", "en")


def test_refusal_target_is_shown_not_interpreted():
    hostile = "{target}{0}\x1b[2J" + "x" * 200
    message = refusal_message("PUBLIC_ADDRESS", hostile, "en")
    assert "\x1b" not in message
    assert "{0}" in message  # braces stay plain text
    assert len(message) < len(REFUSALS["PUBLIC_ADDRESS"]["en"]) + 80
