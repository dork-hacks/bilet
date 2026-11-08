import re

import pytest

from tool.content import (
    LANGS,
    detect_error_message,
    device_type_label,
    file_error_message,
    finding_text,
    hosts_found_message,
    refusal_message,
    scan_message,
    scan_progress_message,
    severity_label,
)
from tool.content.texts import (
    DETECT_ERRORS,
    DEVICE_TYPES,
    FILE_ERRORS,
    FINDINGS,
    GENERIC_FINDING,
    REFUSALS,
    SCAN_MESSAGES,
    SCAN_STEPS,
    SCAN_TIME_LEFT,
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
ERROR_CODES = {"ANALYSIS_FAILED", "EMPTY_FILE", "TOO_LARGE", "NOT_XML", "UNSAFE_XML", "NOT_NMAP"}
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


@pytest.mark.parametrize("code", sorted(CATALOG_CODES))
@pytest.mark.parametrize("lang", LANGS)
def test_generic_steps_mark_one_fix_and_use_it_as_the_first_action(code, lang):
    from tool.content import fix_steps
    from tool.content.device_steps import FIX_PREFIXES
    from tool.web.view import first_fix_step

    prefix = FIX_PREFIXES[lang]
    steps = fix_steps(code, lang, "unknown")
    marked = [step for step in steps if step.startswith(prefix)]
    assert len(marked) == 1, (code, lang)
    assert first_fix_step({}, {"code": code}, lang) == marked[0].removeprefix(prefix)


@pytest.mark.parametrize("lang", LANGS)
def test_generic_http_and_mqtt_prioritize_removing_the_exposure(lang):
    from tool.content.device_steps import FIX_PREFIXES

    prefix = FIX_PREFIXES[lang]
    http = finding_text("HTTP_ADMIN_CLEARTEXT", lang).steps
    mqtt = finding_text("MQTT_EXPOSED", lang).steps
    assert http[0].startswith(prefix)
    assert "HTTPS" in http[0] and "HTTP" in http[0]
    assert ("opriți" if lang == "ro" else "turn off") in http[0]
    assert ("parola" if lang == "ro" else "password") in http[1]
    assert mqtt[1].startswith(prefix)
    assert "MQTT" in mqtt[1]
    assert ("dezactivați" if lang == "ro" else "turn it off") in mqtt[1]
    assert ("avertismentul rămâne" if lang == "ro" else "warning stays") in mqtt[2]


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


def test_history_error_message_in_both_languages_with_a_fallback():
    from tool.content import history_error_message

    en = "Your results are saved, but the history couldn't be updated."
    ro = "Rezultatele sunt salvate, dar istoricul nu a putut fi actualizat."
    assert history_error_message("en") == en
    assert history_error_message("ro") == ro
    assert history_error_message("xx") == history_error_message("ro")
    assert history_error_message(None) == history_error_message("ro")


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


# --- the product name in user-facing texts (#102) --------------------------------------


def _all_strings(value):
    if isinstance(value, dict):
        for item in value.values():
            yield from _all_strings(item)
    elif isinstance(value, list | tuple):
        for item in value:
            yield from _all_strings(item)
    elif isinstance(value, str):
        yield value


def test_texts_name_the_app_through_display_name():
    from tool.config import DISPLAY_NAME
    from tool.content import texts

    tables = [v for k, v in vars(texts).items() if k.isupper() and isinstance(v, dict)]
    strings = [s for table in tables for s in _all_strings(table)]
    assert not [s for s in strings if "{name}" in s]  # every placeholder is filled in
    # Our app is never called "the tool" or "Programul" (a fix step's lower-case
    # "programul" means the device's software and stays).
    assert not [s for s in strings if "the tool" in s.lower() or "Programul" in s]
    for lang in LANGS:
        assert DISPLAY_NAME in refusal_message("PUBLIC_ADDRESS", "8.8.8.8", lang)
        assert DISPLAY_NAME in refusal_message("SOME_NEW_CODE", "8.8.8.8", lang)
        assert DISPLAY_NAME in scan_message("RUN_AS_ROOT", lang)


def test_a_target_that_looks_like_the_name_placeholder_stays_text():
    message = refusal_message("CONFIRM_REQUIRED", "{name}", "en")
    assert "{name}" in message
    assert scan_message("NO_LIVE_HOSTS", "en", targets="{name}") == "No device answered in {name}."


# --- network detect errors (#52, used by `tool detect` in #19) -------------------------

DETECT_CODES = ("NO_NETWORK", "SEVERAL_NETWORKS", "DETECT_FAILED")


@pytest.mark.parametrize("code", DETECT_CODES)
@pytest.mark.parametrize("lang", LANGS)
def test_detect_errors_exist_in_both_languages(code, lang):
    assert set(DETECT_ERRORS) == set(DETECT_CODES)
    message = detect_error_message(code, lang)
    assert message == DETECT_ERRORS[code][lang]
    assert message.strip() and len(message) < 300


def test_detect_errors_tell_the_user_what_to_do():
    for lang in LANGS:
        assert "hotspot" in detect_error_message("NO_NETWORK", lang)
        assert "hotspot" in detect_error_message("SEVERAL_NETWORKS", lang)
        assert "VPN" in detect_error_message("SEVERAL_NETWORKS", lang)


def test_detect_errors_use_comma_below_diacritics():
    for texts in DETECT_ERRORS.values():
        assert not re.search("[şţŞŢ]", texts["ro"])


def test_unknown_detect_code_or_language_falls_back():
    assert detect_error_message("SOMETHING_NEW", "en") == DETECT_ERRORS["DETECT_FAILED"]["en"]
    assert detect_error_message("NO_NETWORK", "de") == DETECT_ERRORS["NO_NETWORK"]["ro"]
    assert detect_error_message("NO_NETWORK", None) == DETECT_ERRORS["NO_NETWORK"]["ro"]


# --- live scan messages (#94, used by `tool scan` from #20) -----------------------------

SCAN_CODES = (
    "RUN_AS_ROOT",
    "START",
    "HOSTS_FOUND",
    "PROGRESS",
    "SELF_SKIPPED",
    "DONE",
    "NMAP_NOT_FOUND",
    "NMAP_DATA_NOT_FOUND",
    "NMAP_FAILED",
    "NO_LIVE_HOSTS",
    "IPV6_NOT_SUPPORTED",
)


@pytest.mark.parametrize("code", SCAN_CODES)
@pytest.mark.parametrize("lang", LANGS)
def test_scan_messages_exist_in_both_languages(code, lang):
    assert set(SCAN_MESSAGES) == set(SCAN_CODES)
    message = SCAN_MESSAGES[code][lang]
    assert message.strip() and len(message) < 300
    assert message != SCAN_MESSAGES[code]["en" if lang == "ro" else "ro"]


def test_scan_messages_use_comma_below_diacritics():
    for texts in SCAN_MESSAGES.values():
        assert not re.search("[şţŞŢ]", texts["ro"])


def test_scan_message_fills_values_as_plain_text():
    done = scan_message("DONE", "en", path="scans/a.xml", score=25, findings=7)
    assert "scans/a.xml" in done and "25/100" in done and "Findings: 7" in done
    # A value that looks like a placeholder is never expanded.
    tricky = scan_message("DONE", "en", path="{score}", score=25, findings=7)
    assert "Scan saved: {score}." in tricky
    # Control characters are dropped and very long values are capped.
    assert "\x1b" not in scan_message("START", "en", targets="10.0.0.0/24\x1b[2J")
    assert len(scan_message("START", "en", targets="x" * 5000)) < 500


def test_scan_message_never_raises():
    assert scan_message("SOMETHING_NEW", "en") == SCAN_MESSAGES["NMAP_FAILED"]["en"]
    assert scan_message("IPV6_NOT_SUPPORTED", "de") == SCAN_MESSAGES["IPV6_NOT_SUPPORTED"]["ro"]
    assert scan_message("IPV6_NOT_SUPPORTED", None) == SCAN_MESSAGES["IPV6_NOT_SUPPORTED"]["ro"]
    assert "{" not in scan_message("DONE", "ro")  # a missing value is shown as "?"


# --- live scan progress (#107) ----------------------------------------------------------


def test_scan_steps_cover_every_step_code_in_both_languages():
    from tool import scan as live

    codes = {getattr(live, name) for name in dir(live) if name.startswith("STEP_")}
    assert set(SCAN_STEPS) == codes
    for texts in [*SCAN_STEPS.values(), *SCAN_TIME_LEFT.values()]:
        assert texts["ro"].strip() and texts["en"].strip() and texts["ro"] != texts["en"]
        assert not re.search("[şţŞŢ]", texts["ro"])


@pytest.mark.parametrize(
    ("step", "percent", "lang", "expected"),
    [
        ("TCP", 39.9, "en", "Checking ports (TCP): 39% done, "),
        ("SERVICES", 80, "en", "Identifying services: 80% done, "),
        ("TITLES", 100, "en", "Reading web page titles: 100% done, "),
        ("DEVICES", 50, "ro", "Se caută dispozitive: 50% gata, "),
        ("UDP", 1, "ro", "Se verifică porturile (UDP): 1% gata, "),
        ("NEW", 1, "en", "The scan is still running: 1% done, "),
    ],
)
def test_scan_progress_message_names_the_step(step, percent, lang, expected):
    assert scan_progress_message(step, percent, 30, lang).startswith(expected)


@pytest.mark.parametrize(
    ("left", "lang", "expected"),
    [
        (11, "en", "less than a minute left."),
        (70, "en", "about 1 minute left."),
        (150, "en", "about 2 minutes left."),
        (None, "en", "time left not known yet."),
        (30, "ro", "mai puțin de un minut rămas."),
        (60, "ro", "aproximativ un minut rămas."),
        (300, "ro", "aproximativ 5 minute rămase."),
        (1500, "ro", "aproximativ 25 de minute rămase."),
    ],
)
def test_scan_progress_message_says_the_time_left(left, lang, expected):
    assert scan_progress_message("TCP", 10, left, lang).endswith(", " + expected)


def test_scan_progress_message_never_raises():
    assert "?%" in scan_progress_message("TCP", "x", 10, "en")
    assert "100%" in scan_progress_message("TCP", 1e9, -5, "de")
    assert "timpul rămas" in scan_progress_message("TCP", 1, -5, None)


def test_hosts_found_message_lists_only_the_addresses():
    hosts = ["192.168.50.1", "192.168.50.10"]
    en = hosts_found_message(hosts, "en")
    assert en.startswith("Devices found: 2 (192.168.50.1, 192.168.50.10).")
    assert "few minutes" in en
    assert hosts_found_message(hosts, "ro").startswith("Dispozitive găsite: 2 (")
    assert len(hosts_found_message([f"192.168.50.{i}" for i in range(254)], "en")) < 500


@pytest.mark.parametrize(
    ("n", "lang", "expected"),
    [
        (0, "ro", "0 puncte de risc"),
        (10, "ro", "10 puncte de risc"),
        (19, "ro", "19 puncte de risc"),
        (20, "ro", "20 de puncte de risc"),
        (60, "ro", "60 de puncte de risc"),
        (100, "ro", "100 de puncte de risc"),
        (105, "ro", "105 puncte de risc"),
        (120, "ro", "120 de puncte de risc"),
        (60, "en", "60 risk points"),
    ],
)
def test_points_text_follows_romanian_grammar(n, lang, expected):
    # Romanian puts "de" before a noun after 20-99 and round hundreds ("60 de puncte").
    from tool.content.ui import points_text

    assert points_text(n, lang) == expected
