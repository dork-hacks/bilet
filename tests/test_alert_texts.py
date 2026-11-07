"""RO/EN texts for the change alerts (FR-13, #76)."""

import pytest

from tool.content import LANGS, alert_message
from tool.content.texts import ALERTS, GENERIC_ALERT


@pytest.mark.parametrize("lang", LANGS)
def test_new_device_names_the_ip(lang):
    message = alert_message("NEW_DEVICE", "192.168.1.23", lang=lang)
    assert "192.168.1.23" in message
    assert "{" not in message


@pytest.mark.parametrize("lang", LANGS)
def test_new_open_port_names_ip_port_and_protocol(lang):
    message = alert_message("NEW_OPEN_PORT", "192.168.1.1", 443, "tcp", lang)
    assert "192.168.1.1" in message
    assert "443/tcp" in message
    assert "{" not in message


def test_languages_differ():
    ro = alert_message("NEW_DEVICE", "192.168.1.23", lang="ro")
    en = alert_message("NEW_DEVICE", "192.168.1.23", lang="en")
    assert ro != en
    assert "rețea" in ro
    assert "network" in en


def test_every_alert_has_both_languages():
    for entry in [*ALERTS.values(), GENERIC_ALERT]:
        assert set(entry) == set(LANGS)
        assert all(text.strip() for text in entry.values())


def test_unknown_code_gives_generic_text():
    message = alert_message("SOME_NEW_CODE", "192.168.1.5", lang="en")
    assert message == GENERIC_ALERT["en"]


def test_unknown_language_falls_back_to_romanian():
    assert alert_message("NEW_DEVICE", "10.0.0.2", lang="de") == alert_message(
        "NEW_DEVICE", "10.0.0.2", lang="ro"
    )


def test_missing_port_never_raises():
    message = alert_message("NEW_OPEN_PORT", "192.168.1.1", None, None, "en")
    assert "192.168.1.1" in message
    assert "{" not in message


def test_values_are_inserted_as_text_only():
    # A value that looks like another placeholder must not be expanded.
    message = alert_message("NEW_OPEN_PORT", "{port}{protocol}", 80, "tcp", "en")
    assert "{port}{protocol}" in message
    assert message.count("80/tcp") == 1


def test_hostile_ip_is_cleaned_and_capped():
    hostile = "192.168.1.1\x1b[31m\n" + "A" * 500
    message = alert_message("NEW_DEVICE", hostile, lang="en")
    assert "\x1b" not in message
    assert "\n" not in message
    assert len(message) < len(ALERTS["NEW_DEVICE"]["en"]) + 80
