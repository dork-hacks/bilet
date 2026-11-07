"""Device-specific fix steps keyed by (code, device type) (#152)."""

import pytest

from tool.content import LANGS, finding_text, fix_steps
from tool.content.device_steps import DEVICE_STEPS
from tool.content.texts import DEVICE_TYPES, FINDINGS


@pytest.mark.parametrize(("key", "variant"), list(DEVICE_STEPS.items()))
def test_every_variant_is_for_a_known_code_and_device_type(key, variant):
    code, device_type = key
    assert code in FINDINGS
    assert device_type in DEVICE_TYPES


@pytest.mark.parametrize(("key", "variant"), list(DEVICE_STEPS.items()))
def test_one_to_five_steps_with_the_same_count_in_both_languages(key, variant):
    assert set(variant) == set(LANGS)
    counts = {len(variant[lang]) for lang in LANGS}
    assert len(counts) == 1
    assert 1 <= counts.pop() <= 5
    for lang in LANGS:
        assert all(step.strip() for step in variant[lang])


@pytest.mark.parametrize(("key", "variant"), list(DEVICE_STEPS.items()))
def test_the_device_ip_appears_and_only_known_placeholders_are_used(key, variant):
    for lang in LANGS:
        text = " ".join(variant[lang])
        assert "{ip}" in text
        leftover = text.replace("{ip}", "").replace("{url}", "")
        assert "{" not in leftover and "}" not in leftover


def test_a_variant_names_the_ip_and_the_settings_page():
    steps = fix_steps("TELNET_OPEN", "en", "camera", "192.168.50.23", web_port=8080)
    assert steps == tuple(
        s.replace("{ip}", "192.168.50.23").replace("{url}", "http://192.168.50.23:8080")
        for s in DEVICE_STEPS[("TELNET_OPEN", "camera")]["en"]
    )
    assert "http://192.168.50.23 " in fix_steps("TELNET_OPEN", "en", "camera", "192.168.50.23")[0]


def test_ipv6_gets_brackets_and_a_bad_port_is_ignored():
    steps = fix_steps("TELNET_OPEN", "en", "camera", "fe80::1", web_port=70000)
    assert "http://[fe80::1] " in steps[0]


@pytest.mark.parametrize(
    ("code", "device_type", "ip"),
    [
        ("TELNET_OPEN", "toaster", "192.168.50.23"),  # unknown device type
        ("TELNET_OPEN", None, "192.168.50.23"),
        ("TELNET_OPEN", "camera", None),  # no IP: never a step with a hole in it
        ("TELNET_OPEN", "camera", ""),
        ("NOT_A_CODE", "camera", "192.168.50.23"),
    ],
)
def test_without_a_variant_or_an_ip_the_generic_steps_are_used(code, device_type, ip):
    assert fix_steps(code, "en", device_type, ip) == finding_text(code, "en").steps


def test_unknown_language_falls_back_to_romanian():
    assert fix_steps("TELNET_OPEN", "xx", "camera", "10.0.0.5") == fix_steps(
        "TELNET_OPEN", "ro", "camera", "10.0.0.5"
    )


def test_a_hostile_ip_value_is_only_text_and_never_expanded():
    steps = fix_steps("TELNET_OPEN", "en", "camera", "{url}\x1b[2J")
    assert "{url}" in steps[0]  # the value is shown as typed, not replaced again
    assert "\x1b" not in " ".join(steps)
