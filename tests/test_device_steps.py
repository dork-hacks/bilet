"""Device-specific fix steps keyed by (code, device type) (#152)."""

import ast
from pathlib import Path

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
    assert (
        "http://192.168.50.23 "
        in fix_steps("TELNET_OPEN", "en", "camera", "192.168.50.23", web_port=80)[0]
    )


def test_ipv6_gets_brackets_and_a_bad_port_is_ignored():
    steps = fix_steps("TELNET_OPEN", "en", "camera", "fe80::1", web_port=70000)
    assert "http://" not in steps[0]
    assert "fe80::1" in steps[0]
    assert (
        "http://[fe80::1]:8080"
        in fix_steps("TELNET_OPEN", "en", "camera", "fe80::1", web_port=8080)[0]
    )


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


_FIX_MARK = {
    "ro": "Acesta este pasul care rezolvă problema",
    "en": "This is the step that fixes it",
}


@pytest.mark.parametrize(("key", "variant"), list(DEVICE_STEPS.items()))
def test_at_most_one_step_is_marked_as_the_fix_and_both_languages_agree(key, variant):
    marked = {
        lang: [i for i, step in enumerate(variant[lang]) if _FIX_MARK[lang] in step]
        for lang in LANGS
    }
    assert marked["ro"] == marked["en"]
    assert len(marked["en"]) <= 1


@pytest.mark.parametrize(("key", "variant"), list(DEVICE_STEPS.items()))
def test_the_first_step_says_where_the_device_is(key, variant):
    for lang in LANGS:
        assert "{ip}" in variant[lang][0]


@pytest.mark.parametrize("device_type", ["camera", "router", "server", "nas", "iot_hub"])
def test_every_lab_device_type_has_at_least_one_variant(device_type):
    assert any(t == device_type for _, t in DEVICE_STEPS)


@pytest.mark.parametrize(
    ("service", "key"),
    [
        ("telnet", ("TELNET_OPEN", "camera")),
        ("ftp", ("FTP_CLEARTEXT", "camera")),
        ("ftp", ("FTP_CLEARTEXT", "server")),
    ],
)
def test_lab_switch_names_match_the_current_settings_pages(service, key):
    # Read label data without importing or starting the fake network service.
    source = Path(__file__).parents[1] / "lab/fakes/fakesvc.py"
    tree = ast.parse(source.read_text())
    switches = next(
        ast.literal_eval(node.value)
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "SWITCHES" for target in node.targets)
    )
    for lang, label in zip(("en", "ro"), switches[service], strict=True):
        assert label in " ".join(DEVICE_STEPS[key][lang])


@pytest.mark.parametrize("lang", LANGS)
def test_camera_does_not_promise_unimplemented_demo_controls(lang):
    text = " ".join(
        step
        for (code, device_type), variant in DEVICE_STEPS.items()
        if device_type == "camera"
        for step in variant[lang]
    )
    assert "HTTPS / secure connection" not in text
    assert "Software update" not in text


@pytest.mark.parametrize("lang", LANGS)
def test_all_default_camera_findings_have_device_steps(lang):
    from tool.engine import analyze_file

    fixture = Path(__file__).parents[1] / "lab/tests/fixtures/default_lab.xml"
    scan = analyze_file(fixture, salt=b"device-steps-test").to_dict()
    camera = next(d for d in scan["devices"] if d["device_type_guess"] == "camera")
    own = [
        f for f in scan["findings"] if f["device_key"] == camera["device_key"] and f["points"] > 0
    ]
    assert {f["code"] for f in own} == {
        "TELNET_OPEN",
        "HTTP_ADMIN_CLEARTEXT",
        "FTP_CLEARTEXT",
        "OUTDATED_SERVICE",
    }
    for finding in own:
        steps = fix_steps(finding["code"], lang, "camera", camera["ip"])
        assert camera["ip"] in steps[0]
        assert steps != finding_text(finding["code"], lang).steps


@pytest.mark.parametrize("lang", LANGS)
@pytest.mark.parametrize("key", list(DEVICE_STEPS))
def test_no_settings_url_without_observed_web_port(lang, key):
    code, kind = key
    steps = fix_steps(code, lang, kind, "192.168.50.23")
    assert "http://192.168.50.23" not in " ".join(steps)
    assert "192.168.50.23" in " ".join(steps)
