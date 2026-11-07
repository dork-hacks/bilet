"""Tests for lab/verify and lab/sanitize (lab/labcheck.py). Nothing here runs nmap.

Run: python3 -m unittest discover -s lab/tests
"""

import contextlib
import importlib.util
import io
import pathlib
import sys
import tempfile
import unittest
from datetime import datetime
from unittest import mock

LAB = pathlib.Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("labcheck", LAB / "labcheck.py")
labcheck = importlib.util.module_from_spec(_spec)
sys.modules["labcheck"] = labcheck
_spec.loader.exec_module(labcheck)

FIXTURE = (LAB / "tests" / "fixtures" / "default_lab.xml").read_text(encoding="utf-8")
ROLES = {"camera": "10.42.0.11", "server": "10.42.0.12", "hub": "10.42.0.13"}
ROLE_ARGS = ["--camera", "10.42.0.11", "--server", "10.42.0.12", "--hub", "10.42.0.13"]
SUBNET = ("10.42.0.0/24", "10.42.0.50")  # what detect() would say on the hotspot
SERVICES = labcheck.load_services()


def _port(proto, number, state, name, method="probed", extra=""):
    return (
        f'<port protocol="{proto}" portid="{number}"><state state="{state}" reason="x"/>'
        f'<service name="{name}" {extra} method="{method}" conf="10"/></port>\n'
    )


def variant(*replacements):
    """The passing fixture with (old, new) text replacements; each must apply once."""
    text = FIXTURE
    for old, new in replacements:
        if text.count(old) != 1:
            raise ValueError(f"replacement must apply exactly once: {old!r}")
        text = text.replace(old, new)
    return text


def insert_port(ip, port_xml):
    """Add a port element to one host of the fixture."""
    anchor = f'<address addr="{ip}" addrtype="ipv4"/>'
    head, tail = FIXTURE.split("<host ", 1)
    hosts = "<host " + tail
    start = hosts.index(anchor)
    ports_at = hosts.index("</ports>", start)
    return head + hosts[:ports_at] + port_xml + hosts[ports_at:]


def check(text, toggles=None, scanner_ip=None):
    hosts = labcheck.hosts_of(labcheck.parse_tree(text.encode("utf-8")))
    toggles = toggles or labcheck.resolve_toggles(SERVICES)
    return labcheck.check_capture(hosts, ROLES, toggles, SERVICES, scanner_ip)


def failures(rows):
    return [(r.role, r.port) for r in rows if r.result == labcheck.FAIL]


def run_main(main, argv, **kwargs):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv, **kwargs)
    return code, out.getvalue(), err.getvalue()


class ServicesTests(unittest.TestCase):
    def test_lab_ports_match_the_capture_port_list(self):
        ports = labcheck.lab_ports(SERVICES)
        self.assertEqual(
            [p for p, proto in ports if proto == "tcp"],
            [21, 22, 80, 139, 445, 554, 1883, 2323, 6379, 9100],
        )
        self.assertEqual([p for p, proto in ports if proto == "udp"], [161, 1900])

    def test_every_service_has_an_expectation_and_consistent_points(self):
        for svc in SERVICES:
            if svc.port is not None:
                self.assertIn(svc.name, labcheck.EXPECT)
            self.assertEqual(svc.points, sum(labcheck.CODES[c][1] for c in svc.codes), svc)

    def test_default_lab_is_score_25_with_7_types(self):
        rows = labcheck.expected_rows("f.xml", ROLES, labcheck.resolve_toggles(SERVICES), SERVICES)
        self.assertEqual(labcheck.expected_score(rows), 25)
        self.assertEqual(len({r[3] for r in rows}), 7)
        self.assertEqual(rows[6], ("f.xml", "10.42.0.13", "", "UNKNOWN_DEVICE", "low"))

    def test_fixing_telnet_and_http_gives_55(self):
        toggles = labcheck.resolve_toggles(SERVICES, off=["telnet,http"])
        rows = labcheck.expected_rows("f.xml", ROLES, toggles, SERVICES)
        self.assertEqual(labcheck.expected_score(rows), 55)

    def test_nmap_command_scans_only_lab_ports_rate_limited(self):
        cmd = labcheck.nmap_command(
            "/usr/bin/nmap", ["10.42.0.11"], pathlib.Path("o.xml"), SERVICES
        )
        self.assertEqual(
            cmd[:8],
            ["/usr/bin/nmap", "-sS", "-sU", "-sV", "--script", "http-title", "--max-rate", "100"],
        )
        self.assertIn("T:21,22,80,139,445,554,1883,2323,6379,9100,U:161,1900", cmd)
        self.assertEqual(cmd[-3:], ["-oX", "o.xml", "10.42.0.11"])


class ToggleTests(unittest.TestCase):
    def test_on_and_off_override_defaults(self):
        toggles = labcheck.resolve_toggles(SERVICES, on=["rtsp"], off=["telnet"])
        self.assertTrue(toggles["rtsp"])
        self.assertFalse(toggles["telnet"])
        self.assertTrue(toggles["http"])

    def test_unknown_service_and_contradiction_are_refused(self):
        with self.assertRaises(labcheck.UsageError):
            labcheck.resolve_toggles(SERVICES, on=["nope"])
        with self.assertRaises(labcheck.UsageError):
            labcheck.resolve_toggles(SERVICES, on=["rtsp"], off=["rtsp"])

    def test_labctl_status_output_is_read(self):
        status = (
            "Role: camera\n\nSERVICE    PORT      CODES   POINTS  STATE\n"
            "telnet     2323/tcp  TELNET_OPEN   20  off (fixed)\n"
            "http       80/tcp    HTTP_ADMIN_CLEARTEXT   10  off (fixed)\n"
            "rtsp       554/tcp   CAMERA_STREAM_EXPOSED  20  ON (weak)\n"
            "\nPoints from this Pi: 20\n"
            "Role: server\nsmb        445/tcp   SMB_EXPOSED   10  not installed\n"
        )
        toggles = labcheck.resolve_toggles(SERVICES, status_text=status)
        self.assertEqual(
            (toggles["telnet"], toggles["http"], toggles["rtsp"], toggles["smb"], toggles["ftp"]),
            (False, False, True, False, True),
        )

    def test_status_row_under_the_wrong_role_is_refused(self):
        with self.assertRaises(labcheck.UsageError):
            labcheck.parse_status("Role: hub\ntelnet 2323/tcp X 20 ON (weak)\n", SERVICES)


class CheckTests(unittest.TestCase):
    def test_passing_capture(self):
        rows = check(FIXTURE)
        self.assertEqual(failures(rows), [])
        self.assertEqual(sum(r.result == labcheck.WARN for r in rows), 0)

    def test_missing_service(self):
        text = variant(
            (
                '<port protocol="tcp" portid="2323"><state state="open"',
                '<port protocol="tcp" portid="2323"><state state="closed"',
            )
        )
        self.assertEqual(failures(check(text)), [("camera", "2323/tcp")])

    def test_wrong_service_name(self):
        text = variant(
            ('<service name="mqtt" method="probed"', '<service name="unknown" method="probed"')
        )
        rows = check(text)
        self.assertEqual(failures(rows), [("hub", "1883/tcp")])
        self.assertIn("catalog needs mqtt", rows[[r.port for r in rows].index("1883/tcp")].note)

    def test_wrong_ftp_version_and_http_title(self):
        text = variant(
            ('version="2.3.4" ostype', 'version="3.0.5" ostype'),
            ('<elem key="title">Camera Login</elem>', '<elem key="title">Welcome</elem>'),
        )
        self.assertEqual(failures(check(text)), [("camera", "80/tcp"), ("server", "21/tcp")])

    def test_extra_open_port(self):
        text = insert_port("10.42.0.12", _port("tcp", 8080, "open", "http-proxy"))
        rows = check(text)
        self.assertEqual(failures(rows), [("server", "8080/tcp")])
        self.assertIn("unexpected open port", rows[[r.port for r in rows].index("8080/tcp")].note)

    def test_lab_port_of_another_role_is_unexpected(self):
        text = insert_port("10.42.0.13", _port("tcp", 21, "open", "ftp"))
        self.assertEqual(failures(check(text)), [("hub", "21/tcp")])

    def test_toggled_off_service_still_open(self):
        text = variant(
            (
                '<port protocol="tcp" portid="554"><state state="closed" reason="reset" '
                'reason_ttl="64"/><service name="rtsp" method="table" conf="3"/>',
                '<port protocol="tcp" portid="554"><state state="open" reason="syn-ack" '
                'reason_ttl="64"/><service name="rtsp" method="probed" conf="10"/>',
            )
        )
        rows = check(text)
        self.assertEqual(failures(rows), [("camera", "554/tcp")])
        self.assertIn("still open", rows[[r.port for r in rows].index("554/tcp")].note)
        # the same capture passes when the human says rtsp is on
        toggles = labcheck.resolve_toggles(SERVICES, on=["rtsp"])
        self.assertEqual(failures(check(text, toggles)), [])

    def test_udp_open_filtered_is_a_failure_with_a_hint(self):
        text = variant(
            (
                '<port protocol="udp" portid="161"><state state="closed" reason="port-unreach" '
                'reason_ttl="64"/><service name="snmp" method="table" conf="3"/></port>\n'
                '<port protocol="udp" portid="1900"><state state="closed" reason="port-unreach" '
                'reason_ttl="64"/><service name="upnp" method="table" conf="3"/></port>\n</ports>\n'
                '<times srtt="4410"',
                _port("udp", 161, "open|filtered", "snmp", "table")
                + _port("udp", 1900, "open", "upnp", "table")
                + '</ports>\n<times srtt="4410"',
            )
        )
        toggles = labcheck.resolve_toggles(SERVICES, on=["snmp,ssdp"])
        rows = check(text, toggles)
        self.assertEqual(failures(rows), [("hub", "161/udp")])
        by_port = {r.port: r for r in rows if r.role == "hub"}
        self.assertIn("open|filtered", by_port["161/udp"].note)
        self.assertEqual(by_port["1900/udp"].result, labcheck.PASS)
        self.assertIn("table is expected", by_port["1900/udp"].note)

    def test_probed_service_named_from_table_is_a_warning(self):
        text = variant(
            ('<service name="mqtt" method="probed"', '<service name="mqtt" method="table"')
        )
        rows = check(text)
        self.assertEqual(failures(rows), [])
        self.assertEqual(
            [(r.role, r.port) for r in rows if r.result == labcheck.WARN], [("hub", "1883/tcp")]
        )

    def test_hub_with_a_vendor_or_hostname_fails_identity(self):
        with_vendor = variant(
            (
                '<address addr="3A:5F:9C:12:34:56" addrtype="mac"/>',
                '<address addr="DC:A6:32:12:34:56" addrtype="mac" '
                'vendor="Raspberry Pi Trading"/>',
            )
        )
        self.assertEqual(failures(check(with_vendor)), [("hub", "identity")])
        with_name = variant(
            (
                '<address addr="3A:5F:9C:12:34:56" addrtype="mac"/>\n<hostnames>\n',
                '<address addr="3A:5F:9C:12:34:56" addrtype="mac"/>\n<hostnames>\n'
                '<hostname name="hub-pi.lan" type="PTR"/>\n',
            )
        )
        rows = check(with_name)
        self.assertEqual(failures(rows), [("hub", "identity")])
        self.assertIn("hostname", rows[-1].note)

    def test_camera_without_pi_vendor(self):
        text = variant(
            (
                '<address addr="DC:A6:32:11:22:33" addrtype="mac" vendor="Raspberry Pi Trading"/>\n'
                '<hostnames>\n<hostname name="cam-pi.lan"',
                '<address addr="DC:A6:32:11:22:33" addrtype="mac" vendor="Raspberry Pi Trading"/>\n'
                '<hostnames>\n<hostname name="cam-pi.lan"'.replace(
                    ' vendor="Raspberry Pi Trading"', ""
                ),
            )
        )
        rows = check(text)
        self.assertEqual(failures(rows), [])
        self.assertIn(
            ("camera", "identity"), [(r.role, r.port) for r in rows if r.result == "WARN"]
        )

    def test_camera_with_no_vendor_and_no_hostname_is_a_false_unknown_device(self):
        text = variant(
            (
                '<address addr="DC:A6:32:11:22:33" addrtype="mac" vendor="Raspberry Pi Trading"/>\n'
                '<hostnames>\n<hostname name="cam-pi.lan" type="PTR"/>\n',
                "<hostnames>\n",
            )
        )
        self.assertEqual(failures(check(text)), [("camera", "identity")])

    def test_scanner_itself_with_open_ports_and_no_mac_warns(self):
        scanner = (
            '<host><status state="up" reason="localhost-response"/>'
            '<address addr="10.42.0.50" addrtype="ipv4"/><hostnames></hostnames><ports>'
            + _port("tcp", 8000, "open", "http-alt")
            + "</ports></host>\n"
        )
        text = FIXTURE.replace("<runstats>", scanner + "<runstats>")
        rows = check(text, scanner_ip="10.42.0.50")
        self.assertEqual(failures(rows), [])
        self.assertEqual(rows[-1].role, "scanner")
        self.assertEqual(rows[-1].result, labcheck.WARN)
        self.assertIn("false UNKNOWN_DEVICE", rows[-1].note)

    def test_missing_host_fails(self):
        hosts = labcheck.hosts_of(labcheck.parse_tree(FIXTURE.encode()))
        rows = labcheck.check_capture(
            hosts, {"hub": "10.42.0.99"}, labcheck.resolve_toggles(SERVICES), SERVICES
        )
        self.assertEqual(rows[0].result, labcheck.FAIL)

    def test_verify_xml_mode_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            good, bad = pathlib.Path(tmp, "good.xml"), pathlib.Path(tmp, "bad.xml")
            good.write_text(FIXTURE, encoding="utf-8")
            bad.write_text(variant(('name="telnet"', 'name="telnet?"')), encoding="utf-8")
            argv = [*ROLE_ARGS, "--scanner-ip", "10.42.0.50", "--xml"]
            code, out, _ = run_main(labcheck.verify_main, [*argv, str(good)])
            self.assertEqual(code, 0)
            self.assertIn("method=table by nmap's design", out)
            self.assertIn("score 25", out)
            self.assertEqual(run_main(labcheck.verify_main, [*argv, str(bad)])[0], 1)


class XmlSafetyTests(unittest.TestCase):
    XXE = (
        '<?xml version="1.0"?>\n<!DOCTYPE nmaprun [<!ENTITY x SYSTEM "file:///etc/passwd">]>\n'
        '<nmaprun><host><address addr="10.42.0.11" addrtype="ipv4"/>'
        '<hostnames><hostname name="&x;"/></hostnames></host></nmaprun>'
    )

    def assert_refused(self, data, code):
        with self.assertRaises(labcheck.ScanFileError) as ctx:
            labcheck.parse_tree(data)
        self.assertEqual(ctx.exception.code, code)

    def test_xxe_and_doctype_refused(self):
        self.assert_refused(self.XXE.encode(), "UNSAFE_XML")
        self.assert_refused(b'<!DOCTYPE nmaprun SYSTEM "http://x/d.dtd"><nmaprun/>', "UNSAFE_XML")

    def test_xxe_refused_without_defusedxml_too(self):
        with mock.patch.object(labcheck, "_defused_et", None):
            self.assert_refused(self.XXE.encode(), "UNSAFE_XML")
            root = labcheck.parse_tree(FIXTURE.encode())  # the stdlib path still reads nmap XML
            self.assertEqual(len(labcheck.hosts_of(root)), 3)

    def test_broken_empty_large_and_foreign_files(self):
        self.assert_refused(b"", "EMPTY_FILE")
        self.assert_refused(FIXTURE.encode()[:500], "NOT_XML")
        self.assert_refused(b"<html></html>", "NOT_NMAP")
        self.assert_refused("<nmaprun/>".encode("utf-16"), "NOT_XML")
        with mock.patch.object(labcheck, "MAX_XML_BYTES", 100):
            self.assert_refused(FIXTURE.encode(), "TOO_LARGE")

    def test_verify_reports_an_unsafe_file_without_crashing(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp, "xxe.xml")
            path.write_text(self.XXE, encoding="utf-8")
            code, _, err = run_main(
                labcheck.verify_main, [*ROLE_ARGS, "--xml", str(path)], detector=lambda: None
            )
        self.assertEqual(code, 2)
        self.assertIn("UNSAFE_XML", err)

    def test_banner_control_characters_are_stripped(self):
        self.assertEqual(labcheck.clean("Camera\x1b[2J Login‮"), "Camera [2J Login")


class GuardrailTests(unittest.TestCase):
    def scan(self, argv, detected=SUBNET):
        calls = []
        code, out, err = run_main(
            labcheck.verify_main,
            argv,
            detector=lambda: detected,
            runner=lambda cmd: calls.append(cmd) or 0,
            which=lambda name: "/usr/bin/nmap",
        )
        return code, out, err, calls

    def assert_refused(self, argv, words, detected=SUBNET):
        code, _, err, calls = self.scan(argv, detected)
        self.assertEqual(code, 2, err)
        self.assertEqual(calls, [], "nothing may run after a refusal")
        self.assertIn("REFUSED", err)
        self.assertIn(words, err)

    def test_public_cgnat_loopback_and_names_refused(self):
        self.assert_refused(["--camera", "8.8.8.8", "--confirm"], "public address")
        self.assert_refused(["--camera", "100.64.1.2", "--confirm"], "mobile operator")
        self.assert_refused(["--camera", "127.0.0.1", "--confirm"], "loopback")
        self.assert_refused(["--camera", "camera.lan", "--confirm"], "not an IP address")
        self.assert_refused(["--camera", "fd00::5", "--confirm"], "IPv4 only")

    def test_outside_the_connected_subnet_refused(self):
        self.assert_refused(["--camera", "192.168.1.5", "--confirm"], "outside the connected")
        self.assert_refused(
            ["--camera", "10.42.0.11", "--subnet", "10.43.0.0/24", "--confirm"],
            "not the network this computer is on",
        )

    def test_scanner_itself_broadcast_and_duplicates_refused(self):
        self.assert_refused(["--camera", "10.42.0.50", "--confirm"], "this computer")
        self.assert_refused(["--camera", "10.42.0.255", "--confirm"], "broadcast")
        self.assert_refused(
            ["--camera", "10.42.0.11", "--hub", "10.42.0.11", "--confirm"], "two roles"
        )

    def test_big_or_several_networks_refused(self):
        self.assert_refused(
            [*ROLE_ARGS, "--confirm"], "larger than a /24", detected=("10.0.0.0/16", "10.0.0.5")
        )

        def several():
            raise labcheck.Refused("network check failed (SEVERAL_NETWORKS: eth0, wlan0)")

        code, _, err = run_main(
            labcheck.verify_main,
            [*ROLE_ARGS, "--confirm"],
            detector=several,
            runner=lambda cmd: self.fail("ran"),
        )
        self.assertEqual(code, 2)
        self.assertIn("SEVERAL_NETWORKS", err)

    def test_undetectable_network_needs_subnet(self):
        self.assert_refused([*ROLE_ARGS, "--confirm"], "pass --subnet", detected=None)

    def test_confirm_required(self):
        self.assert_refused(ROLE_ARGS, "add --confirm")

    def test_print_only_shows_the_command_and_runs_nothing(self):
        code, out, _, calls = self.scan([*ROLE_ARGS, "--print-only"])
        self.assertEqual((code, calls), (0, []))
        self.assertIn("-p T:21,22,80,139,445,554,1883,2323,6379,9100,U:161,1900", out)
        self.assertIn("10.42.0.11 10.42.0.12 10.42.0.13", out)

    def test_confirmed_scan_runs_only_nmap_with_sudo_then_checks(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_file = pathlib.Path(tmp, "scan.xml")

            def fake_nmap(cmd):  # stands in for nmap: writes the capture, scans nothing
                pathlib.Path(cmd[cmd.index("-oX") + 1]).write_text(FIXTURE, encoding="utf-8")
                calls.append(cmd)
                return 0

            calls = []
            with mock.patch.object(labcheck.os, "geteuid", return_value=1000):
                code, out, err = run_main(
                    labcheck.verify_main,
                    [*ROLE_ARGS, "--confirm", "--out", str(out_file)],
                    detector=lambda: SUBNET,
                    runner=fake_nmap,
                    which=lambda name: "/usr/bin/nmap",
                )
        self.assertEqual(code, 0, err)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][:3], ["sudo", "--", "/usr/bin/nmap"])
        self.assertEqual(calls[0][-3:], ["10.42.0.11", "10.42.0.12", "10.42.0.13"])
        self.assertIn("PASS: 0 failed", out)

    def test_default_capture_path_is_in_lab_captures(self):
        with mock.patch.object(labcheck, "CAPTURES_DIR", pathlib.Path("/nonexistent/captures")):
            code, out, _, _ = self.scan([*ROLE_ARGS, "--print-only"])
        self.assertEqual(code, 0)
        self.assertIn("/nonexistent/captures/scan_", out)

    def test_gitignore_keeps_raw_captures_out(self):
        self.assertIn("captures/", (LAB / ".gitignore").read_text(encoding="utf-8").split())


class SanitizeTests(unittest.TestCase):
    OTHER = (
        '<host><status state="up" reason="arp-response"/>'
        '<address addr="10.42.0.77" addrtype="ipv4"/>'
        '<address addr="F0:18:98:AB:CD:EF" addrtype="mac" vendor="Apple"/>'
        '<hostnames><hostname name="andreeas-iphone.lan" type="PTR"/></hostnames><ports>'
        + _port("tcp", 62078, "open", "iphone-sync")
        + "</ports></host>\n"
    )

    def sanitized(self, text=None):
        text = text or FIXTURE.replace("<runstats>", self.OTHER + "<runstats>")
        return labcheck.sanitize_xml(text.encode("utf-8"), ROLES, "L1_default.xml")

    def test_keeps_the_oui_and_replaces_the_device_half(self):
        out, _ = self.sanitized()
        self.assertIn('addr="DC:A6:32:00:00:01" addrtype="mac" vendor="Raspberry Pi Trading"', out)
        self.assertIn('addr="E4:5F:01:00:00:02"', out)
        self.assertIn('addr="3A:5F:9C:00:00:03"', out)
        for device_half in ("11:22:33", "44:55:66", "12:34:56", "AB:CD:EF"):
            self.assertNotIn(device_half, out)

    def test_hostnames_and_other_hosts_are_gone(self):
        text = FIXTURE.replace("<runstats>", self.OTHER + "<runstats>").replace(
            "Camera Login", "Camera Login - cam-pi"
        )
        out, notes = self.sanitized(text)
        for leak in ("cam-pi", "office-pi", "andreeas-iphone", "10.42.0.77", "/home/user"):
            self.assertNotIn(leak, out)
        self.assertIn('<hostname name="camera" type="PTR"', out)
        self.assertIn("Camera Login - camera", out)
        self.assertIn("-oX L1_default.xml", out)
        self.assertIn('<hosts up="3" down="0" total="3"', out)
        self.assertTrue(any("10.42.0.77" in n for n in notes))

    def test_a_stray_mac_in_any_text_is_masked(self):
        text = FIXTURE.replace('output="Camera Login"', 'output="Camera Login 00:11:22:33:44:55"')
        out, _ = self.sanitized(text)
        self.assertNotIn("33:44:55", out)
        self.assertIn("00:11:22:00:00:00", out)

    def test_output_still_parses_and_checks_the_same(self):
        out, _ = self.sanitized()
        root = labcheck.parse_tree(out.encode("utf-8"))  # our own safe parser
        self.assertEqual(set(labcheck.hosts_of(root)), set(ROLES.values()))
        self.assertEqual(failures(check(out)), [])
        self.assertTrue(
            out.startswith('<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE nmaprun>\n')
        )

    def test_engine_parser_and_rules_agree_with_the_expected_rows(self):
        try:
            sys.path.insert(0, str(LAB.parent / "src"))
            from tool.engine import analyze_file
        except ImportError as exc:  # needs defusedxml and Python 3.11+
            self.skipTest(f"engine not importable: {exc}")
        finally:
            sys.path.remove(str(LAB.parent / "src"))
        out, _ = self.sanitized()
        self.assertTrue(
            labcheck.engine_parse(out, "L1_default.xml").startswith("engine parser: OK")
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp, "L1_default.xml")
            path.write_text(out, encoding="utf-8")
            result = analyze_file(path, salt=b"")
        got = [
            (
                result.file,
                f["ip"],
                "" if f["port"] is None else str(f["port"]),
                f["code"],
                f["severity"],
            )
            for f in result.findings
        ]
        want = labcheck.expected_rows(
            "L1_default.xml", ROLES, labcheck.resolve_toggles(SERVICES), SERVICES
        )
        self.assertEqual(got, want)
        self.assertEqual(result.score, 25)

    def test_sanitize_command_writes_fixture_and_expected_csvs(self):
        with tempfile.TemporaryDirectory() as tmp:
            capture = pathlib.Path(tmp, "scan.xml")
            capture.write_text(FIXTURE, encoding="utf-8")
            out_dir = pathlib.Path(tmp, "fixtures")
            argv = [
                str(capture),
                "L1_default.xml",
                *ROLE_ARGS,
                "--out-dir",
                str(out_dir),
                "--expected",
            ]
            code, out, err = run_main(labcheck.sanitize_main, argv)
            self.assertEqual(code, 0, err)
            self.assertTrue((out_dir / "L1_default.xml").is_file())
            argv2 = [
                str(capture),
                "L2_after_fix.xml",
                *ROLE_ARGS,
                "--off",
                "telnet,http",
                "--out-dir",
                str(out_dir),
                "--expected",
            ]
            self.assertEqual(run_main(labcheck.sanitize_main, argv2)[0], 0)
            scores = (out_dir / "expected_scores.csv").read_bytes()
            self.assertEqual(
                scores, b"file,network_score\r\nL1_default.xml,25\r\nL2_after_fix.xml,55\r\n"
            )
            findings = (out_dir / "expected_findings.csv").read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(findings), 1 + 9 + 7)
            # refuses to overwrite, and refuses names that are paths
            self.assertEqual(run_main(labcheck.sanitize_main, argv)[0], 2)
            bad = [str(capture), "../x.xml", *ROLE_ARGS, "--out-dir", str(out_dir)]
            self.assertEqual(run_main(labcheck.sanitize_main, bad)[0], 2)


class FakeClockTests(unittest.TestCase):
    def test_capture_name_uses_the_clock(self):
        code, out, _ = run_main(
            labcheck.verify_main,
            [*ROLE_ARGS, "--print-only"],
            detector=lambda: SUBNET,
            which=lambda name: None,
            now=lambda: datetime(2026, 11, 7, 10, 15, 0),
        )
        self.assertEqual(code, 0)
        self.assertIn("scan_20261107-101500.xml", out)


if __name__ == "__main__":
    unittest.main()
