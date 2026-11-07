"""Tests for lab/switchd.py, the root helper behind the settings switches (#144).
Run: python3 -m unittest discover -s lab/tests"""

import importlib.util
import pathlib
import subprocess
import sys
import tempfile
import unittest

LAB = pathlib.Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("switchd", LAB / "switchd.py")
switchd = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(switchd)

NAMES = switchd.Names.load(LAB / "services.tsv", LAB / "presets.tsv")


class FakeLabctl:
    def __init__(self, returncode=0, stdout=b""):
        self.calls = []
        self.returncode, self.stdout = returncode, stdout

    def __call__(self, argv):
        self.calls.append(argv)
        return subprocess.CompletedProcess(argv, self.returncode, self.stdout, b"")


class SwitchdTests(unittest.TestCase):
    def test_names_come_from_services_tsv_and_presets_tsv(self):
        for name in ("telnet", "redis", "unknown"):
            self.assertIn(name, NAMES.services)
        for name in ("camera", "server", "hub", "printer", "smart-light", "custom"):
            self.assertIn(name, NAMES.presets)

    def test_fix_and_break_run_labctl_with_a_fixed_argv(self):
        # Any service on any Pi (#155): redis isn't a camera service, and that's fine.
        for verb, service in (("fix", "telnet"), ("break", "redis")):
            run = FakeLabctl()
            line = f"{verb} {service}\n".encode()
            self.assertEqual(switchd.handle(line, NAMES, run), b"ok\n")
            self.assertEqual(run.calls, [[switchd.LABCTL, verb, service]])

    def test_preset_runs_labctl_preset(self):
        run = FakeLabctl()
        self.assertEqual(switchd.handle(b"preset smart-light\n", NAMES, run), b"ok\n")
        self.assertEqual(run.calls, [[switchd.LABCTL, "preset", "smart-light"]])

    def test_status_passes_on_only_well_formed_lines(self):
        out = (
            b"preset camera\ntelnet on default\nredis off\nrm -rf / on\ntelnet maybe\n"
            b"preset toaster\nnosuch on\nhttp on default extra\n"
        )
        run = FakeLabctl(stdout=out)
        reply = switchd.handle(b"status\n", NAMES, run)
        self.assertEqual(reply, b"preset camera\ntelnet on default\nredis off\nok\n")
        self.assertEqual(run.calls, [[switchd.LABCTL, "state"]])

    def test_everything_else_is_refused_without_running_labctl(self):
        bad = [
            b"fix nosuch\n",  # not a lab service
            b"preset toaster\n",  # not a preset
            b"preset\n",
            b"preset camera hub\n",
            b"fix telnet; reboot\n",
            b"fix  telnet\n",
            b"fix telnet extra\n",
            b"fix Telnet\n",
            b"fix telnet",  # no newline: the line was cut off
            b"fix telnet\r\n",
            b"reset\n",
            b"leds\n",
            b"state\n",
            b"break $(id)\n",
            b"fix " + b"a" * 80 + b"\n",
            b"\n",
            b"",
            b"fix t\xc3\xa9lnet\n",
            b"status\x00\n",
        ]
        for line in bad:
            with self.subTest(line=line):
                run = FakeLabctl()
                self.assertEqual(switchd.handle(line, NAMES, run), b"refused\n")
                self.assertEqual(run.calls, [])

    def test_without_the_tsv_files_nothing_can_be_switched(self):
        with tempfile.TemporaryDirectory() as tmp:
            names = switchd.Names.load(pathlib.Path(tmp) / "a", pathlib.Path(tmp) / "b")
        run = FakeLabctl()
        self.assertEqual(switchd.handle(b"fix telnet\n", names, run), b"refused\n")
        self.assertEqual(run.calls, [])

    def test_a_labctl_failure_is_reported_as_refused(self):
        self.assertEqual(
            switchd.handle(b"fix telnet\n", NAMES, FakeLabctl(returncode=1)), b"refused\n"
        )

    def test_the_socket_unit_lets_only_root_and_lab_web_connect(self):
        unit = (LAB / "systemd" / "lab-switch.socket").read_text()
        for line in ("SocketUser=root", "SocketGroup=lab-web", "SocketMode=0660", "Accept=yes"):
            self.assertIn(line, unit)
        service = (LAB / "systemd" / "lab-switch@.service").read_text()
        self.assertIn("ExecStart=/usr/bin/python3 -I /opt/lab/switchd.py", service)
        self.assertIn("StandardInput=socket", service)
        dropin = (LAB / "systemd" / "lab-fake@http.service.d" / "switch.conf").read_text()
        self.assertIn("SupplementaryGroups=lab-web", dropin)


class SetupTests(unittest.TestCase):
    """setup.sh needs root and a Pi, so only its device-ID snippet runs here."""

    def device_id_script(self):
        text = (LAB / "setup.sh").read_text()
        body = text.split("device_id() {", 1)[1].split("\n}\n", 1)[0]
        return body.split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]

    def generate_device_id(self, out, machine_id):
        # Run only the extracted Python, never setup.sh or a host machine-id read.
        harness = f"""
import pathlib
from unittest import mock

def read_machine_id(path):
    assert str(path) == "/etc/machine-id", path
    return {machine_id!r}

with mock.patch.object(pathlib.Path, "read_bytes", read_machine_id), \
     mock.patch("secrets.token_bytes", return_value=b"x" * 32):
    exec(compile({self.device_id_script()!r}, "device_id", "exec"))
"""
        subprocess.run(
            [sys.executable, "-I", "-", str(out)],
            input=harness,
            text=True,
            capture_output=True,
            check=True,
            timeout=10,
        )
        return out.read_text().strip()

    def test_the_device_id_is_a_label_style_id_the_settings_page_accepts(self):
        spec = importlib.util.spec_from_file_location("fakesvc_ids", LAB / "fakes" / "fakesvc.py")
        fakesvc = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fakesvc)
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp) / "device-id"
            value = self.generate_device_id(out, b"0123456789abcdef0123456789abcdef\n")
            self.assertEqual(fakesvc.read_device_id(str(out)), value)
            self.assertEqual(
                self.generate_device_id(out, b"0123456789abcdef0123456789abcdef"), value
            )
        self.assertRegex(value, r"^LAB-[A-Z2-9]{4}-[A-Z2-9]{4}$")

    def test_uninitialized_machine_ids_use_the_mocked_random_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp) / "device-id"
            expected = "LAB-2NM5-K9SN"  # HMAC of the mocked random key, b"x" * 32
            for machine_id in (b"", b"uninitialized\n", b"A" * 32):
                with self.subTest(machine_id=machine_id):
                    self.assertEqual(self.generate_device_id(out, machine_id), expected)

    def test_setup_installs_and_removes_the_helper(self):
        text = (LAB / "setup.sh").read_text()
        for needle in (
            "switchd.py",
            "lab-switch.socket",
            "lab-switch@.service",
            "groupadd --system lab-web",
            "enable --now --quiet lab-switch.socket",
            "lab-fake@http.service.d",
        ):
            self.assertIn(needle, text)
        remove = text.split("remove_all() {", 1)[1]
        for needle in ("lab-switch.socket", "lab-fake@http.service.d", "groupdel lab-web"):
            self.assertIn(needle, remove)


if __name__ == "__main__":
    unittest.main()
