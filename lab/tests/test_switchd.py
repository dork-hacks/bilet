"""Tests for lab/switchd.py, the root helper behind the settings switches (#144).
Run: python3 -m unittest discover -s lab/tests"""

import importlib.util
import pathlib
import subprocess
import tempfile
import unittest

LAB = pathlib.Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("switchd", LAB / "switchd.py")
switchd = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(switchd)

CAMERA = switchd.role_services("camera", LAB / "services.tsv")


class FakeLabctl:
    def __init__(self, returncode=0, stdout=b""):
        self.calls = []
        self.returncode, self.stdout = returncode, stdout

    def __call__(self, argv):
        self.calls.append(argv)
        return subprocess.CompletedProcess(argv, self.returncode, self.stdout, b"")


class SwitchdTests(unittest.TestCase):
    def test_roles_come_from_services_tsv(self):
        self.assertIn("telnet", CAMERA)
        self.assertNotIn("redis", CAMERA)
        for role in ("camera", "server", "hub"):
            self.assertTrue(switchd.role_services(role, LAB / "services.tsv"), role)

    def test_fix_and_break_run_labctl_with_a_fixed_argv(self):
        for verb in ("fix", "break"):
            run = FakeLabctl()
            self.assertEqual(switchd.handle(f"{verb} telnet\n".encode(), CAMERA, run), b"ok\n")
            self.assertEqual(run.calls, [[switchd.LABCTL, verb, "telnet"]])

    def test_status_passes_on_only_well_formed_lines_for_this_role(self):
        run = FakeLabctl(stdout=b"telnet on\nhttp off\nredis on\nrm -rf / on\ntelnet maybe\n")
        reply = switchd.handle(b"status\n", CAMERA, run)
        self.assertEqual(reply, b"telnet on\nhttp off\nok\n")
        self.assertEqual(run.calls, [[switchd.LABCTL, "state"]])

    def test_everything_else_is_refused_without_running_labctl(self):
        bad = [
            b"fix redis\n",  # another role's service
            b"fix telnet; reboot\n",
            b"fix  telnet\n",
            b"fix telnet extra\n",
            b"fix Telnet\n",
            b"fix telnet",  # no newline: the line was cut off
            b"fix telnet\r\n",
            b"reset\n",
            b"leds\n",
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
                self.assertEqual(switchd.handle(line, CAMERA, run), b"refused\n")
                self.assertEqual(run.calls, [])

    def test_no_role_means_nothing_can_be_switched(self):
        run = FakeLabctl()
        self.assertEqual(switchd.handle(b"fix telnet\n", [], run), b"refused\n")
        self.assertEqual(run.calls, [])

    def test_a_labctl_failure_is_reported_as_refused(self):
        self.assertEqual(
            switchd.handle(b"fix telnet\n", CAMERA, FakeLabctl(returncode=1)), b"refused\n"
        )

    def test_read_role_rejects_anything_but_a_known_role(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "role"
            self.assertIsNone(switchd.read_role(path))
            for text, expected in (("camera\n", "camera"), ("camera; x", None), ("root", None)):
                path.write_text(text)
                self.assertEqual(switchd.read_role(path), expected)

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

    def test_the_device_id_is_a_label_style_id_the_settings_page_accepts(self):
        spec = importlib.util.spec_from_file_location("fakesvc_ids", LAB / "fakes" / "fakesvc.py")
        fakesvc = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fakesvc)
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp) / "device-id"
            subprocess.run(
                ["python3", "-I", "-", str(out)],
                input=self.device_id_script(),
                text=True,
                check=True,
            )
            value = out.read_text().strip()
            self.assertEqual(fakesvc.read_device_id(str(out)), value)
        self.assertRegex(value, r"^LAB-[A-Z2-9]{4}-[A-Z2-9]{4}$")

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
