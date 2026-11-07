"""Offline tests for labctl's presets (#155): any service on any Pi, `labctl preset NAME`,
`labctl state` and the same-port check. systemctl is a fake that keeps the active units
in a file; nmcli is missing, so the identity row ("unknown") always reads as off.

fix, break and preset need root, so those tests run labctl in a user namespace
(`unshare -r`) and are skipped where that isn't allowed.
Run: python3 -m unittest discover -s lab/tests"""

import importlib.util
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

LAB = pathlib.Path(__file__).resolve().parents[1]

FAKE_SYSTEMCTL = r"""#!/usr/bin/env bash
# Fake systemctl: active units are lines in $FAKE_ACTIVE. lab-fake@* units are installed.
quiet=; args=(); for a in "$@"; do [[ $a == --quiet ]] && quiet=1; [[ $a == --* ]] || args+=("$a"); done
cmd=${args[0]}; unit=${args[1]:-}
case $cmd in
  is-active)  # like systemctl: one line per unit, exit 0 only if all are active
    rc=0
    for u in "${args[@]:1}"; do
      if grep -qx -- "$u" "$FAKE_ACTIVE"; then s=active; else s=inactive; rc=3; fi
      [[ -n $quiet ]] || echo "$s"
    done
    exit $rc ;;
  cat) [[ $unit == lab-fake@* ]] || grep -qx -- "$unit" "$FAKE_INSTALLED" ;;
  enable) grep -qx -- "$unit" "$FAKE_ACTIVE" || echo "$unit" >>"$FAKE_ACTIVE" ;;
  disable) grep -vx -- "$unit" "$FAKE_ACTIVE" >"$FAKE_ACTIVE.tmp" || true; mv "$FAKE_ACTIVE.tmp" "$FAKE_ACTIVE" ;;
  *) exit 0 ;;
esac
"""


def can_unshare() -> bool:
    if not shutil.which("unshare"):
        return False
    done = subprocess.run(["unshare", "-r", "true"], capture_output=True, check=False)
    return done.returncode == 0


class LabctlPresetTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.tmp.name)
        bin_dir = root / "bin"
        bin_dir.mkdir()
        (bin_dir / "systemctl").write_text(FAKE_SYSTEMCTL)
        (bin_dir / "systemctl").chmod(0o755)
        self.active = root / "active"
        self.active.write_text("")
        (root / "installed").write_text("")
        (root / "role").write_text("camera\n")
        self.preset_file = root / "preset"
        # Only bash, coreutils, awk and grep from the system: no real nmcli or systemctl.
        path = [str(bin_dir)]
        for tool in ("bash", "awk", "grep", "paste", "sed", "mv", "cat"):
            found = shutil.which(tool)
            if found and str(pathlib.Path(found).parent) not in path:
                path.append(str(pathlib.Path(found).parent))
        self.env = {
            "PATH": ":".join(path),
            "LAB_SERVICES": str(LAB / "services.tsv"),
            "LAB_PRESETS": str(LAB / "presets.tsv"),
            "LAB_ROLE_FILE": str(root / "role"),
            "LAB_PRESET_FILE": str(self.preset_file),
            "FAKE_ACTIVE": str(self.active),
            "FAKE_INSTALLED": str(root / "installed"),
            "HOME": str(root),
        }
        self.has_nmcli = shutil.which("nmcli", path=self.env["PATH"]) is not None

    def tearDown(self):
        self.tmp.cleanup()

    def labctl(self, *args, root=False):
        argv = ["bash", str(LAB / "labctl"), *args]
        if root:
            argv = ["unshare", "-r", *argv]
        return subprocess.run(
            argv, env=self.env, capture_output=True, text=True, timeout=30, check=False
        )

    def state(self):
        done = self.labctl("state")
        self.assertEqual(done.returncode, 0, done.stderr)
        return done.stdout.splitlines()

    def test_state_lists_the_preset_and_every_service(self):
        self.assertFalse(self.has_nmcli)
        self.active.write_text("lab-fake@telnet\nlab-fake@redis\n")
        lines = self.state()
        self.assertEqual(lines[0], "preset camera")  # no preset file: the installed role
        self.assertIn("telnet on default", lines)
        self.assertIn("ftp off default", lines)  # the camera's preset since #128
        self.assertIn("redis on", lines)  # another role's service, on: still listed
        self.assertIn("mqtt off", lines)
        services = [ln.split()[0] for ln in lines[1:]]
        self.assertEqual(len(services), len(set(services)))

    def test_lab_verify_reads_labctl_status(self):
        # lab/verify --status-file parses `labctl status` (labcheck.parse_status). Before
        # this test, #163's ", in the preset" suffix made it skip every preset row.
        spec = importlib.util.spec_from_file_location("labcheck_status", LAB / "labcheck.py")
        labcheck = importlib.util.module_from_spec(spec)
        sys.modules["labcheck_status"] = labcheck
        spec.loader.exec_module(labcheck)
        services = labcheck.load_services(LAB / "services.tsv")
        self.active.write_text("lab-fake@http\nlab-fake@ftp\n")  # telnet fixed
        camera = self.labctl("status").stdout
        (pathlib.Path(self.tmp.name) / "role").write_text("hub\n")
        self.active.write_text("lab-fake@mqtt\n")
        hub = self.labctl("status").stdout
        states = labcheck.parse_status(camera + hub, services)
        self.assertEqual(
            {k: v for k, v in states.items() if k in ("telnet", "http", "ftp", "rtsp", "mqtt")},
            {"telnet": False, "http": True, "ftp": True, "rtsp": False, "mqtt": True},
        )
        self.assertNotIn("redis", camera)  # another role's service, off: not this Pi's
        self.assertIn("Role: camera", camera)

    def test_presets_lists_the_roles_and_presets_tsv(self):
        done = self.labctl("presets")
        self.assertEqual(done.returncode, 0, done.stderr)
        names = [ln.split()[0] for ln in done.stdout.splitlines()]
        self.assertEqual(names[:3], ["camera", "server", "hub"])
        for name in ("printer", "smart-light", "nas", "custom"):
            self.assertIn(name, names)
        self.assertIn("(nothing on)", done.stdout)

    def test_every_preset_names_only_known_services_without_a_port_clash(self):
        rows = [
            ln.split("\t")
            for ln in (LAB / "services.tsv").read_text().splitlines()
            if not ln.startswith("#") and len(ln.split("\t")) >= 8
        ]
        ports = {r[0]: r[4] for r in rows}
        for line in (LAB / "presets.tsv").read_text().splitlines():
            if line.startswith("#"):
                continue
            name, services, _ = line.split("\t")
            listed = [s for s in services.split(",") if s != "-"]
            with self.subTest(preset=name):
                self.assertRegex(name, r"^[a-z][a-z0-9-]{0,15}$")
                self.assertTrue(set(listed) <= set(ports), listed)
                used = [ports[s] for s in listed if ports[s] != "-"]
                self.assertEqual(len(used), len(set(used)))

    def test_the_default_presets_still_add_up_to_score_25(self):
        # camera + hub are the default lab (#128); the optional server adds 0 points.
        points = 0
        for line in (LAB / "services.tsv").read_text().splitlines():
            cols = line.split("\t")
            if line.startswith("#") or len(cols) < 8:
                continue
            if cols[1] in ("camera", "hub", "server") and cols[7] == "on":
                points += int(cols[6])
        self.assertEqual(100 - points, 25)

    def test_fix_break_and_preset_need_root(self):
        for args in (("fix", "telnet"), ("break", "redis"), ("preset", "hub")):
            done = self.labctl(*args)
            self.assertNotEqual(done.returncode, 0)
            self.assertIn("run with sudo", done.stderr)

    @unittest.skipUnless(can_unshare(), "needs unshare -r (user namespaces)")
    def test_break_works_for_any_service_and_refuses_unknown_ones(self):
        done = self.labctl("break", "redis", root=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("lab-fake@redis", self.active.read_text().split())
        done = self.labctl("break", "toaster", root=True)
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("not a lab service", done.stderr)

    @unittest.skipUnless(can_unshare(), "needs unshare -r (user namespaces)")
    def test_preset_turns_its_services_on_and_the_rest_off(self):
        self.active.write_text("lab-fake@telnet\nlab-fake@http\nlab-fake@redis\n")
        (pathlib.Path(self.tmp.name) / "installed").write_text("snmpd\n")
        done = self.labctl("preset", "printer", root=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(self.preset_file.read_text(), "printer\n")
        self.assertEqual(sorted(self.active.read_text().split()), ["lab-fake@jetdirect", "snmpd"])
        self.assertIn("printer", self.state()[0])
        self.assertIn("jetdirect on default", self.state())

    @unittest.skipUnless(can_unshare(), "needs unshare -r (user namespaces)")
    def test_a_preset_needing_a_missing_package_says_so(self):
        done = self.labctl("preset", "printer", root=True)  # snmpd isn't installed
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("snmp needs snmpd, which isn't installed", done.stderr)

    @unittest.skipUnless(can_unshare(), "needs unshare -r (user namespaces)")
    def test_preset_custom_turns_everything_off_and_reset_keeps_the_preset(self):
        self.active.write_text("lab-fake@telnet\nlab-fake@mqtt\n")
        self.assertEqual(self.labctl("preset", "custom", root=True).returncode, 0)
        self.assertEqual(self.active.read_text().split(), [])
        self.labctl("break", "mqtt", root=True)
        self.assertEqual(self.labctl("reset", root=True).returncode, 0)
        self.assertEqual(self.active.read_text().split(), [])
        self.assertEqual(self.state()[0], "preset custom")

    @unittest.skipUnless(can_unshare(), "needs unshare -r (user namespaces)")
    def test_an_unknown_preset_is_refused_and_changes_nothing(self):
        self.active.write_text("lab-fake@telnet\n")
        for name in ("toaster", "../../etc/passwd", "Camera"):
            done = self.labctl("preset", name, root=True)
            self.assertNotEqual(done.returncode, 0, name)
        self.assertFalse(self.preset_file.exists())
        self.assertEqual(self.active.read_text().split(), ["lab-fake@telnet"])

    @unittest.skipUnless(can_unshare(), "needs unshare -r (user namespaces)")
    def test_two_services_on_the_same_port_are_refused(self):
        # services.tsv has no clash today, so add a second service on port 80 to a copy.
        tsv = pathlib.Path(self.tmp.name) / "services.tsv"
        extra = "webcam2\tcamera\tfake\tlab-fake@webcam2\t80/tcp\tHTTP_ADMIN_CLEARTEXT\t10\toff\n"
        tsv.write_text((LAB / "services.tsv").read_text() + extra)
        self.env["LAB_SERVICES"] = str(tsv)
        self.active.write_text("lab-fake@http\n")
        done = self.labctl("break", "webcam2", root=True)
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("which http already uses", done.stderr)
        self.assertNotIn("lab-fake@webcam2", self.active.read_text().split())


if __name__ == "__main__":
    unittest.main()
