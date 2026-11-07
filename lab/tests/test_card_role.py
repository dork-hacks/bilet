"""Offline tests for lab/card_role.sh (#90). Nothing here touches a block device, runs nmap or sudo.

card_role.sh --to-dir DIR writes into a plain folder that stands in for the Pi's FAT boot partition.
The important property: the first-boot cleanup must restore cmdline.txt exactly, otherwise the
Pi keeps booting into kernel-command-line.target and the lab is down.

Run: python3 -m unittest discover -s lab/tests
"""

import pathlib
import re
import subprocess
import tempfile
import unittest

LAB = pathlib.Path(__file__).resolve().parents[1]
CARD_ROLE = LAB / "card_role.sh"
CMDLINE = (
    "console=serial0,115200 console=tty1 root=PARTUUID=1234abcd-02 rootfstype=ext4 "
    "fsck.repair=yes rootwait cfg80211.ieee80211_regdom=RO\n"
)


def _bash_scripts():
    for path in sorted(LAB.iterdir()):
        if path.is_file():
            with path.open("rb") as f:
                first = f.readline()
            if first.startswith(b"#!") and b"bash" in first:
                yield path


class CardRoleTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.boot = pathlib.Path(self._tmp.name)
        (self.boot / "cmdline.txt").write_text(CMDLINE)

    def tearDown(self):
        self._tmp.cleanup()

    def card_role(self, *args):
        return subprocess.run(
            ["bash", str(CARD_ROLE), "--to-dir", str(self.boot), *args],
            capture_output=True,
            text=True,
            timeout=30,
        )

    def written(self):
        return sorted(p.name for p in self.boot.iterdir())

    def cleanup_hook(self):
        """Run the cleanup() body of the generated lab-firstrun.sh, with B pointing at our folder."""
        script = (self.boot / "lab-firstrun.sh").read_text()
        match = re.search(r"^cleanup\(\) \{\n(.*?)^\}\n", script, re.S | re.M)
        self.assertIsNotNone(match, "lab-firstrun.sh has no cleanup() function")
        body = match.group(1)
        self.assertIn('"$B/cmdline.txt"', body)
        result = subprocess.run(
            ["bash", "-c", 'set -e; B="$1"\n' + body, "_", str(self.boot)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    # --- refused before anything is written -----------------------------------------------

    def test_bad_role_is_refused(self):
        result = self.card_role("toaster")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("role must be camera, server or hub", result.stderr)
        self.assertEqual(self.written(), ["cmdline.txt"])
        self.assertEqual((self.boot / "cmdline.txt").read_text(), CMDLINE)

    def test_toggle_of_another_role_is_refused(self):
        result = self.card_role("camera", "--on", "ssdp")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not a service of the camera role", result.stderr)
        self.assertEqual(self.written(), ["cmdline.txt"])

    def test_unknown_option_is_refused(self):
        result = self.card_role("server", "--force")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.written(), ["cmdline.txt"])

    def test_missing_folder_is_refused(self):
        result = subprocess.run(
            ["bash", str(CARD_ROLE), "--to-dir", str(self.boot / "nope"), "camera"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("is not a folder", result.stderr)

    # --- the payload ----------------------------------------------------------------------

    def test_payload_holds_role_args_and_toggles(self):
        result = self.card_role("hub", "--on", "ssdp,jetdirect", "--with-packages")
        self.assertEqual(result.returncode, 0, result.stderr)
        lab = self.boot / "lab"
        self.assertEqual((lab / "role").read_text(), "hub\n")
        self.assertEqual((lab / "args").read_text(), "--with-packages\n")
        self.assertEqual((lab / "on").read_text().split(), ["ssdp", "jetdirect"])
        for name in ("setup.sh", "labctl", "services.tsv", "install-role.sh", "lab-install.service"):
            self.assertTrue((lab / name).is_file(), name)
        self.assertTrue((lab / "fakes" / "fakesvc.py").is_file())
        self.assertTrue((self.boot / "lab-firstrun.sh").is_file())

    def test_default_payload_has_no_toggles_or_packages(self):
        result = self.card_role("camera")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.boot / "lab" / "role").read_text(), "camera\n")
        self.assertEqual((self.boot / "lab" / "args").read_text().strip(), "")
        self.assertEqual((self.boot / "lab" / "on").read_text().strip(), "")

    def test_generated_scripts_parse(self):
        self.assertEqual(self.card_role("server").returncode, 0)
        for path in (self.boot / "lab-firstrun.sh", self.boot / "lab" / "install-role.sh"):
            result = subprocess.run(["bash", "-n", str(path)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, f"{path.name}: {result.stderr}")

    # --- cmdline.txt ----------------------------------------------------------------------

    def test_cmdline_gets_the_hook_once_on_one_line(self):
        self.assertEqual(self.card_role("camera").returncode, 0)
        cmdline = (self.boot / "cmdline.txt").read_text()
        self.assertEqual(cmdline.count("\n"), 1)
        self.assertTrue(cmdline.startswith(CMDLINE.rstrip("\n") + " "))
        self.assertIn("systemd.run=/boot/firmware/lab-firstrun.sh", cmdline)
        self.assertIn("systemd.unit=kernel-command-line.target", cmdline)

    def test_running_twice_does_not_stack_hooks(self):
        self.assertEqual(self.card_role("camera").returncode, 0)
        once = (self.boot / "cmdline.txt").read_text()
        # A fake toggle, so this test doesn't depend on --with-packages (#96).
        self.assertEqual(self.card_role("hub", "--on", "ssdp").returncode, 0)
        twice = (self.boot / "cmdline.txt").read_text()
        self.assertEqual(once, twice)
        self.assertEqual(twice.count("systemd.run="), 1)
        self.assertEqual((self.boot / "lab" / "role").read_text(), "hub\n")

    def test_first_boot_cleanup_restores_cmdline_exactly(self):
        self.assertEqual(self.card_role("server", "--on", "redis").returncode, 0)
        self.cleanup_hook()
        self.assertEqual((self.boot / "cmdline.txt").read_text(), CMDLINE)
        self.assertEqual(self.written(), ["cmdline.txt"])

    def test_cleanup_after_running_twice_still_restores_cmdline(self):
        self.assertEqual(self.card_role("camera").returncode, 0)
        self.assertEqual(self.card_role("camera").returncode, 0)
        self.cleanup_hook()
        self.assertEqual((self.boot / "cmdline.txt").read_text(), CMDLINE)


class ShellSyntaxTest(unittest.TestCase):
    def test_every_lab_bash_script_parses(self):
        scripts = list(_bash_scripts())
        self.assertIn(CARD_ROLE, scripts)
        for path in scripts:
            result = subprocess.run(["bash", "-n", str(path)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, f"{path.name}: {result.stderr}")

    def test_no_lab_script_uses_sed_in_place(self):
        # GNU and BSD sed disagree on -i (#111): on macOS "sed -i -E" takes -E as the
        # backup suffix and edits nothing. Write to a temporary file and mv it instead.
        in_place = re.compile(r"\bsed\s+(-[A-Za-z]*\s+)*-[A-Za-z]*i")
        for path in _bash_scripts():
            for number, line in enumerate(path.read_text().splitlines(), 1):
                self.assertIsNone(in_place.search(line), f"{path.name}:{number}: {line.strip()}")


if __name__ == "__main__":
    unittest.main()
