"""Offline tests for the SD-card helpers in lab/_card.sh and pi_wifi.sh's card edits (#114).

flash_pi.sh erases whatever device it is given, so check_card in _card.sh is the only thing that
stands between a typo and a wiped laptop disk. These tests pin its refusals.

Nothing here writes to a block device, runs sudo or sends packets:
- lsblk and getent are replaced by stubs on PATH that answer from environment variables;
- check_card only reads, and the device path it gets is an existing block device in /dev that is
  never opened (bash's [[ -b ]] can't be stubbed, the stubbed lsblk decides everything else);
- the pi_wifi.sh pieces run against a temporary folder that stands in for the boot partition.

Run: python3 -m pytest lab/tests/test_card_scripts.py
"""

import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import tempfile
import unittest

LAB = pathlib.Path(__file__).resolve().parents[1]
CARD_SH = LAB / "_card.sh"
PI_WIFI = LAB / "pi_wifi.sh"

# Answers from the environment so each test can describe the disk it wants.
LSBLK_STUB = r"""#!/usr/bin/env bash
case "$1" in
  -dno)
    case "$2" in
      TYPE) printf '%s\n' "${FAKE_TYPE:-disk}" ;;
      RM) printf '%s\n' "${FAKE_RM:-1}" ;;
      *) exit 2 ;;
    esac ;;
  -bdno) printf '%s\n' "${FAKE_SIZE:-32000000000}" ;;
  -nro) [ -n "${FAKE_MOUNTS:-}" ] && printf '%s\n' "$FAKE_MOUNTS"; exit 0 ;;
  -nrpo) printf '%s\n' "$FAKE_NAMES" ;;
  *) echo "lsblk stub: unexpected arguments: $*" >&2; exit 2 ;;
esac
"""

GETENT_STUB = r"""#!/usr/bin/env bash
printf '%s:x:1000:1000::%s:/bin/bash\n' "$2" "$FAKE_HOME"
"""

PUBKEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOfakefakefakefakefakefakefakefake test@lab\n"


def _block_device():
    """Any existing block device path. It is only passed to [[ -b ]] and to the lsblk stub."""
    candidates = []
    try:
        entries = sorted(os.scandir("/dev"), key=lambda e: e.name)
    except OSError:
        return None
    for entry in entries:
        try:
            if stat.S_ISBLK(entry.stat(follow_symlinks=False).st_mode):
                candidates.append(entry.path)
        except OSError:
            continue
    return candidates[0] if candidates else None


def _mmcblk_device():
    try:
        names = sorted(os.listdir("/dev"))
    except OSError:
        return None
    for name in names:
        path = "/dev/" + name
        if re.fullmatch(r"mmcblk\d+", name) and stat.S_ISBLK(os.stat(path).st_mode):
            return path
    return None


@unittest.skipUnless(
    sys.platform.startswith("linux"),
    "the card scripts need Linux (lsblk, udisksctl, bash 4+); macOS ships bash 3.2",
)
class _StubbedShell(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = pathlib.Path(self._tmp.name)
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        for name, body in (("lsblk", LSBLK_STUB), ("getent", GETENT_STUB)):
            path = self.bin / name
            path.write_text(body)
            path.chmod(0o755)
        self.home = self.tmp / "home"
        (self.home / ".ssh").mkdir(parents=True)

    def tearDown(self):
        self._tmp.cleanup()

    def card(self, snippet, *args, **fake):
        env = {
            "PATH": f"{self.bin}:{os.environ.get('PATH', '/usr/bin:/bin')}",
            "FAKE_HOME": str(self.home),
            "SUDO_USER": "labuser",
            "LC_ALL": "C",
        }
        env.update({f"FAKE_{k.upper()}": str(v) for k, v in fake.items()})
        return subprocess.run(
            ["bash", "-c", f'set -euo pipefail; source "$0"; {snippet}', str(CARD_SH), *args],
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )


class CheckCardTest(_StubbedShell):
    def setUp(self):
        super().setUp()
        self.dev = _block_device()
        if self.dev is None:
            self.skipTest("no block device in /dev to stand in for the card")

    def check(self, **fake):
        return self.card('check_card "$1"; echo OK', self.dev, **fake)

    def assertRefused(self, result, message):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertNotIn("OK", result.stdout)
        self.assertIn(message, result.stderr)

    def test_small_removable_card_is_accepted(self):
        result = self.check(type="disk", rm=1, size=32_000_000_000)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "OK")

    def test_partition_is_refused(self):
        self.assertRefused(self.check(type="part"), "is not a whole disk")

    def test_non_removable_disk_is_refused(self):
        self.assertRefused(self.check(rm=0), "is not removable; refusing")

    def test_disk_of_300_gb_or_more_is_refused(self):
        self.assertRefused(self.check(size=300 * 1000**3), "larger than 300 GB")
        self.assertRefused(self.check(size=2 * 1000**4), "larger than 300 GB")

    def test_disk_just_under_300_gb_is_accepted(self):
        result = self.check(size=300 * 1000**3 - 1)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_disk_holding_a_system_mount_is_refused(self):
        for mount in ("/", "/boot", "/boot/efi", "/home"):
            with self.subTest(mount=mount):
                result = self.check(mounts=f"\n/run/media/x/bootfs\n{mount}")
                self.assertRefused(result, "holds a system mount")

    def test_desktop_automount_is_not_a_system_mount(self):
        result = self.check(mounts="\n/run/media/labuser/bootfs\n/run/media/labuser/rootfs")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_path_is_refused(self):
        result = self.card('check_card "$1"; echo OK', str(self.tmp / "no-such-disk"))
        self.assertRefused(result, "is not a whole disk")

    def test_regular_file_is_refused(self):
        img = self.tmp / "card.img"
        img.write_bytes(b"\0" * 512)
        result = self.card('check_card "$1"; echo OK', str(img))
        self.assertRefused(result, "is not a whole disk")


class MmcblkTest(_StubbedShell):
    def test_builtin_card_slot_is_accepted_even_if_not_removable(self):
        dev = _mmcblk_device()
        if dev is None:
            self.skipTest("no /dev/mmcblkN on this machine")
        result = self.card('check_card "$1"; echo OK', dev, rm=0)
        self.assertEqual(result.returncode, 0, result.stderr)


class PartTest(_StubbedShell):
    def test_partition_names(self):
        cases = [
            ("/dev/sdb", "/dev/sdb\n/dev/sdb1\n/dev/sdb2", 1, "/dev/sdb1"),
            ("/dev/sdb", "/dev/sdb\n/dev/sdb1\n/dev/sdb2", 2, "/dev/sdb2"),
            ("/dev/mmcblk0", "/dev/mmcblk0\n/dev/mmcblk0p1\n/dev/mmcblk0p2", 2, "/dev/mmcblk0p2"),
        ]
        for dev, names, n, expected in cases:
            with self.subTest(dev=dev, n=n):
                result = self.card('part "$1" "$2"', dev, str(n), names=names)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), expected)


class LoadPubkeysTest(_StubbedShell):
    def load(self, *files):
        return self.card(
            'load_pubkeys "$@"; printf "%s\\n" "${PUBKEY_LINES[@]}"', *[str(f) for f in files]
        )

    def test_given_public_key_is_loaded(self):
        key = self.tmp / "id_ed25519.pub"
        key.write_text(PUBKEY)
        result = self.load(key)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, PUBKEY)

    def test_private_key_is_refused(self):
        key = self.tmp / "id_ed25519"
        # Built in pieces so secret scanners don't mistake this placeholder for a real key.
        marker = "OPENSSH " + "PRIVATE KEY"
        key.write_text(f"-----BEGIN {marker}-----\nAAAA\n-----END {marker}-----\n")
        result = self.load(key)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("is not an SSH public key", result.stderr)
        self.assertNotIn("PRIVATE", result.stdout)

    def test_missing_key_file_is_refused(self):
        result = self.load(self.tmp / "nope.pub")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing", result.stderr)

    def test_default_is_the_sudo_users_keys(self):
        (self.home / ".ssh" / "id_ed25519.pub").write_text(PUBKEY)
        result = self.load()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, PUBKEY)

    def test_no_key_found_is_refused(self):
        result = self.load()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no SSH public key found", result.stderr)


class PiWifiTest(unittest.TestCase):
    """Runs the file-writing parts of pi_wifi.sh against a temporary boot folder."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.boot = pathlib.Path(self._tmp.name)
        self.script = PI_WIFI.read_text()

    def tearDown(self):
        self._tmp.cleanup()

    def write_network_config(self, ssid, password, country="RO"):
        match = re.search(r"<<'PY'\n(.*?)^PY\n", self.script, re.S | re.M)
        self.assertIsNotNone(match, "pi_wifi.sh has no network-config heredoc")
        target = self.boot / "network-config"
        result = subprocess.run(
            ["python3", "-I", "-", str(target)],
            input=match.group(1),
            capture_output=True,
            text=True,
            timeout=30,
            env={
                "WIFI_SSID": ssid,
                "WIFI_PASS": password,
                "WIFI_COUNTRY": country,
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            },
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return target.read_text(encoding="utf-8")

    @staticmethod
    def access_point(text):
        """The access point block, read back with the same rules a YAML parser uses for it."""
        lines = text.splitlines()
        start = lines.index("      access-points:") + 1
        block = lines[start:]
        key = re.fullmatch(r'        ("(?:[^"\\]|\\.)*"):', block[0])
        assert key, block[0]
        ssid = json.loads(key.group(1))
        if block[1:] == ["          {}"]:
            return ssid, None
        value = re.fullmatch(r'          password: ("(?:[^"\\]|\\.)*")', block[1])
        assert value and len(block) == 2, block
        return ssid, json.loads(value.group(1))

    def test_team_network(self):
        text = self.write_network_config("RSH-dork_unit", "correct horse battery")
        self.assertIn("      regulatory-domain: \"RO\"\n", text)
        self.assertIn("    renderer: NetworkManager\n", text)
        self.assertEqual(self.access_point(text), ("RSH-dork_unit", "correct horse battery"))

    def test_awkward_characters_survive_exactly(self):
        ssid = 'Casa: "Bunica" #2'
        password = "pa'ss\"wo#rd: ș ț \\ end"
        text = self.write_network_config(ssid, password)
        self.assertTrue(text.isascii(), "non-ASCII must be written as \\u escapes")
        self.assertEqual(self.access_point(text), (ssid, password))

    def test_open_network_has_no_password(self):
        text = self.write_network_config("RSH-dork_unit", "")
        self.assertNotIn("password", text)
        self.assertEqual(self.access_point(text), ("RSH-dork_unit", None))

    def test_regdom_edit_twice_leaves_one_entry(self):
        lines = [
            line
            for line in self.script.splitlines()
            if line.startswith("CMD=$(head -n1 \"$MNT/cmdline.txt\"")
            or line.startswith("printf '%s cfg80211.ieee80211_regdom=")
        ]
        self.assertEqual(len(lines), 2, "pi_wifi.sh's cmdline.txt edit changed shape")
        edit = "\n".join(lines)
        base = "console=serial0,115200 console=tty1 root=PARTUUID=1234abcd-02 rootwait resize"
        (self.boot / "cmdline.txt").write_text(base + " cfg80211.ieee80211_regdom=GB\n")
        runner = f'set -euo pipefail; MNT="$1"; COUNTRY="$2"\n{edit}'
        for country in ("RO", "RO"):
            result = subprocess.run(
                ["bash", "-c", runner, "_", str(self.boot), country],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            (self.boot / "cmdline.txt").read_text(), base + " cfg80211.ieee80211_regdom=RO\n"
        )


if __name__ == "__main__":
    unittest.main()
