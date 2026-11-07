"""Offline tests for the demo's "fix" button (#126): `labctl fix|break`, `status`, the hub's
identity toggle and the LEDs. #155's presets and `state` are in test_labctl_presets.py.

systemctl, nmcli and systemd-run are fakes on an isolated PATH that log every call, and the
LEDs are a fake folder (LAB_LED_ROOT). Nothing touches real units, the Wi-Fi or /sys.
fix and break need root, so those tests run in a user namespace (`unshare -r`) and are
skipped where that isn't allowed.
Run: python3 -m unittest discover -s lab/tests"""

import pathlib
import subprocess
import tempfile
import unittest

from test_labctl_presets import FAKE_SYSTEMCTL, LAB, UNSHARE, can_unshare, isolated_path

# Same fake as the presets tests, plus a log line per call.
LOGGED_SYSTEMCTL = FAKE_SYSTEMCTL.replace(
    "#!/usr/bin/env bash\n", '#!/usr/bin/env bash\necho "systemctl $*" >>"$FAKE_LOG"\n', 1
)

# Fake nmcli: one active Wi-Fi connection, whose MAC and hostname settings are files.
FAKE_NMCLI = r"""#!/usr/bin/env bash
echo "nmcli $*" >>"$FAKE_LOG"
case "$*" in
  "-t -f NAME,TYPE connection show --active")
    echo "Wired:802-3-ethernet"; echo "RSH-dork_unit:802-11-wireless" ;;
  "-g 802-11-wireless.cloned-mac-address connection show RSH-dork_unit") cat "$FAKE_NM/mac" ;;
  "-g ipv4.dhcp-send-hostname connection show RSH-dork_unit") cat "$FAKE_NM/host" ;;
  "connection modify RSH-dork_unit "*)
    shift 3
    while (($# >= 2)); do
      case $1 in
        802-11-wireless.cloned-mac-address) echo "$2" >"$FAKE_NM/mac" ;;
        ipv4.dhcp-send-hostname) echo "$2" >"$FAKE_NM/host" ;;
      esac
      shift 2
    done ;;
esac
"""

FAKE_SYSTEMD_RUN = '#!/usr/bin/env bash\necho "systemd-run $*" >>"$FAKE_LOG"\n'

ROOT_ONLY = unittest.skipUnless(can_unshare(), "needs unshare -r (user namespaces)")


class LabctlFixTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.tool("systemctl", LOGGED_SYSTEMCTL)
        self.active = self.root / "active"
        self.active.write_text("")
        self.installed = self.root / "installed"
        self.installed.write_text("")
        self.role_file = self.root / "role"
        self.role_file.write_text("camera\n")
        self.log = self.root / "log"
        self.log.write_text("")
        self.leds = self.root / "leds"
        self.leds.mkdir()
        self.env = {
            "PATH": isolated_path(self.bin),
            "LAB_SERVICES": str(LAB / "services.tsv"),
            "LAB_PRESETS": str(LAB / "presets.tsv"),
            "LAB_ROLE_FILE": str(self.role_file),
            "LAB_PRESET_FILE": str(self.root / "preset"),
            "LAB_LED_ROOT": str(self.leds),
            "FAKE_ACTIVE": str(self.active),
            "FAKE_INSTALLED": str(self.installed),
            "FAKE_LOG": str(self.log),
            "FAKE_NM": str(self.root),
            "HOME": str(self.root),
        }

    def tool(self, name, script):
        path = self.bin / name
        path.write_text(script)
        path.chmod(0o755)

    def labctl(self, *args, root=False):
        argv = ["bash", str(LAB / "labctl"), *args]
        if root:
            argv = [UNSHARE, "-r", *argv]
        return subprocess.run(
            argv, env=self.env, capture_output=True, text=True, timeout=30, check=False
        )

    def ok(self, *args, root=True):
        done = self.labctl(*args, root=root)
        self.assertEqual(done.returncode, 0, done.stderr)
        return done

    def calls(self, prefix):
        return [ln for ln in self.log.read_text().splitlines() if ln.startswith(prefix)]

    def make_led(self, name):
        led = self.leds / name
        led.mkdir()
        for f in ("trigger", "brightness", "delay_on", "delay_off"):
            (led / f).write_text("")
        return led

    def read(self, led, f):
        return (led / f).read_text().strip()

    def with_wifi(self, mac="permanent", host="yes"):
        self.tool("nmcli", FAKE_NMCLI)
        self.tool("systemd-run", FAKE_SYSTEMD_RUN)
        (self.root / "mac").write_text(mac + "\n")
        (self.root / "host").write_text(host + "\n")
        self.role_file.write_text("hub\n")

    # --- fix and break ---------------------------------------------------------

    @ROOT_ONLY
    def test_fix_disables_the_unit_and_break_enables_it(self):
        self.active.write_text("lab-fake@telnet\n")
        done = self.ok("fix", "telnet")
        self.assertIn("telnet: off (fixed)", done.stdout)
        self.assertIn("systemctl disable --now --quiet lab-fake@telnet", self.calls("systemctl"))
        self.assertEqual(self.active.read_text().split(), [])
        done = self.ok("break", "telnet")
        self.assertIn("telnet: ON (weak)", done.stdout)
        self.assertIn("systemctl enable --now --quiet lab-fake@telnet", self.calls("systemctl"))
        self.assertEqual(self.active.read_text().split(), ["lab-fake@telnet"])

    @ROOT_ONLY
    def test_fix_of_a_unit_that_isnt_installed_succeeds_quietly(self):
        done = self.ok("fix", "snmp")  # snmpd isn't installed
        self.assertIn("snmp: off (fixed)", done.stdout)
        self.assertEqual(done.stderr, "")
        self.assertFalse([c for c in self.calls("systemctl") if "snmpd" in c and "able" in c])

    @ROOT_ONLY
    def test_break_of_a_unit_that_isnt_installed_names_the_setup_command(self):
        done = self.labctl("break", "snmp", root=True)
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("sudo lab/setup.sh camera --with-packages", done.stderr)
        self.assertFalse([c for c in self.calls("systemctl") if "enable" in c])

    @ROOT_ONLY
    def test_fix_without_a_service_name_is_a_usage_error(self):
        for args in (("fix",), ("break",), ("fix", "telnet", "ftp")):
            done = self.labctl(*args, root=True)
            self.assertNotEqual(done.returncode, 0, args)
            self.assertIn("usage:", done.stderr)
        self.assertEqual(self.calls("systemctl"), [])

    # --- status ----------------------------------------------------------------

    def test_status_adds_up_only_the_services_that_are_on(self):
        self.active.write_text("lab-fake@telnet\nlab-fake@http\n")  # ftp fixed
        out = self.ok("status", root=False).stdout
        self.assertIn("Points from this Pi: 30", out)  # TELNET_OPEN 20 + HTTP_ADMIN 10
        rows = {ln.split()[0]: ln for ln in out.splitlines()[4:] if ln.strip()}
        self.assertTrue(rows["telnet"].endswith("ON (weak)"))
        self.assertTrue(rows["ftp"].endswith("off (fixed)"))

    def test_status_marks_units_that_arent_installed(self):
        self.role_file.write_text("hub\n")
        out = self.ok("status", root=False).stdout
        snmp = next(ln for ln in out.splitlines() if ln.startswith("snmp "))
        self.assertTrue(snmp.endswith("not installed"), snmp)
        self.assertIn("Points from this Pi: 0", out)

    def test_status_without_a_good_role_file_says_what_to_do(self):
        self.role_file.unlink()
        done = self.labctl("status")
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("Run lab/setup.sh first", done.stderr)
        self.role_file.write_text("toaster\n")
        done = self.labctl("status")
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("bad role 'toaster'", done.stderr)

    # --- the hub's identity toggle (UNKNOWN_DEVICE) ----------------------------

    @ROOT_ONLY
    def test_break_unknown_hides_the_mac_and_hostname_then_reconnects(self):
        self.with_wifi()
        done = self.ok("break", "unknown")
        self.assertIn(
            "nmcli connection modify RSH-dork_unit 802-11-wireless.cloned-mac-address stable"
            " ipv4.dhcp-send-hostname no ipv6.dhcp-send-hostname no",
            self.calls("nmcli"),
        )
        self.assertIn(
            "systemctl disable --now avahi-daemon.service avahi-daemon.socket",
            self.calls("systemctl"),
        )
        self.assertEqual(
            self.calls("systemd-run"),
            ["systemd-run --quiet --on-active=3 nmcli connection up RSH-dork_unit"],
        )
        self.assertIn("unknown: ON (weak)", done.stdout)
        self.assertIn("unknown on default", self.ok("state", root=False).stdout.splitlines())

    @ROOT_ONLY
    def test_fix_unknown_restores_the_mac_hostname_and_avahi(self):
        self.with_wifi(mac="stable", host="no")
        self.ok("fix", "unknown")
        self.assertIn(
            "nmcli connection modify RSH-dork_unit 802-11-wireless.cloned-mac-address permanent"
            " ipv4.dhcp-send-hostname yes ipv6.dhcp-send-hostname yes",
            self.calls("nmcli"),
        )
        # #137: without avahi back on, <hostname>.local stays unresolvable after the fix.
        self.assertIn(
            "systemctl enable --now avahi-daemon.socket avahi-daemon.service",
            self.calls("systemctl"),
        )
        self.assertIn("unknown off default", self.ok("state", root=False).stdout.splitlines())

    @ROOT_ONLY
    def test_unknown_leaves_the_wifi_alone_when_nothing_changes(self):
        # A new NetworkManager (1.52) prints "0" instead of "no": still the hidden identity.
        self.with_wifi(mac="random", host="0")
        self.ok("break", "unknown")
        self.assertFalse([c for c in self.calls("nmcli") if "modify" in c])
        self.assertEqual(self.calls("systemd-run"), [])

    @ROOT_ONLY
    def test_unknown_without_a_wifi_connection_fails_and_changes_nothing(self):
        self.with_wifi()
        self.tool("nmcli", '#!/usr/bin/env bash\necho "nmcli $*" >>"$FAKE_LOG"\n')
        done = self.labctl("break", "unknown", root=True)
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("no active Wi-Fi connection", done.stderr)
        self.assertFalse([c for c in self.calls("nmcli") if "modify" in c])

    # --- LEDs ------------------------------------------------------------------

    @ROOT_ONLY
    def test_a_weak_service_blinks_red_and_turns_green_off(self):
        green, red = self.make_led("ACT"), self.make_led("PWR")
        self.active.write_text("lab-fake@ftp\n")
        done = self.ok("fix", "telnet")  # ftp is still on
        self.assertIn("LEDs: blinking red", done.stdout)
        self.assertEqual(self.read(red, "trigger"), "timer")
        self.assertEqual((self.read(red, "delay_on"), self.read(red, "delay_off")), ("250", "250"))
        self.assertEqual(
            (self.read(green, "trigger"), self.read(green, "brightness")), ("none", "0")
        )

    @ROOT_ONLY
    def test_all_fixed_is_steady_green_and_red_off(self):
        green, red = self.make_led("ACT"), self.make_led("PWR")
        self.active.write_text("lab-fake@ftp\n")
        done = self.ok("fix", "ftp")
        self.assertIn("LEDs: steady green", done.stdout)
        self.assertEqual(self.read(green, "trigger"), "default-on")
        self.assertEqual((self.read(red, "trigger"), self.read(red, "brightness")), ("none", "0"))

    @ROOT_ONLY
    def test_older_led_names_work_and_no_leds_is_not_an_error(self):
        green, red = self.make_led("led0"), self.make_led("led1")
        self.ok("break", "telnet")
        self.assertEqual(
            (self.read(red, "trigger"), self.read(green, "trigger")), ("timer", "none")
        )
        for led in (green, red):
            for f in led.iterdir():
                f.unlink()
            led.rmdir()
        done = self.ok("fix", "telnet")  # the fix itself must still succeed
        self.assertIn("No on-board LEDs found; skipping.", done.stdout)

    @ROOT_ONLY
    def test_leds_restore_gives_the_leds_back_to_the_system(self):
        green, red = self.make_led("ACT"), self.make_led("PWR")
        self.ok("leds-restore")
        self.assertEqual(
            (self.read(green, "trigger"), self.read(red, "trigger")), ("mmc0", "default-on")
        )

    def test_the_real_led_folder_is_still_the_default(self):
        self.assertIn("LED_ROOT=${LAB_LED_ROOT:-/sys/class/leds}", (LAB / "labctl").read_text())


if __name__ == "__main__":
    unittest.main()
