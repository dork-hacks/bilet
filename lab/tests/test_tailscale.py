"""Offline tests for lab/tailscale/setup_pi.sh, the subnet router for teammates at home (#199).

The script decides which network the tailnet can reach, so these pin its refusals: only the one
private (RFC 1918) network this Pi is on, a /24 or smaller, and never CGNAT or a public range.

Nothing here installs, logs in or changes the system: ip, id, tailscale, systemctl and sysctl are
stubs on PATH that answer from environment variables and log their arguments.

Run: python3 -m pytest lab/tests/test_tailscale.py
"""

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

LAB = pathlib.Path(__file__).resolve().parents[1]
SETUP = LAB / "tailscale" / "setup_pi.sh"

IP_STUB = r"""#!/usr/bin/env bash
case "$*" in
  "-4 -j route show default") printf '%s\n' "$FAKE_ROUTES" ;;
  "-4 -j addr show dev "*) printf '%s\n' "$FAKE_ADDRS" ;;
  *) echo "ip stub: unexpected arguments: $*" >&2; exit 2 ;;
esac
"""

ID_STUB = r"""#!/usr/bin/env bash
[ "$1" = -u ] && { printf '%s\n' "${FAKE_UID:-1000}"; exit 0; }
exit 2
"""

LOG_STUB = r"""#!/usr/bin/env bash
printf '%s %s\n' "$(basename "$0")" "$*" >>"$FAKE_LOG"
"""


def routes(*devs):
    return json.dumps([{"dst": "default", "gateway": "192.168.50.1", "dev": d} for d in devs])


def addrs(cidr):
    local, prefix = cidr.split("/")
    info = [{"family": "inet", "local": local, "prefixlen": int(prefix)}]
    return json.dumps([{"ifname": "wlan0", "addr_info": info}])


@unittest.skipUnless(
    sys.platform.startswith("linux") and shutil.which("bash"),
    "setup_pi.sh runs on the Pi (Linux, bash)",
)
class SetupPiTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = pathlib.Path(self._tmp.name)
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        stubs = {"ip": IP_STUB, "id": ID_STUB}
        stubs.update(dict.fromkeys(("tailscale", "systemctl", "sysctl"), LOG_STUB))
        for name, body in stubs.items():
            path = self.bin / name
            path.write_text(body)
            path.chmod(0o755)
        self.log = self.tmp / "log"
        self.conf = self.tmp / "99-bilet-tailscale.conf"

    def tearDown(self):
        self._tmp.cleanup()

    def run_setup(self, *args, devs=("wlan0",), cidr="192.168.50.23/24", uid=1000):
        env = {
            "PATH": f"{self.bin}:{os.environ.get('PATH', '/usr/bin:/bin')}",
            "FAKE_ROUTES": routes(*devs),
            "FAKE_ADDRS": addrs(cidr),
            "FAKE_UID": str(uid),
            "FAKE_LOG": str(self.log),
            "BILET_SYSCTL_CONF": str(self.conf),
            "LC_ALL": "C",
        }
        return subprocess.run(
            ["bash", str(SETUP), *args], capture_output=True, text=True, timeout=30, env=env
        )

    def calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def assertRefused(self, result, message):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(message, result.stderr)
        self.assertNotIn("tailscale up", result.stdout)
        self.assertEqual(self.calls(), [])

    def test_print_only_shows_the_hotspot_subnet_and_changes_nothing(self):
        result = self.run_setup("--print-only")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "This Pi is 192.168.50.23 on wlan0. Advertising 192.168.50.0/24", result.stdout
        )
        self.assertIn("--advertise-routes=192.168.50.0/24", result.stdout)
        self.assertEqual(self.calls(), [])
        self.assertFalse(self.conf.exists())

    def test_small_hotspot_subnet_is_advertised_whole(self):
        result = self.run_setup("--print-only", cidr="172.20.10.5/28")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--advertise-routes=172.20.10.0/28 ", result.stdout)

    def test_public_network_is_refused(self):
        self.assertRefused(
            self.run_setup("--print-only", cidr="8.8.8.8/24"), "not a private RFC 1918"
        )

    def test_cgnat_is_refused(self):
        self.assertRefused(
            self.run_setup("--print-only", cidr="100.64.1.2/24"), "not a private RFC 1918"
        )

    def test_network_larger_than_a_slash_24_is_refused(self):
        self.assertRefused(self.run_setup("--print-only", cidr="10.0.3.7/16"), "larger than a /24")

    def test_several_networks_are_refused(self):
        result = self.run_setup("--print-only", devs=("wlan0", "eth0"))
        self.assertRefused(result, "several networks at once: eth0, wlan0")

    def test_no_network_is_refused(self):
        self.assertRefused(self.run_setup("--print-only", devs=()), "no default route")

    def test_needs_root_to_change_anything(self):
        self.assertRefused(self.run_setup(), "run as root")

    def test_setup_advertises_only_the_subnet_with_snat_and_no_dns_or_routes(self):
        result = self.run_setup(uid=0)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.conf.read_text().splitlines()[-1], "net.ipv4.ip_forward = 1")
        up = [c for c in self.calls() if c.startswith("tailscale up")]
        self.assertEqual(len(up), 1)
        args = up[0].split()[1:]
        self.assertIn("--reset", args)
        self.assertIn("--advertise-routes=192.168.50.0/24", args)
        self.assertIn("--snat-subnet-routes=true", args)
        self.assertIn("--accept-dns=false", args)
        self.assertIn("--accept-routes=false", args)
        self.assertFalse([a for a in args if "exit-node" in a or "auth-key" in a or "authkey" in a])
        self.assertIn("50.168.192.in-addr.arpa", result.stdout)

    def test_remove_logs_out_and_turns_forwarding_off(self):
        self.conf.write_text("net.ipv4.ip_forward = 1\n")
        result = self.run_setup("remove", uid=0)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.conf.exists())
        calls = self.calls()
        self.assertIn("tailscale logout", calls)
        self.assertIn("systemctl disable --now --quiet tailscaled", calls)
        self.assertIn("sysctl -q -w net.ipv4.ip_forward=0", calls)


if __name__ == "__main__":
    unittest.main()
