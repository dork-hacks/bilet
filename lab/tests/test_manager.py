"""Tests for the lab manager (lab/manager/manager.py) and its SSH forced command
(lab/remote.py), #155. SSH is faked: nothing here connects to a Pi.
Run: python3 -m unittest discover -s lab/tests"""

import http.client
import importlib.util
import os
import pathlib
import re
import socket
import subprocess
import sys
import tempfile
import threading
import unittest

LAB = pathlib.Path(__file__).resolve().parents[1]


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # dataclasses look the module up by name
    spec.loader.exec_module(module)
    return module


manager = _load("lab_manager", LAB / "manager" / "manager.py")
remote = _load("lab_remote", LAB / "remote.py")

SERVICES = manager.load_services(LAB / "services.tsv")
PRESETS = manager.load_presets(LAB / "services.tsv", LAB / "presets.tsv")


class FakePis:
    """Stands in for `ssh labmgr@<pi> REQUEST`: keeps each Pi's services like labctl."""

    def __init__(self, pis, down=()):
        self.state = {p.address: {"preset": "camera", "on": set(PRESETS["camera"])} for p in pis}
        self.down = set(down)
        self.calls = []

    def __call__(self, argv, timeout):
        self.calls.append(argv)
        address, request = argv[-2].split("@", 1)[1], argv[-1]
        if address in self.down:
            return 255, ""
        pi = self.state[address]
        verb, _, arg = request.partition(" ")
        if verb == "status":
            lines = [f"preset {pi['preset']}"]
            for svc in SERVICES:
                on = "on" if svc.name in pi["on"] else "off"
                default = " default" if svc.name in PRESETS[pi["preset"]] else ""
                lines.append(f"{svc.name} {on}{default}")
            return 0, "\n".join(lines) + "\nok\n"
        if verb == "fix":
            pi["on"].discard(arg)
        elif verb == "break":
            pi["on"].add(arg)
        elif verb == "preset":
            pi["preset"], pi["on"] = arg, set(PRESETS[arg])
        return 0, "ok\n"


def make(down=()):
    pis = [manager.Pi("pi2", "192.168.50.12"), manager.Pi("pi3", "192.168.50.13")]
    fake = FakePis(pis, down)
    return manager.Manager(pis, SERVICES, PRESETS, fake), fake


class ConfigTests(unittest.TestCase):
    def config(self, text):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "pis.conf"
            path.write_text(text)
            return manager.load_config(path)

    def test_the_example_config_loads(self):
        pis = manager.load_config(LAB / "manager" / "pis.conf.example")
        self.assertEqual([p.name for p in pis], ["pi2", "pi3"])

    def test_only_private_hotspot_addresses_are_accepted(self):
        for line in (
            "pi2 8.8.8.8",
            "pi2 100.64.1.2",  # mobile operator CGNAT
            "pi2 127.0.0.1",
            "pi2 pi2.local",
            "pi2 192.168.50.12 extra",
            "Pi2 192.168.50.12",
            "pi2 192.168.50.12\npi2 192.168.50.13",
            "pi2;id 192.168.50.12",
        ):
            with self.subTest(line=line), self.assertRaises(manager.ConfigError):
                self.config(line)
        self.assertEqual(len(self.config("# lab\npi2 10.42.0.5  # camera\n\n")), 1)

    def test_presets_match_labctl(self):
        self.assertEqual(PRESETS["camera"], ["telnet", "http", "ftp"])
        self.assertEqual(PRESETS["server"], [])
        self.assertEqual(PRESETS["custom"], [])
        self.assertIn("smart-light", PRESETS)


class ManagerTests(unittest.TestCase):
    def test_requests_are_checked_before_ssh(self):
        mgr, fake = make()
        for request in (
            "fix nosuch",
            "preset toaster",
            "fix telnet; reboot",
            "status now",
            "reset",
            "fix  telnet",
            "",
        ):
            with self.subTest(request=request):
                self.assertEqual(mgr.ask(mgr.pis["pi2"], request), "refused\n")
        self.assertEqual(fake.calls, [])

    def test_ssh_uses_the_manager_key_and_never_a_shell(self):
        mgr, fake = make()
        mgr.ask(mgr.pis["pi2"], "status")
        argv = fake.calls[0]
        self.assertEqual(argv[0], "ssh")
        self.assertIn("BatchMode=yes", argv)
        self.assertIn("IdentitiesOnly=yes", argv)
        self.assertEqual(argv[-2:], ["labmgr@192.168.50.12", "status"])

    def test_on_the_openwrt_router_it_uses_dropbears_client(self):
        mgr, fake = make()
        mgr.client, mgr.key = "dropbear", pathlib.Path("/etc/lab-manager/state/id_dropbear")
        mgr.ask(mgr.pis["pi3"], "status")
        self.assertEqual(
            fake.calls[0],
            [
                "dbclient",
                "-i",
                "/etc/lab-manager/state/id_dropbear",
                "-y",
                "-T",
                "labmgr@192.168.50.13",
                "status",
            ],
        )

    def test_run_ssh_gives_dbclient_a_home_for_known_hosts(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out = manager.run_ssh(
                [sys.executable, "-c", "import os; print(os.environ['HOME'])"],
                10,
                home=pathlib.Path(tmp),
            )
        self.assertEqual((code, out.strip()), (0, tmp))

    def test_status_of_every_pi_and_the_expected_score(self):
        mgr, _ = make()
        states = mgr.all_status()
        self.assertTrue(all(s.reachable for s in states))
        self.assertEqual(states[0].preset, "camera")
        self.assertTrue(states[0].on["telnet"])
        self.assertIn("ftp", states[0].default)
        # Two cameras: 2 x (telnet 20 + http 10 + ftp 30) = 120 points, so the score floors at 0.
        self.assertEqual(mgr.expected_score(states), (0, 120))

    def test_presets_toggles_fix_everything_and_back(self):
        mgr, fake = make()
        self.assertTrue(mgr.act("pi3", "preset", "hub"))
        self.assertTrue(mgr.act("pi2", "fix", "telnet"))
        states = mgr.all_status()
        # camera without telnet (10 + 30) + hub (mqtt 10 + unknown 5) = 55, the documented demo.
        self.assertEqual(mgr.expected_score(states), (45, 55))
        self.assertTrue(mgr.act("pi2", "fixall", "-"))
        self.assertFalse(any(mgr.status(mgr.pis["pi2"]).on.values()))
        self.assertTrue(mgr.act("pi2", "reset", "-"))
        self.assertTrue(mgr.status(mgr.pis["pi2"]).on["telnet"])
        self.assertTrue(mgr.act("pi3", "preset", "custom"))
        self.assertTrue(mgr.act("pi3", "break", "redis"))
        self.assertEqual(fake.state["192.168.50.13"]["on"], {"redis"})

    def test_the_default_lab_scores_25(self):
        mgr, _ = make()
        mgr.act("pi3", "preset", "hub")
        self.assertEqual(mgr.expected_score(mgr.all_status()), (25, 75))

    def test_unknown_pis_and_ops_do_nothing(self):
        mgr, fake = make()
        self.assertFalse(mgr.act("pi9", "fix", "telnet"))
        self.assertFalse(mgr.act("pi2", "reboot", "-"))
        self.assertFalse(mgr.act("pi2", "fix", "nosuch"))
        self.assertEqual(fake.calls, [])

    def test_an_unreachable_pi_is_shown_and_not_counted(self):
        mgr, _ = make(down={"192.168.50.13"})
        states = mgr.all_status()
        self.assertFalse(states[1].reachable)
        self.assertFalse(mgr.act("pi3", "fixall", "-"))
        page = manager.render(mgr, states).decode()
        self.assertIn("Not reachable", page)
        self.assertIn("unreachable Pis not counted", page)

    def test_a_garbled_status_reply_is_not_trusted(self):
        pi = manager.Pi("pi2", "192.168.50.12")
        for reply in ("", "telnet on\n", "preset toaster\ntelnet on\nok\n", "refused\n"):
            state = manager.parse_status(pi, reply, [s.name for s in SERVICES], PRESETS)
            self.assertFalse(state.reachable, reply)
        state = manager.parse_status(
            pi, "preset hub\nmqtt on default\n<script> on\nok\n", ["mqtt"], PRESETS
        )
        self.assertEqual(state.on, {"mqtt": True})

    def test_the_page_has_a_card_per_pi_and_every_service(self):
        mgr, _ = make()
        page = manager.render(mgr, mgr.all_status()).decode()
        self.assertIn('id="pi-pi2"', page)
        self.assertIn('id="pi-pi3"', page)
        for svc in SERVICES:
            self.assertIn(f"<td>{svc.name}</td>", page)
        self.assertIn('<option value="smart-light">', page)
        self.assertIn('<option value="camera" selected>', page)
        self.assertEqual(page.count(f'value="{mgr.csrf}"'), page.count("<form"))


class HttpTests(unittest.TestCase):
    def setUp(self):
        self.mgr, self.fake = make()
        self.server = manager.ThreadingHTTPServer(("127.0.0.1", 0), lambda *a: None)
        port = self.server.server_address[1]
        self.server.RequestHandlerClass = manager.make_handler(self.mgr, port)
        self.port = port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def request(self, method, path, body="", host=None, origin=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {"Host": host or f"127.0.0.1:{self.port}"}
        if origin:
            headers["Origin"] = origin
        if method == "POST":
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        conn.request(method, path, body=body.encode(), headers=headers)
        response = conn.getresponse()
        return response.status, response.getheader("Location"), response.read().decode()

    def test_the_page_loads_on_localhost(self):
        status, _, page = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("What the lab should score", page)

    def test_other_host_names_are_refused(self):
        for host in ("evil.example:80", f"192.168.50.1:{self.port}", "127.0.0.1"):
            self.assertEqual(self.request("GET", "/", host=host)[0], 403, host)
        status, _, _ = self.request("POST", "/do", "x=1", origin="http://evil.example")
        self.assertEqual(status, 403)

    def test_a_button_needs_the_csrf_token(self):
        body = "csrf=wrong&pi=pi2&op=fix&arg=telnet"
        self.assertEqual(self.request("POST", "/do", body)[0], 403)
        self.assertEqual(self.fake.calls, [])

    def test_a_button_acts_and_redirects_back_to_the_card(self):
        body = f"csrf={self.mgr.csrf}&pi=pi2&op=fix&arg=telnet"
        status, location, _ = self.request("POST", "/do", body)
        self.assertEqual(status, 303)
        self.assertEqual(location, "/?m=done#pi-pi2")
        self.assertNotIn("telnet", self.fake.state["192.168.50.12"]["on"])
        body = f"csrf={self.mgr.csrf}&pi=pi2&op=fix&arg=nosuch"
        self.assertEqual(self.request("POST", "/do", body)[1], "/?m=refused#pi-pi2")

    def test_an_oversized_form_is_refused(self):
        body = f"csrf={self.mgr.csrf}&pad=" + "x" * manager.MAX_BODY
        self.assertEqual(self.request("POST", "/do", body)[0], 413)

    def test_the_openwrt_scripts_parse_and_keep_loopback(self):
        for name in ("setup_openwrt.sh", "lab-manager.init"):
            done = subprocess.run(
                ["sh", "-n", str(LAB / "manager" / name)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(done.returncode, 0, f"{name}: {done.stderr}")
        init = (LAB / "manager" / "lab-manager.init").read_text()
        self.assertIn("--bind 127.0.0.1", init)
        self.assertIn("--ssh-client dropbear", init)
        self.assertIn("procd_set_param user labmanager", init)
        setup = (LAB / "manager" / "setup_openwrt.sh").read_text()
        self.assertNotIn("bash", setup.splitlines()[0])

    def test_the_manager_only_binds_loopback(self):
        with self.assertRaises(SystemExit):
            manager.main(["--bind", "0.0.0.0", "--config", "/dev/null"])
        unit = (LAB / "manager" / "lab-manager.service").read_text()
        self.assertIn("--bind 127.0.0.1", unit)
        self.assertNotRegex(unit, r"--bind (?!127\.0\.0\.1)")


class RemoteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "switch.sock")
        self.requests = []
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(self.path)
        self.sock.listen(4)
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                self.requests.append(conn.recv(128))
                conn.sendall(b"ok\n")

    def tearDown(self):
        self.sock.close()
        self.tmp.cleanup()

    def test_a_request_is_forwarded_as_one_line(self):
        self.assertEqual(remote.forward("preset smart-light", self.path), "ok\n")
        self.assertEqual(self.requests, [b"preset smart-light\n"])

    def test_what_cant_be_a_request_never_reaches_the_helper(self):
        for request in (
            "",
            "fix telnet\nreboot",
            "fix $(id)",
            "Fix telnet",
            "x" * 80,
            "fix tel;net",
        ):
            self.assertEqual(remote.forward(request, self.path), "refused\n", request)
        self.assertEqual(self.requests, [])

    def test_an_unreachable_helper_is_refused(self):
        self.assertEqual(remote.forward("status", self.path + ".missing"), "refused\n")

    def test_the_forced_command_exits_1_unless_ok(self):
        env = {
            "PATH": os.environ["PATH"],
            "LAB_SWITCH_SOCKET": self.path + ".missing",
            "SSH_ORIGINAL_COMMAND": "status",
        }
        done = subprocess.run(
            [sys.executable, "-I", str(LAB / "remote.py")],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual((done.returncode, done.stdout), (1, "refused\n"))

    def test_setup_restricts_the_manager_key_to_remote_py(self):
        text = (LAB / "setup.sh").read_text()
        self.assertIn('restrict,command="/usr/bin/python3 -I /opt/lab/remote.py"', text)
        self.assertRegex(text, r"install -d -m 0755 -o root -g root /var/lib/labmgr")
        self.assertIn("usermod -a -G lab-web labmgr", text)
        self.assertTrue(re.search(r"userdel labmgr", text.split("remove_all() {", 1)[1]))


if __name__ == "__main__":
    unittest.main()
