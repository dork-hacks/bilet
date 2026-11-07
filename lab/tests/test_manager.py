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
        self.homes = []

    def __call__(self, argv, timeout, home=None):
        self.calls.append(argv)
        self.homes.append(home)
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
        self.assertEqual([p.name for p in pis], ["pi2", "pi3", "pi4"])
        self.assertTrue(all(p.macs and not p.address for p in pis))
        self.assertEqual(len(pis[1].macs), 2)  # the hub: random and real MAC

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
            "pi2 e4:5f:01:00:00",  # not a whole MAC
            "pi2 e4:5f:01:00:00:01\npi3 E4:5F:01:00:00:01",  # the same MAC twice
            "pi3 e6:14:f0:00:00:03,e6:14:f0:00:00:03",
            "pi3 e6:14:f0:00:00:03,192.168.50.13",
        ):
            with self.subTest(line=line), self.assertRaises(manager.ConfigError):
                self.config(line)
        self.assertEqual(len(self.config("# lab\npi2 10.42.0.5  # camera\n\n")), 1)
        (pi,) = self.config("pi3 E6:14:F0:AA:BB:CC,dc:a6:32:00:00:03\n")
        self.assertEqual(pi.macs, ("e6:14:f0:aa:bb:cc", "dc:a6:32:00:00:03"))
        self.assertEqual(pi.address, "")

    def test_dhcp_leases_give_each_mac_its_newest_private_address(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp, "dhcp.leases")
            path.write_text(
                "1799999000 e4:5f:01:00:00:01 192.168.50.158 pi2 01:e4:5f:01:00:00:01\n"
                "1799999900 e6:14:f0:00:00:03 192.168.50.216 * *\n"
                "1799999000 e6:14:f0:00:00:03 192.168.50.146 * *\n"  # older lease
                "1799999000 e4:5f:01:00:00:02 8.8.8.8 evil *\n"  # not private: ignored
                "garbage line\n"
            )
            self.assertEqual(
                manager.read_leases(path),
                {
                    "e4:5f:01:00:00:01": (1799999000, "192.168.50.158"),
                    "e6:14:f0:00:00:03": (1799999900, "192.168.50.216"),
                },
            )
            self.assertEqual(manager.read_leases(pathlib.Path(tmp, "missing")), {})

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
        # Host keys are kept per Pi name, not per IP: a new address still matches.
        known = f"UserKnownHostsFile={manager.STATE}/hosts/pi2/.ssh/known_hosts"
        self.assertIn(known, argv)
        self.assertEqual(fake.homes[0], manager.STATE / "hosts" / "pi2")

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
                home=pathlib.Path(tmp, "pi2"),
            )
            self.assertTrue(pathlib.Path(tmp, "pi2", ".ssh").is_dir())
        self.assertEqual((code, out.strip()), (0, str(pathlib.Path(tmp, "pi2"))))

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

    def test_pis_listed_by_mac_follow_their_dhcp_lease(self):
        with tempfile.TemporaryDirectory() as tmp:
            leases = pathlib.Path(tmp, "dhcp.leases")
            pis = [
                manager.Pi("pi2", "", ("e4:5f:01:00:00:01", "dc:a6:32:00:00:01")),
                manager.Pi("pi3", "192.168.50.13"),
            ]
            fake = FakePis([manager.Pi("pi2", "192.168.50.12"), pis[1]])
            mgr = manager.Manager(pis, SERVICES, PRESETS, fake, leases=leases)
            mgr.locate()  # no lease yet: pi2 is shown, but never asked
            states, _ = mgr.snapshot()
            self.assertFalse(states[0].reachable)
            self.assertIn("no DHCP lease", states[0].error)
            self.assertTrue(all("192.168.50.13" in c[-2] for c in fake.calls))
            leases.write_text("1799999000 e4:5f:01:00:00:01 192.168.50.12 pi2 *\n")
            mgr.locate()
            self.assertEqual(mgr.pis["pi2"].address, "192.168.50.12")
            self.assertEqual(mgr.pis["pi3"].address, "192.168.50.13")  # fixed IPs stay
            self.assertTrue(mgr.all_status()[0].reachable)
            page = manager.render(mgr, mgr.all_status()).decode()
            self.assertIn('action="/locate"', page)
            self.assertNotIn("e4:5f:01", page.lower())  # the MAC never reaches the page
            # The Pi switched MAC (the hub's identity toggle): the newest lease wins.
            leases.write_text(
                "1799999000 e4:5f:01:00:00:01 192.168.50.12 pi2 *\n"
                "1799999500 dc:a6:32:00:00:01 192.168.50.13 pi2 *\n"
            )
            mgr.locate()
            self.assertEqual(mgr.pis["pi2"].address, "192.168.50.13")

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
            self.assertIn(f'value="{svc.name}"', page)
            self.assertIn(manager.LABELS[svc.name], page)
        self.assertIn('<option value="smart-light">', page)
        self.assertIn('<option value="camera" selected>', page)
        self.assertEqual(page.count(f'value="{mgr.csrf}"'), page.count("<form"))
        # Every switch says its state in words, not only in colour.
        self.assertIn('aria-pressed="true" aria-label="Turn telnet off on pi2"', page)
        self.assertIn('aria-pressed="false" aria-label="Turn rtsp on on pi2"', page)
        self.assertNotIn("<script", page)

    def test_the_page_uses_the_remembered_status(self):
        mgr, fake = make()
        states, _ = mgr.snapshot()
        asked = len(fake.calls)
        self.assertEqual(asked, 2)  # one status per Pi, the first time only
        again, age = mgr.snapshot()
        self.assertEqual(len(fake.calls), asked)
        self.assertEqual([s.preset for s in again], [s.preset for s in states])
        self.assertLess(age, 5)
        self.assertTrue(mgr.act("pi2", "fix", "telnet"))  # the fix, then a fresh status
        self.assertFalse(mgr.snapshot()[0][0].on["telnet"])

    def test_polling_stops_when_nobody_looks(self):
        mgr, fake = make()
        now = [1000.0]
        mgr.clock = lambda: now[0]
        stop = threading.Event()
        thread = threading.Thread(target=mgr.poll, args=(stop, 0.01), daemon=True)
        thread.start()
        threading.Event().wait(0.1)
        self.assertEqual(fake.calls, [])  # nobody opened the page yet
        mgr.snapshot()
        threading.Event().wait(0.1)
        self.assertGreater(len(fake.calls), 2)
        stop.set()
        thread.join(1)


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
        self.assertIn("local bind=127.0.0.1", init)
        self.assertIn('--bind "$bind"', init)
        self.assertIn("--ssh-client dropbear", init)
        self.assertIn("procd_set_param user labmanager", init)
        setup = (LAB / "manager" / "setup_openwrt.sh").read_text()
        self.assertNotIn("bash", setup.splitlines()[0])

    def test_the_manager_binds_loopback_or_one_private_hotspot_address(self):
        self.assertEqual(manager.check_bind("127.0.0.1"), "127.0.0.1")
        self.assertEqual(manager.check_bind("192.168.50.1"), "192.168.50.1")
        for bad in ("0.0.0.0", "8.8.8.8", "100.64.0.1", "169.254.1.1", "127.0.0.2", "::1", "pi5"):
            with self.assertRaises(SystemExit, msg=bad):
                manager.main(["--bind", bad, "--config", "/dev/null"])
        setup = (LAB / "manager" / "setup_openwrt.sh").read_text()
        self.assertIn("is not an address of this router", setup)
        unit = (LAB / "manager" / "lab-manager.service").read_text()
        self.assertIn("--bind 127.0.0.1", unit)
        self.assertNotRegex(unit, r"--bind (?!127\.0\.0\.1)")


class SignInTests(unittest.TestCase):
    """--bind on the hotspot: every page needs the access code (#155)."""

    CODE = "LAB-ABCD-EF23"

    def setUp(self):
        self.mgr, self.fake = make()
        self.now = 1000.0
        self.access = manager.Access(self.CODE, clock=lambda: self.now)
        self.server = manager.ThreadingHTTPServer(("127.0.0.1", 0), lambda *a: None)
        self.port = self.server.server_address[1]
        self.host = f"192.168.50.1:{self.port}"
        self.server.RequestHandlerClass = manager.make_handler(
            self.mgr, self.port, "192.168.50.1", self.access
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        manager.SIGNIN_FAIL_DELAY, self.delay = 0.0, manager.SIGNIN_FAIL_DELAY

    def tearDown(self):
        manager.SIGNIN_FAIL_DELAY = self.delay
        self.server.shutdown()
        self.server.server_close()

    def request(self, method, path, body="", cookie=None, host=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {"Host": host or self.host}
        if cookie:
            headers["Cookie"] = cookie
        if method == "POST":
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        conn.request(method, path, body=body.encode(), headers=headers)
        r = conn.getresponse()
        return r.status, r.getheader("Location"), r.getheader("Set-Cookie"), r.read().decode()

    def sign_in(self, code=CODE):
        return self.request("POST", "/signin", f"csrf={self.mgr.csrf}&code={code}")

    def test_without_the_code_only_the_sign_in_page_shows(self):
        status, _, _, page = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn('action="/signin"', page)
        self.assertNotIn("What the lab should score", page)
        self.assertNotIn("192.168.50.12", page)
        self.assertEqual(self.fake.calls, [])
        body = f"csrf={self.mgr.csrf}&pi=pi2&op=fix&arg=telnet"
        self.assertEqual(self.request("POST", "/do", body)[0], 403)
        self.assertEqual(self.request("POST", "/do", body, cookie="lab-session=guess")[0], 403)
        self.assertEqual(self.fake.calls, [])

    def test_a_scan_sees_no_admin_word_in_the_title(self):
        mgr_page = manager.render(self.mgr, self.mgr.all_status()).decode()
        for page in (self.request("GET", "/")[3], mgr_page):
            title = re.search(r"<title>(.*?)</title>", page).group(1).lower()
            for word in ("login", "admin", "config", "setup", "router", "settings"):
                self.assertNotIn(word, title)

    def test_a_wrong_code_gives_no_session(self):
        status, location, cookie, _ = self.sign_in("LAB-AAAA-AAAA")
        self.assertEqual((status, location, cookie), (303, "/?m=badcode", None))
        self.assertIn("access code is wrong", self.request("GET", "/?m=badcode")[3])
        self.assertEqual(self.sign_in("")[1], "/?m=badcode")
        self.assertEqual(self.request("POST", "/signin", f"code={self.CODE}")[0], 403)  # no csrf

    def test_the_code_opens_the_page_and_sign_out_closes_it(self):
        status, location, cookie, _ = self.sign_in(self.CODE.lower())
        self.assertEqual((status, location), (303, "/"))
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        session = cookie.split(";")[0]
        page = self.request("GET", "/", cookie=session)[3]
        self.assertIn("What the lab should score", page)
        self.assertIn('action="/signout"', page)
        body = f"csrf={self.mgr.csrf}&pi=pi2&op=fix&arg=telnet"
        self.assertEqual(self.request("POST", "/do", body, cookie=session)[1], "/?m=done#pi-pi2")
        self.request("POST", "/signout", f"csrf={self.mgr.csrf}", cookie=session)
        self.assertIn('action="/signin"', self.request("GET", "/", cookie=session)[3])

    def test_sessions_expire_and_are_capped(self):
        session = self.sign_in()[2].split(";")[0]
        self.now += manager.SESSION_TTL + 1
        self.assertIn('action="/signin"', self.request("GET", "/", cookie=session)[3])
        tokens = [self.access.sign_in(self.CODE) for _ in range(manager.MAX_SESSIONS + 1)]
        self.assertEqual(len(self.access.sessions), manager.MAX_SESSIONS)
        self.assertFalse(self.access.valid(tokens[0]))
        self.assertTrue(self.access.valid(tokens[-1]))

    def test_find_the_pis_again_needs_a_session(self):
        body = f"csrf={self.mgr.csrf}"
        self.assertEqual(self.request("POST", "/locate", body)[0], 403)
        session = self.sign_in()[2].split(";")[0]
        status, location, _, _ = self.request("POST", "/locate", body, cookie=session)
        self.assertEqual((status, location), (303, "/?m=located"))

    def test_other_host_names_are_still_refused(self):
        self.assertEqual(self.request("GET", "/", host="evil.example")[0], 403)
        self.assertEqual(self.request("GET", "/", host=f"127.0.0.1:{self.port}")[0], 200)

    def test_the_hotspot_needs_an_access_code_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            conf = pathlib.Path(tmp, "pis.conf")
            conf.write_text("pi2 192.168.50.12\n")
            args = ["--bind", "192.168.50.1", "--config", str(conf), "--state-dir", tmp]
            self.assertEqual(manager.main(args), 1)
            pathlib.Path(tmp, "access-code").write_text("hunter2\n")
            self.assertEqual(manager.main(args), 1)
        self.assertEqual(manager.load_access_code(self._code_file()), self.CODE)

    def _code_file(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = pathlib.Path(tmp.name, "access-code")
        path.write_text(self.CODE.lower() + "\n")
        return path


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
