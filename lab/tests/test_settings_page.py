"""Tests for the camera's sign-in and settings switches (#144) in lab/fakes/fakesvc.py.
Run: python3 -m unittest discover -s lab/tests"""

import asyncio
import importlib.util
import pathlib
import re
import tempfile
import unittest

LAB = pathlib.Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("fakesvc_settings", LAB / "fakes" / "fakesvc.py")
fakesvc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fakesvc)

try:
    from tool.content.texts import FINDINGS
except ImportError:  # a Pi, or a checkout without `pip install -e .`
    FINDINGS = None

DEVICE_ID = "CAM-7K3P-Q9XD"

# service -> the catalog code whose fix steps describe its switch
SWITCH_CODES = {
    "telnet": "TELNET_OPEN",
    "rtsp": "CAMERA_STREAM_EXPOSED",
    "ftp": "FTP_CLEARTEXT",
    "redis": "DB_EXPOSED",
    "smb": "SMB_EXPOSED",
    "mqtt": "MQTT_EXPOSED",
    "ssdp": "UPNP_EXPOSED",
    "snmp": "SNMP_EXPOSED",
    "jetdirect": "PRINTER_RAW_EXPOSED",
}
# The words of each label that must appear in that code's fix steps: (English, Romanian).
LABEL_WORDS = {
    "telnet": (["Telnet", "remote access"], ["Telnet", "acces la distanță"]),
    "rtsp": (["video stream", "RTSP"], ["transmisie video", "RTSP"]),
    "ftp": (["FTP", "file-sharing"], ["FTP", "partajare a fișierelor"]),
    "redis": (["database connections"], ["conexiuni la baza de date"]),
    "smb": (["sharing"], ["partajare"]),
    "mqtt": (["MQTT"], ["MQTT"]),
    "ssdp": (["UPnP"], ["UPnP"]),
    "snmp": (["SNMP"], ["SNMP"]),
    "jetdirect": (
        ["direct printing", "JetDirect", "RAW", "9100"],
        ["imprimarea directă", "JetDirect"],
    ),
}


class FakeHelper:
    """A stand-in for lab-switch.socket: answers like switchd.py and records requests."""

    def __init__(self, path):
        self.path = path
        # Like `labctl state` on the camera: the preset's services carry "default".
        self.state = {
            "telnet": "on default",
            "http": "on default",
            "ftp": "on default",
            "rtsp": "off",
            "redis": "off",
        }
        self.requests = []

    async def start(self):
        self.server = await asyncio.start_unix_server(self.on_client, self.path)

    async def on_client(self, reader, writer):
        line = (await reader.readline()).decode().strip()
        self.requests.append(line)
        verb, _, service = line.partition(" ")
        if verb == "status":
            lines = "preset camera\n" + "".join(f"{s} {v}\n" for s, v in self.state.items())
            writer.write(lines.encode() + b"ok\n")
        elif verb in ("fix", "break") and service in self.state:
            rest = self.state[service].split()[1:]
            self.state[service] = " ".join(["off" if verb == "fix" else "on", *rest])
            writer.write(b"ok\n")
        else:
            writer.write(b"refused\n")
        await writer.drain()
        writer.close()


class SettingsPageTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        fakesvc.LOGIN_FAIL_DELAY = 0.05
        self.tmp = tempfile.TemporaryDirectory()
        self.helper = FakeHelper(str(pathlib.Path(self.tmp.name) / "switch.sock"))
        await self.helper.start()
        self.server = await fakesvc.start_service(
            "http", "127.0.0.1", 0, device_id=DEVICE_ID, switch_socket=self.helper.path
        )
        self.port = self.server.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        self.server.close()
        self.helper.server.close()
        self.tmp.cleanup()

    async def request(self, method, path, body=b"", cookie=None):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        head = f"{method} {path} HTTP/1.1\r\nHost: cam\r\n"
        if cookie:
            head += f"Cookie: session={cookie}\r\n"
        if method == "POST":
            head += "Content-Type: application/x-www-form-urlencoded\r\n"
            head += f"Content-Length: {len(body)}\r\n"
        writer.write(head.encode() + b"\r\n" + body)
        response = await asyncio.wait_for(reader.read(65536), 5)
        writer.close()
        return response

    async def login(self, password=DEVICE_ID):
        response = await self.request("POST", "/", f"user=admin&password={password}".encode())
        match = re.search(rb"Set-Cookie: session=([^;]+);", response)
        return response, match.group(1).decode() if match else None

    async def settings(self, cookie):
        page = await self.request("GET", "/settings", cookie=cookie)
        csrf = re.search(rb'name="csrf" value="([^"]+)"', page).group(1).decode()
        return page, csrf

    async def test_the_root_page_title_stays_camera_login(self):
        response = await self.request("GET", "/")
        self.assertTrue(response.startswith(b"HTTP/1.1 200 OK\r\n"))
        self.assertIn(b"<title>Camera Login</title>", response)
        _, cookie = await self.login()
        self.assertIn(b"<title>Camera Login</title>", await self.request("GET", "/", cookie=cookie))

    async def test_other_methods_get_the_old_401_login_page(self):
        # nmap's HTTPOptions probe saw this reply before #144; keep it the same.
        for method in ("OPTIONS", "PUT", "DELETE"):
            response = await self.request(method, "/")
            self.assertTrue(response.startswith(b"HTTP/1.1 401"), method)
            self.assertIn(b"Server: lighttpd/1.4.59", response)
            self.assertIn(b"<title>Camera Login</title>", response)
        self.assertEqual(self.helper.requests, [])

    async def test_the_label_device_id_signs_in(self):
        response, cookie = await self.login()
        self.assertTrue(response.startswith(b"HTTP/1.1 303"))
        self.assertIn(b"Location: /settings", response)
        self.assertIn(b"HttpOnly; SameSite=Strict", response)
        self.assertGreaterEqual(len(cookie), 40)

    async def test_people_may_type_the_id_in_lower_case_without_dashes(self):
        _, cookie = await self.login("cam7k3pq9xd")
        self.assertIsNotNone(cookie)

    async def test_any_other_password_fails_with_the_same_page(self):
        for password in ("", "admin", "CAM-7K3P-Q9XE", DEVICE_ID + "X", "B8:27:EB:00:00:00"):
            with self.subTest(password=password):
                response, cookie = await self.login(password)
                self.assertTrue(response.startswith(b"HTTP/1.1 401"))
                self.assertIn(b"Wrong user name or password.", response)
                self.assertIsNone(cookie)
        response = await self.request("POST", "/", f"user=root&password={DEVICE_ID}".encode())
        self.assertTrue(response.startswith(b"HTTP/1.1 401"))

    async def test_without_a_device_id_no_one_signs_in(self):
        server = await fakesvc.start_service("http", "127.0.0.1", 0, device_id=None)
        self.port = server.sockets[0].getsockname()[1]
        response, cookie = await self.login()
        server.close()
        self.assertTrue(response.startswith(b"HTTP/1.1 401"))
        self.assertIsNone(cookie)

    async def test_settings_need_a_session(self):
        for cookie in (None, "made-up"):
            response = await self.request("GET", "/settings", cookie=cookie)
            self.assertTrue(response.startswith(b"HTTP/1.1 303"))
            self.assertIn(b"Location: /\r\n", response)
        self.assertEqual(self.helper.requests, [])

    async def test_the_settings_page_shows_the_real_state_with_fix_step_labels(self):
        _, cookie = await self.login()
        page, _ = await self.settings(cookie)
        self.assertIn("Telnet / acces la distanță · Telnet / remote access".encode(), page)
        self.assertIn("FTP / partajare a fișierelor".encode(), page)
        self.assertNotIn(b'value="http"', page)  # the page can't switch itself off
        # Services outside the preset only show while they are on (#155).
        self.assertNotIn(b"RTSP", page)
        self.assertNotIn(b"Database", page)
        self.helper.state["redis"] = "on"
        page, _ = await self.settings(cookie)
        self.assertIn(b"Database connections from other devices", page)
        self.assertIn(b"no-store", page)
        self.assertEqual(self.helper.requests, ["status", "status"])

    async def test_a_switch_asks_the_helper_and_the_page_follows(self):
        _, cookie = await self.login()
        _, csrf = await self.settings(cookie)
        body = f"csrf={csrf}&service=telnet&action=fix".encode()
        response = await self.request("POST", "/settings", body, cookie=cookie)
        self.assertTrue(response.startswith(b"HTTP/1.1 303"))
        self.assertIn("fix telnet", self.helper.requests)
        self.assertEqual(self.helper.state["telnet"], "off default")
        page, _ = await self.settings(cookie)
        self.assertRegex(page.decode(), r"Telnet / remote access</legend>\s*<p>Oprit · Off")

    async def test_a_switch_without_the_csrf_token_is_refused(self):
        _, cookie = await self.login()
        for csrf in ("", "wrong"):
            body = f"csrf={csrf}&service=telnet&action=fix".encode()
            response = await self.request("POST", "/settings", body, cookie=cookie)
            self.assertTrue(response.startswith(b"HTTP/1.1 403"))
        self.assertNotIn("fix telnet", self.helper.requests)

    async def test_unknown_services_and_actions_never_reach_the_helper(self):
        _, cookie = await self.login()
        _, csrf = await self.settings(cookie)
        for service, action in (("http", "fix"), ("telnet", "reset"), ("telnet;id", "fix")):
            body = f"csrf={csrf}&service={service}&action={action}".encode()
            await self.request("POST", "/settings", body, cookie=cookie)
        self.assertEqual(self.helper.requests, ["status"])

    async def test_sign_out_ends_the_session(self):
        _, cookie = await self.login()
        _, csrf = await self.settings(cookie)
        await self.request("POST", "/logout", f"csrf={csrf}".encode(), cookie=cookie)
        response = await self.request("GET", "/settings", cookie=cookie)
        self.assertTrue(response.startswith(b"HTTP/1.1 303"))

    async def test_an_unreachable_helper_shows_a_plain_message(self):
        self.helper.server.close()
        await self.helper.server.wait_closed()
        pathlib.Path(self.helper.path).unlink(missing_ok=True)
        _, cookie = await self.login()
        page = await self.request("GET", "/settings", cookie=cookie)
        self.assertIn(b"Settings can&#x27;t be changed right now.", page)

    async def test_an_oversized_form_is_dropped(self):
        response = await self.request("POST", "/", b"x" * (fakesvc.MAX_BODY + 1))
        self.assertEqual(response, b"")


class DeviceIdTests(unittest.TestCase):
    def test_read_device_id_only_accepts_a_label_style_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "device-id"
            self.assertIsNone(fakesvc.read_device_id(str(path)))
            for text, expected in (
                (DEVICE_ID + "\n", DEVICE_ID),
                ("short", None),
                ("cam-lower-case", None),
                ("CAM 7K3P", None),
            ):
                path.write_text(text)
                self.assertEqual(fakesvc.read_device_id(str(path)), expected)


@unittest.skipIf(FINDINGS is None, "the tool package isn't installed")
class LabelWordingTests(unittest.TestCase):
    def test_every_switch_label_uses_the_words_of_its_fix_steps(self):
        self.assertEqual(set(fakesvc.SWITCHES), set(SWITCH_CODES))
        for service, (en, ro) in fakesvc.SWITCHES.items():
            steps = FINDINGS[SWITCH_CODES[service]]["steps"]
            en_words, ro_words = LABEL_WORDS[service]
            for lang, label, words in (("en", en, en_words), ("ro", ro, ro_words)):
                text = " ".join(steps[lang]).lower()
                for word in words:
                    with self.subTest(service=service, lang=lang, word=word):
                        self.assertIn(word.lower(), label.lower())
                        self.assertIn(word.lower(), text)


if __name__ == "__main__":
    unittest.main()
