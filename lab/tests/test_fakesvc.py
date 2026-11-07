"""Tests for lab/fakes/fakesvc.py. Run: python3 -m unittest discover -s lab/tests"""

import asyncio
import contextlib
import importlib.util
import io
import pathlib
import unittest

_PATH = pathlib.Path(__file__).resolve().parents[1] / "fakes" / "fakesvc.py"
_spec = importlib.util.spec_from_file_location("fakesvc", _PATH)
fakesvc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fakesvc)


class FakeServiceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.started = []

    async def asyncTearDown(self):
        for item in self.started:
            item.close()

    async def connect(self, name, **kwargs):
        server = await fakesvc.start_service(name, "127.0.0.1", 0, **kwargs)
        self.started.append(server)
        port = server.sockets[0].getsockname()[1]
        return await asyncio.open_connection("127.0.0.1", port)

    async def read_all(self, reader, timeout=3.0):
        return await asyncio.wait_for(reader.read(65536), timeout)

    async def test_telnet_sends_iac_negotiation_first(self):
        reader, writer = await self.connect("telnet")
        first = await asyncio.wait_for(reader.read(64), 2)
        self.assertEqual(first, fakesvc.TELNET_HELLO)
        writer.write(b"\xff\xfc\x01")
        prompt = await asyncio.wait_for(reader.readuntil(b"login: "), 2)
        self.assertIn(b"login: ", prompt)
        writer.close()

    async def test_telnet_login_never_succeeds(self):
        reader, writer = await self.connect("telnet")
        await asyncio.wait_for(reader.read(64), 2)
        writer.write(b"\r\n")
        await asyncio.wait_for(reader.readuntil(b"login: "), 2)
        writer.write(b"root\r\n")
        await asyncio.wait_for(reader.readuntil(b"Password: "), 2)
        writer.write(b"root\r\n")
        reply = await asyncio.wait_for(reader.readuntil(b"login: "), 3)
        self.assertIn(b"Login incorrect", reply)
        writer.close()

    async def test_ftp_banner_and_failed_login(self):
        reader, writer = await self.connect("ftp")
        self.assertEqual(await reader.readline(), b"220 (vsFTPd 2.3.4)\r\n")
        writer.write(b"USER anonymous\r\n")
        self.assertTrue((await reader.readline()).startswith(b"331"))
        writer.write(b"PASS x\r\n")
        self.assertTrue((await asyncio.wait_for(reader.readline(), 3)).startswith(b"530"))
        writer.write(b"LIST\r\n")
        self.assertTrue((await reader.readline()).startswith(b"530"))
        writer.close()

    async def test_http_admin_title(self):
        reader, writer = await self.connect("http", http_title="Camera <Login>")
        writer.write(b"GET / HTTP/1.0\r\n\r\n")
        response = await self.read_all(reader)
        self.assertTrue(response.startswith(b"HTTP/1.1 200 OK\r\n"))
        self.assertIn(b"<title>Camera &lt;Login&gt;</title>", response)

    async def test_http_post_always_fails(self):
        reader, writer = await self.connect("http")
        writer.write(b"POST / HTTP/1.0\r\nContent-Length: 20\r\n\r\nuser=admin&password=")
        response = await self.read_all(reader)
        self.assertTrue(response.startswith(b"HTTP/1.1 401"))

    async def test_rtsp_options_and_describe(self):
        reader, writer = await self.connect("rtsp")
        writer.write(b"OPTIONS rtsp://x/ RTSP/1.0\r\nCSeq: 7\r\n\r\n")
        reply = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2)
        self.assertTrue(reply.startswith(b"RTSP/1.0 200 OK\r\nCSeq: 7\r\n"))
        writer.write(b"DESCRIBE rtsp://x/ RTSP/1.0\r\nCSeq: 8\r\n\r\n")
        reply = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2)
        self.assertTrue(reply.startswith(b"RTSP/1.0 401"))
        writer.close()

    async def test_rtsp_rejects_garbage_cseq(self):
        reader, writer = await self.connect("rtsp")
        writer.write(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nX: y\r\nCSeq: \r\nInjected: 1\r\n\r\n")
        reply = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2)
        self.assertNotIn(b"Injected", reply)
        writer.close()

    async def test_redis_refuses_without_auth(self):
        reader, writer = await self.connect("redis")
        writer.write(b"*1\r\n$4\r\nINFO\r\n")
        self.assertEqual(await reader.readline(), b"-ERR operation not permitted\r\n")
        writer.close()

    async def test_mqtt_connack_not_authorized(self):
        reader, writer = await self.connect("mqtt")
        writer.write(b"\x10\x0c\x00\x04MQTT\x04\x02\x00\x3c\x00\x00")
        self.assertEqual(await self.read_all(reader), b"\x20\x02\x00\x05")

    async def test_mqtt5_connack_not_authorized(self):
        reader, writer = await self.connect("mqtt")
        writer.write(b"\x10\x0d\x00\x04MQTT\x05\x02\x00\x3c\x00\x00\x00")
        self.assertEqual(await self.read_all(reader), b"\x20\x03\x00\x87\x00")

    async def test_jetdirect_pjl_info_id(self):
        reader, writer = await self.connect("jetdirect")
        writer.write(b"\x1b%-12345X@PJL INFO ID\r\n\x1b%-12345X\r\n")
        reply = await asyncio.wait_for(reader.readuntil(b"\x0c"), 2)
        self.assertEqual(reply, fakesvc.PJL_ID)
        writer.close()

    async def test_read_limit_closes_connection(self):
        reader, writer = await self.connect("jetdirect")
        writer.write(b"A" * (fakesvc.READ_LIMIT + 100))
        await writer.drain()
        self.assertEqual(await self.read_all(reader), b"")

    async def test_overlong_line_closes_connection(self):
        reader, writer = await self.connect("ftp")
        await reader.readline()
        writer.write(b"USER " + b"x" * (fakesvc.READ_LIMIT * 2) + b"\r\n")
        await writer.drain()
        self.assertEqual(await self.read_all(reader), b"")

    async def test_ssdp_answers_m_search(self):
        loop = asyncio.get_running_loop()
        transport = await fakesvc.start_service("ssdp", "127.0.0.1", 0)
        self.started.append(transport)
        port = transport.get_extra_info("sockname")[1]
        got = loop.create_future()

        class Client(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):
                if not got.done():
                    got.set_result(data)

        client, _ = await loop.create_datagram_endpoint(Client, remote_addr=("127.0.0.1", port))
        try:
            client.sendto(
                b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\n'
                b"MX: 1\r\nST: ssdp:all\r\n\r\n"
            )
            reply = await asyncio.wait_for(got, 2)
        finally:
            client.close()
        self.assertTrue(reply.startswith(b"HTTP/1.1 200 OK\r\n"))
        self.assertIn(b"\r\nSERVER: ", reply)

    def test_ssdp_ignores_public_sources(self):
        responder = fakesvc.SsdpResponder()
        sent = []

        class Transport:
            def sendto(self, data, addr):
                sent.append(addr)

        responder.connection_made(Transport())
        responder.datagram_received(b"M-SEARCH * HTTP/1.1\r\n\r\n", ("8.8.8.8", 1900))
        responder.datagram_received(b"M-SEARCH * HTTP/1.1\r\n\r\n", ("100.64.0.5", 1900))
        self.assertEqual(sent, [])

    def test_ssdp_rate_limit(self):
        responder = fakesvc.SsdpResponder()
        sent = []

        class Transport:
            def sendto(self, data, addr):
                sent.append(addr)

        responder.connection_made(Transport())
        for _ in range(50):
            responder.datagram_received(b"M-SEARCH * HTTP/1.1\r\n\r\n", ("192.168.1.10", 1900))
        self.assertEqual(len(sent), fakesvc.UDP_MAX_REPLIES_PER_SECOND)

    def test_bind_is_required(self):
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            fakesvc.main(["telnet"])


if __name__ == "__main__":
    unittest.main()
