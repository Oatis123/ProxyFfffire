import base64
import http.client
import json
import queue
import shutil
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import contextmanager
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import Mock, patch

from controller import Controller
from presets import BUILTIN_PRESETS
from proxy import ProxyError, https_probe, receive, relay
from settings import Profile, Store, domain_rules, make_pac, parse_url
from windows import WindowsProxy, WindowsSettings, protect, unprotect


FIXTURES = Path(__file__).with_name("fixtures")
HOST = "origin.proxyfffire.test"


class Origin(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"OK")

    def do_POST(self):
        self.server.last_headers = self.headers
        if self.headers.get("Transfer-Encoding") == "chunked":
            data = bytearray()
            while size := int(self.rfile.readline().strip(), 16):
                data.extend(self.rfile.read(size))
                self.rfile.readline()
            self.rfile.readline()
        else:
            data = self.rfile.read(int(self.headers["Content-Length"]))
        self.send_response(200)
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        self.wfile.write(f"{len(data):x}\r\n".encode() + data + b"\r\n0\r\n\r\n")

    def log_message(self, *args):
        pass


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while data := self.request.recv(1024):
            self.request.sendall(data)


class MockUpstream(socketserver.StreamRequestHandler):
    rbufsize = 0

    def handle(self):
        self.request.settimeout(5)
        if self.server.protocol == "SOCKS5":
            host, port = self.socks()
        else:
            host, port = self.http()
        self.server.targets.put((host, port))
        if self.server.reject:
            return
        with socket.create_connection(("127.0.0.1", port), timeout=5) as origin:
            if self.server.protocol == "SOCKS5":
                self.wfile.write(b"\x05\x00\x00\x03\x01a\x00\x00")
            else:
                self.wfile.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
            try:
                relay(self.request, origin)
            except (OSError, ProxyError):
                pass

    def http(self):
        method, target, version = self.rfile.readline().decode().split()
        assert (method, version) == ("CONNECT", "HTTP/1.1")
        headers = http.client.parse_headers(self.rfile)
        self.server.auth.put(headers.get("Proxy-Authorization"))
        if self.server.reject:
            self.wfile.write(b"HTTP/1.1 407 Authentication Required\r\n\r\n")
        host, port = target.rsplit(":", 1)
        return host, int(port)

    def socks(self):
        assert receive(self.request, 2) == b"\x05\x01"
        method = receive(self.request, 1)
        self.wfile.write(b"\x05" + method)
        credentials = None
        if method == b"\x02":
            assert receive(self.request, 1) == b"\x01"
            user, password = (receive(self.request, receive(self.request, 1)[0]) for _ in range(2))
            credentials = (user, password)
            self.wfile.write(b"\x01\x00")
        self.server.auth.put(credentials)
        assert receive(self.request, 4) == b"\x05\x01\x00\x03"  # Domain name on the wire.
        host = receive(self.request, receive(self.request, 1)[0]).decode()
        return host, int.from_bytes(receive(self.request, 2), "big")


class ThreadedServer(socketserver.ThreadingTCPServer):
    daemon_threads = True


@contextmanager
def serve(handler, *, tls=False, protocol=None, reject=False):
    factory = ThreadingHTTPServer if handler is Origin else ThreadedServer
    with factory(("127.0.0.1", 0), handler) as server:
        server.port = server.server_address[1]
        server.protocol, server.reject = protocol, reject
        server.auth, server.targets = queue.Queue(), queue.Queue()
        if tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(FIXTURES / "localhost-cert.pem", FIXTURES / "localhost-key.pem")
            server.socket = context.wrap_socket(server.socket, server_side=True)
        worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        worker.start()
        try:
            yield server
        finally:
            server.shutdown()
            worker.join()


class FakeWindows:
    def __init__(self):
        self.current = WindowsSettings(11, "original.example:3128", "*.internal.example", "https://config.example/proxy.pac")
        self.writes = []

    def read(self):
        return self.current

    def write(self, value):
        self.writes.append(value)
        self.current = value


class Integration(unittest.TestCase):
    def setUp(self):
        temp = self.enterContext(tempfile.TemporaryDirectory())
        self.path = Path(temp) / "backup.json"
        self.backend = FakeWindows()
        self.windows = WindowsProxy(self.backend, self.path, lambda value: value, lambda value: value)
        self.original = self.backend.current
        self.context = ssl.create_default_context(cafile=FIXTURES / "localhost-cert.pem")
        self.events = []
        self.controller = Controller(self.windows, lambda *event: self.events.append(event),
                                     lambda profile, url, log: https_probe(profile, url, log, self.context))
        self.addCleanup(self.controller.disconnect)

    def upstream(self, protocol, *, reject=False, auth=False):
        server = self.enterContext(serve(MockUpstream, protocol=protocol, reject=reject))
        return server, Profile(protocol, protocol, protocol, "127.0.0.1", server.port,
                               "fixture-user" if auth else "", "fixture-password" if auth else "")

    def test_real_https_over_both_protocols(self):
        origin = self.enterContext(serve(Origin, tls=True))
        url = f"https://{HOST}:{origin.port}/hidden-path?secret=hidden"
        for protocol in ("HTTP CONNECT", "SOCKS5"):
            for authenticated in (False, True):
                with self.subTest(protocol=protocol, authenticated=authenticated):
                    server, profile = self.upstream(protocol, auth=authenticated)
                    self.assertEqual(200, self.controller.test(profile, url))
                    self.assertEqual((HOST, origin.port), server.targets.get(timeout=2))
                    secret = (b"fixture-user", b"fixture-password")
                    if not authenticated:
                        expected = None
                    elif protocol == "SOCKS5":
                        expected = secret
                    else:
                        expected = "Basic " + base64.b64encode(b":".join(secret)).decode()
                    self.assertEqual(expected, server.auth.get(timeout=2))
        self.assertEqual(4, len(self.events))
        for event in self.events:
            self.assertEqual(HOST, event[0])
            self.assertNotIn("hidden", str(event))
            self.assertNotIn("fixture-password", str(event))

    def test_switch_uses_candidate_only_after_probe_and_preserves_old_tunnel(self):
        origin = self.enterContext(serve(Origin, tls=True))
        echo = self.enterContext(serve(Echo))
        _, first = self.upstream("HTTP CONNECT")
        server_b, second = self.upstream("SOCKS5")
        _, failed = self.upstream("HTTP CONNECT", reject=True)
        url = f"https://{HOST}:{origin.port}/"
        self.controller.connect(first, url, 0, "Manual")
        port = self.controller.active.port
        with socket.create_connection(("127.0.0.1", port), timeout=2) as old:
            old.sendall(f"CONNECT {HOST}:{echo.port} HTTP/1.1\r\nHost: {HOST}\r\n\r\nfirst".encode())
            with old.makefile("rb", buffering=0) as reply:
                self.assertIn(b" 200 ", reply.readline())
                http.client.parse_headers(reply)
                self.assertEqual(b"first", receive(old, 5))
                with self.assertRaisesRegex(ProxyError, "407"):
                    self.controller.connect(failed, url, port, "Manual")
                self.assertEqual(first, self.controller.active.profile)
                self.controller.connect(second, url, port, "Manual")
                self.assertEqual(second, self.controller.active.profile)
                self.assertEqual((HOST, origin.port), server_b.targets.get(timeout=2))
                client = http.client.HTTPSConnection("127.0.0.1", port, context=self.context, timeout=3)
                client.set_tunnel(HOST, origin.port)
                try:
                    client.request("GET", "/private")
                    self.assertEqual(b"OK", client.getresponse().read())
                finally:
                    client.close()
                self.assertEqual((HOST, origin.port), server_b.targets.get(timeout=2))
                old.sendall(b"still first")
                self.assertEqual(b"still first", receive(old, 11))
                self.controller.disconnect()
                self.assertEqual(b"", old.recv(1))
        self.assertEqual([], self.backend.writes)

    def test_plain_http_upload_response_and_pac(self):
        origin = self.enterContext(serve(Origin, tls=True))
        plain = self.enterContext(serve(Origin))
        _, profile = self.upstream("SOCKS5")
        rules = ("example.com", "*.example.org")
        url = f"https://{HOST}:{origin.port}/"
        self.controller.connect(profile, url, 0, "Selected Domains", "Preset", rules)
        active = self.controller.active
        client = http.client.HTTPConnection("127.0.0.1", active.port, timeout=3)
        try:
            client.request("GET", active.pac_path)
            response = client.getresponse()
            self.assertEqual("application/x-ns-proxy-autoconfig", response.headers["Content-Type"])
            self.assertEqual(make_pac(rules, active.port), response.read())
            target = f"http://{HOST}:{plain.port}/secret-path"
            for body in (b"data", iter((b"da", b"ta"))):
                client.request("POST", target, body, {"Proxy-Authorization": "private", "Connection": "X-Hop", "X-Hop": "private"},
                               encode_chunked=True)
                self.assertEqual(b"data", client.getresponse().read())
                self.assertNotIn("Proxy-Authorization", plain.last_headers)
                self.assertNotIn("X-Hop", plain.last_headers)
        finally:
            client.close()
        self.assertNotIn("secret-path", str(self.events))
        self.assertEqual(WindowsSettings(5, pac=f"http://127.0.0.1:{active.port}{active.pac_path}"), self.backend.current)
        self.controller.connect(profile, url, active.port, "System Proxy")
        self.assertEqual(WindowsSettings(3, server=f"127.0.0.1:{active.port}"), self.backend.current)
        self.controller.connect(profile, url, active.port, "Manual")
        self.assertEqual(self.original, self.backend.current)
        self.assertFalse(self.path.exists())

    def test_restore_after_restart_and_external_edit(self):
        ours = WindowsSettings(3, "127.0.0.1:1234")
        self.windows.apply(ours)
        restarted = WindowsProxy(self.backend, self.path, lambda value: value, lambda value: value)
        restarted.restore()
        self.assertEqual(self.original, self.backend.current)
        self.windows.apply(ours)
        user_settings = replace(ours, bypass="changed.example")
        self.backend.current = user_settings
        writes = len(self.backend.writes)
        self.assertIn("changed outside", restarted.restore())
        self.assertEqual(writes, len(self.backend.writes))
        self.assertEqual(user_settings, self.backend.current)
        self.assertFalse(self.path.exists())

    def test_failed_system_change_keeps_old_profile(self):
        origin = self.enterContext(serve(Origin, tls=True))
        _, first = self.upstream("HTTP CONNECT")
        _, second = self.upstream("SOCKS5")
        url = f"https://{HOST}:{origin.port}/"
        self.controller.connect(first, url, 0, "Manual")
        active = self.controller.active

        def denied(value):
            raise OSError("Denied by mock policy.")

        self.backend.write = denied
        with self.assertRaisesRegex(ProxyError, "Denied"):
            self.controller.connect(second, url, active.port, "Selected Domains", "Preset", ("example.com",))
        self.assertEqual(active, self.controller.active)
        self.assertEqual(first, self.controller.listener.profile)
        self.assertEqual({}, self.controller.listener.pacs)
        self.assertEqual(self.original, self.backend.current)


class RelayTests(unittest.TestCase):
    def test_connection_reset_identifies_the_failed_peer(self):
        for reset_client in (False, True):
            for sending in (False, True):
                with self.subTest(reset_client=reset_client, sending=sending):
                    client, upstream = Mock(), Mock()
                    failed, other = (client, upstream) if reset_client else (upstream, client)
                    if sending:
                        other.recv.return_value = b"data"
                        failed.sendall.side_effect = ConnectionResetError
                    else:
                        failed.recv.side_effect = ConnectionResetError
                    with patch("proxy.select.select", return_value=([other if sending else failed], [], [])):
                        if reset_client:
                            relay(client, upstream)
                        else:
                            with self.assertRaisesRegex(ProxyError, "upstream connection"):
                                relay(client, upstream)
                    operation = failed.sendall if sending else failed.recv
                    operation.assert_called_once()


class SettingsTests(unittest.TestCase):
    def test_bundled_presets_load_with_legacy_settings(self):
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp) / "profiles.json", None, None)
            self.assertEqual(BUILTIN_PRESETS, store.load()["presets"])
            legacy = {
                "profiles": [],
                "presets": {
                    "claude": {"name": "Claude Personal", "domains": ["claude.ai"]},
                    "custom": {"name": "GitHub", "domains": ["github.com"]},
                },
                "routing": {"preset": "custom"},
            }
            store.path.write_text(json.dumps(legacy), encoding="utf-8")
            loaded = store.load()
            self.assertEqual(legacy["routing"], loaded["routing"])
            for key, preset in legacy["presets"].items():
                self.assertEqual(preset, loaded["presets"][key])
            self.assertEqual("GitHub (Built-in)", loaded["presets"]["github"]["name"])
            self.assertEqual(BUILTIN_PRESETS.keys() | {"custom"}, loaded["presets"].keys())
            store.save(loaded)
            self.assertEqual(loaded, store.load())

    def test_bundled_preset_rules_and_sources_are_valid(self):
        for key, preset in BUILTIN_PRESETS.items():
            with self.subTest(preset=key):
                self.assertTrue(preset["domains"])
                self.assertEqual(preset["domains"], domain_rules(preset["domains"]))
                parse_url(preset["source"].split("#", 1)[0], "https")

    def test_pac_javascript(self):
        port = 8787
        rules = domain_rules(["EXAMPLE.com.", "*.EXAMPLE.org", "EXAMPLE.com"])
        self.assertEqual(["example.com", "*.example.org"], rules)
        for invalid in ("http://example.com", "example.com:80", "*example.com", "*.127.0.0.1"):
            with self.assertRaises(ValueError):
                domain_rules([invalid])
        cases = {"example.com": True, "a.example.com": False, "example.org": False,
                 "A.B.EXAMPLE.ORG.": True, "a.example.org": True, "notexample.org": False,
                 "a.notexample.org": False, "example.org.wrong.test": False}
        node = shutil.which("node")
        with tempfile.TemporaryDirectory() as temp:
            script = Path(temp) / "pac.js"
            js = make_pac(rules, port).decode()
            for name, forwarded in cases.items():
                expected = f"PROXY 127.0.0.1:{port}" if forwarded else "DIRECT"
                condition = f'FindProxyForURL("https://irrelevant.example/", {json.dumps(name)}) !== {json.dumps(expected)}'
                js += f"if ({condition}) throw new Error({json.dumps(name)});\n"
            script.write_text(js, encoding="ascii")
            command = [node, str(script)] if node else ["cscript.exe", "//Nologo", "//E:JScript", str(script)]
            subprocess.run(command, check=True, timeout=10)

    @unittest.skipUnless(sys.platform == "win32", "Uses Windows DPAPI")
    def test_password_dpapi_roundtrip(self):
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp) / "profiles.json", protect, unprotect)
            data = store.load()
            profile = Profile("fixture-id", "Fixture", "HTTP CONNECT", "fixture.example", 8080, "user", "DPAPI-Only-Password")
            data["profiles"].append(store.pack(profile))
            store.save(data)
            self.assertNotIn(profile.password, store.path.read_text(encoding="utf-8"))
            self.assertEqual(profile, store.unpack(store.load()["profiles"][0]))
            self.assertEqual(BUILTIN_PRESETS["claude"], store.load()["presets"]["claude"])


if __name__ == "__main__":
    unittest.main()
