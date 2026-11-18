"""Upstream handshakes, HTTPS health checks and the local HTTP proxy."""

import base64
import http.client
import re
import select
import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlunsplit

from settings import host_name, parse_url, port_number


TIMEOUT = 12
IDLE_TIMEOUT = 300
BUFFER = 65536
TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
HOP_HEADERS = {
    "connection", "proxy-connection", "keep-alive", "transfer-encoding", "trailer", "te",
    "upgrade", "proxy-authorization", "proxy-authenticate", "expect", "content-length",
}


class ProxyError(Exception):
    pass


def describe_error(error):
    if isinstance(error, ProxyError):
        return str(error)
    if isinstance(error, ssl.SSLCertVerificationError):
        return "TLS certificate verification failed."
    if isinstance(error, ssl.SSLError):
        return "TLS negotiation failed."
    if isinstance(error, socket.gaierror):
        return "Could not resolve the upstream proxy address."
    if isinstance(error, TimeoutError):
        return "The connection timed out."
    if isinstance(error, ConnectionRefusedError):
        return "The connection was refused."
    if isinstance(error, (http.client.HTTPException, OSError)):
        return "The peer closed the connection or returned an invalid response."
    return "An unexpected proxy error occurred."


def authority(host, port):
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def receive(sock, length):
    data = bytearray()
    while len(data) < length:
        part = sock.recv(length - len(data))
        if not part:
            raise ProxyError("The upstream proxy closed the handshake.")
        data.extend(part)
    return bytes(data)


def http_tunnel(sock, profile, host, port):
    target = authority(host, port)
    headers = [f"CONNECT {target} HTTP/1.1", f"Host: {target}"]
    if profile.username:
        secret = f"{profile.username}:{profile.password}".encode("utf-8")
        headers.append("Proxy-Authorization: Basic " + base64.b64encode(secret).decode("ascii"))
    sock.sendall(("\r\n".join(headers) + "\r\n\r\n").encode("ascii"))
    # Reading without buffering leaves the first tunnel bytes in the socket.
    with sock.makefile("rb", buffering=0) as stream:
        for _ in range(5):
            line = stream.readline(8193)
            match = re.fullmatch(rb"HTTP/1\.[01] ([0-9]{3})(?: [^\r\n]*)?\r\n", line)
            if len(line) > 8192 or not match:
                raise ProxyError("Invalid response from the HTTP CONNECT proxy.")
            status = int(match[1])
            for _ in range(100):
                line = stream.readline(8193)
                if line == b"\r\n":
                    break
                if len(line) > 8192 or not line.endswith(b"\r\n"):
                    raise ProxyError("Invalid response headers from the HTTP CONNECT proxy.")
            else:
                raise ProxyError("Too many response headers from the HTTP CONNECT proxy.")
            if 200 <= status < 300:
                return
            if status == 407:
                raise ProxyError("HTTP CONNECT authentication failed (407).")
            if status >= 200 or status == 101:
                raise ProxyError(f"HTTP CONNECT was rejected ({status}).")
    raise ProxyError("Too many interim responses from the HTTP CONNECT proxy.")


def socks_tunnel(sock, profile, host, port):
    method = 2 if profile.username else 0
    sock.sendall(bytes((5, 1, method)))
    if receive(sock, 2) != bytes((5, method)):
        raise ProxyError("The SOCKS5 proxy rejected the configured authentication method.")
    if method == 2:
        user, password = (part.encode("utf-8") for part in (profile.username, profile.password))
        sock.sendall(b"\x01" + bytes((len(user),)) + user + bytes((len(password),)) + password)
        if receive(sock, 2) != b"\x01\x00":
            raise ProxyError("SOCKS5 username/password authentication failed.")
    # ATYP=DOMAIN delegates destination resolution to the upstream SOCKS server.
    name = host.encode("ascii")
    sock.sendall(b"\x05\x01\x00\x03" + bytes((len(name),)) + name + port.to_bytes(2, "big"))
    version, status, reserved, atype = receive(sock, 4)
    if version != 5 or reserved != 0:
        raise ProxyError("Invalid response from the SOCKS5 proxy.")
    if status:
        reasons = {1: "general failure", 2: "blocked by proxy rules", 3: "network unreachable",
                   4: "host unreachable", 5: "connection refused", 6: "TTL expired",
                   7: "command unsupported", 8: "address type unsupported"}
        raise ProxyError(f"SOCKS5 connection failed ({reasons.get(status, str(status))}).")
    if atype == 3:
        address_length = receive(sock, 1)[0]
    elif atype in (1, 4):
        address_length = 4 if atype == 1 else 16
    else:
        raise ProxyError("The SOCKS5 proxy returned an invalid address type.")
    receive(sock, address_length + 2)


def open_tunnel(profile, host, port, track=None):
    try:
        sock = socket.create_connection((profile.host, profile.port), timeout=TIMEOUT)
        try:
            if track:
                track(sock)
            handshake = http_tunnel if profile.protocol == "HTTP CONNECT" else socks_tunnel
            handshake(sock, profile, host, port)
        except Exception:
            sock.close()
            raise
    except (OSError, http.client.HTTPException) as error:
        raise ProxyError(describe_error(error)) from None
    return sock


def https_probe(profile, url, log, context=None):
    parts, host, port = parse_url(url, "https")
    path = urlunsplit(("", "", parts.path or "/", parts.query, ""))
    try:
        try:
            path = path.encode("ascii")
        except UnicodeEncodeError:
            raise ProxyError("Percent-encode non-ASCII characters in the test URL path.") from None
        context = context or ssl.create_default_context()
        with open_tunnel(profile, host, port) as sock, context.wrap_socket(sock, server_hostname=host) as tls:
            tls.sendall(b"GET " + path + b" HTTP/1.1\r\nHost: " + authority(host, port).encode("ascii")
                        + b"\r\nConnection: close\r\nUser-Agent: ProxyFfffire\r\n\r\n")
            with http.client.HTTPResponse(tls) as response:
                response.begin()
                status = response.status
                if not 200 <= status < 400:
                    raise ProxyError(f"The HTTPS test endpoint returned HTTP {status}.")
    except (ProxyError, OSError, http.client.HTTPException) as error:
        reason = describe_error(error)
        log(host, profile.name, f"Test failed — {reason}")
        raise ProxyError(reason) from None
    log(host, profile.name, f"HTTPS test passed ({status})")
    return status


def forward_headers(headers):
    tokens = {token.strip().lower() for value in headers.get_all("Connection", ()) for token in value.split(",")}
    return [(name, value) for name, value in headers.items() if name.lower() not in HOP_HEADERS | tokens]


def relay(client, upstream):
    peers = {client: upstream, upstream: client}
    for sock in peers:
        sock.settimeout(TIMEOUT)
    while peers:
        ready, _, _ = select.select(list(peers), [], [], IDLE_TIMEOUT)
        if not ready:
            return
        for source in ready:
            target = peers[source]
            try:
                data = source.recv(BUFFER)
            except ConnectionError:
                if source is client:
                    return
                raise ProxyError("The upstream connection was interrupted after CONNECT.") from None
            if data:
                try:
                    target.sendall(data)
                except ConnectionError:
                    if target is client:
                        return
                    raise ProxyError("The upstream connection was interrupted after CONNECT.") from None
            else:
                del peers[source]
                try:
                    target.shutdown(socket.SHUT_WR)
                except OSError:
                    pass


class Traffic:
    """Tracks sockets across listener replacements so disconnect closes old tunnels too."""

    def __init__(self):
        self.lock = threading.Lock()
        self.groups = set()
        self.slots = threading.BoundedSemaphore(128)

    def add(self, group, sock, new=False):
        with self.lock:
            if new:
                self.groups.add(group)
            if group not in self.groups:
                raise ProxyError("The local proxy disconnected.")
            group.sockets.append(sock)

    def remove(self, group):
        with self.lock:
            self.groups.discard(group)

    def close(self):
        with self.lock:
            for group in self.groups:
                for sock in group.sockets:
                    try:
                        sock.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    sock.close()
            self.groups.clear()


class LocalProxy(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False
    allow_reuse_port = False
    request_queue_size = 64

    def __init__(self, port, log, traffic):
        self.log = log
        self.traffic = traffic
        self.profile = None
        self.pacs = {}
        super().__init__(("127.0.0.1", port), LocalRequest)

    def server_bind(self):
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()

    def process_request(self, request, client_address):
        if not self.traffic.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.traffic.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.traffic.slots.release()

    def handle_error(self, request, client_address):
        # Default socketserver tracebacks can include request data.
        pass

    def start(self):
        threading.Thread(target=self.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True).start()

    def stop(self):
        self.profile = None
        self.shutdown()
        self.server_close()


class LocalRequest(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    rbufsize = 0  # Preserve pipelined tunnel bytes after CONNECT.
    timeout = TIMEOUT

    def handle(self):
        self.sockets = []
        self.server.traffic.add(self, self.connection, new=True)
        try:
            self.handle_one_request()
        finally:
            self.server.traffic.remove(self)

    def log_message(self, format, *args):
        pass

    def reply(self, code):
        self.send_response_only(code)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()

    def route(self, host, port, exchange):
        profile = self.server.profile
        if not profile:
            self.reply(503)
            return
        self.committed = False
        try:
            with open_tunnel(profile, host, port, lambda sock: self.server.traffic.add(self, sock)) as upstream:
                exchange(upstream, profile)
        except (OSError, ProxyError, http.client.HTTPException) as error:
            self.server.log(host, profile.name, f"Failed — {describe_error(error)}")
            if not self.committed:
                self.reply(502)

    def do_CONNECT(self):
        match = re.fullmatch(r"(?:\[([^\]]+)\]|([^:\[\]]+)):([0-9]{1,5})", self.path)
        try:
            if not match or self.headers.get_all("Content-Length") or self.headers.get_all("Transfer-Encoding"):
                raise ValueError
            host, port = host_name(match[1] or match[2]), port_number(match[3])
        except ValueError:
            self.reply(400)
            return

        def exchange(upstream, profile):
            self.committed = True
            self.send_response_only(200, "Connection Established")
            try:
                self.end_headers()
            except ConnectionError:
                return
            self.server.log(host, profile.name, "Tunnel established")
            relay(self.connection, upstream)

        self.route(host, port, exchange)

    def request_framing(self):
        lengths = self.headers.get_all("Content-Length", [])
        encodings = self.headers.get_all("Transfer-Encoding", [])
        if encodings:
            if lengths or len(encodings) != 1 or encodings[0].strip().lower() != "chunked":
                raise ValueError
            return "chunked", 0
        if not lengths:
            return "", 0
        if len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,19}", lengths[0]):
            raise ValueError
        return "length", int(lengths[0])

    def send_body(self, upstream, framing, size):
        if framing != "chunked":
            self.copy_body(upstream, size)
            return
        while True:
            line = self.rfile.readline(4097)
            match = re.fullmatch(rb"([0-9a-fA-F]{1,16})(?:;[^\r\n]*)?\r\n", line)
            if not match or len(line) > 4096:
                raise ProxyError("Malformed HTTP request body.")
            size = int(match[1], 16)
            if not size:
                for _ in range(100):
                    trailer = self.rfile.readline(8193)
                    if trailer == b"\r\n":
                        upstream.sendall(b"0\r\n\r\n")
                        return
                    if not trailer.endswith(b"\r\n") or len(trailer) > 8192:
                        break
                raise ProxyError("Malformed HTTP request trailers.")
            upstream.sendall(f"{size:x}\r\n".encode("ascii"))
            self.copy_body(upstream, size)
            if self.rfile.readline(3) != b"\r\n":
                raise ProxyError("Malformed HTTP request body.")
            upstream.sendall(b"\r\n")

    def copy_body(self, upstream, size):
        while size:
            data = self.rfile.read(min(size, BUFFER))
            if not data:
                raise ProxyError("Incomplete HTTP request body.")
            upstream.sendall(data)
            size -= len(data)

    def do_http(self):
        pac = self.server.pacs.get(self.path) if self.command in ("GET", "HEAD") else None
        if pac is not None:
            self.send_response_only(200)
            self.send_header("Content-Type", "application/x-ns-proxy-autoconfig")
            self.send_header("Content-Length", str(len(pac)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command == "GET":
                self.wfile.write(pac)
            return
        try:
            parts, host, port = parse_url(self.path, "http")
            path = urlunsplit(("", "", parts.path or "/", parts.query, ""))
            framing, size = self.request_framing()
            headers = [(name, value) for name, value in forward_headers(self.headers) if name.lower() != "host"]
            if any(not TOKEN.fullmatch(name) or "\r" in value or "\n" in value for name, value in headers):
                raise ValueError
        except ValueError:
            self.reply(400)
            return
        target = authority(host, port) if port != 80 else (f"[{host}]" if ":" in host else host)
        headers.extend((("Host", target), ("Connection", "close")))
        if framing == "chunked":
            headers.append(("Transfer-Encoding", "chunked"))
        elif framing == "length":
            headers.append(("Content-Length", str(size)))
        request = f"{self.command} {path} HTTP/1.1\r\n" + "".join(f"{name}: {value}\r\n" for name, value in headers)

        def exchange(upstream, profile):
            upstream.sendall((request + "\r\n").encode("latin-1"))
            self.send_body(upstream, framing, size)
            with http.client.HTTPResponse(upstream, method=self.command) as response:
                response.begin()
                if response.status < 200:
                    raise ProxyError("The HTTP origin returned an unsupported interim response or upgrade.")
                self.committed = True
                self.send_response_only(response.status)
                for name, value in forward_headers(response.headers):
                    if TOKEN.fullmatch(name) and "\r" not in value and "\n" not in value:
                        self.send_header(name, value)
                lengths = response.headers.get_all("Content-Length", [])
                if not response.chunked and response.status != 204:
                    if len(lengths) == 1 and re.fullmatch(r"[0-9]{1,19}", lengths[0]):
                        self.send_header("Content-Length", lengths[0])
                self.send_header("Connection", "close")
                self.end_headers()
                while data := response.read1(BUFFER):
                    self.wfile.write(data)
                if response.length:
                    raise ProxyError("Incomplete HTTP response body.")
                self.server.log(host, profile.name, f"HTTP {response.status}")

        self.route(host, port, exchange)

    do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_http
