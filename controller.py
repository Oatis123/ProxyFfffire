"""Serializes connection changes and leaves the active route in place on failed probes."""

from dataclasses import dataclass
from uuid import uuid4

from proxy import LocalProxy, ProxyError, Traffic, https_probe
from settings import make_pac
from windows import AUTO_URL, DIRECT, PROXY, WindowsSettings


@dataclass(frozen=True)
class Active:
    profile: object
    port: int
    mode: str
    preset: str
    rules: tuple
    pac_path: str = ""


class Controller:
    def __init__(self, windows, log, probe=https_probe):
        self.windows = windows
        self.log = log
        self.probe = probe
        self.traffic = Traffic()
        self.listener = None
        self.active = None

    def test(self, profile, url):
        return self.probe(profile, url, self.log)

    def connect(self, profile, url, port, mode, preset="", rules=()):
        self.test(profile, url)
        previous, active = self.listener, self.active
        listener = previous
        replacement = not previous or previous.server_port != port
        pac_path = ""
        if replacement:
            try:
                listener = LocalProxy(port, self.log, self.traffic)
            except OSError:
                raise ProxyError(f"Could not listen on 127.0.0.1:{port}. Choose an available local port.") from None
            listener.profile = profile
        port = listener.server_port
        if mode == "Selected Domains":
            if active and not replacement and active.rules == rules and active.pac_path:
                pac_path = active.pac_path
            else:
                pac_path = f"/proxy-{uuid4().hex}.pac"
                listener.pacs[pac_path] = make_pac(rules, port)
        if replacement:
            listener.start()

        try:
            if mode == "Selected Domains":
                self.windows.apply(WindowsSettings(DIRECT | AUTO_URL, pac=f"http://127.0.0.1:{port}{pac_path}"))
            elif mode == "System Proxy":
                self.windows.apply(WindowsSettings(DIRECT | PROXY, server=f"127.0.0.1:{port}"))
            elif active and active.mode != "Manual":
                self.windows.restore()
        except OSError as error:
            if replacement:
                listener.stop()
            elif pac_path and pac_path != active.pac_path:
                listener.pacs.pop(pac_path, None)
            raise ProxyError(str(error)) from None

        listener.profile = profile
        self.active = Active(profile, port, mode, preset, tuple(rules), pac_path)
        self.listener = listener
        if previous and replacement:
            previous.stop()
        elif active and active.pac_path and active.pac_path != pac_path:
            listener.pacs.pop(active.pac_path, None)
        return f"Connected to {profile.name}."

    def disconnect(self, recover=False):
        status = ""
        if recover or (self.active and self.active.mode != "Manual"):
            try:
                status = self.windows.restore()
            except OSError as error:
                raise ProxyError(str(error)) from None
        if self.listener:
            self.listener.stop()
        self.traffic.close()
        self.listener = None
        self.active = None
        return status or "Disconnected."
