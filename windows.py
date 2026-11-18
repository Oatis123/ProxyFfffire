"""Current-user WinINet settings, DPAPI and crash-safe proxy recovery."""

import base64
import ctypes as ct
import json
from ctypes import wintypes as w
from dataclasses import asdict, dataclass

from settings import atomic_json


MUTEX = r"Local\ProxyFfffire.Session"
PER_CONNECTION = 75
FLAGS, PROXY_SERVER, PROXY_BYPASS, AUTOCONFIG_URL, FLAGS_UI = 1, 2, 3, 4, 10
DIRECT, PROXY, AUTO_URL = 1, 2, 4


class DataBlob(ct.Structure):
    _fields_ = [("length", w.DWORD), ("data", ct.c_void_p)]


def crypt(value, encrypt):
    source = ct.create_string_buffer(value)
    incoming = DataBlob(len(value), ct.cast(source, ct.c_void_p))
    output = DataBlob()
    library = ct.WinDLL("crypt32", use_last_error=True)
    call = library.CryptProtectData if encrypt else library.CryptUnprotectData
    pointer = ct.POINTER(DataBlob)
    call.argtypes = (pointer, ct.c_void_p, pointer, ct.c_void_p, ct.c_void_p, w.DWORD, pointer)
    call.restype = w.BOOL
    if not call(ct.byref(incoming), None, None, None, None, 1, ct.byref(output)):
        raise OSError("Windows DPAPI could not process data for this user account.")
    try:
        return ct.string_at(output.data, output.length)
    finally:
        ct.memset(output.data, 0, output.length)
        free(output.data, "LocalFree")


def free(address, function):
    release = getattr(ct.WinDLL("kernel32"), function)
    release.argtypes = (ct.c_void_p,)
    release.restype = ct.c_void_p
    release(address)


def protect(value):
    return base64.b64encode(crypt(value.encode("utf-8"), True)).decode("ascii")


def unprotect(value):
    return crypt(base64.b64decode(value, validate=True), False).decode("utf-8")


class Session:
    def __enter__(self):
        kernel = ct.WinDLL("kernel32", use_last_error=True)
        self.close = kernel.CloseHandle
        self.close.argtypes = (w.HANDLE,)
        self.close.restype = w.BOOL
        create = kernel.CreateMutexW
        create.argtypes = (ct.c_void_p, w.BOOL, w.LPCWSTR)
        create.restype = w.HANDLE
        self.handle = create(None, False, MUTEX)
        if not self.handle:
            raise OSError("Could not create the ProxyFfffire session lock.")
        if ct.get_last_error() == 183:
            self.close(self.handle)
            raise OSError("ProxyFfffire is already running in this Windows session.")
        return self

    def __exit__(self, *args):
        self.close(self.handle)


class OptionValue(ct.Union):
    _fields_ = [("number", w.DWORD), ("string", ct.c_void_p), ("time", w.FILETIME)]


class Option(ct.Structure):
    _fields_ = [("option", w.DWORD), ("value", OptionValue)]


class OptionList(ct.Structure):
    _fields_ = [("size", w.DWORD), ("connection", w.LPWSTR), ("count", w.DWORD),
                ("error", w.DWORD), ("options", ct.POINTER(Option))]


@dataclass(frozen=True)
class WindowsSettings:
    flags: int
    server: str = ""
    bypass: str = ""
    pac: str = ""


class WindowsBackend:
    def __init__(self):
        self.lib = ct.WinDLL("wininet", use_last_error=True)
        self.query = self.lib.InternetQueryOptionW
        self.query.argtypes = (w.HANDLE, w.DWORD, ct.c_void_p, ct.POINTER(w.DWORD))
        self.query.restype = w.BOOL
        self.set_option = self.lib.InternetSetOptionW
        self.set_option.argtypes = (w.HANDLE, w.DWORD, ct.c_void_p, w.DWORD)
        self.set_option.restype = w.BOOL

    def read(self):
        try:
            return self.read_options(FLAGS_UI)
        except OSError:
            return self.read_options(FLAGS)

    def read_options(self, flag_option):
        options = (Option * 4)()
        for option, code in zip(options, (flag_option, PROXY_SERVER, PROXY_BYPASS, AUTOCONFIG_URL)):
            option.option = code
        descriptor = OptionList(ct.sizeof(OptionList), None, len(options), 0, options)
        size = w.DWORD(ct.sizeof(descriptor))
        try:
            if not self.query(None, PER_CONNECTION, ct.byref(descriptor), ct.byref(size)):
                raise OSError(f"Could not read Windows proxy settings (error {ct.get_last_error()}).")
            values = [ct.wstring_at(item.value.string) if item.value.string else "" for item in options[1:]]
            return WindowsSettings(options[0].value.number, *values)
        finally:
            for option in options[1:]:
                if option.value.string:
                    free(option.value.string, "GlobalFree")

    def write(self, settings):
        options = (Option * 4)()
        options[0].option = FLAGS
        options[0].value.number = settings.flags
        values = [ct.create_unicode_buffer(value) for value in (settings.server, settings.bypass, settings.pac)]
        for index, code in enumerate((PROXY_SERVER, PROXY_BYPASS, AUTOCONFIG_URL), 1):
            options[index].option = code
            options[index].value.string = ct.cast(values[index - 1], ct.c_void_p)
        descriptor = OptionList(ct.sizeof(OptionList), None, len(options), 0, options)
        if not self.set_option(None, PER_CONNECTION, ct.byref(descriptor), ct.sizeof(descriptor)):
            raise OSError(f"Could not update Windows proxy settings (error {ct.get_last_error()}).")
        for flag in (39, 95, 37):
            self.set_option(None, flag, None, 0)


class WindowsProxy:
    def __init__(self, backend, path, seal=protect, unseal=unprotect):
        self.backend = backend
        self.path = path
        self.seal = seal
        self.unseal = unseal

    def load(self):
        try:
            text = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None, []
        try:
            record = json.loads(self.unseal(json.loads(text)["protected"]))
            return WindowsSettings(**record["original"]), [WindowsSettings(**item) for item in record["owned"]]
        except (KeyError, ValueError, TypeError, OSError):
            raise OSError("The Windows proxy backup could not be read for this user account.") from None

    def save(self, original, owned):
        record = {"original": asdict(original), "owned": [asdict(item) for item in owned]}
        atomic_json(self.path, {"protected": self.seal(json.dumps(record))})

    def apply(self, desired):
        original, owned = self.load()
        current = self.backend.read()
        was_owned = current in owned
        if not was_owned:
            original = current
        if current == desired:
            return
        self.save(original, [current, desired] if was_owned else [desired])
        if self.backend.read() != current:
            raise OSError("Windows proxy settings changed while connecting. Try again.")
        try:
            self.backend.write(desired)
            if self.backend.read() != desired:
                raise OSError("Windows did not retain the requested proxy settings. Check Windows proxy policy.")
        except OSError:
            if self.backend.read() == desired:
                self.backend.write(current)
            raise
        if was_owned:
            try:
                self.save(original, [desired])
            except OSError:
                # The on-disk transition already contains the new state and original backup.
                pass

    def restore(self):
        original, owned = self.load()
        if original is None:
            return "No Windows proxy backup was found."
        current = self.backend.read()
        if current not in owned or current == original:
            self.path.unlink(missing_ok=True)
            if current == original:
                return "Original Windows proxy settings are already in place."
            return "Windows proxy settings changed outside ProxyFfffire. Those settings were kept."
        self.backend.write(original)
        if self.backend.read() != original:
            raise OSError("Windows did not retain the restored proxy settings.")
        self.path.unlink(missing_ok=True)
        return "Windows proxy settings restored."
