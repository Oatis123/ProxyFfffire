"""Windows notification-area icon on the Tk UI thread."""

import ctypes as ct
from collections import deque
from ctypes import wintypes as w


WM_NULL, WM_CONTEXTMENU, WM_TRAY = 0, 0x007B, 0x8001
NIN_SELECT, NIN_KEYSELECT = 0x0400, 0x0401
NIM_ADD, NIM_DELETE, NIM_SETFOCUS, NIM_SETVERSION = 0, 2, 3, 4
NIF_MESSAGE, NIF_ICON, NIF_TIP, NIF_SHOWTIP = 1, 2, 4, 0x80
NOTIFYICON_VERSION_4 = 4
OPEN, EXIT = 1, 2
SubclassProc = ct.WINFUNCTYPE(ct.c_ssize_t, w.HWND, w.UINT, w.WPARAM, w.LPARAM, ct.c_size_t, ct.c_size_t)


class NotifyIconData(ct.Structure):
    _fields_ = [
        ("size", w.DWORD), ("window", w.HWND), ("id", w.UINT), ("flags", w.UINT),
        ("callback_message", w.UINT), ("icon", w.HICON), ("tip", w.WCHAR * 128),
        ("state", w.DWORD), ("state_mask", w.DWORD), ("info", w.WCHAR * 256),
        ("version", w.UINT), ("info_title", w.WCHAR * 64), ("info_flags", w.DWORD),
        ("guid", ct.c_byte * 16), ("balloon_icon", w.HICON),
    ]


def bind(dll, name, result, *args):
    function = getattr(dll, name)
    function.restype = result
    function.argtypes = args
    return function


class TrayIcon:
    def __init__(self, root, title, icon_path, on_open, on_exit):
        self.root = root
        self.on_open = on_open
        self.on_exit = on_exit
        self.events = deque()
        self.visible = False
        self.window = None
        self.icon = None
        user = ct.WinDLL("user32", use_last_error=True)
        controls = ct.WinDLL("comctl32", use_last_error=True)
        shell = ct.WinDLL("shell32", use_last_error=True)
        self.notify = bind(shell, "Shell_NotifyIconW", w.BOOL, w.DWORD, ct.POINTER(NotifyIconData))
        self.destroy_window = bind(user, "DestroyWindow", w.BOOL, w.HWND)
        self.destroy_icon = bind(user, "DestroyIcon", w.BOOL, w.HICON)
        self.remove_subclass = bind(controls, "RemoveWindowSubclass", w.BOOL, w.HWND, SubclassProc, ct.c_size_t)
        self.default_proc = bind(controls, "DefSubclassProc", ct.c_ssize_t, w.HWND, w.UINT, w.WPARAM, w.LPARAM)
        self.create_menu = bind(user, "CreatePopupMenu", w.HMENU)
        self.append_menu = bind(user, "AppendMenuW", w.BOOL, w.HMENU, w.UINT, ct.c_size_t, w.LPCWSTR)
        self.destroy_menu = bind(user, "DestroyMenu", w.BOOL, w.HMENU)
        self.track_menu = bind(user, "TrackPopupMenu", w.BOOL, w.HMENU, w.UINT, ct.c_int, ct.c_int,
                               ct.c_int, w.HWND, ct.c_void_p)
        self.foreground = bind(user, "SetForegroundWindow", w.BOOL, w.HWND)
        self.cursor = bind(user, "GetCursorPos", w.BOOL, ct.POINTER(w.POINT))
        self.post_message = bind(user, "PostMessageW", w.BOOL, w.HWND, w.UINT, w.WPARAM, w.LPARAM)
        register_message = bind(user, "RegisterWindowMessageW", w.UINT, w.LPCWSTR)
        self.taskbar_created = register_message("TaskbarCreated")

        load_icon = bind(user, "LoadImageW", w.HANDLE, w.HINSTANCE, w.LPCWSTR, w.UINT, ct.c_int, ct.c_int, w.UINT)
        create_window = bind(user, "CreateWindowExW", w.HWND, w.DWORD, w.LPCWSTR, w.LPCWSTR, w.DWORD,
                             ct.c_int, ct.c_int, ct.c_int, ct.c_int, w.HWND, w.HMENU, w.HINSTANCE, ct.c_void_p)
        set_subclass = bind(controls, "SetWindowSubclass", w.BOOL, w.HWND, SubclassProc, ct.c_size_t, ct.c_size_t)
        self.callback = SubclassProc(self.window_proc)
        try:
            # A hidden top-level window also receives the broadcast when Explorer recreates the taskbar.
            self.window = create_window(0, "Static", title, 0x80000000, 0, 0, 0, 0, None, None, None, None)
            self.icon = load_icon(None, str(icon_path), 1, 0, 0, 0x10 | 0x40)
            if not self.window or not self.icon or not set_subclass(self.window, self.callback, 1, 0):
                raise OSError("Could not create the Windows tray icon.")
            flags = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP
            self.data = NotifyIconData(ct.sizeof(NotifyIconData), self.window, 1, flags, WM_TRAY, self.icon, title)
            self.data.version = NOTIFYICON_VERSION_4
        except Exception:
            self.close()
            raise

    def show(self):
        if self.visible:
            return True
        if not self.notify(NIM_ADD, ct.byref(self.data)):
            return False
        self.visible = bool(self.notify(NIM_SETVERSION, ct.byref(self.data)))
        if not self.visible:
            self.notify(NIM_DELETE, ct.byref(self.data))
        return self.visible

    def restore_icon(self):
        self.visible = False
        if not self.show() and self.root.state() == "withdrawn":
            self.on_open()

    def window_proc(self, hwnd, message, wparam, lparam, subclass_id, ref_data):
        # Tk may be inside its native event dispatcher. Let its regular poll handle these callbacks.
        if message == WM_TRAY:
            event = lparam & 0xFFFF
            if event in (NIN_SELECT, NIN_KEYSELECT):
                self.events.append(self.on_open)
            elif event == WM_CONTEXTMENU:
                self.events.append(self.open_menu)
            return 0
        if message == self.taskbar_created:
            self.events.append(self.restore_icon)
            return 0
        return self.default_proc(hwnd, message, wparam, lparam)

    def poll(self):
        for _ in range(len(self.events)):
            self.events.popleft()()

    def open_menu(self):
        menu = self.create_menu()
        if not menu:
            return
        try:
            if not self.append_menu(menu, 0, OPEN, "Open ProxyFfffire") or not self.append_menu(menu, 0, EXIT, "Exit"):
                return
            point = w.POINT()
            self.cursor(ct.byref(point))
            self.foreground(self.window)
            # TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON
            action = self.track_menu(menu, 0x100 | 0x80 | 2, point.x, point.y, 0, self.window, None)
            self.post_message(self.window, WM_NULL, 0, 0)
        finally:
            self.destroy_menu(menu)
        if action == OPEN:
            self.on_open()
        elif action == EXIT:
            self.on_exit()
        else:
            self.notify(NIM_SETFOCUS, ct.byref(self.data))

    def close(self):
        if self.visible:
            self.notify(NIM_DELETE, ct.byref(self.data))
            self.visible = False
        if self.window:
            self.remove_subclass(self.window, self.callback, 1)
            self.destroy_window(self.window)
            self.window = None
        if self.icon:
            self.destroy_icon(self.icon)
            self.icon = None
