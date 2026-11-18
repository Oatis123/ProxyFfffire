"""ProxyFfffire Windows desktop client."""

import ctypes as ct
import os
import queue
import sys
import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import ttk
from uuid import uuid4

from controller import Controller
from proxy import ProxyError
from settings import (APP_NAME, DEFAULT_PORT, DEFAULT_TEST_URL, MODES, PROTOCOLS,
                      Profile, Store, data_dir, domain_rules, parse_url, port_number)
from tray import TrayIcon
from windows import Session, WindowsBackend, WindowsProxy, protect, unprotect


BG, PANEL, INPUT, BORDER = "#0E1019", "#151827", "#20243A", "#353A55"
TEXT, MUTED, CYAN, PINK = "#EDF1FC", "#B0B8D1", "#67F7E3", "#FF74BE"
FORM_FIELDS = ("name", "protocol", "host", "port", "username", "password")
LIMITATION = "Windows-aware apps only. Apps with their own network settings may ignore the system proxy."


def style_window(root):
    root.configure(bg=BG)
    root.option_add("*TCombobox*Listbox.background", INPUT)
    root.option_add("*TCombobox*Listbox.foreground", TEXT)
    root.option_add("*TCombobox*Listbox.selectBackground", CYAN)
    root.option_add("*TCombobox*Listbox.selectForeground", BG)
    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure(".", background=BG, foreground=TEXT, font=("Segoe UI", 10), bordercolor=BORDER,
                    lightcolor=BORDER, darkcolor=BORDER, focuscolor=CYAN, troughcolor=BG)
    style.configure("Panel.TFrame", background=PANEL)
    style.configure("Panel.TLabel", background=PANEL)
    style.configure("Muted.TLabel", foreground=MUTED)
    style.configure("Note.TLabel", foreground=MUTED, background=PANEL)
    style.configure("Active.TLabel", foreground=CYAN, font=("Consolas", 10, "bold"))
    style.configure("TButton", background=INPUT, padding=(10, 6), relief="flat")
    style.map("TButton", background=[("active", BORDER)], foreground=[("disabled", "#828BA8")])
    style.configure("Primary.TButton", background=CYAN, foreground=BG, font=("Segoe UI", 10, "bold"))
    style.map("Primary.TButton", background=[("disabled", INPUT), ("active", "#A7FFF3")],
              foreground=[("disabled", MUTED)])
    style.configure("TEntry", fieldbackground=INPUT, insertcolor=CYAN, padding=6)
    style.configure("TCombobox", fieldbackground=INPUT, arrowcolor=CYAN, padding=5)
    style.map("TCombobox", fieldbackground=[("readonly", INPUT)], foreground=[("readonly", TEXT)],
              selectbackground=[("readonly", INPUT)], selectforeground=[("readonly", TEXT)])
    style.configure("Treeview", fieldbackground=PANEL, background=PANEL, rowheight=26)
    style.map("Treeview", background=[("selected", BORDER)], foreground=[("selected", TEXT)])
    style.configure("Treeview.Heading", background=INPUT, foreground=MUTED, padding=(7, 4))
    style.map("Treeview.Heading", background=[("active", INPUT)])
    style.configure("TNotebook", background=BG, borderwidth=0)
    style.configure("TNotebook.Tab", background=INPUT, foreground=MUTED, padding=(15, 6))
    style.map("TNotebook.Tab", background=[("selected", PANEL), ("active", BORDER)],
              foreground=[("selected", CYAN)])


def list_widget(parent, columns):
    frame = ttk.Frame(parent, style="Panel.TFrame")
    tree = ttk.Treeview(frame, columns=[key for key, _, _ in columns], show="headings", selectmode="browse")
    bar = ttk.Scrollbar(frame, command=tree.yview)
    tree.configure(yscrollcommand=bar.set)
    for index, (key, label, width) in enumerate(columns):
        tree.heading(key, text=label, anchor="w")
        tree.column(key, width=width, minwidth=width, stretch=(index == len(columns) - 1), anchor="w")
    tree.pack(side="left", fill="both", expand=True)
    bar.pack(side="right", fill="y")
    return frame, tree


def notice(parent, message, confirm="OK", cancel=False):
    dialog = tk.Toplevel(parent, bg=BG)
    dialog.title(APP_NAME)
    if parent.winfo_viewable():
        dialog.transient(parent)
    dialog.resizable(False, False)
    content = ttk.Frame(dialog, padding=18)
    content.pack(fill="both", expand=True)
    ttk.Label(content, text=message, wraplength=390).pack(anchor="w", pady=(0, 16))
    accepted = False

    def accept():
        nonlocal accepted
        accepted = True
        dialog.destroy()

    action = ttk.Button(content, text=confirm, command=accept, style="Primary.TButton")
    action.pack(side="right")
    if cancel:
        ttk.Button(content, text="Cancel", command=dialog.destroy).pack(side="right", padx=(0, 8))
    dialog.bind("<Escape>", lambda event: dialog.destroy())
    dialog.wait_visibility()
    previous_grab = dialog.grab_current()
    dialog.grab_set()
    action.focus_set()
    dialog.wait_window()
    if previous_grab is not None and previous_grab.winfo_exists():
        previous_grab.grab_set()
    return accepted


class Window:
    def __init__(self, root, path):
        self.root = root
        self.store = Store(path / "profiles.json", protect, unprotect)
        self.data = self.store.load()
        self.logs = queue.Queue(maxsize=500)
        self.results = queue.SimpleQueue()
        self.controller = Controller(WindowsProxy(WindowsBackend(), path / "windows-proxy-backup.json"), self.log)
        self.busy = self.closing = False
        self.tray = None
        self.edit_id = ""
        self.form = {key: tk.StringVar(root) for key in FORM_FIELDS}
        self.open_label = tk.StringVar(root)
        self.active_label = tk.StringVar(root, "Offline")
        self.endpoint = tk.StringVar(root, "")
        self.status = tk.StringVar(root, "Add a profile to get started.")
        if self.controller.windows.path.exists():
            self.status.set("A Windows proxy backup is available. Use Restore Windows Proxy to check it.")
        routing = self.data["routing"]
        self.mode = tk.StringVar(root, routing.get("mode", MODES[0]))
        self.port = tk.StringVar(root, str(routing.get("port", DEFAULT_PORT)))
        self.test_url = tk.StringVar(root, routing.get("test_url", DEFAULT_TEST_URL))
        self.preset_id = routing.get("preset", "claude")
        self.preset = tk.StringVar(root)
        self.actions = []
        root.title(APP_NAME)
        root.geometry("1040x780")
        root.minsize(940, 700)
        style_window(root)
        self.build()
        records = self.data["profiles"]
        self.load_editor(records[0] if records else None)
        self.refresh_presets()
        self.refresh_active()
        self.form["name"].trace_add("write", self.update_title)
        root.protocol("WM_DELETE_WINDOW", self.hide_window)
        root.after(60, self.poll)

    def button(self, parent, text, command, primary=False, action=False):
        button = ttk.Button(parent, text=text, command=command, style="Primary.TButton" if primary else "TButton")
        if action:
            self.actions.append(button)
        return button

    def build(self):
        page = ttk.Frame(self.root, padding=(24, 14, 24, 18))
        page.pack(fill="both", expand=True)
        mast = ttk.Frame(page)
        mast.pack(fill="x", pady=(0, 10))
        tk.Label(mast, text="Proxy", fg=TEXT, bg=BG, font=("Consolas", 31, "bold"), padx=0).pack(side="left")
        tk.Label(mast, text="Ffffire", fg=PINK, bg=BG, font=("Consolas", 31, "bold"), padx=0).pack(side="left")
        self.button(mast, "Restore Windows Proxy", self.restore, action=True).pack(side="right")
        stripe = tk.Frame(page, bg=BORDER, height=2)
        stripe.pack(fill="x", pady=(0, 14))
        tk.Frame(stripe, bg=PINK, width=100, height=2).pack(side="left")
        tk.Frame(stripe, bg=CYAN, width=44, height=2).pack(side="left", padx=5)

        body = ttk.Frame(page)
        body.pack(fill="both", expand=True)
        side = ttk.Frame(body, style="Panel.TFrame", padding=12)
        side.pack(side="left", fill="y", padx=(0, 16))
        ttk.Label(side, text="Profiles", style="Panel.TLabel", font=("Segoe UI", 14, "bold")).pack(anchor="w")
        frame, self.profiles = list_widget(side, (("state", "Active", 56), ("name", "Profile", 158)))
        frame.pack(fill="both", expand=True, pady=(9, 9))
        self.profiles.bind("<<TreeviewSelect>>", self.select_profile)
        self.button(side, "Add Profile", self.add_profile).pack(fill="x")

        editor = ttk.Frame(body)
        editor.pack(side="left", fill="both", expand=True)
        ttk.Label(editor, textvariable=self.open_label, font=("Segoe UI", 15, "bold")).pack(anchor="w")
        status = ttk.Frame(editor)
        status.pack(fill="x", pady=(3, 2))
        ttk.Label(status, textvariable=self.active_label, style="Active.TLabel").pack(side="left")
        self.copy = self.button(status, "Copy Local Address", self.copy_endpoint)
        self.copy.pack(side="right")
        ttk.Label(editor, textvariable=self.endpoint, style="Muted.TLabel").pack(anchor="w")
        ttk.Label(editor, textvariable=self.status, wraplength=610).pack(anchor="w", pady=(2, 8))
        tabs = ttk.Notebook(editor)
        tabs.pack(fill="both", expand=True)
        profile = ttk.Frame(tabs, style="Panel.TFrame", padding=(14, 11))
        routing = ttk.Frame(tabs, style="Panel.TFrame", padding=(14, 11))
        tabs.add(profile, text="Profile")
        tabs.add(routing, text="Routing")
        self.profile_fields(profile)
        self.routing_fields(routing)

        buttons = ttk.Frame(editor)
        buttons.pack(fill="x", pady=(10, 0))
        self.button(buttons, "Save", self.save).pack(side="left", padx=(0, 7))
        self.delete_button = self.button(buttons, "Delete", self.delete)
        self.delete_button.pack(side="left")
        self.button(buttons, "Connect", self.connect, primary=True, action=True).pack(side="right")
        self.disconnect_button = self.button(buttons, "Disconnect", lambda: self.run(self.controller.disconnect), action=True)
        self.disconnect_button.pack(side="right", padx=7)
        self.button(buttons, "Test Proxy", self.test, action=True).pack(side="right")

        ttk.Label(page, text="Connection Log", font=("Segoe UI", 12, "bold")).pack(anchor="w", pady=(12, 5))
        frame, self.log_tree = list_widget(page, (("time", "Time", 86), ("host", "Domain", 257),
                                                  ("profile", "Profile", 158), ("result", "Result", 270)))
        self.log_tree.configure(height=5)
        self.log_tree.tag_configure("error", foreground=PINK)
        frame.pack(fill="x")

    def profile_fields(self, panel):
        for column in (0, 1):
            panel.columnconfigure(column, weight=1, uniform="form")
        labels = ("Name", "Protocol", "Address", "Port", "Username (optional)", "Password (optional)")
        for index, (field, label) in enumerate(zip(FORM_FIELDS, labels)):
            row, column = divmod(index, 2)
            gap = (0, 12) if column == 0 else 0
            ttk.Label(panel, text=label, style="Panel.TLabel").grid(row=row * 2, column=column, sticky="w", padx=gap)
            if field == "protocol":
                control = ttk.Combobox(panel, textvariable=self.form[field], state="readonly", values=PROTOCOLS, width=14)
            else:
                control = ttk.Entry(panel, textvariable=self.form[field], show="•" if field == "password" else "", width=14)
            control.grid(row=row * 2 + 1, column=column, sticky="ew", padx=gap, pady=(2, 8))
        ttk.Label(panel, text="Passwords are protected by Windows DPAPI for this user.", style="Note.TLabel").grid(
            row=6, columnspan=2, sticky="w")

    def routing_fields(self, panel):
        panel.columnconfigure(1, weight=1)
        fields = (("Routing mode", self.mode, MODES), ("Local port", self.port, ()),
                  ("HTTPS test URL", self.test_url, ()), ("Domain preset", self.preset, ("",)))
        for row, (label, var, choices) in enumerate(fields):
            ttk.Label(panel, text=label, style="Panel.TLabel").grid(row=row, column=0, sticky="w", padx=(0, 10), pady=3)
            control = (ttk.Combobox(panel, textvariable=var, state="readonly", values=choices) if choices
                       else ttk.Entry(panel, textvariable=var))
            control.grid(row=row, column=1, sticky="ew", pady=3, columnspan=1 if row == 3 else 3)
            if row == 0:
                control.bind("<<ComboboxSelected>>", self.update_mode)
            if row == 3:
                self.preset_menu = control
                control.bind("<<ComboboxSelected>>", self.choose_preset)
        self.edit_preset = self.button(panel, "Edit Preset", lambda: self.preset_dialog(self.preset_id))
        self.edit_preset.grid(row=3, column=2, padx=(6, 0))
        self.new_preset = self.button(panel, "New Preset", self.preset_dialog)
        self.new_preset.grid(row=3, column=3, padx=(6, 0))
        self.mode_note = ttk.Label(panel, style="Note.TLabel", wraplength=610)
        self.mode_note.grid(row=4, column=0, columnspan=4, sticky="w", pady=(7, 0))
        ttk.Label(panel, text=LIMITATION, style="Note.TLabel", wraplength=610).grid(
            row=5, column=0, columnspan=4, sticky="w", pady=(2, 0))
        self.update_mode()

    def update_mode(self, event=None):
        mode = self.mode.get()
        self.mode_note.configure(text={
            "Manual": "Copy the local address into your app's HTTP proxy settings after connecting.",
            "Selected Domains": "The Windows PAC proxies the preset's domains. Other domains connect directly.",
            "System Proxy": "Windows uses the local proxy for HTTP and HTTPS.",
        }[mode])
        self.preset_menu.configure(state="readonly" if mode == "Selected Domains" else "disabled")
        for button in (self.edit_preset, self.new_preset):
            button.state(["!disabled" if mode == "Selected Domains" else "disabled"])

    def refresh_presets(self):
        self.preset_ids = list(self.data["presets"])
        if self.preset_id not in self.preset_ids:
            self.preset_id = self.preset_ids[0]
        self.preset_menu.configure(values=[self.data["presets"][key]["name"] for key in self.preset_ids])
        self.preset_menu.current(self.preset_ids.index(self.preset_id))

    def choose_preset(self, event=None):
        self.preset_id = self.preset_ids[self.preset_menu.current()]

    def preset_dialog(self, key=None):
        existing = self.data["presets"].get(key, {})
        window = tk.Toplevel(self.root, bg=BG)
        window.title("Edit Domain Preset" if key else "New Domain Preset")
        window.transient(self.root)
        window.grab_set()
        form = ttk.Frame(window, padding=16)
        form.pack(fill="both", expand=True)
        name = tk.StringVar(window, existing.get("name", ""))
        ttk.Label(form, text="Preset name").pack(anchor="w")
        entry = ttk.Entry(form, textvariable=name)
        entry.pack(fill="x", pady=(3, 9))
        ttk.Label(form, text="One rule per line. Use *.example.com for subdomains.").pack(anchor="w")
        rules = tk.Text(form, width=60, height=13, bg=INPUT, fg=TEXT, insertbackground=CYAN,
                        relief="flat", padx=8, pady=6, font=("Consolas", 11), undo=True)
        rules.pack(fill="both", expand=True, pady=6)
        rules.insert("1.0", "\n".join(existing.get("domains", [])))
        if existing.get("source"):
            ttk.Label(form, text=f"Source checked {existing['verified_date']}", style="Muted.TLabel").pack(anchor="w")
            source = ttk.Entry(form, textvariable=tk.StringVar(window, existing["source"]), state="readonly")
            source.pack(fill="x", pady=(3, 8))

        def save_preset():
            try:
                label = name.get().strip()
                if not label or len(label) > 80 or not label.isprintable():
                    raise ValueError("Enter a preset name of up to 80 printable characters.")
                if any(item["name"].casefold() == label.casefold() for item_key, item in self.data["presets"].items()
                       if item_key != key):
                    raise ValueError("Use a unique preset name.")
                domains = domain_rules(rules.get("1.0", "end-1c").splitlines())
                new_key = key or uuid4().hex
                data = {**self.data, "presets": {**self.data["presets"], new_key: {**existing, "name": label, "domains": domains}}}
                data["routing"] = {**data["routing"], "preset": new_key}
                self.store.save(data)
                self.data = data
            except (ValueError, OSError) as error:
                notice(window, str(error))
                return
            self.preset_id = new_key
            self.refresh_presets()
            self.status.set("Preset saved. Use Connect to apply routing changes.")
            window.destroy()

        self.button(form, "Save Preset", save_preset, primary=True).pack(side="right")
        self.button(form, "Cancel", window.destroy).pack(side="right", padx=(0, 7))
        entry.focus_set()

    def current_form(self):
        return tuple(self.form[key].get() for key in FORM_FIELDS)

    def record(self, key):
        return next((record for record in self.data["profiles"] if record["id"] == key), None)

    def update_title(self, *args):
        name = self.form["name"].get().strip()[:55] or "New profile"
        self.open_label.set(f"Editing: {name}")

    def load_editor(self, record):
        if record:
            try:
                profile = self.store.unpack(record)
            except (ValueError, OSError):
                notice(self.root, "This password could not be decrypted. Re-enter it and save the profile.")
                profile = Profile(**{key: record[key] for key in ("id", *FORM_FIELDS[:-1])})
            self.edit_id = profile.id
            values = [getattr(profile, key) for key in FORM_FIELDS]
        else:
            self.edit_id = uuid4().hex
            values = ("", PROTOCOLS[0], "", "", "", "")
        for key, value in zip(FORM_FIELDS, values):
            self.form[key].set(str(value))
        self.baseline = self.current_form()
        self.update_title()
        self.refresh_profiles()

    def refresh_profiles(self):
        active = self.controller.active
        self.profiles.delete(*self.profiles.get_children())
        for record in self.data["profiles"]:
            key = record["id"]
            self.profiles.insert("", "end", iid=key, values=("●" if active and active.profile.id == key else "", record["name"]))
        if self.profiles.exists(self.edit_id):
            self.profiles.selection_set(self.edit_id)
            self.profiles.see(self.edit_id)
        self.delete_button.state(["!disabled" if self.record(self.edit_id) else "disabled"])

    def discard(self):
        return self.current_form() == self.baseline or notice(self.root, "Discard unsaved profile edits?", "Discard", cancel=True)

    def select_profile(self, event=None):
        selection = self.profiles.selection()
        if selection and selection[0] != self.edit_id:
            if self.discard():
                self.load_editor(self.record(selection[0]))
            else:
                self.refresh_profiles()

    def add_profile(self):
        if self.discard():
            self.load_editor(None)

    def save(self):
        try:
            profile = Profile.from_form(self.edit_id, *self.current_form())
            record = self.store.pack(profile)
            records = [record if item["id"] == profile.id else item for item in self.data["profiles"]]
            if not self.record(profile.id):
                records.append(record)
            routing = {"mode": self.mode.get(), "port": port_number(self.port.get()), "preset": self.preset_id,
                       "test_url": self.test_url.get().strip()}
            parse_url(routing["test_url"], "https")
            data = {**self.data, "routing": routing, "profiles": records}
            self.store.save(data)
            self.data = data
            self.baseline = self.current_form()
            self.refresh_profiles()
            self.status.set(f"Saved {profile.name}. Use Connect to apply changes to the active connection.")
        except (ValueError, OSError) as error:
            self.status.set(str(error))

    def delete(self):
        record = self.record(self.edit_id)
        if not record or not notice(self.root, f"Delete the saved profile '{record['name']}'?", "Delete", cancel=True):
            return
        records = [item for item in self.data["profiles"] if item["id"] != self.edit_id]
        data = {**self.data, "profiles": records}
        try:
            self.store.save(data)
            self.data = data
            self.load_editor(records[0] if records else None)
            self.status.set("Profile deleted.")
        except OSError as error:
            self.status.set(str(error))

    def test(self):
        try:
            profile = Profile.from_form(self.edit_id, *self.current_form())
            url = self.test_url.get().strip()
            parse_url(url, "https")
            self.run(lambda: f"HTTPS test passed ({self.controller.test(profile, url)}).", "Testing proxy…")
        except ValueError as error:
            self.status.set(str(error))

    def connect(self):
        try:
            profile = Profile.from_form(self.edit_id, *self.current_form())
            url = self.test_url.get().strip()
            parse_url(url, "https")
            mode, port = self.mode.get(), port_number(self.port.get())
            preset = self.data["presets"][self.preset_id]
            rules = tuple(domain_rules(preset["domains"])) if mode == "Selected Domains" else ()
            name = preset["name"] if mode == "Selected Domains" else ""
            self.run(lambda: self.controller.connect(profile, url, port, mode, name, rules), "Checking the candidate proxy…")
        except ValueError as error:
            self.status.set(str(error))

    def restore(self):
        self.run(lambda: self.controller.disconnect(recover=True), "Checking Windows proxy settings…")

    def copy_endpoint(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.endpoint.get())
        self.status.set("Local address copied.")

    def refresh_active(self):
        active = self.controller.active
        if active:
            label = f"Active: {active.profile.name[:38]}  /  {active.mode}"
            self.active_label.set(f"{label}  /  {active.preset[:26]}" if active.preset else label)
            self.endpoint.set(f"127.0.0.1:{active.port}")
        else:
            self.active_label.set("Offline")
            self.endpoint.set("")
        self.copy.state(["!disabled" if active else "disabled"])
        self.disconnect_button.state(["!disabled" if active else "disabled"])
        self.refresh_profiles()

    def run(self, operation, message="Disconnecting…"):
        if self.busy:
            return
        self.busy = True
        self.status.set(message)
        for button in self.actions:
            button.state(["disabled"])

        def worker():
            try:
                self.results.put((True, operation()))
            except ProxyError as error:
                self.results.put((False, str(error)))
            except Exception:
                self.results.put((False, "The operation could not be completed."))

        threading.Thread(target=worker, daemon=True).start()

    def log(self, host, profile, result):
        try:
            self.logs.put_nowait((datetime.now().strftime("%H:%M:%S"), host, profile, result))
        except queue.Full:
            pass

    def poll(self):
        if self.tray:
            self.tray.poll()
        for _ in range(100):
            try:
                row = self.logs.get_nowait()
            except queue.Empty:
                break
            item = self.log_tree.insert("", "end", values=row, tags=("error",) if "failed" in row[-1].lower() else ())
            children = self.log_tree.get_children()
            if len(children) > 250:
                self.log_tree.delete(children[0])
            self.log_tree.see(item)
        try:
            success, status = self.results.get_nowait()
        except queue.Empty:
            pass
        else:
            self.busy = False
            self.status.set(status)
            for button in self.actions:
                button.state(["!disabled"])
            self.refresh_active()
            if self.closing:
                if success and self.closing == "disconnecting":
                    self.root.destroy()
                    return
                if self.closing == "waiting":
                    self.finish_close()
                else:
                    self.closing = False
                    self.show_window()
                    notice(self.root, status)
        self.root.after(60, self.poll)

    def finish_close(self):
        self.closing = "disconnecting"
        self.run(self.controller.disconnect)

    def hide_window(self):
        if self.closing:
            return
        if self.tray and self.tray.show():
            self.root.withdraw()
        else:
            self.request_exit()

    def show_window(self):
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()

    def request_exit(self):
        if self.closing:
            return
        if dialog := self.root.grab_current():
            self.show_window()
            dialog.lift()
            return
        if self.current_form() != self.baseline:
            self.show_window()
            if not self.discard():
                return
        if self.busy:
            self.closing = "waiting"
            self.status.set("Finishing the current operation before closing…")
        else:
            self.finish_close()


def main():
    if sys.argv[1:] == ["--restore-windows-proxy"]:
        try:
            with Session():
                WindowsProxy(WindowsBackend(), data_dir() / "windows-proxy-backup.json").restore()
        except OSError:
            return 1
        return 0
    smoke = sys.argv[1:] == ["--smoke-test"]
    root = None
    try:
        root = tk.Tk()
        root.withdraw()
        with Session():
            if smoke and getattr(sys, "frozen", False):
                verify_runtime(root)
            icon_dir = Path(__file__).parent
            if not getattr(sys, "frozen", False):
                icon_dir /= "installer"
            icon = icon_dir / "ProxyFfffire.ico"
            if icon.is_file():
                root.iconbitmap(default=str(icon))
            window = Window(root, data_dir())
            root.deiconify()
            if smoke:
                root.after(250, window.request_exit)
            else:
                try:
                    window.tray = TrayIcon(root, APP_NAME, icon, window.show_window, window.request_exit)
                    window.tray.show()
                except OSError:
                    pass
            try:
                root.mainloop()
            finally:
                if window.tray:
                    window.tray.close()
    except (OSError, ValueError, KeyError, TypeError, tk.TclError) as error:
        report = os.environ.get("PROXYFFFIRE_SMOKE_REPORT") if smoke else None
        if report:
            Path(report).write_text(f"{type(error).__name__}: {error}\n", encoding="utf-8")
        elif not smoke and root is not None:
            style_window(root)
            notice(root, "Could not start ProxyFfffire. Check for an open window or unreadable local data.")
        return 1
    return 0


def verify_runtime(root):
    bundle = Path(sys._MEIPASS).resolve()
    loaded_path = ct.create_unicode_buffer(32768)
    module_path = ct.WinDLL("kernel32").GetModuleFileNameW
    module_path.argtypes = (ct.c_void_p, ct.c_wchar_p, ct.c_uint32)
    module_path.restype = ct.c_uint32
    if not module_path(ct.pythonapi._handle, loaded_path, len(loaded_path)):
        raise OSError("Could not locate the Python runtime DLL.")
    paths = {"Python DLL": loaded_path.value, "Tcl": root.tk.call("info", "library"), "Tk": root.getvar("tk_library")}
    for component, path in paths.items():
        # Tk can return a Tcl path object even when its string value is a filename.
        resolved = Path(str(path)).resolve()
        if not resolved.is_relative_to(bundle):
            raise OSError(f"{component} loaded from {resolved} instead of {bundle}.")


if __name__ == "__main__":
    sys.exit(main())
