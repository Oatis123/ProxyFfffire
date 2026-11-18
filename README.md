# ProxyFfffire

A Windows 10/11 x64 desktop proxy client with a loopback HTTP listener, saved upstream profiles, and Windows proxy routing. It forwards ordinary HTTP and tunnels HTTPS without inspecting TLS. Upstream protocols are HTTP CONNECT (optional Basic authentication) and SOCKS5 (optional username/password authentication). SOCKS5 receives the destination in domain-name form.

## Install or run from source

Download `ProxyClient-Setup-vX.Y.Z-x64.exe` and its `.sha256` file from the repository’s **Releases** page. Compare the reported hash with the checksum file before launching Setup.

```powershell
Get-FileHash .\ProxyClient-Setup-vX.Y.Z-x64.exe -Algorithm SHA256
```

Setup installs for the current user without elevation. Open **ProxyFfffire** from Start. To remove it, find **ProxyFfffire** in **Settings → Apps**. The installer includes Python and Tcl/Tk. It requires no separately installed Python, pip, compiler, or network driver.

The installer, app and uninstaller are unsigned. Windows may warn about or block them, especially when Smart App Control is enabled. See [Microsoft’s Smart App Control FAQ](https://support.microsoft.com/en-us/windows/security/threat-malware-protection/smart-app-control-frequently-asked-questions).

To run the source checkout, use Windows CPython 3.11 or later with the Python launcher and Tcl/Tk. The app uses the standard library.

```powershell
py -3 --version
py -3 app.py
```

## Connect and verify traffic

1. Click **Add Profile** and enter the proxy’s name, protocol, address, port and optional credentials. Click **Save**. The app starts with an empty profile list.
2. Open **Routing** and choose a mode, local port, and HTTPS test URL. **Save** also remembers these settings. **Test Proxy** checks the profile in the editor. **Connect** checks it again and then applies the new configuration if the certificate validates and the endpoint returns HTTP 2xx or 3xx. A failed test leaves the previous profile active. Existing tunnels keep their original upstream until they close or you disconnect.
3. Generate a request in the client app. Check **Connection Log** for the target domain, active profile name and `Tunnel established` (HTTPS) or an HTTP status. An `HTTPS test passed` row comes from ProxyFfffire’s own probe. The in-window log retains recent rows for the current session.

| Mode | What it routes |
| --- | --- |
| **Manual** | Copy the local address into an app’s HTTP proxy settings. This mode runs without taking over Windows proxy settings. |
| **Selected Domains** | The Windows PAC proxies only listed domains and sends all other traffic directly. `example.com` matches that exact host. `*.example.com` matches subdomains at any depth. |
| **System Proxy** | The Windows system proxy applies to web traffic from apps that honor it. Apps with independent networking, non-web traffic and connections that bypass Windows proxy settings can go directly. |

For **Claude Desktop**, select **Selected Domains → Claude Desktop**, connect, restart Claude Desktop and send a message. Look for a matching domain row such as `claude.ai` or `api.anthropic.com`. Use **Edit Preset** or **New Preset** to maintain domain lists. The bundled preset retains the requested rules and the verification date `2026-11-18`. Its broader wildcards cover domains for which the current source lists more specific hosts. [Anthropic network access requirements](https://code.claude.com/docs/en/desktop#network-access-requirements).

For a manual check with the default local port, run the following after connecting. The HTTP CONNECT upstream must permit tunneling to the target port, including port 80 when forwarding plain HTTP to that port.

```powershell
curl.exe --proxy http://127.0.0.1:8787 https://example.com/
```

## Local data and recovery

Profiles and presets are stored separately from the installation in `%LOCALAPPDATA%\ProxyFfffire`. Passwords and the Windows proxy recovery record use current-user DPAPI. Updates and uninstall preserve the profile data. Windows proxy settings are backed up before a system mode takes over and restored on disconnect or normal exit. After a crash, reopen the app and click **Restore Windows Proxy**. Recovery compares the current settings with the recorded settings that ProxyFfffire applied and skips the write if they differ.

## Build, test and release

Run on Windows with x64 CPython 3.13 including Tcl/Tk, and [Inno Setup 6.7](https://jrsoftware.org/isdl.php). PyInstaller is a build dependency. Tests use loopback servers, an isolated TLS fixture and a fake Windows proxy backend. PAC tests execute the generated JavaScript with Node.js when available or Windows Script Host otherwise.

```powershell
py -3 -m unittest discover -s tests -v
py -3 -m pip install pyinstaller==6.22.0
.\installer\build.ps1 -Tag v0.1.0
.\installer\smoke-test.ps1 -Installer .\release\ProxyClient-Setup-v0.1.0-x64.exe
```

Use `-Iscc 'C:\path\to\ISCC.exe'` if the compiler is outside the usual install locations, and `-Python 'C:\path\to\python.exe'` for an explicit interpreter. The build uses PyInstaller `onedir`, then Inno Setup. The smoke test installs, checks that the GUI loads its Python DLL and Tcl/Tk libraries from the bundle, reinstalls, checks that a saved profile survives, and uninstalls. Run it under a standard account on clean Windows 10 and 11 x64 VMs without Python to verify a release on both target systems.

Commit the release changes and push a new version tag to the GitHub repository. The workflow runs the tests, builds the installer, exercises install and uninstall, and attaches the `.exe` and `.exe.sha256` to the matching GitHub Release.

```powershell
git tag -a v0.1.0 -m "ProxyFfffire v0.1.0"
git push origin v0.1.0
```
