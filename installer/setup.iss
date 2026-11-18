#ifndef AppVersion
  #error AppVersion must be passed as a command-line define.
#endif

#define AppName "ProxyFfffire"
#define AppExe "ProxyFfffire.exe"

[Setup]
AppId=ProxyFfffire
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppName}
AppMutex=Local\ProxyFfffire.Session
DefaultDirName={localappdata}\Programs\{#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
MinVersion=10.0
ArchitecturesAllowed=x64os
ArchitecturesInstallIn64BitMode=x64os
UsePreviousAppDir=yes
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\{#AppExe}
OutputDir=..\release
OutputBaseFilename=ProxyClient-Setup-v{#AppVersion}-x64

[Files]
Source: "..\dist\ProxyFfffire\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{userprograms}\{#AppName}"; Filename: "{app}\{#AppExe}"; WorkingDir: "{app}"

[Run]
Filename: "{app}\{#AppExe}"; Description: "Launch ProxyFfffire"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{app}\{#AppExe}"; Parameters: "--restore-windows-proxy"; RunOnceId: "RestoreProxyFfffireWindowsProxy"; Flags: skipifdoesntexist
