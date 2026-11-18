param(
    [Parameter(Mandatory)]
    [string] $Installer
)

$ErrorActionPreference = 'Stop'
$installerPath = (Resolve-Path -LiteralPath $Installer).Path
$uninstallKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\ProxyFfffire_is1'
$shortcut = Join-Path ([Environment]::GetFolderPath('Programs')) 'ProxyFfffire.lnk'
if ((Test-Path -LiteralPath $uninstallKey) -or (Test-Path -LiteralPath $shortcut)) {
    throw 'Run this test in a Windows account without an existing ProxyFfffire installation.'
}

$qaRoot = Join-Path $env:TEMP ('ProxyFfffire-smoke-' + [Guid]::NewGuid().ToString('N'))
$appDir = Join-Path $qaRoot 'App'
$exe = Join-Path $appDir 'ProxyFfffire.exe'
$uninstaller = Join-Path $appDir 'unins000.exe'
$localData = Join-Path $qaRoot 'LocalAppData'
$profileDir = Join-Path $localData 'ProxyFfffire'
$profileFile = Join-Path $profileDir 'profiles.json'
$profileFixture = '{"profiles":[{"id":"sample","name":"Smoke Profile","protocol":"HTTP CONNECT","host":"proxy.example","port":8080,"username":"","protected_password":""}],"presets":{"sample":{"name":"Smoke Preset","domains":["example.com"]}},"routing":{"preset":"sample"}}'
$environment = @{}
foreach ($name in @('PATH', 'LOCALAPPDATA', 'PYTHONPATH', 'PYTHONHOME', 'TCL_LIBRARY', 'TK_LIBRARY')) {
    $environment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}

function Invoke-QaProcess([string] $File, [string] $Arguments, [int] $Timeout = 90000) {
    $start = @{ FilePath = $File; WindowStyle = 'Hidden'; PassThru = $true }
    if ($Arguments) { $start.ArgumentList = $Arguments }
    $process = Start-Process @start
    if (-not $process.WaitForExit($Timeout)) {
        $process.Kill()
        throw "Timed out running $File"
    }
    if ($process.ExitCode -ne 0) { throw "$File returned exit code $($process.ExitCode)" }
}

function Invoke-QaUninstall {
    Invoke-QaProcess $uninstaller '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART'
    # Inno's temporary uninstaller removes the original executable after its launcher exits.
    for ($attempt = 0; $attempt -lt 100 -and (Test-Path -LiteralPath $uninstaller); $attempt++) {
        Start-Sleep -Milliseconds 100
    }
    if (Test-Path -LiteralPath $uninstaller) { throw 'The temporary uninstaller did not finish.' }
}

New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
try {
    $env:PATH = "$env:SystemRoot\System32;$env:SystemRoot"
    $env:LOCALAPPDATA = $localData
    foreach ($name in @('PYTHONPATH', 'PYTHONHOME', 'TCL_LIBRARY', 'TK_LIBRARY')) {
        [Environment]::SetEnvironmentVariable($name, $null, 'Process')
    }
    $setupArgs = '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- /DIR="' + $appDir + '"'
    Invoke-QaProcess $installerPath $setupArgs
    if (-not (Test-Path -LiteralPath $uninstallKey)) { throw 'Missing current-user uninstall entry.' }
    if (-not (Test-Path -LiteralPath $shortcut)) { throw 'Missing Start Menu shortcut.' }
    Invoke-QaProcess $exe '--smoke-test' 15000

    Set-Content -LiteralPath $profileFile -Value $profileFixture -Encoding ascii
    Invoke-QaProcess $installerPath $setupArgs
    if ((Get-Content -LiteralPath $profileFile -Raw).Trim() -ne $profileFixture) { throw 'Setup altered user settings.' }
    Invoke-QaProcess $exe '--smoke-test' 15000

    Invoke-QaUninstall
    foreach ($path in @($exe, $uninstallKey, $shortcut)) {
        if (Test-Path -LiteralPath $path) { throw "Uninstall left $path" }
    }
    if (-not (Test-Path -LiteralPath $profileFile)) { throw 'Uninstall removed the user settings.' }
    Write-Host 'Install, bundled GUI launch, reinstall, profile preservation and uninstall passed.'
} finally {
    try {
        if ((Test-Path -LiteralPath $uninstallKey) -and (Test-Path -LiteralPath $uninstaller)) { Invoke-QaUninstall }
    } finally {
        foreach ($entry in $environment.GetEnumerator()) {
            [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, 'Process')
        }
        $fullRoot = (Resolve-Path -LiteralPath $qaRoot).Path
        $fullTemp = (Resolve-Path -LiteralPath $env:TEMP).Path.TrimEnd('\') + '\'
        if ((Test-Path -LiteralPath $uninstallKey) -or (Test-Path -LiteralPath $shortcut)) {
            Write-Warning "The test installation is still registered. Its files are under $fullRoot."
        } elseif ($fullRoot.StartsWith($fullTemp, [StringComparison]::OrdinalIgnoreCase) -and
            (Split-Path $fullRoot -Leaf) -match '^ProxyFfffire-smoke-[a-f0-9]{32}$') {
            Remove-Item -LiteralPath $fullRoot -Recurse -Force
        }
    }
}
