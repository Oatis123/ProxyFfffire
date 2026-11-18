param(
    [Parameter(Mandatory)]
    [ValidatePattern('^v[0-9]+\.[0-9]+\.[0-9]+$')]
    [string] $Tag,
    [string] $Python = 'py',
    [string] $Iscc
)

$ErrorActionPreference = 'Stop'
$pythonArgs = @()
if ($Python -eq 'py') { $pythonArgs = @('-3') }
if (-not $Iscc) {
    $compiler = Get-Command ISCC.exe -ErrorAction SilentlyContinue
    if ($compiler) { $Iscc = $compiler.Source }
    if (-not $Iscc) {
        $candidates = @(
            (Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'),
            (Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe')
        )
        $Iscc = $candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    }
}
if (-not $Iscc) { throw 'Install Inno Setup 6.7 or pass -Iscc with the full path to ISCC.exe.' }
$Iscc = (Resolve-Path -LiteralPath $Iscc).Path

Push-Location (Join-Path $PSScriptRoot '..')
try {
    & $Python @pythonArgs -c "import sysconfig, tkinter; assert sysconfig.get_platform() == 'win-amd64', 'Use x64 Python'"
    if ($LASTEXITCODE) { throw 'The x64 Python / tkinter check failed.' }
    $basePrefix = & $Python @pythonArgs -c "import json, sys; print(json.dumps(sys.base_prefix))"
    $pythonLicense = Join-Path (ConvertFrom-Json -InputObject $basePrefix) 'LICENSE.txt'
    if (-not (Test-Path -LiteralPath $pythonLicense -PathType Leaf)) { throw 'Use a CPython installation with LICENSE.txt.' }
    & $Python @pythonArgs -m PyInstaller --noconfirm --clean --onedir --windowed --name ProxyFfffire --log-level WARN `
        --icon installer/ProxyFfffire.ico --add-data 'installer/ProxyFfffire.ico:.' `
        --add-data "${pythonLicense}:licenses/CPython" --add-data 'installer/licenses:licenses' app.py
    if ($LASTEXITCODE) { throw 'PyInstaller failed.' }
    $bundle = 'dist/ProxyFfffire/_internal'
    foreach ($required in @('python3*.dll', 'tcl*.dll', 'tk*.dll', '_tcl_data/init.tcl', '_tk_data/tk.tcl')) {
        if (-not (Test-Path (Join-Path $bundle $required))) { throw "Missing bundled runtime file $required" }
    }
    & $Iscc /Q "/DAppVersion=$($Tag.Substring(1))" installer/setup.iss
    if ($LASTEXITCODE) { throw 'Inno Setup failed.' }
    $name = "ProxyClient-Setup-$Tag-x64.exe"
    $file = Join-Path 'release' $name
    $hash = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
    Set-Content -LiteralPath "$file.sha256" -Value "$hash  $name" -Encoding ascii
    Write-Host "Built $file and $file.sha256"
} finally {
    Pop-Location
}
