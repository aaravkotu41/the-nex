#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$InstallDir = Join-Path $env:ProgramData 'TheNex'
$ServiceName = 'TheNex'
$ModelName = 'thenex_model.onnx'
$ModelSource = Join-Path $ProjectRoot $ModelName
$IconSource = Join-Path $ProjectRoot 'crates\the-nex-gui\icons\icon.ico'
$ReleaseDir = Join-Path $ProjectRoot 'target\release'
$Binaries = @('the-nex.exe', 'the-nex-gui.exe')
$DaemonTarget = Join-Path $InstallDir 'the-nex.exe'

function Resolve-Tool {
    param([string[]]$Names, [string[]]$Fallbacks = @())
    foreach ($name in $Names) {
        $command = Get-Command $name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($command) { return $command.Source }
    }
    foreach ($candidate in $Fallbacks) {
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    return $null
}

function Invoke-Native {
    param([string]$FilePath, [string[]]$Arguments)
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $FilePath @Arguments | Out-Host
        return $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previous
    }
}

$python = Resolve-Tool -Names @('python', 'py')

if (-not (Test-Path -LiteralPath $IconSource)) {
    if (-not $python) { throw 'Python 3 is required to generate the icons (scripts\gen_icons.py).' }
    Write-Host 'Generating icons ...'
    if ((Invoke-Native $python @((Join-Path $ProjectRoot 'scripts\gen_icons.py'))) -ne 0) { throw 'gen_icons.py failed.' }
}

if (-not (Test-Path -LiteralPath $ModelSource)) {
    if (-not $python) { throw 'Python 3 is required to generate thenex_model.onnx (install it, then re-run).' }
    Write-Host "Generating $ModelName ..."
    if ((Invoke-Native $python @('-c', 'import numpy, onnx')) -ne 0) {
        Write-Host 'Installing numpy and onnx for the training script ...'
        if ((Invoke-Native $python @('-m', 'pip', 'install', '--disable-pip-version-check', 'numpy', 'onnx')) -ne 0) {
            throw 'pip install numpy onnx failed.'
        }
    }
    if ((Invoke-Native $python @((Join-Path $ProjectRoot 'scripts\train_onnx.py'), '--out', $ModelSource)) -ne 0) {
        throw 'train_onnx.py failed.'
    }
}

if (-not $SkipBuild) {
    $cargo = Resolve-Tool -Names @('cargo') -Fallbacks @((Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe'))
    if (-not $cargo) { throw 'cargo not found. Install Rust from https://rustup.rs and re-run.' }
    Push-Location $ProjectRoot
    try {
        $code = Invoke-Native $cargo @('build', '--release', '--workspace')
    }
    finally {
        Pop-Location
    }
    if ($code -ne 0) { throw "cargo build --release --workspace failed (exit $code)." }
}
foreach ($binary in $Binaries) {
    $path = Join-Path $ReleaseDir $binary
    if (-not (Test-Path -LiteralPath $path)) { throw "Build output not found: $path" }
}

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing -and $existing.Status -ne 'Stopped') {
    Write-Host 'Stopping the running TheNex service ...'
    Stop-Service -Name $ServiceName -Force
    $existing.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
}
Get-Process -Name 'the-nex', 'the-nex-gui' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
foreach ($binary in $Binaries) {
    Copy-Item -LiteralPath (Join-Path $ReleaseDir $binary) -Destination (Join-Path $InstallDir $binary) -Force
}
Copy-Item -LiteralPath $ModelSource -Destination (Join-Path $InstallDir $ModelName) -Force
Copy-Item -LiteralPath $IconSource -Destination (Join-Path $InstallDir 'icon.ico') -Force

$code = Invoke-Native $DaemonTarget @('--install')
if ($code -ne 0) { throw "the-nex.exe --install failed (exit $code)." }

Start-Service -Name $ServiceName
(Get-Service -Name $ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
Start-Process -FilePath $DaemonTarget -ArgumentList '--tray' -WindowStyle Hidden

Write-Host ''
Get-Service -Name $ServiceName | Format-List Name, DisplayName, Status, StartType
Invoke-Native (Join-Path $env:SystemRoot 'System32\sc.exe') @('qfailure', $ServiceName) | Out-Null
Write-Host "Installed to $InstallDir. Open the dashboard with $(Join-Path $InstallDir 'the-nex-gui.exe') or the tray icon."
