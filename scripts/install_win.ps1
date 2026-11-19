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
$ExeSource = Join-Path $ProjectRoot 'target\release\the-nex.exe'
$ExeTarget = Join-Path $InstallDir 'the-nex.exe'

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

if (-not (Test-Path -LiteralPath $ModelSource)) {
    Write-Host "Generating $ModelName ..."
    $python = Resolve-Tool -Names @('python', 'py')
    if (-not $python) { throw 'Python 3 is required to generate thenex_model.onnx (install it, then re-run).' }
    if ((Invoke-Native $python @('-c', 'import numpy, onnx')) -ne 0) {
        Write-Host 'Installing numpy and onnx for the training script ...'
        if ((Invoke-Native $python @('-m', 'pip', 'install', '--disable-pip-version-check', 'numpy', 'onnx')) -ne 0) {
            throw 'pip install numpy onnx failed.'
        }
    }
    if ((Invoke-Native $python @((Join-Path $ProjectRoot 'train_onnx.py'), '--out', $ModelSource)) -ne 0) {
        throw 'train_onnx.py failed.'
    }
}

if (-not $SkipBuild) {
    $cargo = Resolve-Tool -Names @('cargo') -Fallbacks @((Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe'))
    if (-not $cargo) { throw 'cargo not found. Install Rust from https://rustup.rs and re-run.' }
    Push-Location $ProjectRoot
    try {
        $code = Invoke-Native $cargo @('build', '--release')
    }
    finally {
        Pop-Location
    }
    if ($code -ne 0) { throw "cargo build --release failed (exit $code)." }
}
if (-not (Test-Path -LiteralPath $ExeSource)) { throw "Build output not found: $ExeSource" }

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing -and $existing.Status -ne 'Stopped') {
    Write-Host 'Stopping the running TheNex service ...'
    Stop-Service -Name $ServiceName -Force
    $existing.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
}
Get-Process -Name 'the-nex' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item -LiteralPath $ExeSource -Destination $ExeTarget -Force
Copy-Item -LiteralPath $ModelSource -Destination (Join-Path $InstallDir $ModelName) -Force

$code = Invoke-Native $ExeTarget @('--install')
if ($code -ne 0) { throw "the-nex.exe --install failed (exit $code)." }

Start-Service -Name $ServiceName
(Get-Service -Name $ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
Start-Process -FilePath $ExeTarget -ArgumentList '--notifier' -WindowStyle Hidden

Write-Host ''
Get-Service -Name $ServiceName | Format-List Name, DisplayName, Status, StartType
Invoke-Native (Join-Path $env:SystemRoot 'System32\sc.exe') @('qfailure', $ServiceName) | Out-Null
Write-Host "Installed to $InstallDir. Events: $(Join-Path $InstallDir 'logs\events.jsonl')"
