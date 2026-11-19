#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    # Also delete C:\ProgramData\TheNex (logs, model and every quarantined file).
    [switch]$Purge
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$InstallDir = Join-Path $env:ProgramData 'TheNex'
$ServiceName = 'TheNex'
$Exe = Join-Path $InstallDir 'the-nex.exe'
$RunKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
$RunValue = 'TheNexNotifier'
$TaskName = 'TheNex Notifier'
$Sc = Join-Path $env:SystemRoot 'System32\sc.exe'

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

if (Test-Path -LiteralPath $Exe) {
    $code = Invoke-Native $Exe @('--uninstall')
    if ($code -ne 0) { Write-Warning "the-nex.exe --uninstall exited with $code; falling back to sc.exe." }
}
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Invoke-Native $Sc @('stop', $ServiceName) | Out-Null
    Start-Sleep -Seconds 2
    Invoke-Native $Sc @('delete', $ServiceName) | Out-Null
}

if (Get-ItemProperty -Path $RunKey -Name $RunValue -ErrorAction SilentlyContinue) {
    Remove-ItemProperty -Path $RunKey -Name $RunValue
    Write-Host "Removed $RunKey\$RunValue"
}
$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($task) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "Removed scheduled task '$TaskName'"
}

Get-Process -Name 'the-nex' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

if ($Purge) {
    if (Test-Path -LiteralPath $InstallDir) {
        Remove-Item -LiteralPath $InstallDir -Recurse -Force
        Write-Host "Deleted $InstallDir"
    }
}
else {
    Write-Host "Kept $InstallDir (quarantine, logs, model). Re-run with -Purge to delete it."
}
Write-Host 'The Nex has been uninstalled.'
