#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    # Also delete C:\ProgramData\TheNex (logs, model, settings and every quarantined file).
    [switch]$Purge
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$InstallDir = Join-Path $env:ProgramData 'TheNex'
$ServiceName = 'TheNex'
$Exe = Join-Path $InstallDir 'the-nex.exe'
$MachineRunKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
$UserRunKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
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

function Remove-RunValue {
    param([string]$Key, [string]$Name)
    if (Get-ItemProperty -Path $Key -Name $Name -ErrorAction SilentlyContinue) {
        Remove-ItemProperty -Path $Key -Name $Name
        Write-Host "Removed $Key\$Name"
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

Remove-RunValue -Key $MachineRunKey -Name 'TheNexNotifier'
Remove-RunValue -Key $UserRunKey -Name 'TheNexTray'
$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($task) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "Removed scheduled task '$TaskName'"
}

Get-Process -Name 'the-nex', 'the-nex-gui' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

if ($Purge) {
    if (Test-Path -LiteralPath $InstallDir) {
        Remove-Item -LiteralPath $InstallDir -Recurse -Force
        Write-Host "Deleted $InstallDir"
    }
}
else {
    Write-Host "Kept $InstallDir (quarantine, logs, settings, model). Re-run with -Purge to delete it."
}
Write-Host 'The Nex has been uninstalled.'
