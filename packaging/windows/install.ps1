#Requires -Version 5.1
<#
.SYNOPSIS
Unattended install of the Weave platform agent as the WeaveAgent service.

.DESCRIPTION
Run elevated (Administrator or SYSTEM) from the unpacked release zip, which
holds weaveboot.exe, weave-agent.exe and weavectl.exe beside this script and,
optionally, a modules\ tree. The work is done by `weaveboot service install`:
this wrapper gives autounattend one stable command line, writes a log, and
exits non-zero on any failure. Re-running it upgrades in place.

.PARAMETER ChannelKey
The host's base64 Ed25519 channel public key file, absolute or relative to
this script. Installed where core looks for it (%ProgramData%\weave\channel.pub).

.PARAMETER Environment
KEY=VALUE pairs for the service environment, passed on to core. Separate
several with ';' (powershell.exe -File passes an array as one string).

.EXAMPLE
powershell.exe -NoProfile -ExecutionPolicy Bypass -File D:\weave\install.ps1 -ChannelKey channel.pub
#>
[CmdletBinding()]
param(
    [string]$ChannelKey,
    [string[]]$Environment = @(),
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'Weave'),
    [string]$LogFile = (Join-Path $env:ProgramData 'Weave\logs\install.log'),
    [switch]$NoStart
)

New-Item -ItemType Directory -Force -Path (Split-Path -Parent $LogFile) | Out-Null

function Write-Log([string]$Message) {
    $line = '{0:u} {1}' -f (Get-Date), $Message
    Add-Content -LiteralPath $LogFile -Value $line
    Write-Output $line
}

function Stop-WithFailure([string]$Message) {
    Write-Log "FAILED: $Message"
    exit 1
}

$weaveboot = Join-Path $PSScriptRoot 'weaveboot.exe'
if (-not (Test-Path -LiteralPath $weaveboot)) {
    Stop-WithFailure "weaveboot.exe not found beside install.ps1 in $PSScriptRoot"
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Stop-WithFailure 'must run elevated (Administrator or SYSTEM)'
}

$arguments = @('service', 'install', '-source-dir', $PSScriptRoot, '-install-dir', $InstallDir)
if ($ChannelKey) {
    if (-not [IO.Path]::IsPathRooted($ChannelKey)) {
        $ChannelKey = Join-Path $PSScriptRoot $ChannelKey
    }
    $arguments += @('-channel-key', $ChannelKey)
}
foreach ($kv in ($Environment -split ';' | Where-Object { $_ })) {
    $arguments += @('-env', $kv)
}
if (-not $NoStart) {
    $arguments += '-start'
}

Write-Log "running: $weaveboot $($arguments -join ' ')"
# ErrorActionPreference stays at Continue on purpose: under Stop, Windows
# PowerShell 5.1 turns the first line the tool writes to stderr into a
# terminating error, and the log would lose the reason for the failure.
& $weaveboot @arguments 2>&1 | ForEach-Object { Write-Log "$_" }
$code = $LASTEXITCODE
if ($code -ne 0) {
    Stop-WithFailure "weaveboot service install exited $code"
}
Write-Log 'WeaveAgent installed'
exit 0
