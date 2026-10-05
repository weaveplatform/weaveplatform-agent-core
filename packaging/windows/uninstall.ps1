#Requires -Version 5.1
<#
.SYNOPSIS
Removes the Weave platform agent that install.ps1 installed.

.DESCRIPTION
Run elevated. The install copies this script into the install directory, so
it is there to run after the media is gone:

    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$env:ProgramFiles\Weave\uninstall.ps1"

The work is `weaveboot service uninstall -remove-files -untrust`, run from a
copy of weaveboot.exe in a temporary directory: Windows will not delete a
running image, and the installed weaveboot.exe is one of the files removed.
It stops and deletes the WeaveAgent service, removes core's binaries and the
modules its media installed, and takes the weaveplatform code-signing
certificate out of LocalMachine\Root and LocalMachine\TrustedPublisher.

Module packages installed after core (each recorded as uninstall.d\<id>.ps1)
are left alone, and while any remains the certificate stays trusted: those
packages were installed on the strength of it. Run their uninstallers first
for a clean machine.

%ProgramData%\Weave (the device identity, its store and policy) stays unless
-Purge is given.

.PARAMETER InstallDir
The install directory: the directory holding this script when that has a
weaveboot.exe, otherwise %ProgramFiles%\Weave.

.PARAMETER KeepCert
Leave the code-signing certificate trusted.

.PARAMETER Purge
Also delete %ProgramData%\Weave.
#>
[CmdletBinding()]
param(
    [string]$InstallDir = '',
    [switch]$KeepCert,
    [switch]$Purge,
    [string]$LogFile = (Join-Path $env:TEMP 'weave-uninstall.log')
)

function Write-Log([string]$Message) {
    $line = '{0:u} {1}' -f (Get-Date), $Message
    Add-Content -LiteralPath $LogFile -Value $line
    Write-Output $line
}

function Stop-WithFailure([string]$Message) {
    Write-Log "FAILED: $Message"
    exit 1
}

if (-not $InstallDir) {
    if (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'weaveboot.exe')) {
        $InstallDir = $PSScriptRoot
    } else {
        $InstallDir = Join-Path $env:ProgramFiles 'Weave'
    }
}
$weaveboot = Join-Path $InstallDir 'weaveboot.exe'
if (-not (Test-Path -LiteralPath $weaveboot)) {
    Stop-WithFailure "no weaveboot.exe in $InstallDir"
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Stop-WithFailure 'must run elevated (Administrator or SYSTEM)'
}

$temp = Join-Path $env:TEMP ('weave-uninstall-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $temp | Out-Null
$copy = Join-Path $temp 'weaveboot.exe'
Copy-Item -LiteralPath $weaveboot -Destination $copy

$arguments = @('service', 'uninstall', '-install-dir', $InstallDir, '-remove-files')
if (-not $KeepCert) {
    $arguments += '-untrust'
}
Write-Log "running: weaveboot $($arguments -join ' ')"
# As in install.ps1: Continue, so the tool's stderr reaches the log.
& $copy @arguments 2>&1 | ForEach-Object { Write-Log "$_" }
$code = $LASTEXITCODE
Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
if ($code -ne 0) {
    Stop-WithFailure "weaveboot service uninstall exited $code"
}
if ($Purge) {
    $state = Join-Path $env:ProgramData 'Weave'
    Write-Log "purging $state"
    Remove-Item -LiteralPath $state -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Log 'WeaveAgent uninstalled'
exit 0
