# Installing on Windows

How core gets onto a Windows machine and runs from boot as SYSTEM. In practice the machine
is a guest built by the guestweave tooling: HCS on a Windows host, or Virtualization.framework
for Windows ARM64 on a Mac.

## The installer: a signed zip and `install.ps1`, not an MSI

The Windows release zip (`weaveplatform-agent_<ver>_windows_<arch>.zip`) carries
`weaveboot.exe`, `weave-agent.exe`, `weavectl.exe`, `weavemanifest.exe`, `install.ps1`,
`uninstall.ps1` and `weave-codesign.crt`, the weaveplatform code-signing certificate. Every
`.exe` and both scripts are Authenticode signed with that certificate and timestamped.

It is a zip and a script rather than an MSI on purpose:

- **guestweave installs a fresh guest unattended**, from Windows install media and an
  unattend file (the `specialize` pass, below), or over SSH or exec onto a running guest.
  Both are one command line either way. The media already carries a directory, so the zip
  unpacked onto it needs no extraction step, and `install.ps1 -ChannelKey channel.pub` is
  what both the unattend file and an SSH session run.
- **The install logic is Go, in `weaveboot service install`** (`internal/winsvc`). CI unit
  tests every step of it on Linux, macOS and Windows, and runs it against the real SCM on
  `windows-latest`. An MSI would move the service registration, ACLs and certificate trust
  into WiX custom actions, which can only be tested by installing the MSI.
- **Modules install the same way.** agent-modules ships each Windows module as a signed zip
  with its own `install.ps1` (`packaging/modulezip` there). One mechanism covers core and
  modules, on the media and on a running guest. No WiX and no Windows build machine is
  needed to release.

`install.ps1` is a thin wrapper that logs and sets the exit code. The work is done by
`weaveboot service install`, so the registration is written by the same binary the SCM then
runs.

## What the install does

1. Validates its inputs before changing anything.
   - **`-ChannelKey`** must be one base64 Ed25519 public key.
   - **The certificate** must be one PEM or DER certificate. It must be self-signed, not a CA,
     and have code signing as its only extended key usage (`internal/certtrust`).
   - A bad key or certificate fails the install with nothing touched.
2. Stops a running `WeaveAgent`, if this is an upgrade: Windows will not replace a running
   image.
3. Copies the four binaries and `uninstall.ps1` into `%ProgramFiles%\Weave` (the counterpart
   of `/usr/lib/weave`).
   - **When the media has a `modules\` tree**, the modules it carries are installed into
     `%ProgramFiles%\Weave\modules`, each replacing its own directory. A module the media no
     longer carries is removed.
   - **Module packages are left alone.** These are modules installed after core from an
     agent-modules zip, each recorded as `uninstall.d\<id>.ps1`. Even when the media carries
     the same id, the package's copy stays, so a core upgrade never wipes or downgrades a
     module installed later.
   - **When the media has no `modules\` tree**, the existing tree is not touched.
4. Creates `%ProgramData%\Weave` (the state root, `internal/platform`) and replaces its ACL
   with full control for SYSTEM and Administrators only.
   - The ACL is protected from inheritance and pushed down to anything already inside.
   - This is the Windows reading of the modes that `layout.Ensure` enforces on unix, where
     `tighten_windows.go` is a no-op.
5. With `-ChannelKey`, writes the key to `%ProgramData%\weave\channel.pub`. That is where
   core looks when it has no `--channel-pub` (`transport.DefaultChannelKeyPath`).
6. **Trusts the code-signing certificate** (below). It keeps a copy as
   `%ProgramFiles%\Weave\weave-codesign.crt`, then adds the certificate to
   `LocalMachine\Root` and `LocalMachine\TrustedPublisher`. This happens before the service
   starts, so core's first module discovery already verifies against it.
7. Creates the `WeaveAgent` service, or reconfigures it in place, then starts it and waits
   for it to report running.

| Setting | Value | Mirrors (Linux unit) |
|---|---|---|
| Name / display name | `WeaveAgent` / "Weave platform agent" | `weave-agent.service` |
| Command line | `"C:\Program Files\Weave\weaveboot.exe" -- --modules-dir "C:\Program Files\Weave\modules"` (resolved at install) | `ExecStart=/usr/lib/weave/weaveboot -- --modules-dir /usr/lib/weave/modules` |
| Account | LocalSystem | root |
| Start | Automatic — **not** delayed: delayed start holds the agent back about two minutes after boot, and it is the channel a host drives a fresh guest through | no `After=network-online.target` |
| Recovery | Restart after 2 s on every failure, including a non-crash failure (`FailureActionsOnNonCrashFailures`) | `Restart=always`, `RestartSec=2` |
| Shutdown budget | Accepts PreShutdown, timeout 30 s | `TimeoutStopSec=30` |
| Environment | `-Environment KEY=VALUE` → the service's `Environment` value, inherited by core | `Environment=` |

Every step is idempotent: re-running the same command upgrades the binaries and
converges the registration on exactly what was asked for — an environment variable
left off the new command line is removed, and a hand-set delayed start is reverted.

## Trusting the code-signing certificate

Core runs a Windows module only if the module's Authenticode signature passes
`WinVerifyTrust` **and** its signing certificate matches the pin in the module manifest
(`internal/verify/authenticode_windows.go`):

- **`signing.authenticode_thumbprint`** is the certificate's SHA-1 thumbprint, 40 hex digits
  in either case. It is sufficient on its own and is preferred, because it names exactly one
  certificate.
- **`signing.authenticode_subject`** is the subject's display name. It is a pin only when
  there is no thumbprint, because a CN is something anyone can get into a certificate.
- **Given both, both must match.** Given neither, the module is refused.

The weave-windows-* modules are signed with a **self-signed** certificate:
`CN=weaveplatform code signing, O=weaveplatform`, thumbprint
`A6A3936288B9409ED7A3458CF81014A77AB59B51`. A paid CA certificate comes when the products are
sold.

A self-signed chain passes `WinVerifyTrust` only once the certificate is in the machine's
trusted roots. That is what step 6 does.

**It is an install-time, out-of-band trust step**, in the same class as the channel key and
for the same reasons:

- The certificate arrives on the install media, inside the zip that the cosign-signed
  checksum file covers. It is committed at `packaging/windows/weave-codesign.crt` because it
  is public.
- Nothing on the channel can add, change or remove it, and core has no operation that would.
- Moving to another certificate is a new core release. The modules' manifests move to the
  new thumbprint in the same release.

**`LocalMachine`, not `CurrentUser`.** Core runs as LocalSystem, so a CurrentUser store would
belong to whoever ran the install. A CurrentUser\Root add also raises a modal confirmation
dialog by design, which hangs an unattended install.

**What it allows.** A certificate in `LocalMachine\Root` is trusted machine-wide for whatever
its own extensions permit. That is why the install refuses anything but a self-signed,
non-CA, code-signing-only certificate:

- it cannot issue other certificates (`CA:FALSE`);
- it cannot serve TLS (its only extended key usage is code signing).

What it does allow is that Windows treats code signed with its key as signed by a trusted
publisher, for modules and for PowerShell's `AllSigned`. The private key lives only in the
release workflow's `WINDOWS_CODESIGN_PFX` secret.

Pass `-NoTrustCert` to `install.ps1` (or leave out `weaveboot`'s `-trust-cert`) to trust
nothing. Core then refuses every Windows module whose certificate the machine does not
already trust.

## The unattended command

From the **specialize** pass (runs as SYSTEM, before OOBE, so the agent is up before
anyone logs on), with the zip unpacked to `weave\` on install media whose drive letter
is not known in advance:

```xml
<settings pass="specialize">
  <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64"
             publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
    <RunSynchronous>
      <RunSynchronousCommand wcm:action="add">
        <Order>1</Order>
        <Description>Install the Weave platform agent</Description>
        <Path>cmd.exe /c for %d in (D E F G H I) do @if exist %d:\weave\install.ps1 powershell.exe -NoProfile -ExecutionPolicy Bypass -File %d:\weave\install.ps1 -ChannelKey channel.pub</Path>
      </RunSynchronousCommand>
    </RunSynchronous>
  </component>
</settings>
```

With a known drive, the command alone is:

```bat
powershell.exe -NoProfile -ExecutionPolicy Bypass -File D:\weave\install.ps1 -ChannelKey channel.pub
```

The same line works as an `oobeSystem` `FirstLogonCommands` `SynchronousCommand`
(runs elevated as the first logged-on administrator). Add
`-Environment "WEAVE_LOG_LEVEL=debug;WEAVE_CHANNEL=hvsocket:2010"`
for core settings — several pairs separated by `;`, because `powershell -File` passes
an array as one string — and `-NoStart` to register without starting.

On a running guest, over SSH or exec, the same command runs from an elevated session in the
unpacked zip.

Without the script, the binary does the same from any elevated prompt:

```bat
D:\weave\weaveboot.exe service install -channel-key D:\weave\channel.pub -trust-cert D:\weave\weave-codesign.crt -env WEAVE_LOG_LEVEL=debug -start
```

## Checking it

| Command | A pass looks like |
|---|---|
| `"C:\Program Files\Weave\weaveboot.exe" service status` | `running`, exit 0 (3 = installed but not running or not installed, 1 = could not ask) |
| `type %ProgramData%\Weave\logs\install.log` | ends `WeaveAgent installed`; a failure ends `FAILED: …` with the tool's own message above it |
| `type %ProgramData%\Weave\logs\weaveboot.log` | `starting core`, then core's own log lines — the service has no console, so both weaveboot and core log here (one 10 MiB generation kept as `.1`) |
| `sc qc WeaveAgent`, `sc qfailure WeaveAgent` | the table above |
| `icacls %ProgramData%\Weave` | only `NT AUTHORITY\SYSTEM` and `BUILTIN\Administrators`, `(OI)(CI)(F)` |
| `dir Cert:\LocalMachine\Root\A6A3936288B9409ED7A3458CF81014A77AB59B51` (PowerShell), and the same under `TrustedPublisher` | the weaveplatform code signing certificate |
| `Get-AuthenticodeSignature "C:\Program Files\Weave\weave-agent.exe"` | `Valid`, signer thumbprint `A6A39362…9B51`, and a `TimeStamperCertificate` |

A non-zero exit from the install means nothing was started; the reason is the last
lines of `install.log`. Exit 1 with "is this elevated?" means the caller could not open
the SCM with full rights — the specialize pass and an elevated FirstLogonCommand both
can.

## Modules on a running guest

Core reloads its modules directory as it changes, so a module zip installed after core takes
effect without a restart. On Windows a `ReadDirectoryChangesW` watch on
`%ProgramFiles%\Weave\modules` and every directory under it triggers the same debounced
reconcile as inotify on Linux ([architecture](architecture.md#module-reload)).

- The watch ignores staging names: the module zip's `<name>.new`, Windows Installer's `~*.tmp`
  and `*.tmp`, and weaveboot's own `.install-*`. A file counts once it is renamed into place.
- `weavectl reload` (what the module zip's installer runs) and the one-minute rescan cover
  anything the watch misses.

## Removing it

```bat
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%ProgramFiles%\Weave\uninstall.ps1"
```

`uninstall.ps1` runs `weaveboot service uninstall -remove-files -untrust` from a copy of
`weaveboot.exe` in a temporary directory, because Windows will not delete a running image. It
logs to `%TEMP%\weave-uninstall.log`.

- **The service** is stopped and deleted.
- **Core's files** are removed: the four binaries, both scripts, the certificate copy, and the
  modules core's media installed. If nothing else is left, `%ProgramFiles%\Weave` goes too.
- **The certificate** is removed from `LocalMachine\Root` and `LocalMachine\TrustedPublisher`
  only when no weave package remains.
  - A module package (an `uninstall.d\<id>.ps1`) was installed on the strength of that
    trust. While any remains, its module directory, its uninstaller and the certificate all
    stay.
  - Run the packages' uninstallers first for a clean machine.
  - `-KeepCert` leaves the certificate trusted regardless.
- **`%ProgramData%\Weave` stays** unless `-Purge` is given. It holds the device identity and its
  policy; see `packaging/linux/postremove.sh` for why that matters. Deleting it is the purge.

`weaveboot service uninstall` with no flags still removes only the service, like `apt remove`.
