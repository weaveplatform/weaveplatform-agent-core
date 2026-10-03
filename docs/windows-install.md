# Installing on Windows

How core gets onto a Windows machine — in practice a guest built by the guestweave
tooling (HCS, or Hyper-V via HV.framework) — and runs from boot as SYSTEM.

## What the install does

The Windows release zip (`weaveplatform-agent_<ver>_windows_<arch>.zip`) carries
`weaveboot.exe`, `weave-agent.exe`, `weavectl.exe` and `install.ps1`. The script is a
thin wrapper that logs and sets the exit code; the work is
`weaveboot service install`, so the registration is written by the same binary the SCM
then runs:

1. Stops a running `WeaveAgent`, if this is an upgrade — Windows will not replace a
   running image.
2. Copies the three binaries and, when present, a `modules\` tree into
   `%ProgramFiles%\Weave` (the counterpart of `/usr/lib/weave`). The modules tree is
   replaced wholesale; it is package-owned, like `/usr/lib/weave/modules`.
3. Creates `%ProgramData%\Weave` (the state root, `internal/platform`) and replaces its ACL
   with SYSTEM + Administrators full control, protected from inheritance and pushed
   down to anything already inside. This is the Windows reading of the `0700` that
   `layout.Ensure` enforces on unix, where `tighten_windows.go` is a no-op.
4. With `-ChannelKey`, validates the file as one base64 Ed25519 public key and writes it
   to `%ProgramData%\weave\channel.pub` — where core looks when it has no `--channel-pub`
   (`transport.DefaultChannelKeyPath`). A bad key fails the install rather than booting
   a guest that authenticates nobody.
5. Creates, or reconfigures in place, the `WeaveAgent` service, then starts it and waits
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

Without the script, the binary does the same from any elevated prompt:

```bat
D:\weave\weaveboot.exe service install -channel-key D:\weave\channel.pub -env WEAVE_LOG_LEVEL=debug -start
```

## Checking it

| Command | A pass looks like |
|---|---|
| `"C:\Program Files\Weave\weaveboot.exe" service status` | `running`, exit 0 (3 = installed but not running or not installed, 1 = could not ask) |
| `type %ProgramData%\Weave\logs\install.log` | ends `WeaveAgent installed`; a failure ends `FAILED: …` with the tool's own message above it |
| `type %ProgramData%\Weave\logs\weaveboot.log` | `starting core`, then core's own log lines — the service has no console, so both weaveboot and core log here (one 10 MiB generation kept as `.1`) |
| `sc qc WeaveAgent`, `sc qfailure WeaveAgent` | the table above |
| `icacls %ProgramData%\Weave` | only `NT AUTHORITY\SYSTEM` and `BUILTIN\Administrators`, `(OI)(CI)(F)` |

A non-zero exit from the install means nothing was started; the reason is the last
lines of `install.log`. Exit 1 with "is this elevated?" means the caller could not open
the SCM with full rights — the specialize pass and an elevated FirstLogonCommand both
can.

## Removing it

```bat
"C:\Program Files\Weave\weaveboot.exe" service uninstall
rmdir /s /q "C:\Program Files\Weave"
rmdir /s /q "%ProgramData%\Weave"
```

`uninstall` stops and deletes the service and leaves files alone, like `apt remove`;
deleting `%ProgramData%\Weave` is the purge — it holds the device identity and its
policy (see `packaging/linux/postremove.sh` for why that matters).
