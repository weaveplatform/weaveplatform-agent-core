# Windows / platform security — validation handoff

The platform-specific security code, and what an engineer or agent on a
**Windows host** (and, where noted, a macOS host with a login keychain or a
Linux host with a TPM) has to run to validate it. The code is written and
cross-compiles; what it needs is **runtime validation** on the target OS, plus
a few clearly marked follow-ups that need infrastructure CI does not have.

Everything below builds with:

```sh
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build ./...
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go vet ./...
```

## What is implemented (needs Windows runtime validation)

### S9 — DPAPI master-key protection with machine-bound entropy
`internal/store/keyprotect/dpapi_windows.go`. DPAPI machine scope alone lets
any local process `CryptUnprotectData` the blob; this binds secondary
entropy derived from `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`
(machine-bound, not stored beside `store.key`).

**Run on Windows:** `go test ./internal/store/keyprotect/`
- `TestDPAPIRoundTrip` — seal/unseal survives; sealed blob ≠ plaintext.
- `TestDPAPIEntropyBinding` — unseal with wrong entropy fails (entropy is
  actually applied). If this passes on a machine with no MachineGuid, check
  the registry read.

### S11 — named-pipe SDDL
`internal/protocol/ipc/ipc_windows.go` (the module SDK's copy lives in
`weaveplatform-agent-modules`). Pipes are created with
`D:(A;;GA;;;SY)(A;;GA;;;BA)` (SYSTEM + Administrators only), not go-winio's
broad default, which lets any local user open the control/host pipe.
`ListenPipeSDDL` is provided for privilege-dropped modules that need a wider
descriptor.

**Validate on Windows:**
- As a non-admin user, attempt to open `\\.\pipe\weave-control` — must be
  denied. As admin/SYSTEM — allowed.
- Confirm a running module (SYSTEM today) can still reach its host pipe.
- `per-user-console` modules get a host pipe whose SDDL also grants the
  console user's SID (`sessionPipeSDDL`, `internal/supervise/spawn_windows.go`).
  `service` modules still use the default.

### S12 — Authenticode revocation + thumbprint pin
`internal/verify/authenticode_windows.go`. Revocation is on
(`WTD_REVOKE_WHOLECHAIN`, cache-only + exclude-root so offline installs
don't fail-closed on a network CRL fetch), and the leaf is pinned by SHA-1
thumbprint (`AuthenticodeThumbprint` in the manifest) when provided, falling
back to the subject display name.

**Run on Windows:** `go test ./internal/verify/` — see
`authenticode_windows_test.go`. It needs a self-signed cert; the file header
has the PowerShell to mint one. The tests must show:
1. unsigned binary refused;
2. self-signed (untrusted-chain) binary refused — the Authenticode analogue
   of the macOS "anchor apple" fix;
3. thumbprint mismatch refused when a thumbprint is pinned.

### WeaveAgent service and the unattended installer
`internal/winsvc`, `cmd/weaveboot/service.go`, `packaging/windows/install.ps1`;
operator view in [`windows-install.md`](windows-install.md). weaveboot detects
that the SCM started it (session 0 and a `services.exe` parent), runs under the
service control dispatcher, and turns Stop / Shutdown / PreShutdown into the
same context cancel SIGTERM is on unix — reporting `STOP_PENDING` with an
advancing checkpoint while core drains, then `STOPPED`. Core itself is
stopped with `CTRL_BREAK` to its own process group (weaveboot allocates a
console for this when it has none), which core's runtime delivers as
`os.Interrupt`, rather than with `TerminateProcess`.
`weaveboot service install|uninstall|start|stop|status` registers the service:
LocalSystem, automatic start, restart after 2s on any failure, 30s
preshutdown budget, `Environment` from `-env`, state root ACL'd to SYSTEM +
Administrators.

CI runs the real thing on `windows-latest` (elevated):
`TestRealServiceLifecycle` installs a uniquely named service whose binary is
the winsvc test binary, reads the registration back from the registry,
re-installs in place, starts it, stops it gracefully and deletes it;
`TestRestrictDir` applies and reads back the state-root DACL;
`TestWeavebootStopsCoreGracefully` runs on Windows and proves the
`CTRL_BREAK` path. What each failure would mean:
- `TestServiceChild` reports `service=false` — detection is wrong, and a real
  weaveboot under the SCM would run interactively and be killed by the SCM's
  start timeout (error 1053).
- start times out, or "stopped while starting" — the dispatcher or the
  `RUNNING` report is broken; nothing else in this repo would notice, because
  weaveboot interactively still works.
- the `stopped` marker is missing — a stop reached the SCM but not the body,
  so core would be killed at the end of the wait rather than drained.
- `Environment` mismatch — `-env` would silently not reach core.
- `TestWeavebootStopsCoreGracefully` fails only on Windows — the break did not
  reach core (no shared console, or core not in its own group), and every
  service stop is a hard kill again.

**Not yet run anywhere:** a full guest install from autounattend media
(specialize pass) with a real core and modules, and a real system shutdown
with the preshutdown budget. Run the command in `windows-install.md` on a
fresh guest; a pass is `weaveboot service status` → `running` after boot, a
`weaveboot.log` showing core started, and, after `shutdown /s /t 0` and boot,
no store-recovery warning from core. **Known gap:** modules are in core's
process group, so they receive the same `CTRL_BREAK` as core and may exit
before core asks them to — the race `KillMode=mixed` avoids on Linux. The fix
is `CREATE_NEW_PROCESS_GROUP` for modules in `internal/supervise`.
**Unverified risk:** a console process in the services session receives
`CTRL_LOGOFF_EVENT` whenever any user logs off (the reason JVM services need
`-Xrs`), and Go delivers it as SIGTERM — which core treats as shutdown. If
that holds here, core exits on every user logoff and weaveboot restarts it
two seconds later (a ready core's exit does not count toward revert). Check
by logging on and off a guest and reading `weaveboot.log`; the fix would be
in core, which cannot tell logoff from shutdown through `os/signal`.

## Follow-ups that need target-OS infrastructure

### S5 — Windows per-peer identity on the host/control pipes
`internal/protocol/ipc/peercred_windows.go` returns no uid, so the
authorizers fall through to the SDDL (S11) as the gate — which is correct and
sufficient on its own. To add per-peer PID/identity checks:
- Get the pipe HANDLE (go-winio does not expose it on `net.Conn`; either
  vendor a small pipe type that exposes `Fd()`, or use the win32 bindings'
  `GetNamedPipeClientProcessId`), then map PID→SID and compare.
- Wire it into the host listener (`target.listenHost`, `internal/supervise/spawn_windows.go`)
  and `controlAuthorizer` (`internal/controlsock/authorize_windows.go`),
  which are allow-all placeholders today.

The **unix** side of S5 is done and validated on macOS: `SO_PEERCRED` /
`LOCAL_PEERCRED` in `peercred_{linux,darwin}.go`, enforced by
`target.authorizePeer` (host socket) and `controlAuthorizer` (control socket).

### S5 — per-module service accounts
`internal/supervise/spawn_unix.go` drops all `service`-privilege
modules to one shared account (`serviceAccount()`), so the peer-uid check
distinguishes modules from non-modules but not modules from each other. True
per-module isolation needs an account per module, created by the supervisor
lazily (the installers — the deb and `weaveboot service install` — do not
know which modules a device will receive) and returned by
`systemCreds`. Tracked, not code-complete.

### S9 — macOS Keychain / Secure Enclave and Linux TPM
`internal/store/keyprotect/file_unix.go` is a plaintext passthrough on
unix (the master key sits in `store.key`). Targets:
- **macOS:** back the `Protector` with the login/System keychain via
  `go-bindings-macosplatform/opinionated/tools/keychain` (store the master
  key as a generic password; `store.key` holds only a marker). Validate that
  a daemon context can read it without a UI prompt (needs the right
  entitlement/keychain-access-group).
- **Linux:** seal the key to the TPM (`go-tpm/tpm2` Seal/Unseal) or
  `systemd-creds`. Needs a TPM (or swtpm) to validate.

Until these land, `keyprotect.New()` on unix returns the file protector; the
startup directory-permission tightening (`internal/layout/tighten_unix.go`,
`Ensure()`: data directories 0700, the key and store 0600 files) is the interim gate.

## Summary for the Windows-host validator

1. `go test ./internal/store/keyprotect/` — DPAPI round-trip + entropy.
2. `go test ./internal/verify/` — Authenticode (mint a self-signed cert per
   the file header).
3. Manual: non-admin cannot open `\\.\pipe\weave-control`; a module still
   reaches its host pipe.
4. Install from autounattend media per `windows-install.md`; check the service
   is running after boot and survives a shutdown without store recovery.
5. Report back so the allow-all Windows authorizers (S5) can be tightened to
   real per-peer checks.
5. Manual, as LocalSystem with a user logged on at the console: install a
   `per-user-console` module; it must show `running: console session <id>`
   in `weavectl modules`, appear in Task Manager under that user (not
   SYSTEM, not elevated), and see the user's clipboard. Log off: it must go
   to `waiting-for-session`. Fast-user-switch: it must restart under the new
   user. A module that runs but cannot see the clipboard means the
   `winsta0\default` desktop did not take (see architecture.md, Sessions).
