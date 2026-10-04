# The macOS package

How core gets onto a macOS guest, what it puts where, and how to take it off again.

## The package

| Artifact | Built by | Attached to each release as |
|---|---|---|
| A flat component package, identifier `run.weaveplatform.agent` | `packaging/darwin/build-pkg.sh` (`pkgbuild`), run by `release.yml` on a macOS runner from the darwin/arm64 binaries goreleaser released | `weave-agent_<version>_darwin_arm64.pkg`, plus a cosign bundle `…pkg.sigstore.json` |

arm64 only: macOS guests under Virtualization.framework exist only on Apple silicon. The
`preinstall` script refuses any other architecture and any macOS before 12 (Go's minimum)
before anything is unpacked.

**It is not signed or notarised.** No Developer ID Installer identity is configured for this
repository. `build-pkg.sh` signs when `WEAVE_PKG_SIGN_IDENTITY` names one in the keychain;
notarisation would follow that. Until then, provenance is the cosign bundle, checked the
same way as the release's checksum file:

```sh
cosign verify-blob \
  --bundle weave-agent_<version>_darwin_arm64.pkg.sigstore.json \
  --certificate-identity-regexp 'https://github.com/weaveplatform/weaveplatform-agent-core/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  weave-agent_<version>_darwin_arm64.pkg
```

Core's own verification does not depend on the package's signature: on macOS core checks
every module binary's code signature against the Team ID its manifest pins before each launch
(`internal/verify/codesign_darwin.go`).

## Installing

In the guest, as an administrator:

```sh
sudo installer -pkg weave-agent_<version>_darwin_arm64.pkg -target /
```

The command-line installer installs an unsigned package without a Gatekeeper prompt. Opening
the same file in Installer.app from a browser download is refused (it is unsigned and
quarantined); use the command line.

`postinstall` then makes the service account and loads the daemon (below). It is safe to
run again, and that is how an upgrade works: the same command with a newer package.

Installing onto a volume that is not the running system (`-target /Volumes/Image`, building
an image) unpacks the files, and launchd loads the daemon when that volume boots, but the
service account is not created there: run the package once on that system after it boots.

## What goes where

| Path | What | Owner, mode |
|---|---|---|
| `/usr/local/libexec/weave/{weaveboot,weave-agent,weavectl,weavemanifest}` | the binaries, side by side: weaveboot runs core as "the binary beside me" until it has staged a core of its own | root:wheel 0755 |
| `/usr/local/libexec/weave/modules/` | the package-owned modules directory, where module packages install (`--modules-dir`) | root:wheel 0755 |
| `/usr/local/libexec/weave/uninstall.sh` | the uninstaller | root:wheel 0755 |
| `/usr/local/bin/weavectl` | symlink to the above | |
| `/Library/LaunchDaemons/run.weaveplatform.agent.plist` | the daemon | root:wheel 0644 |
| `/Library/Logs/Weave/weave-agent.log` | weaveboot's and core's output | dir root:admin 0750 |
| `/Library/Application Support/Weave/` | core's state: store, identity, `core/` versions, staged module copies, sockets under `run/` | made by core ([layout](architecture.md#filesystem-layout)) |
| `/etc/weave/channel.pub` | the channel trust anchor — not in the package (below) | root:wheel 0644 |

The modules directory sits beside the binaries rather than under the state directory for the
reason the Linux package puts it at `/usr/lib/weave/modules`: it is what packages install
into, so it belongs to the package tree, not to core's private state. `/usr/lib` itself is
not an option on macOS (System Integrity Protection).

The payload carries only directories macOS already has at the same mode (`/usr/local`,
`/usr/local/bin`, `/Library/LaunchDaemons`, all root:wheel 0755) plus its own. That matters:
installer applies a payload directory's mode to one that already exists, so shipping
`/Library/Logs/Weave` in the payload would also reset `/Library/Logs` (root:admin 0775).
`postinstall` creates the log directory instead.

## The daemon

Label `run.weaveplatform.agent`. launchd runs weaveboot and nothing else; weaveboot runs core
and core runs the modules, exactly as under systemd and the Windows SCM.

| Key | Value | Why |
|---|---|---|
| `ProgramArguments` | `weaveboot -- --modules-dir /usr/local/libexec/weave/modules` | everything after `--` goes to core |
| `RunAtLoad`, `KeepAlive` | true | started at boot and restarted whenever it exits; launchd throttles a respawn to one per 10 seconds |
| `ExitTimeOut` | 30 | weaveboot gives core 15 seconds to drain the modules and close the store after SIGTERM; launchd's default 20 would come close to cutting that short |
| `StandardOutPath`, `StandardErrorPath` | `/Library/Logs/Weave/weave-agent.log` | weaveboot's log and core's (core inherits weaveboot's output) |

When launchd stops the job it signals weaveboot, which stops core, which stops the modules;
anything left in the process group after that is killed with it.

```sh
sudo launchctl print system/run.weaveplatform.agent          # state, pid, last exit
sudo launchctl kickstart -k system/run.weaveplatform.agent   # restart
sudo launchctl kill HUP system/run.weaveplatform.agent       # reread the modules directory
tail -f /Library/Logs/Weave/weave-agent.log
```

**Settings.** launchd has no equivalent of the Linux unit's `EnvironmentFile`. A `WEAVE_*`
setting goes in an `EnvironmentVariables` dictionary in the plist, which an upgrade replaces;
on a Virtualization.framework guest none is normally needed, since the channel is the virtio
console port the probe finds by name (`/dev/cu.org.weave.agent.0`).

**The log is not rotated.** launchd holds the file open, so `newsyslog` rotation would leave
weaveboot writing to the rotated file. Core logs lifecycle events, not traffic, so it grows
slowly; to start a fresh one, move it aside and restart the daemon (`kickstart -k`).

## The service account

`_weaveagent` is the account `service`-privilege modules run as when core is root
(`internal/supervise`: `serviceAccount`, `systemCreds`); core uses only its uid and primary
gid. `postinstall` makes it with `dscl`: a hidden user and a group of the same name, the
highest id below 500 (the system range) that no user or group has, shell `/usr/bin/false`,
home `/var/empty`, no password. `sysadminctl` is not used because it makes interactive
users. A group left by an earlier install is adopted, and a record a failed run left
half-made is completed rather than refused. Without the account every `service` module fails
to start with `service account "_weaveagent" missing`.

## Installing a module while it runs

Module packages install into `/usr/local/libexec/weave/modules/<id>/`, and core picks the
change up without restarting anything else ([module reload](architecture.md#module-reload)):

- **kqueue** watches the modules directory, each module directory and the files in them.
  The macOS installer stages a payload in a sandbox outside the destination and moves
  finished files in; hidden names (`.*`) are ignored, so a file is seen when it lands under
  its real name. Deeper levels are not watched.
- **SIGHUP**: `sudo launchctl kill HUP system/run.weaveplatform.agent` signals weaveboot,
  which forwards it to core.
- **`weavectl reload`** runs a pass at once and prints what changed.
- **The rescan**, every minute, catches anything else.

A module package's `postinstall` should end with the `launchctl kill HUP` line (`|| true`),
the counterpart of the Linux module packages' `systemctl reload`.

## The channel trust anchor

The host proves possession of a per-VM key before it may drive the guest
([authentication](architecture.md#authentication)); the guest trusts the public half at
`/etc/weave/channel.pub`. The package does not ship it — it is per VM — and macOS has no
cloud-init, so it comes from a **provisioning volume**: the host attaches a read-only
filesystem labelled `WEAVEPROV` with `weave/channel.pub` on it, and core installs that key at
start if, and only if, no anchor is installed yet. It never replaces one.

On macOS core accepts the volume only at `/Volumes/WEAVEPROV`, only as the root of a
read-only mount, and only if the system mounted it (statfs owner uid 0). A user-attached disk
image is refused, so the host must attach the volume read-only, and it has to be mounted by
the system at boot. Core looks for it at start and then every 2 seconds for 3 minutes, since
macOS mounts attached disks some seconds into boot. On the host, a volume can be made with:

```sh
mkdir -p prov/weave && cp channel.pub prov/weave/
hdiutil create -fs HFS+ -volname WEAVEPROV -srcfolder prov -format UDRO prov.dmg
```

Core logs `hypervisor channel trust anchor installed from the provisioning volume` with the
key's fingerprint, `sha256:<hex>`, which `base64 -d channel.pub | shasum -a 256` reproduces
on the host.

## Uninstalling

```sh
sudo /usr/local/libexec/weave/uninstall.sh            # remove the agent, keep its state
sudo /usr/local/libexec/weave/uninstall.sh --purge    # also its state and logs
```

It boots the daemon out (which drains the modules), removes the plist, the binaries and the
`weavectl` link, removes the modules directory only if no module package left anything in
it, and forgets the package receipt. `--purge` also removes
`/Library/Application Support/Weave`, `/Library/Logs/Weave` and `/var/run/weave`: the state
holds the device identity, and a reinstall that found it would silently resume being a
device its operator believed removed.

What stays, and why:

- **The `_weaveagent` account and group.** Files elsewhere may carry its uid, and a freed uid
  could be handed to a later account that would then own them; this is what Debian does with
  system accounts, and what the Linux package does. A reinstall adopts it. Remove it with
  `sudo dscl . -delete /Users/_weaveagent` and `sudo dscl . -delete /Groups/_weaveagent`.
- **`/etc/weave/channel.pub`.** It is provisioning, not part of the package, and removing it
  changes who may drive the guest. `weave seal` removes it before a template is cloned.

## Checking a build without installing it

```sh
make pkg-darwin              # dist/weave-agent_<version>_darwin_arm64.pkg
make package-test-darwin     # plist, postinstall dry run, uninstall, payload and modes
pkgutil --payload-files dist/weave-agent_*_darwin_arm64.pkg
pkgutil --expand dist/weave-agent_*_darwin_arm64.pkg /tmp/x && lsbom -p MUGf /tmp/x/Bom
WEAVE_PKG_DRYRUN=1 sh packaging/darwin/scripts/postinstall pkg / /   # prints, changes nothing
```

The quality gate runs `make package-test-darwin` on a macOS runner. A package built on a Mac
whose shell tags new files with `com.apple.provenance` lists `._*` entries in its payload:
those are the build machine's extended attributes, which installer restores as attributes,
not files. CI builds carry none.

## What is not verified yet

The package has been built and inspected, and its scripts run dry, but it has not yet been
installed in a real macOS guest; that is the guestweave CLI's end-to-end run. Until then:

- **The provisioning volume's mount owner.** Core assumes DiskArbitration mounts a disk the
  host attached at boot as root. If it mounts it as the console user (an auto-login guest),
  core refuses it as user-mounted, logs `provisioning volume refused … mounted by a user`, and
  the channel stays closed.
- **What `installer` leaves in a module directory while it works.** The watch ignores hidden
  names and the rescan catches anything the watch misreads; neither has been seen against a
  real module package install.

| Symptom | What it means |
|---|---|
| `weave-agent: this package is for arm64 Macs` | An Intel Mac. There is no x86_64 package. |
| `could not load run.weaveplatform.agent` from postinstall | launchd refused the job; `launchctl print system/run.weaveplatform.agent` says why. The files are installed and launchd loads them at the next boot. |
| `service account "_weaveagent" missing` | postinstall did not run on this system (an install onto another volume) or failed; run the package again. |
| `hypervisor channel will authenticate nobody` | No anchor yet: no provisioning volume was attached, or it was refused (the log line before says why). |
| `provisioning volume refused … mounted read-write` | The host attached the volume writable. |
