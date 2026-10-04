# The Linux package

How core gets onto a Linux machine, and why it arrives this way.

## Why a package at all

macOS has `codesign` and Windows has Authenticode: a signature the OS itself
checks at exec time. Linux has no such construct, so it uses the mechanism it
does have — **a signed package from a GPG-signed repository**, with dpkg
verifying provenance at install. That is what every Linux agent in the field
relies on, and it is why the Linux verifier
(`internal/verify/release_linux.go`) does not re-check a signature it has no key
for. Its job is to confirm that what dpkg vouched for has not since become
writable by anyone who is not root.

That is also why the module binary and the directory holding it must be
root-owned and not group- or world-writable. A root-owned `0755` binary can still
be swapped wholesale by anyone able to write the directory around it, so checking
only the file would be a check in name. The packages below set both.

## The package

| Package | Built by | Contents |
|---|---|---|
| `weave-agent` | `.goreleaser.yaml` (`nfpms:`) in this repo | `/usr/lib/weave/{weave-agent,weaveboot,weavectl,weavemanifest}`, `/usr/bin/weavectl` → symlink, `/lib/systemd/system/weave-agent.service`, `/usr/lib/weave/modules/` |

Core ships no modules. A guest gets its modules from the channel: core verifies
the signed channel manifest, fetches each module's artifact by digest and installs
it under `/usr/lib/weave/modules/<id>/`. That is the product path, and bring-up
uses it too. For local bring-up without a channel, weaveplatform-agent-modules
builds a `.deb` per Linux module (`weave-linux-presence`, `weave-linux-exec`, …)
that installs `/usr/lib/weave/modules/<id>/{<id>,module.manifest.json}` with
`Depends: weave-agent`.

Details that are load-bearing rather than stylistic:

- **All three binaries in one directory.** `weaveboot.currentBinary` resolves core
  as "the binary beside me" when no staged version layout exists — the fresh
  install case — so they must be siblings.
- **The unit runs `weaveboot`, not core.** systemd supervises weaveboot, weaveboot
  supervises core, core supervises modules. A unit pointing at core directly takes
  away the in-place core replace (stage, health-gate, roll back).
- **`KillMode=mixed`.** Core runs its own module shutdown; the default
  (`control-group`) signals the modules directly at the same moment, so core finds
  their sockets gone and reports a failed shutdown for what is really a race.
- **The module binary is named for the module id.** `core.discoverModules` looks
  for `<dir>/<id>`; a differently-named binary is simply never found — no error,
  no log line.
- **`EnvironmentFile=-/etc/default/weave-agent`.** Per-image settings go there
  rather than into the unit, so a package upgrade never overwrites them. Every
  `weave-agent` flag that has a `WEAVE_*` variable can be set this way; weaveboot
  passes its whole environment to core. The package ships no such file.
- **The `weave-agent` service account.** `postinstall` creates a system user and
  group named `weave-agent` — no login shell, home `/nonexistent`, nothing created
  on disk — which `service`-privilege modules (`weave-linux-presence`, for one) run
  as when core is root. Core uses only its uid and gid. Creation is idempotent and
  adopts a group that already exists, and it happens before the systemd check, so
  an image built in a container or chroot has the account too; `make package-test`
  checks both in Docker. The package depends on `passwd` for `useradd`. Removal,
  purge included, leaves the account in place, as Debian does with system
  accounts: files elsewhere may still carry its uid, and a freed uid could be
  reused by an account that would then own them. `userdel weave-agent` removes it.
- **Where a dropped module's binary runs from.** A module running as `weave-agent`
  cannot reach `/usr/lib/weave/modules/<id>/` through core's 0700 state, and `/run`
  is mounted `noexec`, so core stages a root-owned read-only copy under
  `/var/lib/weave/exec/<id>/` and execs that. `/var/lib/weave`, its `run/` and its
  `exec/` are `0711` (search-only for others); everything holding data is `0700` or
  a `0600` file. [Architecture](architecture.md#filesystem-layout) has the full
  model.
- **No sandboxing directives in the unit.** A module such as `weave-linux-exec`
  exists to execute what the host asks inside this guest; `ProtectSystem` and friends would
  break the feature rather than harden it. The isolation boundary is the VM.

## The repository

`packaging/apt/aptrepo` builds a flat apt repository from a directory of `.deb`s
and signs it. `packaging/apt/build-repo.sh` builds the `weave-agent` package
with goreleaser (a snapshot of the working tree) and the repository that serves
it, in one command.

What apt actually verifies, and therefore what the signature has to cover: it
fetches `InRelease`, checks it against the key named in the source's `signed-by=`,
checks `Packages` against the digests inside that signed file, then checks each
`.deb` against the digest inside `Packages`. **The signature over `Release` is what
makes every byte downstream of it trusted.** A repository of individually signed
`.deb`s with an unsigned `Release` would give apt nothing it checks by default —
which is why the repository signature is the gate here, not a `_gpgorigin` member
inside the package. (nfpm can add one when `WEAVE_DEB_SIGN_KEY` is set; it is
belt-and-braces.)

```sh
# Build the weave-agent package and a signed repository.
GNUPGHOME=~/.weave/bringup/gnupg ./packaging/apt/build-repo.sh <gpg-key-id>

# Re-check what was built, the way apt will.
go run ./packaging/apt/aptrepo -verify ~/.weave/bringup/repo
```

`aptrepo` reads the `.deb` control data itself (an `ar` archive containing
`control.tar.gz`) rather than shelling out to `dpkg-deb`, because the machines
that build and test this package are macOS hosts with no dpkg. It supports gzip
control archives — what these configs produce — and refuses others by name rather
than guessing.

## Installing into a guest

`packaging/cloudinit/` builds a NoCloud seed ISO that installs `weave-agent` at
first boot, with nobody touching the guest. Modules then arrive from the channel:

```sh
./packaging/cloudinit/make-seed.sh agent-test http://192.168.64.1:8000/ \
    ~/.weave/bringup/repo/weave-archive-keyring.asc \
    ~/.weave/bringup/seed.iso

weave run agent-test --mount ~/.weave/bringup/seed.iso --no-graphics
```

Two keys, two jobs: the **archive key** is what apt checks to trust the packages;
the **channel key** is what the guest checks to decide whether the host may command
it afterwards (see `architecture.md`). Neither substitutes for the other.

You name the VM, not its channel key. Weave mints that key when the VM is created
or cloned, so the seed builder reads it from the VM's own directory — passing it by
hand would mean hand-carrying a credential the tooling already knows how to find,
where a wrong path yields a guest that installs cleanly and then refuses every
command. A VM with no key is an error, not a seed built without one.

### Hyper-V (HCS) guests

A guest on a Windows host's Hyper-V has no virtio-serial port; the channel is
AF_VSOCK, with the guest listening. That is never inferred (see
`architecture.md`), so the image or seed must say so:

```sh
echo 'WEAVE_CHANNEL=vsock:2010' > /etc/default/weave-agent
```

A healthy start then logs `"hypervisor channel listening","kind":"vsock","port":"2010"`
instead of `connected`, and the host's connection appears later. A guest without
`/dev/vsock` (no `hv_sock`/`vmw_vsock_virtio_transport` loaded) claims no channel,
and the modules that need it are not launched — the same symptom as a missing
virtio-serial port. A mistyped value logs `hypervisor channel disabled` and core
runs without a channel.

### Things that will waste an afternoon

- **A repeated `instance-id`** makes cloud-init treat the boot as resumed and skip
  every module. The guest boots clean with nothing installed and nothing in the
  log to say why. `make-seed.sh` stamps a fresh one every build — so rebuild the
  seed for every boot that should reinstall.
- **A snapshot version never changes.** `0.9.1~snapshot` is `0.9.1~snapshot` however many
  times its binaries change, so a guest that has it already correctly decides
  there is nothing to do, and runs the previous binaries while every log line says
  the install succeeded. The seed uses `apt-get install --reinstall` for exactly
  this; released versions would not need it.
- **`/dev/console` in a Debian arm64 cloud guest under Virtualization.framework
  goes nowhere the host can read.** The image's kernel cmdline names a serial
  console this hypervisor does not provide, so `weave run --serial-path` produces
  an empty file — not even boot messages. Evidence has to go to a runcmd's stdout,
  which cloud-init records in `/var/log/cloud-init-output.log`.

### Reading evidence out of a stopped guest

When the guest is down and the question is what happened inside it, mount its disk
read-only. The root partition starts at sector 262144 on the Debian arm64 cloud
image:

```sh
docker run --rm --privileged -v ~/.weave/vms/agent-test:/vm debian:12 sh -c '
  mkdir -p /mnt/g && mount -o ro,loop,offset=134217728 /vm/disk.img /mnt/g
  journalctl -D /mnt/g/var/log/journal -u weave-agent --no-pager | tail -40'
```

## What a healthy first boot looks like

```
Started weave-agent.service - Weave platform agent.
{"msg":"core starting","modules_dir":"/usr/lib/weave/modules","capabilities":2}
{"msg":"hypervisor channel connected","device":"/dev/virtio-ports/org.weave.agent.0"}
{"msg":"module running","module":"weave-linux-presence","pid":661,"protocol":1}
{"msg":"module running","module":"weave-linux-exec","pid":668,"protocol":1}
```

(Abbreviated: core also logs `time`, `level` and `component` on every line. The
module lines appear once the channel has delivered the modules.)

And on the host, from the guestweave CLI's run process (the version is whatever
the presence module reports in its hello):

```
guest channel: guestweave <version> answered (linux/arm64)
guest channel: authenticated
```

Failure meanings worth knowing before you meet them:

| Symptom | What it means |
|---|---|
| `module not launched: requirements unmet` | The channel device is missing, so the module was gated. The host published no **named** port — see the capability probe. On a vsock guest: `WEAVE_CHANNEL` is set but `/dev/vsock` is absent. |
| `hypervisor channel disabled` | `WEAVE_CHANNEL` / `-channel` holds a value core cannot honour (unknown kind, no port, or `hvsocket:` on Linux). Core runs without a channel rather than guess. |
| A refusal from `release_linux.go` | dpkg installed the module with the wrong ownership or mode; check the directory as well as the file. |
| `guest channel: the guest refused this host's key` | The guest's `/etc/weave/channel.pub` is a different key, or absent. The guest is healthy; provisioning is not. |
| No cloud-init output at all | The `instance-id` was not fresh. |
