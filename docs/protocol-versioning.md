# Releasing a new protocol version

The protocol is the contract between core and every module, so a new protocol version
needs the same coordination across repositories every time. This is the checklist for
adding protocol N+1 (a new `weave/agent/vN+1` package). [`PROTOCOL.md`](PROTOCOL.md) says
what the protocol integer is and which changes need a new one; this document says how one is
added and released.

It follows the shape of Terraform's own checklist,
[`docs/plugin-protocol/releasing-new-version.md`](https://github.com/hashicorp/terraform/blob/main/docs/plugin-protocol/releasing-new-version.md)
in `hashicorp/terraform`, for the same reason: core owns the protocol, the module SDK
implements the other side in another repository, and the registry decides what a device may
run ([`decisions/0001`](decisions/0001-core-owns-its-protocol.md)).

Additive changes do not need any of this. A new optional field, a new RPC or a new service
lands in the current package under the current integer, gated by `buf breaking`.

## 1. New proto package in core

The protocol is defined by the `.proto` files under `proto/` in this repository. Copy
`proto/weave/agent/vN/` to `proto/weave/agent/vN+1/`, change the package to
`weave.agent.vN+1`, and make the breaking change there. `vN` stays as it is: core serves both
for as long as the window includes N.

Run `make gen`. `buf.gen.yaml` writes `internal/gen/go/weave/agent/vN+1` beside `vN`; commit
both. `make buf-lint` must pass. `buf breaking` passes because `vN` is unchanged and `vN+1` is
new; a breaking edit to `vN` itself is the mistake this gate exists to catch.

If the change is to the handshake (environment, stdout line) or the hypervisor channel
framing, it is hand-written rather than generated: change `internal/protocol/handshake` or
`internal/protocol/hvchannel`, keep the old shape readable for as long as the window includes
N, and record the new shape in [`PROTOCOL.md`](PROTOCOL.md).

## 2. Core serves the new version

- Serve the `vN+1` services beside `vN` in `internal/hostserv` and call the module's
  `ModuleService` at the version it declared in its handshake (`internal/supervise`).
- Move `core.Window` (`internal/core/core.go`) to `{Min: N-1, Max: N+1}`, the N-2 window.
  Core advertises it at spawn as `WEAVE_PROTOCOL_MIN` / `WEAVE_PROTOCOL_MAX`.
- A protocol that leaves the window is deleted from `proto/` and `internal/gen` in the same
  change, with its server code.

## 3. A pinned fixture for the new version

Add `test/protocompat/vN+1/`: a module built from the SDK release that speaks protocol N+1,
with its own go.mod pinned to that release. `TestEveryWindowMemberHasFixture` fails until
every protocol in `core.Window` has a fixture, and the existing fixtures prove core still
accepts N and N-1 and refuses what has left the window. Fixtures for protocols still in the
window are never edited.

## 4. The module SDK

The module side lives in `weaveplatform-agent-modules`. Its `sdk/` generates its own copy of
the protocol from this repository's `proto/` at the core release named in its
`.github/agent-core-version`, and implements the module half of the handshake and channel.
Open a PR there that adds `sdk/gen/go/weave/agent/vN+1` and serves it from `modulesdk`, once
the core release from step 6 exists for it to pin. Modules move to the new protocol by
upgrading the SDK and declaring `"protocol": N+1` in `module.manifest.json`; until they do,
they keep running in the window.

## 5. The schemas and the registry

- `schema/module-manifest.schema.json` and `schema/channel-manifest.schema.json` carry the
  protocol as an integer. A new value needs no schema change; a change to the manifest shape
  is its own decision and its own schema version.
- `weaveplatform-channels` records, per channel, the protocol window the core release
  assumes and the protocol each module speaks. Promote the new core release there first, and
  modules on N+1 only into channels whose core advertises N+1. A module outside a core's
  window is refused at handshake (exit 78) and never restarted, so a mis-promotion shows up as
  a module that does not run, not as a crash loop.

## 6. Release core

Merge the core change. Its release (release-please, `vX.Y.0`; a protocol is always a
`feat:`) is the first core that accepts N+1. Record the protocol in the registry table in
[`PROTOCOL.md`](PROTOCOL.md) with the release that introduced it.

## 7. Test a module end to end

- In `weaveplatform-agent-modules`, bump `.github/agent-core-version` to the release from
  step 6 and run `make sdk-gen`; the SDK's `compat` job then runs a module built on the new
  SDK under that released `weave-agent` on Linux, macOS and Windows.
- Publish one module built against N+1 to a staging channel, install core from its release
  on a guest (`packaging/cloudinit`, [`linux-package.md`](linux-package.md)), and check that
  core fetches, verifies, runs and health-checks it, and that a module at N-1 still runs
  beside it.

Only after that does a production channel carry a module at N+1.
