# 0001 — Core owns its protocol; the module SDK and modules live in agent-modules

- **Status:** accepted
- **Date:** 2026-10-03

## Context

The platform has two sides that meet on a wire protocol. Core is the host: it verifies,
spawns, supervises and serves modules. Modules are separate processes, one per capability,
written against a module-side library (`modulesdk`, `testkit` and the client half of the
protocol). The question is where the protocol, its implementations, that library and the
modules themselves live, and which of them core is allowed to depend on.

Terraform answers the same question. Terraform core owns the plugin protocol: the `.proto`
lives in core at `docs/plugin-protocol/tfplugin5.proto`, core generates its own Go into
`internal/tfplugin5` and implements the client side in `internal/plugin`, and it never
imports the provider SDK. `hashicorp/terraform`'s `go.mod` lists `terraform-plugin-go` only
as `// indirect`, not as something core builds the protocol from. The provider side is a
separate family of libraries: `terraform-plugin-go` carries its own copy of the proto and
generated code at `tfprotov5/internal/tfplugin5`, and `terraform-plugin-framework` and
`terraform-plugin-testing` are built on it in their own repositories. Core does not ship
providers either: `internal/builtin/providers/terraform` (the `terraform_remote_state` data
source) is the only provider in the core repository, and every other provider releases
independently. Core ships the protocol and the machinery to run plugins; it does not ship
the plugins or the library used to write them. The two sides agree on the wire, not on a Go
package.

## Decision

Core owns the protocol and keeps a private implementation of it. The module SDK and every
module live in `weaveplatform-agent-modules`. Core depends on neither.

- `proto/` and `schema/` live in this repository and are core's: the protocol is defined
  where it is served.
- Core's implementation is private, under `internal/`: `internal/protocol/{handshake,ipc,hvchannel,manifest}`,
  `internal/{retry,wlog,werror,platform}`, and `internal/gen/go/weave/{agent,control}/v1`,
  generated from `proto/` by `buf.gen.yaml`. CI fails if the generated code drifts.
- This repository is a single Go module. It ships no module SDK and no modules, and it has
  no module release pipeline: the release-please manifest has one component (`.`), tagged
  `vX.Y.Z`, and its release builds core alone. Each module releases and publishes itself from
  `weaveplatform-agent-modules`, as each Terraform provider releases from its own repository.
- The quality gate's `core-independent` job fails if the root module depends on anything under
  `weaveplatform-agent-modules`, by import (`go list -deps -test ./...`, so a test-only
  import is caught too) or by requirement (`go list -m all`).
- Core's test fixture modules speak the protocol directly — handshake line, `ModuleService`,
  token on host calls — and the protocol-compatibility test drives a pinned protocol-1
  module with core's real supervisor. Core is tested against the wire, not the library.

The three repositories:

- **weaveplatform-agent-core** owns the protocol (`proto/`, `schema/`, `docs/PROTOCOL.md`)
  and its private implementation (`internal/protocol`, `internal/gen`), and runs modules.
- **weaveplatform-agent-modules** owns the module SDK
  (`github.com/weaveplatform/weaveplatform-agent-modules/sdk`, the counterpart of
  `terraform-plugin-go` and `terraform-plugin-framework`) and every module, one per
  capability per OS, named `weave-<os>-<capability>` (for example `weave-linux-presence`),
  each with its own release.
- **weaveplatform-channels** is the signed registry, the counterpart of the Terraform
  Registry: channel manifests that say which module versions a device may run, verified by
  core before anything is executed.

## Consequences

- Core and modules agree on the wire only. Compatibility is held by `buf breaking` on
  `proto/`, the rules in [`../PROTOCOL.md`](../PROTOCOL.md), and `test/protocompat`, which
  runs a module built against the protocol-1 SDK against today's core.
- A protocol change lands here first; the SDK in `weaveplatform-agent-modules` follows with
  its own generated code ([`../protocol-versioning.md`](../protocol-versioning.md)).
- Two hand-written pieces of the wire exist on both sides — the handshake line and the
  hypervisor channel framing (`hvchannel`), which has no negotiation to catch a mismatch. A
  change to either is a protocol change and must land on both sides; generated code cannot
  drift, but these can.
- Fixing a parser bug on one side does not fix the other. Core fuzzes its own parsers; the
  SDK's fuzz targets run in `weaveplatform-agent-modules`.
- Core can change its internals — logging, error helpers, IPC plumbing — without an SDK
  release. An SDK or module release never needs a core change or a core CI run, and a core
  release never carries module code.

## References

- Terraform core, protocol definition: `hashicorp/terraform` `docs/plugin-protocol/tfplugin5.proto`
- Terraform core, private generated code and client: `hashicorp/terraform` `internal/tfplugin5`, `internal/plugin`
- Terraform core's `go.mod`: `github.com/hashicorp/terraform-plugin-go` appears only as `// indirect`
- Provider side, own proto copy: `hashicorp/terraform-plugin-go` `tfprotov5/internal/tfplugin5`
- Provider libraries in their own repositories: `hashicorp/terraform-plugin-framework`, `hashicorp/terraform-plugin-testing`
- Terraform's one in-core provider: `hashicorp/terraform` `internal/builtin/providers/terraform`
- Terraform's checklist for a new protocol version: `hashicorp/terraform` `docs/plugin-protocol/releasing-new-version.md`
- The module SDK: `github.com/weaveplatform/weaveplatform-agent-modules/sdk`, guide at [`sdk/docs/writing-a-module.md`](https://github.com/weaveplatform/weaveplatform-agent-modules/blob/main/sdk/docs/writing-a-module.md) in `weaveplatform-agent-modules`
