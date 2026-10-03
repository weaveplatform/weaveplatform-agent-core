# Documentation

- [`../spec.md`](../spec.md) — the governing architecture specification: core/module split,
  process model, protocol, handshake, lifecycle, install footprint.
- [`architecture.md`](architecture.md) — how the pieces are built and relate: repository
  graph, process model, handshake sequence, supervision state machine, install flow, the
  hypervisor channel (with diagrams).
- [`decisions/`](decisions/) — architecture decision records:
  [0001](decisions/0001-core-owns-its-protocol.md), core owns its protocol and keeps a
  private implementation, the Terraform model; the module SDK and every module live in
  `weaveplatform-agent-modules`.
- [`PROTOCOL.md`](PROTOCOL.md) — what the protocol integer is and what bumps it; the
  handshake; the N-2 window.
- [`protocol-versioning.md`](protocol-versioning.md) — how a new protocol version is added
  and released across core, the SDK and the registry.
- [`services.md`](services.md) — the gRPC service map: who serves what, on which socket.
- [`development.md`](development.md) — local setup, running the agent, testing, the quality
  gate and releasing.
- [`linux-package.md`](linux-package.md) — the deb, the apt repository and the cloud-init seed.
- [`windows-install.md`](windows-install.md) — the `WeaveAgent` service and the unattended
  installer.
- [`WINDOWS_HANDOFF.md`](WINDOWS_HANDOFF.md) — platform security work that needs a Windows,
  macOS or Linux host to validate, and what each failure would mean.
- [`sdk/docs/writing-a-module.md`](https://github.com/weaveplatform/weaveplatform-agent-modules/blob/main/sdk/docs/writing-a-module.md)
  in `weaveplatform-agent-modules` — the module author's guide, for the module SDK
  `github.com/weaveplatform/weaveplatform-agent-modules/sdk`.
