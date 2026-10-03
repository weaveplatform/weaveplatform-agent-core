# weaveplatform-agent-core — engineering conventions

The weave agent core: `weave-agent`, `weaveboot`, `weavectl` and `weavemanifest`, the
protocol (`proto/`, `schema/`) and core's private implementation of it (`internal/`). Read
[`spec.md`](spec.md) before changing anything; [`docs/`](docs/README.md) explains the rest.

## Working conventions

- **Correctness loop first.** The quality gate and tests against real processes come before
  features, so every change lands inside a working test loop. Integration tests build real
  module binaries and drive the real handshake.
- **Coverage gate.** ≥95% total and ≥90% per package, merged across the unit tests on Linux,
  macOS and Windows, enforced by `.testcoverage.yml`. It blocks merges.
- **Layout.** One Go module. Project packages in `internal/`, entry points in `cmd/`. There
  is no public Go API: the protocol is the public surface, and it is `proto/` and `schema/`.
- **CLI.** The binaries use the standard `flag` package: they run under service managers and
  installers, and their flags are part of the install contract (`packaging/`), so they stay
  small and stable.
- **CI.** OS matrices use the `-latest` runner labels. Actions are pinned by commit SHA with
  the version in a comment; Dependabot keeps them current. `actionlint` (with shellcheck)
  is clean.
- **Linting.** golangci-lint with `.golangci.yml` is the only linter, it blocks at zero
  issues, and it runs as linux, darwin and windows (`make lint`), because build tags decide
  which files exist. Fix the code: sentinel errors wrapped with `%w`, wrapped external
  errors, real bounds checks. A `//nolint:<linter> // reason` is for the case where the fix
  would be wrong — a wire-format JSON tag, a gRPC status that must reach the client
  unwrapped, a child process whose lifetime the supervisor owns.
- **Builds** run with `GOWORK=off` so a local `go.work` never hides a missing dependency
  that CI would catch.
- **Commits and PR titles** follow Conventional Commits; release-please derives versions and
  the changelog from them. No `!` and no `BREAKING CHANGE` footers: protocol compatibility is
  the protocol integer's job ([`docs/PROTOCOL.md`](docs/PROTOCOL.md)), not semver's.

## OS APIs: always use the house Go bindings when technically viable

When core needs an operating-system API (verify, keyprotect, supervise,
capability, transport, layout, …), use the house bindings — not
`golang.org/x/sys/*`, cgo, or shelling out — whenever it is technically viable:

- **macOS** → `github.com/deploymenttheory/go-bindings-macosplatform`
- **Windows** → `github.com/deploymenttheory/go-bindings-win32` and
  `github.com/deploymenttheory/go-bindings-wmi`

Prefer the binding even when an `x/sys` or stdlib path looks shorter. If a
binding is missing a call you need, the default is to add it to the binding SDK
rather than bypass it; if that is genuinely out of scope, note the gap and use
the narrowest fallback.

"Technically viable" means the binding exposes the call **and** builds where it
is used. Both SDKs are pure Go and build under `CGO_ENABLED=0`, so both are
always viable: Windows (`go-bindings-win32`/`-wmi`) is generated Go over
`syscall`, and macOS (`go-bindings-macosplatform`, **v0.19.0+**) runs its whole
`bindings/` surface — Objective-C frameworks and Apple C libraries alike — on
`github.com/ebitengine/purego`, `dlopen`ing the dylib at runtime.

> purego does change one thing: an uncaught `NSException` is not converted to a
> Go panic — it terminates the process. Validate before calling.

Coverage, not cgo, is the remaining macOS limit: `bindings/libraries/bsd` is
essentially empty, so bare POSIX calls (`sysctl`, `settimeofday`, `fcntl`) have
no house wrapper and take the fallback below.

### Only sanctioned fallbacks (no house binding exists)

- **Linux** has no house bindings SDK — use `golang.org/x/sys/unix` there.
- OS-neutral plumbing shared with Linux in a `//go:build unix` file (e.g.
  raw-tty via `golang.org/x/term` in `internal/transport`) may stay on `x/*`
  because it must also compile for Linux.
- A bare POSIX syscall with no framework/service equivalent (e.g. `O_NOCTTY`)
  is not an "OS API" the bindings cover; plain `syscall`/`x/sys` is fine.

## Comments: what and why, sparse and deep

Comment the **reasoning a reader cannot recover from the code**. Delete anything
that restates it.

```go
// BAD — the signature already says this
// SetTime sets the time. t is the time to set.

// GOOD — says what the code cannot
// A step, not a slew: a guest resuming from a snapshot can be days out, and
// adjtime would take longer to converge than the guest is likely to run.
```

**Sparse, not uniform.** Most code carries no comment at all. Effort concentrates
at the few places where a decision was made and the alternative was plausible —
an ordering that must not be reversed, a fallback that must not fail open, a
number that must match something elsewhere. A file where every function has a
paragraph is not thorough, it is undifferentiated: the reader has no way to tell
the load-bearing note from the throat-clearing.

**Length is not the metric.** A comment earns its lines by carrying content, and
some genuinely need twenty. Never pad one to look thorough, and never cut one
that is doing real work to hit a length. If it took an afternoon to learn, write
it down in full.

What is worth the space:

- **Why this and not the obvious alternative.** "PDH means opening a query,
  adding counters by localised path string, and collecting twice before the
  first number appears — three FILETIME counters do it here."
- **What a failure would look like**, especially the silent ones. "A truncated
  count silently gives an available-memory reading of zero, which reads as a
  quiet guest rather than a broken call."
- **Orderings and invariants** whose violation is not a compile error. "The
  acknowledgement must be on the wire before the command that kills the OS."
- **What was deliberately NOT done**, when a reader would otherwise add it.
  "Sizes the ABI passes by reference stay skipped rather than being passed
  truncated for the callee to read as garbage."
- **Facts learned the hard way** — an API that reports success while doing
  nothing, a field the kernel validates strictly, a service that silently
  reverses your change.

What is not:

- Restating a name, signature, or the line below it.
- Narrating structure: `// loop over the items`, `// error handling`.
- Marking sections: `// --- helpers ---`.
- Changelog or attribution. That is what git is for.
- Apologising for code. Fix it, or write down why it stays.

**Exported identifiers** get the standard Go doc comment, starting with the
name, and usually one sentence. Add paragraphs below it only when the caller
needs the reasoning to use the thing correctly.

**Prefer one home for a rationale.** When the same "why" applies in several
places, write it once where the decision lives and point at it from the others,
rather than restating it in each.

## Documentation

Docs describe what the code does **now**. A feature that changes behaviour,
adds a wire operation, or moves a boundary is not finished until the docs that
describe that area say so — in the same change, not a follow-up.

- **README** is the entry point: what this repo is, what it is for, how to build
  and test it. Not a feature list.
- **`docs/`** covers the things a reader cannot get from the code: architecture,
  protocols and their compatibility rules, trust chains, release pipelines.
- **Handoff documents** (work another person or machine must finish) state what
  to run, what a pass looks like, and **what each failure would mean** — the
  last one matters most where a call can fail by returning a plausible zero.
- Say plainly what is unverified. "Compiles but has never run on Windows" is
  more useful than silence, and far more useful than implied confidence.

## Repository layout: core owns its protocol; the SDK and modules live elsewhere

This repository is core (`github.com/weaveplatform/weaveplatform-agent-core`, tags `vX.Y.Z`),
the only Go module here. It owns the protocol — `proto/` and `schema/` are its sources — and
keeps a private implementation of it, the way Terraform core keeps `internal/tfplugin5` and
never imports the provider SDK
([`docs/decisions/0001-core-owns-its-protocol.md`](docs/decisions/0001-core-owns-its-protocol.md)):

- `internal/protocol/` — `handshake`, `ipc`, `hvchannel`, `manifest`
- `internal/` — `retry`, `wlog`, `werror`, `platform` and the rest of core
- `internal/gen/go` — generated from `proto/` by `buf generate` (`make gen`)

The module SDK (`github.com/weaveplatform/weaveplatform-agent-modules/sdk`) and every module
(`weave-<os>-<capability>`, for example `weave-linux-presence`) live in
`weaveplatform-agent-modules`, and each module releases from there;
`weaveplatform-release-channels` is the signed registry of which module versions a device may run.
Core ships no modules and no module release pipeline, the way Terraform core ships only
`internal/builtin/providers/terraform`. Module work goes to `weaveplatform-agent-modules`.

**Core never depends on a module or the module SDK, tests included.** No `require`, no
`replace`; the quality gate's `core-independent` job fails if `go list -deps -test ./...` (as
each OS) or `go list -m all` reaches anything under `weaveplatform-agent-modules`. Core's
fixture modules speak the protocol directly (handshake line, `ModuleService`), never through
`modulesdk`.

Regenerate with `make gen` and commit `internal/gen`; CI fails if it drifts. The handshake
line and `hvchannel` framing are hand-written on both sides of the wire: a change to either is
a protocol change and must land here and in the SDK in `weaveplatform-agent-modules`
([`docs/protocol-versioning.md`](docs/protocol-versioning.md)).

`test/protocompat/v1` pins the protocol-1 module SDK's own module paths
(`weaveplatform-sdk v0.2.1`, `weaveplatform-api v0.2.0`). It is the protocol-1 fixture and
must not be rewritten, tidied, or bumped by Dependabot.

Bring-up packaging (`packaging/apt`, `packaging/cloudinit`) packages core only; modules reach
a guest from the channel.
