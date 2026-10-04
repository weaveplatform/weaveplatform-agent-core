# Development

## Local setup

This repository is one Go module, `github.com/weaveplatform/weaveplatform-agent-core`, plus
the protocol-1 fixture under `test/protocompat/v1`, which has a go.mod of its own. Core keeps
its own implementation of the protocol under `internal/protocol` and `internal/gen`
([`decisions/0001`](decisions/0001-core-owns-its-protocol.md)) and depends on neither the
module SDK nor any module: both live in
[`weaveplatform-agent-modules`](https://github.com/weaveplatform/weaveplatform-agent-modules).
Every Go module core uses is public, so no `GOPRIVATE` and no token is needed to fetch them.

Tools:

- Go at the version in `go.mod`.
- [golangci-lint](https://golangci-lint.run) at the version in `.github/golangci-lint-version`.
- [buf](https://buf.build) and the protoc plugins `buf.gen.yaml` runs, at the versions
  stamped in the committed headers (`make protoc-plugins`).
- [goreleaser](https://goreleaser.com) v2, only for packaging (`make snapshot`).

`govulncheck` and `go-test-coverage` are `go.mod` tools: `go tool <name>` runs the pinned
version, and `make` does that for you.

The Makefile exports `GOWORK=off`. A `go.work` above this checkout never changes what is
built: CI and goreleaser build from the recorded `go.mod` pins, and so does every local
target.

A change to `proto/` regenerates core's copy, which is committed:

```sh
make gen            # buf generate: internal/gen
```

The module SDK in `weaveplatform-agent-modules` follows a protocol change with its own
generated code ([`protocol-versioning.md`](protocol-versioning.md)). Module authors start from
[`sdk/docs/writing-a-module.md`](https://github.com/weaveplatform/weaveplatform-agent-modules/blob/main/sdk/docs/writing-a-module.md)
there and build against `github.com/weaveplatform/weaveplatform-agent-modules/sdk`.

## Running the agent locally

Release builds fail closed on module signatures. Dev builds (`-tags dev`) accept unsigned
binaries and log the bypass loudly; the escape hatch does not exist in release binaries.

```sh
# Build
CGO_ENABLED=0 go build -tags dev -o /tmp/wv/weave-agent ./cmd/weave-agent
CGO_ENABLED=0 go build -o /tmp/wv/weavectl ./cmd/weavectl

# Lay out a module, built from weaveplatform-agent-modules (on Linux)
mkdir -p /tmp/wv/state/modules/weave-linux-presence
(cd ../weaveplatform-agent-modules/modules/weave-linux-presence &&
  CGO_ENABLED=0 go build -o /tmp/wv/state/modules/weave-linux-presence/weave-linux-presence . &&
  cp module.manifest.json /tmp/wv/state/modules/weave-linux-presence/)

# Optional: give it a policy (re-read within --policy-interval of a change)
echo '{"revision":1,"modules":{"weave-linux-presence":{"interval_seconds":60}}}' > /tmp/wv/state/policy.json

# Run
/tmp/wv/weave-agent --state-dir /tmp/wv/state --policy-interval 5s

# Inspect
/tmp/wv/weavectl -socket /tmp/wv/state/run/control.sock status
/tmp/wv/weavectl -socket /tmp/wv/state/run/control.sock modules
/tmp/wv/weavectl -socket /tmp/wv/state/run/control.sock surfaces

# Install / hot-swap / roll back
/tmp/wv/weavectl -socket ... install -local ./path-to-module-dir
/tmp/wv/weavectl -socket ... rollback weave-linux-presence

# Reread the modules directory after changing it by hand
/tmp/wv/weavectl -socket ... reload
```

Core rereads the modules directory while it runs, so a module laid out, rebuilt or deleted
under `--modules-dir` takes effect without restarting core. On Linux the directory watch
notices within about half a second; everywhere, `weavectl reload` (or `kill -HUP` on the
weave-agent process) does it at once, and the periodic rescan (`--module-rescan`, default 1m,
`0` disables) catches anything else. `weavectl reload` prints what it did:

```
added     weave-linux-exec
replaced  weave-linux-presence
invalid   weave-linux-broken  manifest: unexpected end of JSON input
```

`removed` lists modules stopped because their directory went away, and `no module changes`
ends the output when nothing started, stopped or was replaced. `invalid` rows are every
module directory core cannot run as things stand, found by this pass or an earlier one; fix
the directory and reload again.

`WEAVE_STATE_DIR` redirects the entire filesystem layout; without it the platform paths
apply (`/Library/Application Support/Weave`, `%ProgramData%\Weave`, `/var/lib/weave`).
`WEAVE_LOG_LEVEL=debug` raises verbosity everywhere.

## Testing

```sh
make test          # race, shuffle, coverage into cover/unit
make cover         # merge cover/* and enforce >=95% total, >=90% per package
make gate          # everything CI runs, in order
```

Integration tests build real module binaries and drive the full handshake — supervision
(kill → backoff → start limit), lifecycle (install → hot-swap → auto-rollback), policy
(file change → module Watch stream), weaveboot (staged core → crash-loop → revert), and the
protocol-compat fixture. Two conventions the tests rely on:

- Socket dirs come from short `os.MkdirTemp` paths, not `t.TempDir()` — long test names push
  unix socket paths past the 104-byte `sun_path` limit on macOS.
- Test binaries are built with an `.exe` suffix on Windows — Windows cannot exec a binary
  without its extension.

Some tests only mean something unprivileged (a root test run owns every file it creates), so
run the Linux suite as a normal user, for example
`docker run --rm -u 1000:1000 -e HOME=/tmp -v "$PWD":/src -w /src golang:<go.mod version> go test -race ./...`.

## The quality gate

One workflow, `.github/workflows/quality-gate.yml`, and one required check, `Quality gate`,
which needs every job below:

| Job | What it proves |
|---|---|
| Unit tests (Linux, macOS, Windows) | `go vet` and `make test`: race detector, shuffled order, coverage |
| Lint (Linux, macOS, Windows) | golangci-lint with `.golangci.yml`, blocking at zero issues, on each OS so each OS's files are linted |
| govulncheck | no known vulnerability reachable as linux, darwin or windows |
| Cross-compile | every `cmd/*` binary for six platforms, CGO disabled; `go.mod` and `go.sum` tidy; shellcheck on the macOS package scripts |
| macOS package | `make package-test-darwin` on a macOS runner: the plist, `postinstall` run dry against a stand-in `dscl`, the uninstaller, and the built `.pkg`'s payload, owners and modes — nothing installed |
| Protocol | `buf lint`; `buf breaking` against the base branch; `internal/gen` matches `proto/` |
| Core never depends on weaveplatform-agent-modules | `go list -deps -test ./...` as each OS, and `go list -m all`, reach nothing under `weaveplatform-agent-modules` |
| Coverage gate | the three OS profiles merged; >=95% total, >=90% per package (`.testcoverage.yml`) |

`fuzz.yml` soaks the handshake and manifest parsers nightly; `make fuzz` runs them locally.
PR titles follow Conventional Commits (`pr-title-validation.yml`), and `dependency-review.yml`
checks new dependencies.

Dependencies track their latest release: Dependabot opens daily grouped PRs for Go modules
and action pins, `deps-refresh.yml` moves the `go` directive, the `go.mod` tools and the
linter version, and `auto-merge.yml` merges either once the gate passes on that exact commit.
`.github/deps-refresh.pins` holds a module back when its newest release is not the one to
take (gRPC, today, for GO-2026-6443).

## Releasing

Releases are automatic. Conventional commits accumulate on `main`; release-please
(`release-please.yml`, with the org's release-please App token) keeps a release PR open, and
merging it tags `vX.Y.Z` and creates the GitHub release. The tag runs `release.yml`, which
runs goreleaser: binaries for linux, darwin and windows on amd64 and arm64, one archive per
platform carrying `weaveboot`, `weave-agent`, `weavectl` and `weavemanifest`, the
`weave-agent` `.deb`, and a checksum file signed keylessly with cosign. A second job on a
macOS runner then verifies the darwin/arm64 archive against that checksum file, builds
`weave-agent_<version>_darwin_arm64.pkg` from it with `pkgbuild`, signs it keylessly
(`.pkg.sigstore.json`) and attaches both ([`macos-package.md`](macos-package.md)). Before 1.0, `feat:`
bumps the minor version and `fix:` the patch; `ci:`, `docs:` and `chore:` do not release.

There is one component, at the repository root, tagged plain `vX.Y.Z`.

Core releases no modules and no SDK. Each module is released and published from
`weaveplatform-agent-modules`, and promoted through `weaveplatform-release-channels`.

`make snapshot` runs the same goreleaser configuration locally, unsigned, into `dist/`.
