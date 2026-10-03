# weaveplatform-template

The starting point for weaveplatform Go repositories: a blocking quality gate
(lint, unit tests on Linux, macOS and Windows, govulncheck, cross-compile, and a
≥95% merged coverage gate), release-please through the organisation's App,
dependencies that track their latest release from the day a repository is born,
and conventional-commit PR titles.

## After creating a repository from this template

1. **Rename the module.** `make init NAME=<repository name>` rewrites
   `weaveplatform-template` everywhere (module path, this README) and tidies.
2. **Set the owners** in `.github/CODEOWNERS`.
3. **Protect `main`.** Require the `Quality gate` and `✅ Validate PR Title` checks,
   and enable auto-merge so Dependabot updates merge once the gate passes.
4. **Releases** start at 0.1.0 and need nothing per repository: the organisation's release-please
   App is installed on all repositories and its credentials are organisation
   variables and secrets. The workflow warns in its log if it falls back to a
   `RELEASE_PLEASE_PAT`.
5. **Replace this README** with the project's own.

## Dependencies stay at latest

| Piece | What it moves | When |
|---|---|---|
| `deps-refresh.yml` | The `go` directive (latest stable Go), every module and every `go.mod` tool (`go get -u ./... tool`), and `.github/golangci-lint-version` | On the push that creates `main` (repository birth), daily, and on demand |
| Dependabot | Go modules and GitHub Actions pins, majors included, one grouped PR per ecosystem | Daily |
| `auto-merge.yml` | Merges either kind of PR once the quality gate has passed on that exact commit | When the gate finishes |

The gate is the only thing that holds an update back. A major that breaks the
build fails it, and the PR stays open for a person. Dependabot owns the action
pins because changing workflow files needs a permission the org App does not
have.

This repository itself refreshes the same way, so a repository created from it
starts from a current snapshot and updates again within minutes of creation.

## Layout

| Path | What |
|---|---|
| `cmd/<binary>/` | Entry points: thin cobra shims over `internal/`; excluded from the coverage gate |
| `internal/` | Project-only packages; `internal/buildinfo` carries the version stamped in by `make build` |
| `pkg/` | Public, importable packages |
| `docs/` | Design notes and decision records |
| `test/acceptance/` | Acceptance tests against real dependencies (excluded from `make test`) |

## Make targets

| Target | What |
|---|---|
| `make gate` | Everything CI runs: vet, lint, test, cover, vuln, build |
| `make test` | Unit tests with `-race -shuffle=on`, coverage to `cover/unit` |
| `make cover` | Merges every `cover/*` directory and enforces `.testcoverage.yml` |
| `make lint` / `make fmt` | golangci-lint with `.golangci.yml` |
| `make build` | Cross-compiles every `cmd/*` binary for six platforms, CGO disabled |

Acceptance tests write their coverage to another `cover/<name>` directory; the
coverage job merges whatever it downloads, so adding one is a new CI job that
uploads a `cover-<name>` artifact plus an entry in the gate's `needs`.
