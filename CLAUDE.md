# Engineering conventions

These apply to every weaveplatform repository created from this template.

- **Correctness loop first.** Stand up the quality gate and acceptance tests
  against real dependencies (Docker via testcontainers) before most features
  exist, so every later change lands inside a working test loop.
- **Coverage gate.** ≥95% total and ≥90% per package, merged across unit tests on
  every OS and acceptance runs, enforced by `.testcoverage.yml`. It blocks merges.
- **Layout.** Public packages in `pkg/`, project-only packages in `internal/`,
  entry points in `cmd/`.
- **CLI.** cobra, without viper. Configuration is strict YAML that rejects unknown
  keys, with flag > environment > file precedence.
- **REST.** All HTTP APIs, including test servers that model an API, use
  [chi](https://github.com/go-chi/chi).
- **CI.** OS matrices use the `-latest` runner labels. Actions are pinned by commit
  SHA with the version in a comment; Dependabot keeps them current.
- **Linting.** golangci-lint with `.golangci.yml` is the only linter, and it blocks.
- **Builds** run with `GOWORK=off` so a local `go.work` never hides a missing
  dependency that CI would catch.
- **Commits and PR titles** follow Conventional Commits; release-please derives
  versions and the changelog from them.

## Comments

Comment the reasoning a reader cannot recover from the code: why this and not the
obvious alternative, what a silent failure would look like, a number that must
match something elsewhere. Do not restate what the code says.
