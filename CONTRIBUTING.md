# Contributing

Thanks for considering a contribution. Please follow the
[code of conduct](CODE_OF_CONDUCT.md) in all interactions.

Before opening a pull request, read [`spec.md`](spec.md): it is the governing architecture
document, and two of its rules gate every change here.

- **Core stays boring.** Anything product-shaped belongs in a module, however tempting the
  generalisation. If only one product needs it, it is not core.
- **The `Host` surface is closed by default.** A module needing a new host method is an
  architecture decision raised as an issue, not a pull request.

How to contribute:

- **Issues.** File bugs and feature requests with the issue templates. Report a
  vulnerability privately ([`SECURITY.md`](SECURITY.md)).
- **Pull requests.** Titles follow [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:`, `docs:`, `chore:` …); release-please builds the changelog and the version
  from them, and a check enforces the format.
- **Before pushing,** run `make gate`. CI runs the same targets, and `Quality gate` is the
  required check ([`docs/development.md`](docs/development.md#the-quality-gate)).
- **Protocol changes** happen in `proto/` and are gated by `buf breaking` and
  [`docs/PROTOCOL.md`](docs/PROTOCOL.md). Regenerate with `make gen` and commit
  `internal/gen`; CI fails if it drifts. A new protocol version follows
  [`docs/protocol-versioning.md`](docs/protocol-versioning.md).

Modules and the module SDK are not developed here. They live in
[`weaveplatform-agent-modules`](https://github.com/weaveplatform/weaveplatform-agent-modules)
([`docs/decisions/0001`](docs/decisions/0001-core-owns-its-protocol.md)); module authors start
from its
[`sdk/docs/writing-a-module.md`](https://github.com/weaveplatform/weaveplatform-agent-modules/blob/main/sdk/docs/writing-a-module.md).
