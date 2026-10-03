# Contributing

Thanks for considering a contribution. Please follow the
[code of conduct](CODE_OF_CONDUCT.md) in all interactions.

- **Issues.** File bugs and feature requests with the issue templates.
- **Pull requests.** Titles follow [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:`, `docs:`, `chore:` …); release-please builds the changelog and
  the version from them, and a check enforces the format.
- **Before pushing,** run `make gate`. CI runs the same targets and the quality
  gate is the required check.
