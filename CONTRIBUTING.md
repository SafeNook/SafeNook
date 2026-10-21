# Contributing to SafeNook

SafeNook is early and moves fast. Issues with ideas, questions and bug reports are welcome; for larger changes please open an issue first so we can agree on the approach.

## Ground rules

- **No secrets in logs, exceptions, `ToString()` or console output** unless the user explicitly asked to reveal them.
- **No home-made cryptography.** Only well-known primitives through the BCL or reviewed libraries, see [`docs/adr/`](docs/adr/).
- `SafeNook.Core` must not reference the console, clipboard, network or UI frameworks.
- Library and CLI code must stay Native AOT compatible: no reflection-based JSON, no dynamic code.

## Workflow

1. Fork and create a branch from `main`.
2. Make the change with tests. `dotnet build` must pass with zero warnings (warnings are errors).
3. Run `dotnet test`.
4. Use [Conventional Commits](https://www.conventionalcommits.org/) for commit messages, e.g. `feat(core): add Argon2id key derivation`.
5. Open a pull request. CI must be green on Windows, macOS and Linux.

## Design decisions

Changes to the vault format, cryptography or public CLI behaviour need an Architecture Decision Record in `docs/adr/` (see [the template](docs/adr/template.md)).
