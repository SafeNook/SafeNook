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

## Test infrastructure

`global.json` selects Microsoft.Testing.Platform (MTP) for .NET 10.
Test projects use `xunit.v3` 4.x (the xUnit v3 framework with MTP v2),
not the VSTest packages `Microsoft.NET.Test.Sdk` or `xunit.runner.visualstudio`.
Use an MTP-capable IDE test runner or run tests from the command line:

```bash
dotnet test -c Release --minimum-expected-tests 16
dotnet test -c Release --list-tests
```

The minimum count guards the existing 16 Core test cases against incomplete discovery.
Future test projects must support MTP; when adding projects, choose an appropriate
per-assembly minimum rather than assuming the solution-wide count applies to each one.
Keep package versions in `Directory.Packages.props`.

CLI regression checks require PowerShell 7 (`pwsh`) and run against both managed
and Native AOT executables in CI. After building, run:

```powershell
./tests/Test-Cli.ps1 -Executable ./src/SafeNook.Cli/bin/Release/net10.0/nook.exe
./tests/Test-Cli.ps1 -Executable ./publish/nook.exe
```

On Linux/macOS, use `nook` instead of `nook.exe`. The checks capture output without
logging generated passwords. Major xUnit dependency updates are reviewed separately
from grouped minor/patch updates.

## Design decisions

Changes to the vault format, cryptography or public CLI behaviour need an Architecture Decision Record in `docs/adr/` (see [the template](docs/adr/template.md)).
