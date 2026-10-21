# SafeNook — notes for Claude Code

## What this is
Local-first secrets vault for developers; CLI command `nook`. C#, .NET 10, pre-alpha.
Plan: docs/ROADMAP.md. Decisions: docs/adr/. Vault format (source of truth once written): docs/vault-format.md.

## Commands
- Build (warnings are errors): `dotnet build -c Release`
- Test: `dotnet test -c Release`
- Native AOT: `dotnet publish src/SafeNook.Cli -c Release -r <rid> -o publish`, then `./publish/nook --help`

## Layout
- src/SafeNook.Core: vault format, crypto, models, services. Must not reference Console, clipboard, network or UI. IsAotCompatible=true.
- src/SafeNook.Cli: the `nook` command. System.CommandLine 2.0 API (Option/Command, SetAction, ParseResult.GetValue). Handlers stay thin: parse, call Core, print.
- tests/*.Tests: xUnit v3.

## Hard rules
1. Never put secrets (passwords, keys, decrypted items) into logs, exception messages, ToString() or console output, unless the user explicitly asked to reveal them.
2. No home-made cryptography. Only System.Security.Cryptography and libraries accepted in docs/adr. Do not change algorithms, parameters or the vault format without an ADR and the owner's approval.
3. Keys and master passwords live in byte[] / Span<byte>, are wiped with CryptographicOperations.ZeroMemory, and compared with CryptographicOperations.FixedTimeEquals.
4. Randomness only from RandomNumberGenerator.
5. Native AOT: JSON only through source-generated JsonSerializerContext, no reflection or dynamic code. Fix trim/AOT warnings, never suppress them silently.
6. Package versions only in Directory.Packages.props. Every new dependency needs a reason in the PR description; prefer the BCL.
7. Disk writes are atomic (temp file, flush to disk, rename) with owner-only permissions.
8. Every change comes with tests. Crypto code is tested with known-answer vectors whose source is cited in a comment.

## Workflow
- Branch from main: feat/, fix/, docs/, chore/, ci/, spike/. Never push to main; a ruleset blocks it anyway.
- Conventional Commits. The PR title becomes the squash commit on main.
- Before opening a PR: build and tests pass locally; for Core or CLI changes also run the AOT publish and a quick smoke test.
- PR description: what and why, how it was tested, risks, roadmap task IDs (for example F-5).
- Tick the task's checkbox in docs/ROADMAP.md in the same PR.
- Ask the owner before: changing the vault format or crypto parameters, changing public CLI behaviour, adding a dependency, touching CI permissions or security settings.

## Language
- English: code, comments, XML docs, commits, PRs, README, SECURITY, CONTRIBUTING, docs/vault-format.md, docs/threat-model.md.
- Russian: docs/ROADMAP.md and docs/adr/*.

## Style
.editorconfig is the source of truth. File-scoped namespaces, sealed classes by default, records for data, nullable enabled, XML docs on public APIs.
