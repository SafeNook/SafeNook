# SafeNook

[![CI](https://github.com/SafeNook/safenook/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/SafeNook/safenook/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/github/license/SafeNook/safenook)](LICENSE)

**A safe little nook for your secrets.** SafeNook is a local-first, cross-platform secrets vault for developers: passwords, SSH keys, age identities, `.env` sets, small files and notes — encrypted on your machine and driven from the terminal with the `nook` command.

> [!WARNING]
> **Pre-alpha. Do not store real secrets in SafeNook yet.**
> The vault format and CLI will change without migrations until 1.0. There are no releases or packages yet.

## Current implementation and scope

The repository currently implements password generation through `nook gen`, with
Core tests, CLI regression checks and Native AOT CI configuration. Vault storage,
encryption services, SSH/age storage, files and interactive mode are not implemented yet.
The NSec/AOT spike is separate from the application.

SafeNook is an independent project. It will not read or migrate PasswordGeneratorCLI
data and will not provide an importer for that format.
SSH keys, age identities and small files are priorities for the first useful local
vault; storing them does not require a background agent. Server and GUI implementation
must wait until the local core is stable. The selected visual direction is **Vault Monogram**.

The [SN-001 milestone proposal](docs/ROADMAP.md) and
[open architecture questions](docs/SN-001-ARCHITECTURE-QUESTIONS.md) require review
before SN-002. Future version numbers are proposals, not release commitments.

## What it will be

- **One vault for developer secrets** — logins, SSH keys, age identities, environment variable sets, small files, secure notes, TOTP.
- **Modern, boring cryptography** — Argon2id for the master password, AES-256-GCM for every item, versioned and authenticated file formats.
- **Terminal first** — scriptable commands with `--json` output, plus a friendly interactive mode with search and auto-lock.
- **Developer workflows** — built-in ssh-agent, `nook run -- <cmd>` to inject secrets into a process environment.
- **Your sync, your server** — sync through git or any synced folder, later through a small zero-knowledge server you can self-host.
- **Single binary** — native AOT builds for Windows, macOS and Linux, no .NET runtime required.

The full plan lives in [`docs/ROADMAP.md`](docs/ROADMAP.md) (in Russian for now), design decisions in [`docs/adr/`](docs/adr/).

## A taste of the CLI (planned across multiple milestones)

```bash
nook init
nook add login --name GitHub --username me@example.com --generate
nook copy github                  # copies the password, clears the clipboard after 30 s
nook ssh gen --name deploy-key    # stored in the vault, served by nook's ssh-agent
nook run --env my-api -- dotnet run
nook                              # interactive mode
```

## Building from source

Requires the [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0).

```bash
dotnet build
dotnet test
dotnet run --project src/SafeNook.Cli -- --help
```

Native AOT build for your platform:

```bash
dotnet publish src/SafeNook.Cli -c Release -r <rid>   # e.g. linux-x64, osx-arm64, win-x64
```

## Project layout

```
src/SafeNook.Core      vault format, cryptography, models — no console or UI code
src/SafeNook.Cli       the `nook` command
tests/                 unit tests
docs/                  roadmap and architecture decision records
```

## Security

Please report vulnerabilities privately — see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
