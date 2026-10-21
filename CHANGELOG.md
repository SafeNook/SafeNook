# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Password generator in `SafeNook.Core`: configurable length (8–128) and character classes, optional exclusion of look-alike characters, at least one character from every selected class, randomness from `RandomNumberGenerator`, entropy estimate.
- `nook gen` command with `--length`, `--no-symbols`, `--exclude-similar`, `--count` and `--entropy`.
- CI on Linux, Windows and macOS: build with warnings as errors, tests, native AOT publish and a smoke test of the binary.
- Dependabot updates for NuGet packages and GitHub Actions.
- Documentation: README, roadmap, architecture decision records 0001–0005, contributing guide and security policy.
- Issue forms, pull request template and code owners.

[Unreleased]: https://github.com/SafeNook/safenook/commits/main
