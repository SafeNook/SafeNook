# SN-003C1 — Vault CLI and application layer

Date: 2026-11-16. **Experimental, synthetic-data qualification only. Not qualified for real
secrets. Production writes remain disabled.** No wire-format, algorithm, KDF minimum, ADR,
GC or storage durability release-gate change.

## Baseline and architecture

Started from clean main at `6368b3f066ff478925a64567ae6cac969fa21c56`, containing SN-CI-001
merged as PR #13. Created `feat/sn-003c1-vault-cli`. Local main and recorded origin/main
matched; no Git network synchronization was performed. Read-only GitHub verification found
[SN-CI-001 CI run 43743530368](https://github.com/SafeNook/SafeNook/actions/runs/43743530368)
successful, including Windows capability preflight/tests and all three platform jobs; the
NSec spike run also succeeded. These are baseline results, not CI results for this change.

Dependency direction: CLI -> Application -> Storage -> Core. CLI also retains its existing
Core reference for gen. Core has no filesystem/UI dependency.

- `VaultApplication`: public Init/List/Show/Add/Remove operations and fixed error categories.
  Public construction never grants qualification writes. It checks the production gate
  before interaction, allocation policy, KDF, filesystem access or candidate generation.
- `IVaultInteraction`: explicit interactive readiness, bounded owned UTF-8 input, dedicated
  recovery display, and removal confirmation. Password/RK arrays transfer ownership and are
  wiped on success, rejection or cancellation. No environment/argv credential channel exists.
- `GenerationBuilder`: application orchestration of typed items, immutable encrypted objects
  and manifests using existing Core codecs. Fresh IDs/write IDs, revision links, same-epoch
  parent hashes and both key slots are validated by Core/Storage before publication.
- `KeySlots.AdvanceHeader`: a small Core API using existing header authentication/signing to
  advance a same-epoch generation without replacing either slot. It authenticates the old
  header, verifies next sequence/parent/new IDs, and preserves both slots exactly. No custom
  crypto protocol is implemented in Application or a command handler.
- `QualificationStore.ReadManifest`: internal authenticated manifest access under its existing
  operation gate; new app code does not enumerate or construct object paths itself.
- `VaultReply` / `ItemSummary`: explicit metadata allowlist, not whole DTO serialization.
  `RevealedItem` is created only for explicit reveal and has no generated record ToString.
- `ForQualification`: internal application factory, accessible only to the tests and a
  separately built synthetic harness. The nook assembly has no Storage friend access and
  cannot call the factory. No CLI argument, environment variable, reflection or public
  constructor switches the gate off. The harness is not packaged inside the nook executable.

The application samples available physical memory through
[GlobalMemoryStatusEx](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-globalmemorystatusex)
and the documented
[MEMORYSTATUSEX layout](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/ns-sysinfoapi-memorystatusex),
then applies Core's min(256 MiB, available/4) admission heuristic. This is a volatile estimate,
not an allocation guarantee. It does
not take a budget from the vault and does not downgrade saved KDF parameters. Qualification
init uses the existing m=64 MiB / t=3 minimum; calibration and hard KDF deadlines are not
implemented. Vault operations currently require Windows x64 and a local fixed NTFS volume.
Reads use the existing exclusive lock and authenticate the selected state before returning.

## CLI contract

`--vault` is required on every vault command and must identify an absolute path. No implicit
current-directory search, default vault, environment selector, ID prefix matching or fallback.
IDs are canonical lowercase 32-character strings. No JSON output is implemented in C1.

| Command | Behavior |
|---|---|
| `nook init --vault <absolute-path>` | Exit 5 before credentials while gate is closed. Internal qualification path confirms password and complete recovery key before publication. |
| `nook ls --vault <absolute-path>` | Authenticate, then list live records only: id, numeric type, revision, title, tags. No payload fields. |
| `nook show <id> --vault <absolute-path>` | Authenticate and show the same safe metadata; missing/tombstoned ID returns 2. |
| `nook show <id> --vault <absolute-path> --reveal` | Explicitly reveal login username/password/URLs/notes or secure note text on an interactive terminal. Other payload types are not exported. |
| `nook add --type login\|note --vault <absolute-path>` | Exit 5 before credentials while gate is closed. Harness prompts bounded fields without echo and commits a fresh record. |
| `nook rm <id> --vault <absolute-path>` | Exit 5 before credentials while gate is closed. Harness requires the complete ID as confirmation and creates a tombstone for login/note; it never deletes files. |
| `nook --help`, `nook <command> --help` | No credential prompts; explain required vault and experimental status. |
| `nook gen ...` | Existing behavior and regression suite retained. |

Examples (writes are deliberately refused):

```powershell
nook init --vault 'C:\Vaults\demo'
nook add --vault 'C:\Vaults\demo' --type login
nook ls --vault 'C:\Vaults\synthetic-test-vault'
nook show 0123456789ab4def8123456789abcdef --vault 'C:\Vaults\synthetic-test-vault'
nook show 0123456789ab4def8123456789abcdef --vault 'C:\Vaults\synthetic-test-vault' --reveal
nook rm 0123456789ab4def8123456789abcdef --vault 'C:\Vaults\synthetic-test-vault'
```

Metadata is still sensitive, especially user-entered titles/tags. Terminal control and format
characters are escaped in both metadata and revealed fields; newlines appear as escapes in
rendered note output. Numeric type 1 means login; 2 means note. Add accepts one optional URL;
notes support multiline entry (Ctrl+D terminates, Esc cancels). Tags are initially empty.
C1 does not provide record edits, SSH/age/file import/export or removal of those payload types.

| Exit | Meaning for vault commands |
|---|---|
| 0 | Requested read/qualified operation completed |
| 1 | Invalid arguments/input or rejected operation |
| 2 | Record missing/tombstoned |
| 3 | Authentication or data-integrity verification failed; deliberately combined |
| 5 | Production writes disabled, no credentials requested |
| 6 | Interactive channel/platform/payload operation unsupported |
| 7 | Commit outcome uncertain; preserve evidence, explicitly reopen, do not automatically retry |
| 8 | Trusted resource limit exceeded |
| 130 | Cancelled before operation completion |

Existing gen codes remain unchanged. Vault parser errors are fixed messages that do not echo
unknown argument values. Write-policy refusal takes precedence over semantic input checks;
syntactic command errors are rejected by the parser. An acknowledged mutation is not labelled
cancelled just because cancellation arrives while rendering its success. A broken output
stream cannot undo a commit or already delivered reveal bytes.

## Credential and output boundaries

Interactive access requires stdin, stdout and stderr to be attached to a terminal; redirected
reads/reveal are refused before password input. No password/RK flag, environment variable,
implicit stdin, plaintext file or fallback channel is accepted. Protected inherited-channel
support is deferred; noninteractive vault use is currently rejected rather than simplified.

Console input always calls ReadKey with intercept=true. Bounded character buffers are cleared;
strict UTF-8 encoding preserves input without normalization/trim. Backspace, cancellation,
input bounds and no-echo behavior have deterministic key-source tests. Ctrl+C/Esc cancel;
Console.CancelKeyPress cancellation is installed only for vault commands, preserving gen.
Cooperative cancellation is not a promise to interrupt an in-flight native Argon2 call.

Qualification init reads/compares the password twice, generates VK/RK independently, verifies
both slots through Storage, displays canonical SN1 text on the nonredirected recovery screen,
and requires complete no-echo re-entry. Key checksum and constant-time byte comparison precede
filesystem publication. False confirmation/cancellation leaves no vault root. The terminal
screen warns about recording; no RK is written to normal command stdout or a log/clipboard.

The console implementation uses terminal stderr for prompts/recovery display only after all
three standard streams are verified nonredirected. Terminal scrollback/recording, compromised
OS, managed payload/recovery strings and runtime copies cannot be wiped reliably. Owned byte
and character buffers are cleared; no stronger erasure claim is made. No real credential or
real-secret vault was used during validation. A live human TTY session was not automated;
key-source tests plus redirected-process refusal checks cover the implemented input contract.

Application authenticates before returning any output; CLI constructs a complete response
before writing. Default list/show never serialize password, username, URL, note or blob fields.
No partial state is returned on authentication/corruption/allocation/cancellation failure.
Explicit reveal is intentional plaintext output; physical terminal/stream writes are not atomic
and cannot be rolled back on an output failure. No plaintext temporary files are created.

## Tests and Native AOT

Executed on Windows x64, local fixed NTFS, .NET SDK 10.0.404:

| Check | Actual result |
|---|---|
| Release build | Passed, 0 warnings, 0 errors |
| Full MTP test run | 212 passed, 0 failed, 0 skipped: Core 123, Storage 62, Application/CLI 27 |
| MTP discovery | 212 cases in 3 test assemblies |
| Managed CLI process regression | 165 existing checks + 22 vault checks passed |
| win-x64 Native AOT CLI publish and process regression | Published successfully; 165 + 22 checks passed |
| win-x64 Native AOT application/store harness | Published with static libsodium; init, login/note, reveal, tombstone/reopen, public read/memory policy and owned input clearing passed |
| Whitespace and local Markdown file links | Checked after report completion |

Tests cover gate-before-interaction, argv/env refusal, hidden character input, input bounds,
cancellation, default metadata versus explicit reveal, password/recovery mismatch, wrong
password, corrupted root, missing records, declined removal, fault boundaries and uncertain
commit reopening. Assertions check absence of synthetic passwords/RK from ordinary output
and errors, clearing of transferred input arrays, and absence of synthetic plaintext in
persisted files. Explicit reveal and the dedicated recovery screen are intentional exceptions.
Both key slots survive generation advancement; invalid lineage/header authentication fails.

Build/test/publish logs are retained locally under ignored `artifacts/sn-003c1-*`. An intermediate
build overlapped a running Storage test process and emitted four MSB3026 copy retries; it
completed, and the subsequent sequential Release build had zero warnings. No cleanup or
suppression of a failing test was used. The final harness-only change exercised public memory
admission in native code and was verified by republishing/running that harness.

The workflow now runs the vault process regression beside the existing CLI checks for managed
and native executables. No CI permissions changed. This branch has not been published and no
new GitHub Actions result is claimed. Linux/macOS and a live human terminal session were not
executed locally; inherited cross-platform CI must still run after publication. These tests do
not qualify power-loss durability or authorize production writes.

## Files and remaining work

Modified tracked files:

- `.github/workflows/ci.yml`
- `SafeNook.slnx`
- `docs/ROADMAP.md`
- `src/SafeNook.Cli/Program.cs`
- `src/SafeNook.Cli/SafeNook.Cli.csproj`
- `src/SafeNook.Core/Vault/KeySlots.cs`
- `src/SafeNook.Storage/QualificationStore.cs`
- `src/SafeNook.Storage/SafeNook.Storage.csproj`
- `tests/SafeNook.Core.Tests/Vault/VaultTests.cs`

New files:

- `docs/SN-003C1-IMPLEMENTATION.md`
- `spikes/ApplicationQualification/ApplicationQualification.csproj`
- `spikes/ApplicationQualification/Program.cs`
- `spikes/ApplicationQualification/SyntheticInteraction.cs`
- `src/SafeNook.Application/Contracts.cs`
- `src/SafeNook.Application/GenerationBuilder.cs`
- `src/SafeNook.Application/SafeNook.Application.csproj`
- `src/SafeNook.Application/VaultApplication.cs`
- `src/SafeNook.Application/WindowsMemory.cs`
- `src/SafeNook.Cli/Commands/VaultCommands.cs`
- `src/SafeNook.Cli/ConsoleVaultInteraction.cs`
- `tests/SafeNook.Application.Tests/CliTests.cs`
- `tests/SafeNook.Application.Tests/SafeNook.Application.Tests.csproj`
- `tests/SafeNook.Application.Tests/VaultApplicationTests.cs`
- `tests/Test-VaultCli.ps1`

No tracked files were deleted. Existing ignored artifacts and prior work were preserved.
No commit, staging, fetch, push, merge or rebase was performed. HEAD remains the baseline above.

The next stage should review the user-facing contract and application boundaries, run native
CLI/TTY validation on target Windows configurations, decide a separately reviewed protected
noninteractive input protocol, and continue the independent Storage/durability qualification.
Keep production writes closed until that evidence and explicit owner approval exist. Linux/
macOS/ARM64 vault adapters, backup/restore, password rotation, rekey, sync/agent/GUI, GC and KDF
worker remain outside this task. No prior SN-001/SN-002/SN-003 report or accepted ADR is replaced.

Suggested Conventional Commit:

```text
feat(cli): add gated vault commands and application orchestration
```
