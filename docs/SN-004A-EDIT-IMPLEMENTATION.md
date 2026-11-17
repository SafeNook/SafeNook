# SN-004A — Edit login and secure note

Date: 2026-11-17. Implemented and verified on Windows x64. Production writes and GC remain disabled.

## Git and scope

Owner-saved Q5 is included in local main 09734c5 (PR #20). Clean tracked/untracked
state at start; ignored build outputs and all lab evidence retained. Created
feat/sn-004a-edit-login-notes from that local main. Base/current HEAD 09734c5.
Recorded origin/main matched; no remote freshness claim, fetch/pull/commit/push,
merge/rebase, VM operation or cleanup. No Core/Storage, crypto, wire format or ADR
changes and no dependency added.

## Application and CLI contracts

`VaultApplication.Edit(string path, string id, CancellationToken token = default)`
returns only safe `VaultReply` metadata after confirmed publication. It requires
`IVaultEditInteraction`, an extension of the existing interaction interface:

- `ReplaceField(SecretPrompt field, CancellationToken token)`: false keeps the old
  field; true requests a complete replacement. No old value is passed to the UI.
- `ConfirmEdit(CancellationToken token)`: explicit final publication approval;
  false cancels without creating a new root.
- Existing `ReadSecret` supplies bounded mutable UTF-8 buffers; ownership transfers
  to Application and every owned buffer is wiped on disposal, including failure.

Login supports title, tags, username, password, the complete URL array and notes.
Note supports title, tags and text. No fields were added to schema 1. Unselected
fields are copied without reconstruction/loss. All-keep is an authenticated no-op:
no encryption, new revision or commit. Selecting replacement with empty input
explicitly clears that field; it is not interpreted as omission.

```text
nook edit --vault C:\SyntheticVault --id 0123456789abcdef0123456789abcdef
nook edit --help
```

Public writes return exit code **5 before credentials or interaction**. Invalid CLI
syntax is still rejected by the parser (exit 1). There is no payload/credential argv
or environment option, external editor, plaintext temporary file, reveal behavior
or public qualification switch. Only internal qualification construction enables
synthetic writes. CLI handlers delegate to Application and format safe metadata.

Future interactive flow (exercised through tests while gate is closed): hidden
master-password input, per-field `yes` to replace / Enter to keep, hidden replacement,
then `yes` to publish / Enter to cancel. Password, login notes and note text require
full repeated input with fixed-time byte comparison. Tags/URLs are entered one per
line; Ctrl+D ends multiline input, Enter ends single-line input. Esc/Ctrl+C cancel.
Existing values are never shown. Unknown choices and malformed/oversized input fail
closed; existing Core schema validation supplies array/tag/UTF-8 bounds. No trimming
or secret normalization. An invalid replacement is classified InvalidArguments,
not as corruption of the existing vault.

## Revision and COW behavior

Opening authenticates the current root and objects through existing Storage.
Canonical ID lookup rejects missing/tombstoned entries (NotFound), malformed IDs
(InvalidArguments), and unsupported payload types (UnsupportedItem). Corrupt records
refuse authentication before any replacement is requested or published.

The candidate preserves logical ID, type, schema, CreatedAt and every unselected
field; UpdatedAt never moves backward, revision increments with checked arithmetic,
and Previous is the authenticated predecessor ciphertext SHA-256. The unchanged
GenerationBuilder.Change creates a fresh write ID and nonce through ObjectCodec,
updates the manifest reference and advances the header. Existing Change/Commit
performs fresh credential authentication, candidate validation, immutable install,
retained-root creation, atomic publication and readback authentication. Both slots,
Vault Key and epoch remain unchanged. Old ciphertext and retained root are preserved;
GC remains off. No success reply is built before committed outcome. Indeterminate
maps to exit 7 with explicit reopen instructions, with no automatic mutation retry.

## Tests and fault model

New tests cover login/note edit then reopen, title-only preservation, complete arrays
and all payload fields, explicit empty arrays/title, secret replacements and mismatch,
no-op, final cancellation, invalid/missing ID, tombstones, bad password, corrupted
active ciphertext, duplicate tags and excessive URLs. Tests compare unchanged slots,
ID/type/CreatedAt, Previous hash, fresh write ID and nonce, exact previous ciphertext,
exact retained predecessor header and successful old-object decryption. All retained
roots found are fully authenticated. CLI tests cover named --id/help, missing ID,
forbidden payload options, no secret echo, hidden choices and gate-before-interaction.
Owned buffers are checked for zeroing and vault files scanned for synthetic plaintext.

Fault injection uses the existing MatrixFault/IStoreFaults hooks only:

| Fault | Expected result |
|---|---|
| BeforePublish, short write, file/directory flush before publication | Rejected; exact old root remains |
| BeforeRename | Indeterminate conservatively; test injects before native rename and old root remains |
| AfterPublish, BeforeReadback | Indeterminate; new revision reopens successfully |
| Cancellation before operation / at fresh authentication | Cancelled; old root remains |
| Cancellation after publication | Indeterminate; new revision reopens |

Each fault asserts at most one publication, explicitly reopens through the normal
Application path and recovery key, verifies retained roots, and checks safe errors
without inner exceptions. These are modeled faults, not physical disk-full, VM cuts
or proof of hardware durability. Q5's VM results are not extended to Edit by inference.

## Validation results

- Release build: passed, zero warnings/errors, cached packages (--no-restore).
- Initial targeted Edit filter: 20 passed before four further negative cases and the
  exact retained-header assertion were added; final results below supersede this run.
- Final MTP execution: **558 passed, 0 failed, 0 skipped**, 7m 32s 086ms.
  Discovery: **558** cases in three assemblies; counts match. All 26 added cases
  and every prior test are included in this final run.
- Managed CLI regression: 165 general/gen + 27 vault checks passed.
- Native AOT win-x64 CLI and Application publish: passed, no warnings/errors.
- Actual Native AOT Application lifecycle with login/note edit, reopen, credentials
  and backup/restore: passed. Native CLI regression: 165 + 27 passed.
- git diff --check and changed-document relative links: passed.

Logs are retained under artifacts/sn-004a-*. No Linux/macOS execution or remote CI
verification was performed. Windows-only integration tests use existing xUnit skip
classification; platform-independent parser/gate/input tests remain portable.

## Limitations and next work

The existing typed model uses immutable managed strings. Owned byte/char inputs and
serialized plaintext buffers are wiped, but CLR string/JSON copies cannot be reliably
erased; this existing limitation is not represented as a secure-memory guarantee.
The edit conversation holds the existing store lock while collecting input. No new
background worker, session model or noninteractive credential channel is introduced.

Public writes/GC stay closed. Editing SSH/age/file, blob reference mutation, external
editors, GUI/server/sync and hardware qualification are outside scope. The next
functional step can be M2 import/export with exact-byte SSH/age/file round trips;
opening production writes remains a separate owner decision under the existing gate.

## Files

Added:
- src/SafeNook.Application/VaultEditing.cs
- tests/SafeNook.Application.Tests/EditTests.cs
- docs/SN-004A-EDIT-IMPLEMENTATION.md

Modified:
- src/SafeNook.Application/Contracts.cs (edit interaction/prompts)
- src/SafeNook.Application/VaultApplication.cs (partial declaration only)
- src/SafeNook.Cli/Commands/VaultCommands.cs (edit routing/--id/help)
- src/SafeNook.Cli/ConsoleVaultInteraction.cs (hidden choices/confirmation/multiline)
- spikes/ApplicationQualification/SyntheticInteraction.cs (synthetic edit responses)
- spikes/ApplicationQualification/Program.cs (native edit lifecycle)
- tests/SafeNook.Application.Tests/CliTests.cs (gate/parser/terminal tests)
- tests/Test-VaultCli.ps1 (managed/AOT CLI regression)
- docs/ROADMAP.md (scope and result)

No deletions. No unrelated tracked/untracked changes at completion; pre-existing
ignored artifacts remain in place. Commit not executed.

```text
feat(vault): add secure editing for login and notes
```
