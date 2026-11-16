# SN-003D2 — Recovery and backup fault qualification

## Scope and baseline

Windows x64, local NTFS. Clean main 696aade (SN-003D1 merged by owner), branch
fix/sn-003d2-fault-qualification. Local main matched recorded origin/main; remote freshness
was not checked. No commit, push, fetch, pull, merge, rebase or artifact deletion.
Production writes remain false; GC remains refused. No wire/crypto/ACL relaxation or public
qualification switches. Internal fault points are not CLI arguments or environment channels.

## Findings and fixes

1. Open, backup and restore erased resource-failure identity: OOM/admission failures could
   surface as vault corruption. Preserve OOM and ResourceLimit before publication so Application
   returns ResourceLimit (exit 8). The existing safe boundary removes messages/inner exceptions.
2. Credential orchestration collapsed RecoveryRequired into Rejected. Preserve the distinction
   as AuthenticationOrCorruption; do not turn a damaged current generation into ordinary retry.
3. VerifyBackup could expose wrong-credential cryptographic failures as a generic rejection.
   Application now maps CryptographicException to the fixed AuthenticationOrCorruption category,
   without exposing provider exception text.
4. Resource failures AFTER publication must remain Indeterminate (exit 7), even if cancellation
   is also requested. Catch ordering now explicitly preserves this precedence. No retries.

Added internal Authenticated, BeforeRename and BeforeReadback hooks. Existing enum values stay
unchanged. Native rename/path/ACL logic itself is unchanged; hooks inject exceptions immediately
before calling it or reading back. A separate existing-destination test exercises an actual
Windows no-replace rename rejection and proves the original archive survives unchanged.

## Operation/failure matrix

S = new simulated fault tests through Application; R = real OS behavior; E = retained existing
regression evidence. N/A = operation has no such side effect. These labels are NOT physical
hardware qualification. All six operations have explicit tests, not only a shared commit test.

| Failure | passwd | recover | recovery rotate | backup | backup verify | restore |
|---|---|---|---|---|---|---|
| Cancel before authentication | S | S | S | S | S | S |
| Wrong selected credentials | S | S | S | S | S | S |
| Cancel after authentication | S | S | S | S | S | S |
| OOM via fault hook / refusing allocator | S | S | S | S | S | S |
| Short write / disk-full exception | S | S | S | S | N/A: no write | S |
| File flush failure | S | S | S | S | N/A: no flush | S |
| Directory flush failure before publication | S | S | S | N/A: first directory flush follows rename | N/A | S |
| Directory flush failure after publication | S | S | S | S | N/A | S |
| Rename/replace failure | S | S | S | S + R existing destination | N/A: no rename | S + E existing destination |
| Readback failure | S | S | S | S | N/A: no publication readback; input corruption tested | S |
| Root/manifest/item/blob corruption | S | S | S | S | S | S |
| Immediately before publication | S | S | S | S | N/A: no publication | S |
| After publication / post-publication OOM | S | S | S | S | N/A | S |
| Explicit reopen after Indeterminate | S | S | S | S | N/A: no commit | S |
| Archive substitution while pinned | N/A | N/A | N/A | E native pinned handles | R shared-handle denial | R shared-handle denial |

Restore cancellation is injected at Validated, ObjectWritten, ObjectFlushed, ObjectInstalled,
ManifestVerified, RootWritten, RootFlushed, BeforePublish, AfterPublish, BeforeReadback and
RootReadback. Before publication no live root is permitted; afterwards outcome is uncertain,
and the published root must reopen correctly. An injected rename refusal occurs after entering
the publication attempt and is conservatively Indeterminate even if this test knows no rename
occurred. Production code must not infer that certainty for arbitrary native failures.

## Credentials and retained generations

For each credential-operation failure, tests compare the old root byte-for-byte before
publication, verify both old password and recovery still open it, check unchanged slot bytes,
and compare recovered VK and vault/epoch IDs. After publication, new password or rotated RK
opens the current generation. Old header plus old recovery still unwraps the same VK, documenting
historical-copy access rather than claiming revocation. Existing lifecycle tests cover confirmation
mismatch, old-password rejection, old-RK rejection for new root, and recovery after password loss.
The matrix checks at most one publication callback and there is no automatic retry loop.

## Backup/restore and secrecy

Backup failures never change source root; source opens afterwards. A prepublication failure
leaves no final archive. Postpublication errors require explicit VerifyBackup; it performs full
cryptographic validation, not only opening the root. Existing destination test compares its
full verified hash before and after failed native publication.

Archive substitution tests attempt rename and destructive write from the Authenticated hook
while VerifyBackup/Restore retain the input handle; Windows rejects both. The original hash
still verifies. Corruption cases include a blob never requested by UI, for all six operations.
Restore retains exact source slots/IDs/ciphertext (D1 byte/round-trip regressions retained).
Existing empty/nonempty destinations remain refused. No source-vault cleanup is performed.

Exceptions contain neither synthetic credential markers nor inner exceptions; transferred
credential buffers are asserted zeroed. Existing encrypted-staging/plaintext scan and CLI
no-secret-output tests are retained. Owned buffers can be wiped; GC strings, OS/runtime copies,
terminal recording and hostile same-user/admin activity remain outside erasure guarantees.

## Execution results

| Check | Executed result |
|---|---|
| Release build | Passed, 0 warnings, 0 errors |
| Full MTP suite | 368 passed, 0 failed, 0 skipped (4m 03.833s) |
| MTP discovery | 368 cases in 3 assemblies |
| Managed CLI regression | 165 existing/gen + 22 vault checks passed |
| Native AOT win-x64 CLI | Publish passed; 165 + 22 regression checks passed |
| Native AOT lifecycle/backup harness | Static libsodium publish and synthetic credentials/backup/verify/restore/reopen passed |
| Documentation links / git diff --check | Passed |

Compared with baseline D1's 250 tests, 118 cases were added. Intermediate complete runs
passed 314 and 363 cases as the matrix expanded. Final logs are retained under ignored
`artifacts/sn-003d2-*`, including `sn-003d2-verified.log`, `sn-003d2-discovery.log`,
`sn-003d2-build-verified.log` and native publish logs. No artifacts were removed.

Final source status: 8 modified tracked files and 2 new files; no deletions or unrelated
tracked changes. Base and HEAD remain 696aadefc199a654376441f510510c0ceaf2e794.
No remote CI result is claimed for these unpublished changes.

## Evidence classes and untested scenarios

- Simulated: injected OOM, allocator refusal, disk-full exception, short writes, file/directory
  flush errors, rename/readback exceptions and cooperative cancellation. No deliberate process-wide
  memory exhaustion or storage-controller error was induced.
- Real OS: native rename collision and pinned archive write/delete-sharing denial, local NTFS
  IO, existing ACL/reparse/hardlink and contention tests.
- Process crash: retained Storage suite kills its synthetic helper at 11 common COW boundaries.
  This is common commit-path evidence, not new per-operation kill coverage for all six commands.
- Physical: no abrupt VM/device power-cut, real full-volume/quota exhaustion, controller fault,
  write-cache-loss or unplug campaign. Process kill and injected errors do not qualify these.
- No Linux/macOS, interactive human TTY or new GitHub Actions run is claimed.

SN-003D3 should add dedicated process-crash helpers for credential/archive publication, then
run the existing isolated power-cut plan and real quota/full-volume campaign, obtain independent
native review and qualify target platforms. Keep production writes and GC closed until explicit
owner approval backed by that evidence. Recovery copies must use their historical credentials;
authentic complete rollback still requires external trusted state to detect.

The current-root tampering test also proves explicit retained-generation recovery remains
possible while the damaged live root is left untouched: no hidden rollback is performed.

## Changed files

- `src/SafeNook.Application/VaultApplication.cs`
- `src/SafeNook.Storage/QualificationBackup.cs`
- `src/SafeNook.Storage/QualificationStore.cs`
- `src/SafeNook.Storage/StorageContracts.cs`
- `src/SafeNook.Storage/WindowsFileSystem.cs`
- `tests/SafeNook.Application.Tests/SafeNook.Application.Tests.csproj`
- `tests/SafeNook.Application.Tests/VaultApplicationTests.cs`
- `tests/SafeNook.Application.Tests/FaultQualificationTests.cs`
- `docs/SN-003D2-FAULT-QUALIFICATION.md` (this report)
- `docs/ROADMAP.md`

Suggested Conventional Commit:

```text
fix(storage): preserve resource failures and qualify recovery backup faults
```
