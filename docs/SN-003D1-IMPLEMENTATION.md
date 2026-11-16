# SN-003D1 — Portable encrypted backup and restore

## Architecture and contracts

ADR 0010 is Accepted by explicit owner approval. SNBACKUP v1 frames existing ciphertext and
exact decoded header; no vault crypto, wire layout, parameters or accepted crypto ADR changed.
The specification includes external SHA-256, independent 2 GiB ceiling and separation of
Backup / VerifyBackup / Restore. The digest is outside the container and is not rollback proof.

BackupArchive scans framing sequentially and builds a bounded offset index (20,001 objects),
not an archive-sized array. It checks fixed magic/version/flags, lengths, reserved bytes,
canonical ordering, uniqueness, envelope kinds and exact EOF. Verification uses existing Core
header/manifest/items authentication and decrypts every blob, disposing its plaintext promptly.
Exact inventory comparison rejects missing/extra objects. Full-file SHA-256 is streamed.

Application APIs: Backup(vault, output, recovery=false), VerifyBackup(input, recovery=false),
Restore(input, destination, recovery=false), each with CancellationToken and returning verified
archive SHA-256. Credentials use IVaultInteraction; explicit recovery selection never probes
another slot. CLI contracts:

```text
nook backup --vault C:\Vaults\demo --output C:\Backups\demo.snbak
nook backup verify --input C:\Backups\demo.snbak --credential recovery
nook restore --input C:\Backups\demo.snbak --vault C:\Vaults\restored
```

Backup/restore return 5 before interaction in public construction. Verify is read-only but
requires interactive credentials. No bypass flag/environment setting/public qualification API.
CLI returns existing fixed safe error categories; success prints SHA-256, no payload metadata.

## Filesystem and publication

Internal Windows adapter pins ancestors and archive-parent handles; native relative opens reject
reparse/hardlinked/nonregular files. Archive inputs require the existing owner-only protected ACL
policy and are opened without write/delete sharing. A copied archive may need restrictive local
permissions established by its owner before it can be verified. Byte portability does not waive
filesystem admission. Archives are not extracted by filenames. Output has generated private
ciphertext-only staging, no-replace rename and checked flush. Backup source lock covers copying,
verification and publication. Destinations inside source vault are refused by Application.

Restore performs full verification before creating the destination. Existing destinations,
including empty directories, fail exclusive creation. Objects retain exact bytes and IDs; root
is published last after installed-object authentication. Root readback and full blob verification
precede success. Prepublication failures leave no live root; postpublication failures return
Indeterminate, retain evidence and require explicit reopen. Unknown or staged ciphertext is not
automatically deleted. No GC, fallback generation selection, rekey or production gate change.

## Qualification

- Release build: succeeded with zero warnings/errors (final log `sn-003d1-build-verified.log`).
- Full MTP suite: 250 passed, 0 failed, 0 skipped; discovery found 250 cases in three assemblies.
- Managed CLI regression: 165 gen/existing checks and 22 existing vault checks passed.
- Native AOT win-x64 CLI: publish and the same 165 + 22 checks passed.
- Native AOT application harness with static libsodium: login/note/tombstone, credentials and
  backup -> full verify -> restore -> reopen passed; hash equality was asserted.
- Local Markdown links and git diff --check passed.

The first 25 MiB fixture failed because it supplied only a one-buffer codec budget. The fixture
was corrected to 50 MiB, preserving Core admission and format limits; the failed 249/250 log
is retained as `artifacts/sn-003d1-complete.log`. All new blob boundary cases use the same
unchanged production codec. Final run: `artifacts/sn-003d1-verified.log`.

The tests use only synthetic credentials/data. New suites cover empty/login/note lifecycle via
ApplicationQualification; attachment restore and recovery authentication; damaged root/manifest/
item/blob; wrong credentials; missing, duplicate and extra frames; truncation, trailing data,
unknown versions/reserved bytes and oversize length claims. Fault injection covers object write,
flush/install, manifest verification, root write/flush, before/after publish and readback.
Short writes, injected disk full, flush refusal and cancellation fail closed. Retained source
state is never replaced. Tests reopen restored vaults and compare exact header and blob bytes.

## Limits and remaining risks

Windows x64/local NTFS only was executed. Linux/macOS, live human TTY, physical disk-full and
power-cut campaigns are not claimed. Existing Store security tests remain relevant but do not
prove absence of native races or hostile-OS attacks. No power-loss durability qualification.
Imported archives must satisfy local ACL/path policy; cross-owner copying is not automatic ACL
repair. Full valid rollback remains undetectable without trusted external state. Credentials
must match the archived root, even after current-vault password/recovery rotation. Plaintext is
bounded and owned buffers disposed, but managed/runtime/OS copies cannot be reliably erased.

The new CLI gate and verify-help cases are MTP tests; the 22-process suite is the retained C1 regression.

## Git and changed files

Started from clean 9456430 (committed format proposal, based on SN-003C2 5365aed), branch
feat/sn-003d1-portable-backup. Existing ignored artifacts preserved. No commits or remote Git
operations. Local main remains 5365aed; remote freshness was not checked.

- `docs/adr/0010-portable-backup-container.md`
- `docs/adr/README.md`
- `docs/portable-backup-format.md`
- `docs/storage-protocol.md`
- `spikes/ApplicationQualification/Program.cs`
- `spikes/StoreQualification/GenerationFixture.cs`
- `src/SafeNook.Application/VaultApplication.cs`
- `src/SafeNook.Cli/Commands/VaultCommands.cs`
- `src/SafeNook.Cli/Program.cs`
- `src/SafeNook.Storage/QualificationStore.cs`
- `src/SafeNook.Storage/WindowsFileSystem.cs`
- `tests/SafeNook.Application.Tests/CliTests.cs`
- `tests/SafeNook.Storage.Tests/StoreTests.cs`
- `src/SafeNook.Storage/BackupArchive.cs`
- `src/SafeNook.Storage/QualificationBackup.cs`
- `tests/SafeNook.Storage.Tests/BackupTests.cs`

Additional changed document: `docs/ROADMAP.md`. This report is also new.

Suggested Conventional Commit:

```text
feat(backup): add verified portable backup and gated restore
```
