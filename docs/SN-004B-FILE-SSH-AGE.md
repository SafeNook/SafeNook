# SN-004B — File, SSH and age opaque import/export

Date: 2026-11-19. Implemented and verified on Windows x64. Production writes and GC closed.

## Architecture and API

Existing schema-1 file/SSH/age payloads and whole-object algorithm 1 blobs are reused.
No cryptography, wire fields, ADR status or package dependencies changed. Each imported
blob has a fresh ID/write ID/nonce; its exact ciphertext hash and plaintext length are
referenced by the authenticated manifest. Item and blobs publish in the existing COW
transaction; retained roots and ciphertext remain intact. No plaintext hash deduplication.

VaultApplication exposes ImportFile, ImportSshKey, ImportAgeIdentity and ExportFile,
ExportSshKey, ExportAgeIdentity. Inputs are absolute external file paths; outputs must
also be outside the vault. Imports authenticate the vault before reading sources.
Read-only source handles are opened relative to pinned ancestor handles, deny concurrent
write/delete sharing, reject reparse/hardlinks and check bounded length/exact reads.
Source ACL need not be owner-only; no source permission is modified. Source bytes are
kept in bounded RAM, encrypted without decoding or normalization and then wiped.
The input file is never modified. Admission reserves transient RAM before input allocation.

Limits: general file 25 MiB including empty; opaque private SSH/age input 1 MiB;
optional public/recipient companion 64 KiB. BOM, NUL/non-UTF8 bytes, CR/LF and trailing
newline are preserved. Keys are unvalidated opaque storage: IVaultFileInteraction
requires explicit acknowledgement; no parse, generation, matching check, plugin or agent.

CLI:

```text
nook file add --vault PATH --input FILE
nook file extract --vault PATH --id ID --output FILE
nook ssh add --vault PATH --input PRIVATE --public-input PUBLIC
nook ssh extract --vault PATH --id ID --output PRIVATE
nook ssh extract --vault PATH --id ID --public-output PUBLIC
nook age add --vault PATH --input IDENTITY --recipient-input RECIPIENT
nook age extract --vault PATH --id ID --output IDENTITY
nook age extract --vault PATH --id ID --recipient-output RECIPIENT
```

Companions are optional. Extract selects exactly one destination per invocation;
primary and companion are separate explicit operations, not a multi-file atomic promise.
No argv/env contents, stdout payload, overwrite option or qualification flag. All six
public operations check the closed write gate before credential/interaction/filesystem
access, including plaintext exports. Successful import returns ID; export returns ok.

## Approved plaintext staging policy

After full authenticated opening and ReadBlob (context, ciphertext hash/length and
complete AEAD tag), export pins the existing destination directory on local fixed NTFS.
The directory must itself have exact protected owner-only DACL; ordinary broadly
inherited directories are refused. Files use the same protected owner-only descriptor.
No reparse ancestor, ADS, relative traversal or hardlinked file is accepted. Stored
originalName is display metadata, never an output path.

A random 128-bit name with .sn-export suffix is created exclusively in the selected
directory, same volume; the secret name is absent. The handle denies all sharing.
Write length, file flush, exact readback and file identity/security are checked, then
native no-replace rename publishes. Existing output is never replaced. Namespace flush
and handle validation follow publication. Before-publication handled failures delete
only the owned staging via FILE_DISPOSITION_INFORMATION on the exclusively held handle.
No path-based deletion, scanning or unknown-file cleanup occurs.

An uncertain rename/publication or post-publication failure returns Indeterminate,
with no retry or deletion. Existing-target rename refusal is conservatively Indeterminate;
original target survives and private staging may remain. Failure to delete own staging
is a safe redacted refusal. Cancellation before publication removes owned staging;
after publication the published result is not undone. Crash can leave private plaintext
staging. No automatic scavenging or secure erase guarantee on NTFS/SSD/snapshots/swap.
This permission applies solely to deliberate external export; vault writes still stage
ciphertext only. Required rights/NTFS/policy failures cause refusal.

## Verification

Initial targeted run: 10 passed (0/1-byte/25-MiB files, opaque SSH/age companions,
short writes, file flush and publication hook faults; final suite also includes readback refusal). Final discovery: 582 cases;
**582 passed, 0 failed, 0 skipped**, 8m 33s 996ms; execution/discovery counts match. Final Release build: 0 warnings/errors. Managed CLI regression:
165 + 27 passed. Native AOT harness/CLI publish passed; final corrected Native AOT lifecycle executed successfully, including file/SSH/age exact-byte round trips.

Added tests also cover wrong credentials, missing ID, tombstone, missing source, blob corruption, pre-cancellation,
unsafe output directory, oversized source, existing output and COW import failures.
Before-publication export faults leave no .sn-export; after-publication injected failure
leaves exact complete bytes. Source vault root is compared and owned input buffers
checked for wiping. File/SSH/age CLI gate-before-interaction tests run on all platforms.

Remaining qualification gaps: no new physical disk-full/quota/power-cut qualification,
no Linux/macOS filesystem adapter/run, and no independent native review of the new
FILE_DISPOSITION_INFORMATION cleanup path. Existing Storage reparse/ACL/hardlink tests
remain in the full regression; this does not prove absence of filesystem races.
The conservative existing storage publication/flush guarantees and production gate
remain in force. Cleanup failure/crash retains evidence; operators must treat orphan
.sn-export files as sensitive plaintext and never assume secure deletion.

## Git and files

Base/current HEAD 4c0f030 contains owner-saved SN-004A on main. New branch
feat/sn-004b-file-key-import-export. Recorded upstream matched at start; remote
freshness not checked. No commit/push/fetch/pull/merge/rebase. Ignored evidence preserved.

Added ExternalFiles.cs (internal pinned I/O), VaultFiles.cs (Application orchestration),
FileTests.cs and this report. Modified WindowsFileSystem partial declaration,
GenerationBuilder blob inventory support, interaction/CLI contracts, synthetic and
Native AOT harness, CLI tests and ROADMAP. No deletion or VM operation.

```text
feat(vault): add secure file and key import export
```

## Review notes and evidence provenance

A review found that the initial synthetic native fixture selected a restored test
vault directory for external source/output. It was corrected to a separate private
-external directory before final qualification. Existing intermediate artifacts
were preserved. This fixture mistake did not alter product vault storage code.
The first full run was stopped after adding readback and missing-source/tombstone
coverage; it is not counted as a final pass. Final logs use sn-004b-*-final.*.

The new readback hook fires before inspecting staged plaintext and uses the existing
IStoreFaults contract; no alternate write engine. All publication retries remain
forbidden. No success is claimed for a failed/unknown publication. New tests use
synthetic arbitrary binary keys; they establish storage round-trip, not key usability.

Native cleanup contract checked against Microsoft [FILE_DISPOSITION_INFORMATION](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_file_disposition_information): a BOOLEAN DeleteFile, DELETE access required, deletion on close. The owned handle already requests DELETE for rename and is closed after disposition; no further I/O is attempted on it. This source check is not an independent security audit.

Final validation commands (existing cached packages; no network restore):

```powershell
dotnet build -c Release --no-restore
dotnet test -c Release --no-build --no-restore
dotnet test -c Release --no-build --no-restore --list-tests
dotnet publish spikes/ApplicationQualification -c Release -r win-x64 --no-restore -p:PublishAot=true -p:SelfContained=true -p:LibsodiumStaticLib=<existing-static-libsodium.lib> -o artifacts/sn-004b-native-harness-final
dotnet publish src/SafeNook.Cli -c Release -r win-x64 --no-restore -p:PublishAot=true -p:SelfContained=true -p:LibsodiumStaticLib=<existing-static-libsodium.lib> -o artifacts/sn-004b-native-cli-final
# For managed nook.exe and newly published native nook.exe:
./tests/Test-Cli.ps1 -Executable <executable>
./tests/Test-VaultCli.ps1 -Executable <executable>
# Fresh synthetic path; executed, not only published:
ApplicationQualification.exe <new-vault-path>
git diff --check
```

Final logs: artifacts/sn-004b-build-final.log, suite-final.log and discovery-final.log
(with sn-004b- prefix), aot-harness-final.log, aot-cli-final.log and
native-execution-final.log. Managed/native CLI runs each passed 165+27 checks.

Final git diff --check and changed-document relative links: PASS. Final Git status:
9 modified tracked files, 4 new files (the report, VaultFiles.cs, ExternalFiles.cs,
FileTests.cs); no deletions or unrelated changes. Existing ignored artifacts retained.
ProductionWritesSupported remains false; GarbageCollectionStatus still refuses deletion.
