# SN-003B2 — NTFS store and COW transaction qualification

Date: 2026-11-12. The internal API creates, commits and reopens encrypted vault generations
on the tested Windows x64 / local NTFS host. **This is not production writable support.**
`StorageSupport.ProductionWritesSupported` is false and `RequireProductionWrites()` refuses
all platforms. Mutating store APIs and fault hooks are internal, accessible to the explicit
test/qualification assemblies. Power-loss qualification and independent native-code review
remain release gates; no option silently bypasses the production gate.

## Git, files and scope

Started from clean `main`, with SN-003B1 already saved in
`0236873ee408c4025d5aa93b42d01e7dfb2f3cbc` (`feat/sn 003b1 authenticated state (#11)`).
Branch: `feat/sn-003b2-secure-filesystem-store`. Base and HEAD remain that commit.
Local main and recorded origin/main were 0/0; remote freshness was not checked. No commit,
push, fetch, pull, merge or rebase was performed. Previous tracked work, ignored research,
publish outputs and test artifacts were preserved. No recursive cleanup was performed.

Created:

- `src/SafeNook.Storage/SafeNook.Storage.csproj`
- `src/SafeNook.Storage/StorageContracts.cs`
- `src/SafeNook.Storage/WindowsNative.cs`
- `src/SafeNook.Storage/WindowsFileSystem.cs`
- `src/SafeNook.Storage/QualificationStore.cs`
- `tests/SafeNook.Storage.Tests/SafeNook.Storage.Tests.csproj`
- `tests/SafeNook.Storage.Tests/StoreTests.cs`
- `spikes/StoreQualification/StoreQualification.csproj`
- `spikes/StoreQualification/Program.cs`
- `spikes/StoreQualification/GenerationFixture.cs`
- `docs/SN-003B2-IMPLEMENTATION.md`

Modified: `SafeNook.slnx`; `src/SafeNook.Core/Vault/VaultAdmissionPolicy.cs` (public transient
reservation lease, no filesystem dependency); `docs/ROADMAP.md`, `docs/storage-protocol.md`,
`docs/SN-002-VERIFICATION.md`. No files deleted. No new NuGet packages, crypto changes,
wire changes, CLI commands or CI permission changes.

## Layering and native adapter

`SafeNook.Storage` depends on Core; Core does not depend on storage or platform APIs.
`WindowsFileSystem` implements `IVaultObjectSource`. It is deliberately limited to local
fixed NTFS volumes on Windows x64, with absolute drive-letter roots. UNC/network/removable
volumes, other filesystems, other architectures and platforms are not inferred supported.

The adapter opens the drive and every ancestor directory, then keeps those handles alive
without delete sharing. Vault subdirectories are likewise pinned. Child opens use
`NtCreateFile` relative to those directory handles, a single validated component,
`OBJ_DONT_REPARSE`, `FILE_OPEN_REPARSE_POINT` and explicit directory/non-directory options.
This is not a precheck followed by an unanchored path open. Reparse points, non-disk objects,
unexpected directory/file types and hard-linked files are refused. Immutable paths are
constructed only from kind and canonical write ID; imported original names never enter a path.

Creation supplies an explicit security descriptor before bytes are written: current user
owner, protected DACL, one full-control ACE for that user. Opened vault directories/files
are checked through handle-based security queries. Broadened, inherited or unexpected ACLs
fail closed; the adapter does not modify system configuration or repair existing permissions.
Ancestor directories are pinned/type-checked but are not rewritten to vault-private ACLs.
Handle file identity and length are checked around reads. Reads fill only the caller's
bounded destination, check exact EOF at the reported physical end, and never allocate from
an unchecked on-disk length. Security descriptor allocation is bounded separately.

Backup filename enumeration uses the pinned directory path without recursion; enumerated
names are untrusted and actual file reads always use the directory-relative API. Backup
root content must match the requested generation ID, not merely be a valid root with a
different name. Existing immutable objects are never overwritten: even identical supplied
identities are rejected as collisions; callers omit reused objects from the new-object list.
This is the stricter permitted collision policy, without automatic idempotent write retries.

Native interop uses source-generated LibraryImport and explicit x64 layouts. Relevant
primary contracts:

- [NtCreateFile](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile): native relative opens and create options.
- [FILE_RENAME_INFORMATION](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information): destination root handle, replacement flag and exact name length.
- [ZwSetInformationFile](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwsetinformationfile): file-information operations; the user-mode adapter invokes the ntdll Nt entry point.
- [GetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo): handle-based owner/DACL queries and descriptor ownership.
- [GetFileInformationByHandle](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfileinformationbyhandle): volume/file identity and file information.

These references describe APIs, not qualification of SafeNook or a guarantee about every
NTFS/storage-controller combination. Native layout, security and race handling need an
independent review before a production writable path is exposed.

## Locking and publication protocol

An exclusive [LockFileEx](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-lockfileex)
byte-range lock on persistent `.lock` covers the full store lifetime, including reads,
validation, staging and publication. Waiting polls the OS lock with cancellation; it never
uses a PID, deletes the lock file or steals a supposedly stale lock. Closing/terminating
the holder releases the OS lock. In-process operations are also serialised through the
store gate. The caller must dispose the store to release its exclusive lock.

The API accepts a bounded snapshot of encrypted candidate objects and a complete next
header, prepared with the existing Core APIs. Candidate arrays/credentials must be stable
while passed to the API. Trusted reservation leases cover copied transaction buffers;
Core supplies authenticated-state/KDF/blob admission. No plaintext staging occurs.

1. Lock and authenticate the selected live root, manifest, every current item and all blobs.
   Fresh selected-credential authentication is required for each commit.
2. Validate the next root's vault/epoch, generation, parent hash and sequence. Same-epoch VK
   must remain unchanged. Require complete item inventory, explicit tombstones, valid
   revision/hash transitions and immutable references. Reject supplied unreachable objects.
3. Authenticate the complete candidate through an overlay of copied new ciphertext and
   existing immutable files. Verify all candidate blobs, not just their prefixes.
4. Exclusively create CSPRNG-named encrypted `.tmp` files with private ACLs. Write exact
   bytes, check length, flush, compare readback, then rename by handle with no replacement.
   Install item/blob dependencies before the manifest. Check namespace flush results.
5. Reopen installed dependencies and authenticate the candidate. Save the exact previous
   root as `.backup/<oldGenerationId>.json`, or verify an existing identical backup. Preserve
   every old object. No deletion or old-root move is used to make room.
6. Stage and flush the next wrapper. Recheck the live root against the selected old root.
   Use handle-relative native rename: exclusive installation for init, replacement for commit.
7. Flush namespace metadata, read back the published root, verify exact bytes/MAC, and
   **re-authenticate its manifest, items and blobs** before acknowledging the qualification
   commit. An error after the publication attempt marks the handle unusable until reopen.

All real flush return values are checked. On this host, directory-handle FlushFileBuffers
calls returned success. [FlushFileBuffers](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers)
is not treated as portable proof of directory/power-loss durability. `QualificationCommit`
reports `PowerLossQualified=false` even after successful process-visible readback. The
public production write gate remains closed.

| Outcome | Meaning and action |
|---|---|
| Committed | Internal qualification commit passed flush/readback/authentication; **not** production or power-loss qualification. |
| RejectedBeforePublication | Root publication was not attempted; old root remains selected. Encrypted staging/orphans may remain. |
| Indeterminate | Publication was attempted and an error/cancellation occurred before acknowledgement; preserve all candidates, close and explicitly reopen. Never automatically retry the mutation. |
| RecoveryRequired | Selected root/required dependency cannot be verified, or a faulted store needs reopen. Never select an older root automatically. |

## Recovery and retention invariants

Init requires sequence 1, an empty authenticated inventory, both independently verified
slots wrapping the same VK, and a mandatory caller callback returning the re-entered RK.
There is no default affirmative callback in the store API. The returned byte array transfers
to the operation and is wiped; callback failure/mismatch prevents root publication.
Confirmation UX/delivery remains a future application responsibility.

Password replacement verifies the new password slot and preserves recovery bytes exactly.
Recovery replacement preserves password bytes and requires both confirmation of the new
RK and fresh password authentication in this first store API. Recovery-authenticated RK
rotation and full VK/epoch rotation are not implemented; a known password must first be
established through the existing password-replacement path. Both slots cannot change in
one ordinary commit. Failure before publication retains the old root and its recovery path.
Old backups intentionally remain usable with their historical credentials.

`InspectRecoveryCandidate` requires an explicitly selected generation and credential,
verifies its root/manifest/items/all blobs under the OS lock, and returns only its sequence.
It works even when the live root is damaged and never changes it. No restore/rollback API,
automatic fallback, timestamp selection or user recovery CLI is implemented. A future restore
must require explicit rollback confirmation and use a new destination, per the protocol.

The store retains the previous root and all immutable dependencies; older roots/objects
also remain. GC is explicitly refused because durable publication/reachability deletion
qualification is incomplete. No unknown file, orphan, retained dependency or encrypted
staging file is deleted. This is conservative retention, not bounded automatic cleanup or
secure erasure. Disk growth and disk exhaustion remain operational limits.

## Checks and findings

Final executed results on the Windows host:

| Check | Result |
|---|---|
| `dotnet restore` | Passed. |
| `dotnet build -c Release` | Passed, 0 warnings and 0 errors. |
| `dotnet test -c Release` | 169 passed: 122 Core and 47 Storage; 0 failed, 0 skipped. |
| MTP discovery | 169 tests discovered in 2 assemblies. |
| Native AOT store, win-x64, static libsodium | Publish and real NTFS create/commit/backup/blob/reopen passed; directory flush returned true; power-loss qualified remains false. |
| `nook gen` regression | 165 managed and 165 Native AOT checks passed using `tests/Test-Cli.ps1`. |
| Diff and documentation | `git diff --check`, changed/new file whitespace and local Markdown target checks passed. |

Build/test/discovery/publish logs are retained under ignored `artifacts/sn-003b2-*`.
Final Git state contains 5 modified tracked files and 11 new source/project/document files;
none staged, no deletions or unrelated tracked changes. Existing ignored artifacts remain.
Test categories are kept separate; injected errors are not physical disk or power failures.

| Category | Actual coverage |
|---|---|
| Core regression | Existing 122 tests retained. |
| Storage unit/integration | Init/reopen, add/edit/tombstone, slot changes, recovery refusal, retained roots, bounded naming, ACL/type/link checks. |
| Fault injection | Exceptions at 11 commit boundaries; short write/disk-full simulation; file and namespace flush failure; cancellation; post-publication dependency corruption. |
| Real OS failure | Atomic replacement refused by an incompatible open root handle; no blind retry; previous root remains valid after explicit reopen. |
| Process crash | Separate helper killed at 11 boundaries, including after native replacement; selected root reopened and fully authenticated. |
| Process locking | Two independent helpers contend, waiting cancellation, holder termination, waiter acquisition, persistent lock file. |
| Filesystem security | Real junction root rejection, pinned-directory rename refusal, hard-link rejection, inappropriate file rejection, broadened ACL rejection. |
| Native AOT | Real NTFS create/commit/backup verification/blob decrypt/reopen using static libsodium, not a mock filesystem. |
| Power loss | **Not run.** Process termination leaves the OS/cache running and is not a power-cut test. |

An initial AfterPublish crash test failed closed with native error 32 (sharing violation).
The preserved artifact later authenticated as the complete new generation; it was not a
mixed-generation success. Read-only opens now retry only that error, under the acquired OS
lock, at most 50 waits of 10 ms. Persistent conflicts still return RecoveryRequired. This
handles observed transient handle contention without retrying publication. Exact kernel/
filter-driver cleanup timing is not claimed proven. Eight extra AfterPublish kill/reopen
runs and a deterministic transient/persistent-sharing test exercise this change.

A separate harness issue was corrected: the qualification project was initially built in
Debug through an unmapped solution reference while tests launched its older Release helper.
It is now an explicit solution project, and test helper selection follows build configuration.
The final runs use current binaries. Earlier failed logs/artifacts were preserved.

Tests additionally verify that corruption after publication but before acknowledgement
returns Indeterminate; normal reopening rejects the damaged current root, while explicit
backup inspection succeeds without altering live root bytes. A wrong password rejects a
commit without invalidating an otherwise usable store; corruption of current dependencies
during commit returns RecoveryRequired and invalidates the state. Errors contain fixed codes,
not credentials, plaintext JSON or injected source messages. Staging scans found ciphertext
or root wrappers, not synthetic password/item plaintext.

## Platform matrix and remaining work

| OS / filesystem | Execution | Writable production status |
|---|---|---|
| Windows x64, NT 10.0.26300.0, local fixed C: NTFS | Real filesystem tests, process contention/crashes and Native AOT executed | Blocked: no power-loss qualification or independent native review |
| Windows ARM64 / ReFS / removable / network | Not tested; adapter refuses unsupported architecture/volume types | Unsupported |
| Linux / ext4 / XFS / other | No adapter implemented or executed | Unsupported |
| macOS / APFS / other | No adapter implemented or executed | Unsupported |

For Linux, implement and qualify handle-relative openat/openat2 no-follow/beneath behavior,
owner/mode/link checks, OS locks, no-replace installation, rename and ordered file/directory
fsync. For macOS, separately qualify corresponding anchored APIs, APFS rename semantics,
directory persistence and F_FULLFSYNC. Do not copy the Windows result into either matrix row.

Outstanding: destructive power-cut VM/device campaigns, storage/controller/cache coverage,
independent review of NT interop/ACLs/TOCTOU, real quota/ENOSPC tests, safe reachability GC,
full backup/restore and full epoch rotation. The API serialises large reads but has not had
a new process-memory benchmark. Same-user malware/compromised OS and complete rollback
remain explicit non-goals, not solved by locks, ACLs or parent hashes.

The next stage should review this internal API and qualify Windows durability before exposing
production writes; implement/test additional OS adapters independently. Keep CLI vault,
backup/restore UX, sync/agent/GUI and KDF worker behind separately authorised scopes.

Suggested Conventional Commit:

```text
feat(storage): add NTFS COW store and crash qualification tests
```
