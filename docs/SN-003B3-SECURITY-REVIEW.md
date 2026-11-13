# SN-003B3 — Windows storage security and durability review

Date: 2026-11-13. Scope: Windows x64, local fixed NTFS; existing SN-003B2 internal API.
**Production writes remain disabled. GC remains disabled.** No crypto, wire format,
CLI behavior, dependency or CI changes. This is an implementation review against primary
contracts with new regression tests, not independent third-party security certification.
The authoring agent also contributed to SN-003B2; independent human/native review remains open.

## Baseline and reproducibility

Clean working tree on `feat/sn-003b2-secure-filesystem-store`, HEAD `c96c658`.
That commit contains all 16 SN-003B2 files, despite its unrelated commit subject
`perf(import): cache successful image validation by content and settings`.
After explicit owner approval to branch from this base rather than older main,
created `feat/sn-003b3-windows-storage-qualification`. No commits or network Git operations.
Local main and recorded origin/main remain `0236873`; remote freshness is unknown.
Existing ignored artifacts and research outputs were preserved.

## Findings and changes

| ID | Finding | Change / evidence | Limit |
|---|---|---|---|
| B3-01 | Raw directory handles embedded in native structures bypass SafeHandle parameter retention. The store gate reduced exposure but did not express native-call lifetime ownership. | Explicit `NativeHandleLease` uses DangerousAddRef/Release for relative open and rename. NtCreateFile returns an owned SafeFileHandle directly. Test disposes original owner while the lease keeps the OS handle valid, then checks final release. | Defensive lifetime fix; no demonstrated exploit of the previous serialized store. |
| B3-02 | ACL validation accepted a callback CommonAce with matching qualifier/SID/mask although the contract permits only a plain allow ACE. | Reject IsCallback; a synthetic descriptor test exercises this precise acceptance gap. | Not evidence of privilege escalation; real broadened ACL tests remain separate. |
| B3-03 | Root changed/deleted after initial authentication could be reported as ordinary pre-publication rejection, leaving cached state usable. | Final root read/binding failures invalidate state and return RecoveryRequired. Tests mutate/delete the selected root after root staging. | Same-user malware remains outside the threat model. |
| B3-04 | Backup reuse enumerated all directory entries into an unbounded array through a path. | Read only the exact expected backup via relative handle; only native file-not-found permits creation. Existing backup must match; reflush its namespace. Unknown entries never drive selection. | No garbage enumeration/deletion introduced. |
| B3-05 | Rename buffer used field offset plus filename bytes, smaller than the WDK documentation's sizeof-plus-name requirement. | Allocate 24 + UTF-16 filename byte count on x64, zero padding, retain length at offset 16/name at 20. | Old length worked on the host; compatibility hardening to the documented bound, not proof of a prior memory overrun. |
| B3-06 | Pinned namespace ACLs and saved previous root were not rechecked immediately before publication. | Validate vault/subdirectory/lock handle security at commit start, before publication, and after publication; compare the saved previous root before publication. ACL/backup mutation tests refuse acknowledgement. | Cannot make ACLs immutable against the same user/admin or atomically freeze all files against a hostile OS. |
| B3-07 | A pre-cancelled direct adapter creation could create directories before observing cancellation. | Observe cancellation before filesystem creation; regression verifies no directory appears. | No rollback/deletion of already written ciphertext on later cancellation. |

`Committed` still means internal process-visible flush/readback/authentication, with
`PowerLossQualified=false`. Failure after root publication is attempted is Indeterminate;
no automatic mutation retry. Corrupt current root/namespace or previous-root check yields
RecoveryRequired. A normal injected pre-publication fault remains RejectedBeforePublication.

## Native API audit

- **ABI:** SDK 10.0.26100.0 `winternl.h`, `fileapi.h`, `minwinbase.h`, `winbase.h` were read
  locally. `WindowsAbiProbe.cpp` compiles x64 static assertions against SDK declarations;
  managed tests assert sizes/offsets independently. UNICODE_STRING 16, OBJECT_ATTRIBUTES 48,
  IO_STATUS_BLOCK 16, BY_HANDLE_FILE_INFORMATION 52 (Pack=4), OVERLAPPED 32; rename prefix
  offsets 8/16/20 and SDK structure size 24. FILETIME consists of two DWORDs, explaining
  the four-byte layout. The SDK FILE_RENAME_INFO sequence is checked; WDK `ntifs.h` is
  not installed/compiled, so its native declaration is separately checked against Microsoft docs.
- **Marshalling:** x64 Windows ABI, UTF-16 strings, BOOL as 32-bit marshalled Bool,
  NTSTATUS as signed int, pointer-sized union slot/ULONG_PTR, explicit SetLastError only
  for Win32 error APIs. LibraryImport-generated stubs and Native AOT are exercised.
  FILE_SYNCHRONOUS_IO_NONALERT plus SYNCHRONIZE makes IO_STATUS_BLOCK stack storage valid
  for these synchronous operations. x86/ARM64 are refused, not inferred from x64 results.
- **Relative paths:** one validated component, parent handle, OBJ_DONT_REPARSE and
  FILE_OPEN_REPARSE_POINT; every opened object is type/reparse checked. No check-then-open
  of a full child path. Ancestors and store directories stay open without share-delete.
  [NtCreateFile](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile)
  and [OBJECT_ATTRIBUTES](https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_object_attributes)
  define the relative-name and no-reparse inputs.
- **Ownership:** SafeFileHandle owns returned handles; embedded handles get explicit leases.
  Failed validation disposes handles, constructors unwind pinned handles and LocalAlloc
  descriptors, temporary rename buffers use finally. Store gate serializes operations and
  Dispose; the low-level internal adapter itself is not a public concurrent API.
  [DangerousGetHandle](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.safehandle.dangerousgethandle?view=net-10.0)
  does not itself protect lifetime. Close is not used as a durability acknowledgement;
  SafeHandle/LocalFree cleanup failures are not injectable/tested and are an audit limitation.
- **ACLs:** current-token owner, protected DACL, exactly one noncallback owner full-control ACE;
  security is supplied at creation before writing. GetSecurityInfo uses READ_CONTROL,
  returns LocalFree-owned storage, and is rechecked around reads/publication. Its documented
  concurrent-security-change caveat prevents treating the check as an immutable ACL guarantee.
  [GetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo).
- **Identity/links:** disk object, expected directory bit, no reparse bit, one link for files;
  bounded exact-length/EOF reads and before/after file identity. Read handles deny write/delete
  sharing. Tests exercise junctions, hard links, wrong file types and pinned directory moves.
  Already-open hostile memory mappings/admin actions are not defeated by share flags.
- **Lock:** persistent file, exclusive LockFileEx range, fail-immediate bounded polling with
  cancellation, no PID takeover, close releases lock. Independent-process contention and
  termination tests run. This coordinates cooperating store clients, not an adversary ignoring
  the protocol. Microsoft notes release after termination can be delayed and mapped views
  are not blocked by the byte-range lock.
  [LockFileEx](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-lockfileex).

## Durability reasoning and guarantee matrix

The order remains encrypted object write/file flush/readback -> immutable install ->
namespace flush -> manifest authentication -> exact old-root backup -> next-root staging/
file flush -> relative same-volume rename/replace -> namespace flush -> exact root readback
and full dependency authentication. No delete-old-then-move-new and no plaintext staging.

[FILE_RENAME_INFORMATION](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information)
specifies same-volume rename, target replacement/collision behavior, relative destination,
DELETE access and buffer sizing. This establishes the operation requested, not a promise
that every NTFS/controller/cache combination persists a multi-file transaction across power loss.

[FlushFileBuffers](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers)
requires write access and reports flush failure; volume flushing requires a privileged volume
handle. This implementation does not silently acquire such privileges. Successful flushes
on directory handles were observed, but a supported ordering/durability contract equivalent
to POSIX directory fsync has not been established for this protocol.

Microsoft's [File Caching](https://learn.microsoft.com/en-us/windows/win32/fileio/file-caching)
explains cached data/metadata, lazy writes and loss of unflushed cache after failure. Readback
may be satisfied by OS caches. A controller that loses volatile cache or misreports flush
completion can invalidate persistence assumptions. Controller fault handling and physical
power removal need dedicated equipment and evidence; neither is simulated by killing a process.

| Property/scenario | Evidence | Status |
|---|---|---|
| Cooperative one-writer/read consistency | Real independent processes, cancellation, holder termination | Tested on this host |
| Process-crash consistency | 11 commit boundaries; reopen authenticates old/new generation | Tested; no power-loss inference |
| Namespace replacement / collision refusal | Real NTFS rename, sharing-error path, immutable installation | Tested operation semantics; not a universal NTFS atomicity proof |
| Full current/retained authentication | Items/blobs/manifest/root, all selected retained generations, corruption tests | Tested synthetic generations |
| ACL/path constraints | Real ACL/junction/hardlink/type tests plus callback ACE/ABI checks | Tested subset; external native audit open |
| Late dependency substitution | Delete/replace after verification leads to Indeterminate then refused reopen | Tested; no mixed-generation success |
| Disk full/short write/flush error | Fault injection and actual rename rejection | Simulations except native rename; real ENOSPC/quota not run |
| Namespace ACL/backup change | Pre/post-publication mutation tests | Refuses acknowledgement |
| Power loss / controller reset / volatile write cache | No destructive rig available | Unqualified |
| Windows x64 local fixed C: NTFS | Real managed and Native AOT execution | Internal qualification only |
| ARM64, ReFS, network/removable, Linux/macOS | Not executed; adapter refuses | Unsupported |

A crash before publication may leave encrypted orphans. After publication attempt, either
root may be visible; missing/corrupt required dependencies require explicit recovery. After
power loss even an acknowledged process-visible result is not yet promised durable. A future
power-loss acceptance campaign must distinguish pre-ACK ambiguity from loss of acknowledged
commits. Older-root recovery is explicit and may mean data loss; it is never silent fallback.

## GC and retention proposal (not enabled)

Retain current and previous confirmed root, every explicitly retained historical root, and
all uncertain commit candidates/dependencies. Unknown files and encrypted `.tmp` evidence
remain untouched. Current code returns a refusal and deletes nothing; tests compare the
complete file inventory and verify every retained generation, including after tombstones.

Before any future destructive GC:

1. Acquire the same exclusive OS lock and a trusted bounded enumeration budget. No timestamps
   or directory names establish that a root is authoritative. Refuse if commit status is uncertain.
2. Authenticate current root, previous root, every retained/candidate root and each manifest,
   item and blob. Old credentials may be required after slot rotation. If a root is unreadable,
   unknown, corrupt or unavailable, abort deletion rather than treating it as unreachable.
3. Build the union of authenticated write IDs, types, sizes and hashes. Never delete current
   root, previous root, retained roots or dependencies, unknown names/types/versions, links,
   malformed ciphertext, or files whose ownership/identity cannot be established.
4. Only a known, fully authenticated object with proved origin/context and no reachability
   from that union could become a candidate. A mere orphan envelope is insufficient: v1 has
   no durable commit-intent registry proving an orphan is outside an uncertain commit. Retain it.
5. Revalidate selected roots, native handle identity, ACL/link status and membership immediately
   before handle-relative deletion. Qualify crash ordering for retention-set updates and deletion;
   do not release a root's protection based only on an in-memory decision.
6. Begin with a bounded read-only dry-run plan, fuzz graph/identity races, inject failures at
   every deletion boundary and validate all retained generations after actual disk crashes.

No new intent log/wire format is introduced by this task. Durable retention policy and a proof
of safe orphan classification need separate design approval; disabled GC is the current safe
policy. Disk growth is explicit, not hidden by opportunistic cleanup.

## Executed checks

| Check | Actual result |
|---|---|
| Release build (`dotnet build -c Release --no-restore`) | Passed, 0 warnings / 0 errors. |
| Full suite (`dotnet test -c Release --no-build`) | 182 passed: 122 Core + 60 Storage; 0 failed / 0 skipped. |
| MTP (`dotnet test -c Release --no-build --list-tests`) | 182 discovered in 2 assemblies. |
| Native AOT store, win-x64, existing static libsodium | Publish and real NTFS create/commit/backup/blob/reopen passed; directoryFlush=True, powerLossQualified=False. |
| CLI regression (`tests/Test-Cli.ps1`) | 165 managed + 165 Native AOT checks passed; native CLI freshly published. |
| SDK C++ ABI probe | MSVC x64, explicit Windows SDK 10.0.26100.0, /W4 /WX, all static assertions passed. |
| Documentation / diff | Local Markdown targets and changed/new-file whitespace checked; git diff --check passed. |
| Destructive power cut / physical controller loss / real quota | Not executed; see lab plan and limits above. |

The 13 added cases cover managed ABI offsets, raw-handle owner disposal, callback ACE,
changed/deleted root, replaced/deleted manifest after verification, every retained generation,
unknown backup entries, cancelled creation, damaged previous root, and ACL changes before/after
publication. Existing 11 process-kill boundaries, independent-process contention, real native
rename rejection, injected disk-full/short-write/flush errors and plaintext-staging checks
were rerun. This is not a new memory/performance benchmark or physical disk-failure campaign.

An intermediate run reported 181/182 passing: an injected BeforePublish exception was
misclassified as RecoveryRequired by the new checking-current scope. The hook was moved
outside that scope and the complete suite rerun successfully. The failed log is preserved
as `artifacts/sn-003b3-tests-intermediate-failure.log`; other logs use `sn-003b3-*`.
An initial discovery invocation with an extra `--` produced no listing; the exact direct
`--list-tests` command above produced the verified 182-test listing.

SDK probe reproduction from an x64 VS developer prompt with SDK 10.0.26100.0:

```text
cl /nologo /W4 /WX /EHsc spikes\StoreQualification\WindowsAbiProbe.cpp /Foartifacts\sn-003b3-abi.obj /Feartifacts\sn-003b3-abi.exe
artifacts\sn-003b3-abi.exe
```

Modified files:

- `src/SafeNook.Storage/WindowsNative.cs`: owned native return handles and explicit embedded-handle leases.
- `src/SafeNook.Storage/WindowsFileSystem.cs`: strict ACL, exact backup lookup, namespace revalidation, documented rename allocation, early cancellation.
- `src/SafeNook.Storage/QualificationStore.cs`: current/backup/namespace checks and correct failure outcomes.
- `tests/SafeNook.Storage.Tests/StoreTests.cs`: 13 additional regression cases.
- `docs/ROADMAP.md`, `docs/SN-002-VERIFICATION.md`: qualification status and links.

Created: this report, `docs/SN-003B3-POWER-CUT-PLAN.md`,
`docs/SN-003B3-PRODUCTION-WRITES-CHECKLIST.md`, and
`spikes/StoreQualification/WindowsAbiProbe.cpp`.
Final Git state: 6 modified tracked files, 4 new files, none staged, none deleted, no unrelated
tracked changes. Base and HEAD remain `c96c658a6e423e5964d89733d0b0a217e06255dc`.
No source VM, system security setting, quota, production gate or historical SN-003B2 report
was changed. Existing ignored artifacts were retained.

## Next stage

Use the [production-write checklist](SN-003B3-PRODUCTION-WRITES-CHECKLIST.md) and
[destructive qualification plan](SN-003B3-POWER-CUT-PLAN.md). Obtain independent native
review, build an isolated lab, run real quota/full-volume and power-cut campaigns, then bring
results to the owner. Do not expose production writes, GC or new product features automatically.

Suggested commit:

```text
fix(storage): harden Windows native IO and document durability gates
```
