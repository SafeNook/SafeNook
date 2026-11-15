# Storage transactions and recovery — SN-002 draft

Status: Accepted architecture under SN-002-R2, 2026-11-12; [ADR 0008](adr/0008-generation-commit.md).
The internal Windows x64/NTFS implementation and executed process/fault tests are recorded
in [SN-003B2](SN-003B2-IMPLEMENTATION.md). Power-loss durability remains unqualified and
production writable mode remains refused; this does not weaken the release gate below.
This protocol uses the exact authenticated references in [vault-format.md](vault-format.md).
It does not claim that File.Move/File.Replace alone makes a directory transaction durable.

## Alternatives and recommendation

| Approach | Complexity | Crash/recovery characteristics | Future sync |
|---|---|---|---|
| Replace individual live files | Low | Atomic file does not prevent item/blob/header combinations from different transactions | Easy files, unsafe whole-vault snapshots without another protocol |
| Write-ahead journal/transaction manifest | Medium/high | Needs authenticated replay, idempotence, ordering, journal truncation and recovery-state rules | Journal replay conflicts across devices need another protocol |
| Immutable COW object versions + one root | Medium; recommended | Publish dependencies first, root last; old state remains addressable; extra disk/GC needed | Preserves alternate versions, but does not resolve concurrent roots |
| Entire directory generation copy | Simple selection, high I/O | Complete snapshot per mutation; expensive with attachments | Large churn; not necessary for unchanged encrypted files |
| Database/WAL | Mature transactions if qualified | Additional dependency/format, not ADR 0004's file-per-record model | Binary merge and deployment complications |

Choose immutable per-write files and encrypted manifest, with `vault.json` the only live
commit point. Every read/write in M1/M2 holds an **exclusive OS lock** on persistent `.lock`
from root selection through output/mutation completion. Serial reads are deliberately
simple. Locks are cooperative; malware with equivalent permissions is outside this guarantee.
No process-ID existence check, lock-file deletion on unlock, or timestamp stale-lock takeover.
Process termination releases the OS lock; persistent file remains. A cancelled lock wait
has no side effects. Lock unsupported or ownership uncertain means fail closed.

## Path and permission rules

Open a trusted vault parent/root through directory handles, refuse symlink/reparse roots
and components, validate opened file identity/type and prevent follow-on path substitution.
Use handle-relative operations (POSIX openat/no-follow equivalents; Windows opened-directory/
reparse-aware operations), not a vulnerable check-path-then-open sequence. Reject hard-linked
mutable root/lock/staging files and unexpected hard links on owned object files; unsupported
link-count or path guarantees block qualified writable operation. Scope is supported local
filesystems, not arbitrary network shares or a folder concurrently edited by cloud sync.

Create directories0700 and files0600 on POSIX independent of a permissive umask. On Windows
create restrictive protected DACL before data is written and verify it; ACL errors abort.
Reject non-regular files/devices, Windows alternate data streams and unexpected directory
structure. Never use imported filenames as paths. `.tmp` contains only encrypted files and
bounded header wrappers; no plaintext KDF inputs, RK, decrypted blobs or item JSON on disk.
Disk-space preflight is advisory; every short write/flush/rename error is handled.

## Transaction state machine

All writes happen on the same filesystem. The current root must already fully authenticate.
For initial creation there is no old root, parentHash=zero, sequence=1; do not expose a usable
vault until RK delivery/acknowledgement succeeds. Create into a fresh private directory,
never initialise over an existing nonempty target. The identity of the lock inode/file
must remain stable throughout initial publication and later access.

1. **Lock and validate.** Authenticate current root and items, validate mutation and budgets.
   Snapshot current decoded-header hash; recheck it immediately before publication to detect
   cooperative mistakes/external writes. This is not a defence against same-user malware.
2. **Prepare immutable dependencies.** Encrypt changed items/blobs with fresh write IDs into
   `.tmp`; no user-visible success. Complete writes, flush file content, install each at its
   final generated path by no-replace rename, flush relevant parent directory where supported.
   Existing names are fatal collisions unless exact existing encrypted bytes are verified
   as this transaction's idempotent installation. Unchanged files may be reused unchanged.
3. **Prepare manifest.** Build complete bounded inventory including tombstones; authenticate
   references/limits, install and flush its encrypted file similarly. Reopen/readback all
   new files, verify hashes, tags and schemas; validate unchanged referenced files before
   commit (including blobs for credential rotation/full backup). Abort on inconsistency.
4. **Retain prior root.** Exclusively create `.backup/<oldGenerationId>.json` with exact old
   header bytes, flush file and directory. Verify existing backup of that name or fail.
   Preserve its dependencies. First init has no prior root. Recovery/new-key confirmation
   must be complete before proceeding.
5. **Prepare next root.** New generationId, sequence+1, parent hash, manifest reference;
   keep/correctly rewrap slots, compute MAC. Write and flush a restrictive `.tmp` root,
   reopen/authenticate it and its manifest before publication.
6. **Commit.** Atomically replace `vault.json` (exclusive installation on init) using the
   qualified platform adapter. Flush required namespace metadata; re-read and authenticate
   the resulting root. A durable-success acknowledgement is emitted only after required
   flushes succeeded. Never implement replace by delete-old-then-move-new.
7. **Post-commit.** Keep the new current and its immediate previous root; GC is a separate
   locked operation. Wipe operation buffers, release lock. If a post-publication flush or
   acknowledgement fails, report **commit outcome uncertain**, preserve all candidates and
   require reopen. Do not report an ordinary retryable abort or blindly repeat a mutation.

## Whole-object blob boundary and resource failure

Blob v1 is envelope118 + ciphertext[L] + tag16, algorithm1, maximum 26,214,534 bytes.
Its single GCM tag, exact size/EOF, context and manifest hash must pass before export or
commit validation succeeds. No partial plaintext/chunk publication is allowed. Reserve
space for separate ciphertext/plaintext arrays (2L, up to 50 MiB) plus operational overhead,
and for old/new COW files on disk. Check local admission and serialize/bound large operations.
OOM, failed authentication or cancellation before root publication leaves the old root;
clean only owned staging files, wipe sensitive buffers, and never overwrite existing data
or silently switch algorithm/limits to recover. After root publication retain the existing
uncertain-commit handling; cleanup cannot pretend a published commit never happened.

## Failure matrix and explicit recovery

| Interruption point | Expected process-crash state | Reopen/recovery |
|---|---|---|
| Before any new files | Old root | Normal old generation |
| Partial ciphertext/temp | Old root plus unreachable files | Ignore temps; later conservative GC |
| Complete objects, no manifest | Old root plus orphans | Never import orphan records automatically |
| Manifest ready, root not replaced | Old root; new candidate exists | Old generation; candidate is not committed by timestamp/sequence alone |
| During atomic replacement | Old or new root under qualified atomicity | Authenticate selected root/dependencies; otherwise recovery-required |
| After replace, before durable flush/ack | New visible root, durability uncertain | Reopen and inspect; power loss may lose new namespace writes |
| After durable commit | New root, previous root retained | New generation; old backup intentionally still decryptable |
| Missing/invalid live root or dependency | No complete normal session | Preserve evidence; enumerate explicit recovery candidates, no silent fallback |

A valid HMAC plus missing referenced file is not a valid complete generation. Do not
combine files from arbitrary generations by matching logical IDs. Recovery verifies each
candidate root with a credential, manifest, all item schemas and **all blob authentication**.
Present candidate identity and omissions; do not select highest sequence/time automatically.
A complete older generation can be restored only after explicit rollback confirmation.
Copy it into a **new destination directory** and verify before presenting success; leave the
original damaged directory untouched. Incomplete salvage exports only individually verified
objects with a loss report, never labels the result a complete restore.

A lost password can be recovered only from an authentic intact root with its recovery slot.
Header corruption may require a previous root and its credential; recovery key is not a
replacement for that root. A previous root may lack newly added objects and may need an
older RK. User must distinguish restored access, restored data and recovered latest state.

## Filesystem qualification and durability limits

On POSIX, file fsync does not by itself persist its directory entry: the adapter must fsync
affected directories in dependency-before-root order. This requirement follows
[fsync(2)](https://man7.org/linux/man-pages/man2/fsync.2.html). Atomic rename is a visibility
primitive; test the filesystem's power-loss ordering separately. On macOS investigate and
qualify F_FULLFSYNC and directory/rename ordering on APFS; do not infer hardware durability
from a generic successful flush. No macOS adapter was implemented or power-tested in SN-002.

On Windows, use explicit file flush and qualified replace/creation operations with ACL
preservation and errors checked. [FlushFileBuffers](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers)
flushes file buffers; [ReplaceFileW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-replacefilew)
has documented partial-failure states and does not support REPLACEFILE_WRITE_THROUGH.
Do not claim portable directory-flush guarantees or ignore replacement/ACL errors.
Verify resulting candidates after any ambiguous failure. NTFS/Windows durability requires
power-cut VM/device qualification; ReFS/removable/network filesystems are not inferred safe.

Required guarantees are: no mixed generation presented as valid, no old reachable data
removed before durable new root, and explicit uncertain/recovery-required errors. On
unqualified storage, M1/M2 writable mode is refused; a read-only verification/salvage mode
may operate without claiming durability. Even qualified storage may lie about flush or fail
physically; independent backup is mandatory operational guidance. This is a release gate,
not an unresolved binary format field. Power loss can still require explicit backup restore.

## Backup, rotation, garbage collection and sync boundary

Encrypted backup in M1 is a private directory snapshot: while holding lock, copy the current
root and exactly its manifest-reachable immutable files into a fresh destination, excluding
`.lock`, `.tmp`, previous roots and unrelated files. Verify source/copy complete hashes,
authentication and schemas; flush destination and publish its root last. No archive parser
or plaintext export is needed. A backup created from an uncoordinated directory copy may
be inconsistent and is not reported verified. One-file backup packaging is future scope,
not an invented implicit zip format. Backup verification never prints secret values.

Restore to a new directory validates every byte before activation, creates a fresh lock,
refuses overwrite of existing content, reports historical credentials/epoch and rollback
limitations. Restoring keeps the snapshot root; the first subsequent mutation generates
fresh IDs/nonces and parent linkage. It does not manufacture a trusted newer chronology.
New VK rotation is a normal full COW transaction: both current and previous epochs may
coexist physically for recovery. A saved old root can still unlock that older epoch.

GC: lock; authenticate/validate all retained roots and reachability first. Mark files
reachable from current and the one automatic previous root plus any explicitly retained
local recovery candidates. If any retained root is malformed/unsupported/unauthenticatable,
stop GC rather than deleting its possible dependencies. Remove only generated regular
files positively proven unreachable after successful durable commit; never follow links,
never traverse external backups, never delete unknown filenames. Delete obsolete backup
root only after policy confirmation/new previous root is durable, then perform reachability
again. An old epoch whose credential is unavailable blocks automatic cleanup, requiring a
separate explicit destructive decision after independent backup verification. Tombstone
purge and user history retention are separate, not inferred from orphan GC or wall clock.
Deletion is not secure erasure on CoW/SSD/snapshots.

M1/M2 do not allow concurrent sync tools to mutate an active vault. Future sync must preserve
conflicting roots/items and resolve slot changes, delete-vs-edit and blob GC explicitly.
Parent hashes and immutable versions aid analysis; they are not signatures, causal vectors
or an external anti-rollback anchor. Revision/updatedAt alone never selects a winner.
