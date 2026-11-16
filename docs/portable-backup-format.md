# Portable encrypted backup container — proposal v1

Status: Accepted for SN-003D1 by the owner; implementation qualification is separate. See
[ADR 0010](adr/0010-portable-backup-container.md). Existing directory snapshot rules in
[storage protocol](storage-protocol.md) are extended by this approved container.
This is framing of existing authenticated vault bytes, not a new cryptographic protocol.

## Binary encoding

All integers unsigned little endian, no padding except explicit zero reserved bytes.
One file (suggested extension .snbak), no compression, ZIP, paths, timestamps, permissions,
comments, indexes, additional encryption, checksum or signature. Exact EOF is mandatory.

| Offset | Size | Field |
|---|---:|---|
| 0 | 8 | ASCII SNBACKUP |
| 8 | 2 | Container version = 1 |
| 10 | 2 | Flags = 0 |
| 12 | 4 | Encrypted object count N, 1..20,001 |
| 16 | 8 | Exact total file length, at most 2,147,483,648 bytes |
| 24 | 414 | Exact decoded authenticated vault header |
| 438 | variable | N object frames |

Each frame is: kind (1 byte: 1=item, 2=blob, 3=manifest), seven zero reserved bytes,
LE64 ciphertext-file length, then that many exact bytes of an existing envelope+ciphertext+tag.
The frame kind must equal envelope kind. No filename or logical ID is supplied separately.
Exactly one manifest comes first; items then blobs, each group in strictly increasing raw
32-byte write-ID order. Reject duplicate write IDs globally, duplicate logical references,
unknown kinds/versions/flags, nonzero reserved bytes, wrong order, trailing or truncated data.
Total length is 438 + 16*N + sum(ciphertext-file lengths), checked for overflow.
For an empty vault N=1: length is 454 + encrypted manifest length (not zero).

Bounds from [vault format](vault-format.md) remain unchanged: item ciphertext <=65,670,
manifest <=8,388,742, blob <=26,214,534; minimum object length 134. At most 10,000 items
including tombstones and 10,000 blobs. Aggregate plaintext limits remain 256 MiB items and
1 GiB blobs. Container ceiling is an independent reject limit, not permission to exceed
vault limits. Trusted RAM/KDF admission can refuse an otherwise valid backup. Never allocate
the entire container or trust frame counts/lengths before bounds and checked arithmetic.

## Authentication and exact inventory

Select exactly one credential kind explicitly. Validate header structure/KDF admission,
unwrap that slot and verify the complete header MAC. No slot fallback. Authenticate the
manifest against header generation/write-ID/hash, then validate all item schemas, references,
context, sizes and hashes using existing Core. Include tombstones and exactly every object
referenced by this selected manifest; no retained roots, historical revision files, orphan
objects, lock/temp files or memory secrets. A revision predecessor hash is not an instruction
to include historical files. Historical parent root need not exist in a standalone snapshot.

Authenticate EVERY blob AEAD tag with its full ciphertext in bounded RAM, sequentially,
then wipe plaintext before proceeding. Successful normal Open is insufficient. Require exact
bijection of frames and authenticated references, exact physical lengths and EOF. Missing or
extra frames fail. Framing is not separately MACed: strict canonical parsing plus the existing
root/manifest hashes and contextual AEAD validate every accepted payload. An attacker replacing
the entire file with an authentic older snapshot is still undetectable without trusted external
state. Header identifiers, sizes/counts and ciphertext lengths are not confidential metadata.

## Export and restore protocol

Export holds the existing exclusive source lock from selecting root through complete copying
and verification. Read through pinned relative handles; generate inventory from authenticated
manifest, not filesystem enumeration. Write only ciphertext/header into an exclusively created
private staged file in a trusted destination parent. Reopen the staged container and perform
full verification including every blob, flush, no-replace publish, validate readback before
success. No stdout export. Reject destinations inside the source vault. On prepublication
failure leave no final backup; retain/report uncertain publication without automatic retry.

Restore accepts only a newly created destination directory; reject ALL pre-existing paths,
even apparently empty ones (a conservative subset of new-empty-directory requirement).
First fully verify a safely opened input snapshot; pin its handle against substitution and
copy only ciphertext into private staging if a stable source cannot be guaranteed. Then
create a fresh protected destination with existing native path/ACL/reparse/hardlink checks.
Derive object filenames only from validated kinds and write IDs. Never extract archive paths.
Install exact immutable bytes without encryption, preserving IDs, header, sequence, epoch,
slots and VK; create a fresh local lock and empty operational directories, not imported ones.
Revalidate installed dependencies and all blob tags, flush them before publishing a canonical
vault.json wrapper of the exact 414 header bytes LAST. Existing Create (which initializes a
new vault/recovery delivery) must not be used to change the imported root. A dedicated internal
RestoreVerified operation must enforce all validation itself, not trust a caller-supplied bool.

Reopen the resulting vault with the selected historical credential and fully verify blobs
again before success. Prepublication failure/cancellation leaves no live root. After publication
failure/cancellation is Indeterminate: preserve destination and require explicit verification;
do not claim no root exists or delete an authentic published vault. No automatic old-generation
selection, overwrite, rollback repair, retry, GC or cleanup of unknown files. Wipe owned secret
buffers on every exit. Process consistency is not power-loss qualification.

## Application, CLI and production policy

Application Backup, VerifyBackup, Restore accept explicit source/destination and credential kind;
credentials only through existing protected interaction. Proposed CLI: backup --vault PATH --output
PATH; backup verify --input PATH; restore --input PATH --vault NEWPATH; explicit --credential
password|recovery (default password). No credential values in argv/env. Output contains safe status
only. Backup and restore are writes and return 5 before credentials while gate is closed; verify
is read-only. Internal synthetic harness exercises writes, with no public qualification switch.
Physical format is portable; initial filesystem implementation remains Windows x64/local NTFS.
Linux/macOS are not qualified merely because bytes are platform-independent.

## Required implementation validation

Deterministic framing fixtures built around existing independent crypto vectors; exact offsets,
length sums, endian/order, unknown fields, truncation at every structural boundary, overflow,
2 GiB ceiling, per-object/aggregate limits, duplicates, extra/missing frames, swapped context.
Round-trip empty/login/note/tombstone and attachments (empty, 1 byte, 25 MiB), password and
recovery, source removed after backup, byte-identical header/objects after restore. Mutate root,
manifest, item, blob/tag independently and require failure. Test wrong credentials and checksum.

Inject short write, disk full, flush/rename/readback errors, cancellation and process termination
before/after root publication. Test archive replacement, reparse/hardlink/ACL/path races and
existing empty/nonempty destination refusal. Before publication assert no vault.json; afterwards
assert explicit uncertain outcome and reopen rather than automatic retry. Scan outputs/errors/
staging for synthetic plaintext. Run Release build, full MTP/discovery, native AOT harness and
CLI/gen regressions. Test all blobs: corrupt a blob whose item is never explicitly shown.
Executed results and remaining limits are recorded in [SN-003D1 implementation](SN-003D1-IMPLEMENTATION.md).

## Approved clarifications

Backup creates a verified encrypted artifact; VerifyBackup performs complete credential-based
cryptographic verification, including ALL blob AEAD tags; Restore verifies and publishes a new
vault. These are separate operations, not aliases for normal Open.

An optional SHA-256 of every byte of the complete archive may be returned for external comparison.
It is not stored in the container, replaces no authentication check and prevents no rollback
without a trusted external reference.

The 2,147,483,648-byte ceiling is an independent defensive transport/parser bound, with room
for the existing aggregate payload limits and framing. It does not raise any vault limit or
require a 2 GiB allocation. Parsing is sequential, retaining bounded metadata and at most one
object buffer; subsequent authenticated reads use a bounded offset index on the pinned input.
