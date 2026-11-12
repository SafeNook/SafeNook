# SafeNook threat model — SN-002 draft

Status: proposed specification, 2026-11-12. No implementation or security certification.
Owner-confirmed scope: local-first, mandatory recovery in M1, developer-secret storage
in M2; no PasswordGeneratorCLI compatibility. See [decision register](SN-002-DECISIONS.md),
[wire format](vault-format.md), [recovery](recovery-and-io.md) and
[verification plan](SN-002-VERIFICATION.md). New ADRs remain Proposed.

## Assets, actors and trust boundaries

Assets include passwords, private/public key material, file contents, notes, titles,
URLs, usernames, tags, relationships, history, key slots, master-password bytes,
recovery key (RK), Vault Key (VK), derived keys and authentic backup inventories.
Public keys may still identify users and are private metadata by default.

The trusted computing base is the running client, OS/kernel, CSPRNG, cryptographic
libraries, compiler/distribution and the filesystem adapter. A backup destination,
all persisted bytes, filenames and all CLI inputs are untrusted. Successful AEAD
verification establishes authenticity under a key, not trust in application content.
A secret read from a record is still untrusted input to a shell or external program.

| Actor | Capability | Expected boundary |
|---|---|---|
| Thief of powered-off device | Reads disks, snapshots, hibernation/swap, backups | Vault ciphertext resists recovery without a credential; plaintext remnants and weak passwords remain risks |
| Holder of vault copy | Unlimited offline guesses; edits, replaces, deletes bytes | Password KDF raises guessing cost; recovery has 256 random bits; authentication detects unauthorised edits |
| Backup attacker | Reads and supplies historical, partial or mixed snapshots | Authentication and inventory detect partial/mixed state; a complete authentic old snapshot remains replayable |
| Same-user malware | Reads files, watches input, accesses clipboard, may debug/replace client | ACLs do not isolate equal principals; no general confidentiality guarantee, even if UI says locked |
| Administrator/compromised OS | Reads memory, tampers execution and RNG, bypasses ACL | Outside cryptographic protection; no promise of host-compromise resistance |
| Accidental fault/concurrent client | Torn writes, full disk, crashes, racing mutation | Transaction protocol either selects a complete generation or reports recovery required |

Locked means the process has released and best-effort wiped its credential/VK buffers.
It does not prove absence of copies in GC, swap, dumps, prior processes or stolen RK.
Unlocked means plaintext and keys may be in RAM; local malware can steal them.
Full-disk encryption and OS hardening complement, but do not replace, vault encryption.

## Threat-to-control matrix

| ID | Threat / security goal | Proposed mechanism | Residual risk / verification |
|---|---|---|---|
| T01 | Offline password guessing / confidentiality | Argon2id p=1, salt16, m>=64 MiB, t>=3; bounded calibration | Password entropy still decisive; KDF vectors and cost tests V02 |
| T02 | Stolen recovery artifact | Independent random RK256, no plaintext RK in vault; separate storage | RK plus snapshot grants access; recovery lifecycle V03 |
| T03 | Header edit, slot removal, KDF downgrade | Slot AEAD, whole-header HMAC, limits before KDF | Header destruction prevents unlock; cannot authenticate before KDF; V04 |
| T04 | Swap ciphertext across vaults, records, types or revisions | Context-bound keys/AAD, immutable write IDs, authenticated manifest hashes | Complete old-generation replay is distinct; V04/V05 |
| T05 | Blob truncation/reorder/duplicate/append | Specified streaming profile, final marker, exact length and whole-blob verification before output | Profile requires independent review/interoperability before code is accepted; V06 |
| T06 | Deletion/corruption / availability | Manifest inventory and retained generation; independent verified backups | Detection does not recreate deleted bytes; no redundancy means permanent loss; V07/V08 |
| T07 | Full rollback | Explicit restore warning; local sequence/parent hash only assist diagnostics | No trusted external monotonic anchor in M1/M2; fully authentic rollback is undetectable; V08 |
| T08 | Attacker-selected resource exhaustion | Fixed header, file/JSON/count caps, one KDF, local memory/time budget | Bounded expensive operations and disk-filling remain possible; V02/V04 |
| T09 | Multi-file crash, disk full, competing writer | Immutable COW objects, single authenticated root commit, exclusive OS lock | Power-loss durability depends on qualified filesystem/storage; V07 |
| T10 | Path traversal, symlink/reparse substitution | Root-relative handles, no-follow opens, generated names, restrictive creation ACL | Same-user/root adversary can still control execution or mutate open files; V09 |
| T11 | Logs, argv, JSON, terminal injection | No secret argv/env; allowlisted diagnostics; explicit reveal; escape metadata controls | Explicit output can be captured by terminal/session recorder; V10 |
| T12 | Temp, export, clipboard, swap, crash dump | No plaintext vault temp; authenticated export then restrictive destination; wipe buffers | Export is intentionally plaintext; SSD snapshots, dumps and clipboard histories cannot be reliably erased; V10 |
| T13 | Rotation mistaken for revocation | Distinguish password/RK slot replacement from fresh VK re-encryption | Old slots plus old VK may decrypt future data if VK unchanged; V03 |
| T14 | Supply-chain compromise | Pinned compatible NSec/libsodium, verified sources, review and release qualification | Existing spike is evidence about primitives, not the designed vault; V01/V11 |
| T15 | Conflicting devices silently lose data | No automatic live-folder sync in M1/M2; preserve conflict candidates | Revision/time are not causal ordering; full sync needs a later ADR; V08 |

## Observable metadata and explicit non-goals

An observer can see vault/epoch IDs, KDF cost, slot kinds and IDs, generation numbers,
parent relationships, ciphertext sizes, file counts, filesystem timestamps and update
patterns. This draft also exposes item type in its authenticated envelope to bind type
before payload parsing; changing this leakage requires a revised format proposal.
Record titles, user timestamps, names, URLs and relationship inventories are encrypted.
There is no padding or traffic-analysis protection in M1/M2.

Availability cannot be guaranteed against deletion, ransomware, destructive admins or
loss of all replicas. Recovery key restores access to surviving wrapped VK and data;
it is not a backup and cannot reconstruct a missing header or ciphertext. Wrong
credential and invalid slot authentication need not be distinguishable to the caller.
No automatic rollback repair is allowed to turn corruption into apparent success.

Protect memory with bounded lifetimes and mutable byte buffers; avoid managed strings
where possible, but do not promise complete zeroisation with .NET GC or native APIs.
Swap/hibernation/crash-dump protections are operational recommendations, not changes to
system configuration made by the client. Clipboard is excluded from M1/M2; later timed
clearing cannot erase history or defeat clipboard readers. Terminal scrollback is not
secure storage. Do not render untrusted ANSI/control sequences during metadata listing.

## Assurance boundary

The specification chooses reviewed primitives; their composition and filesystem protocol
still require review. [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final)
specifies GCM, not this vault. The [verification plan](SN-002-VERIFICATION.md) separates
known-answer vectors, interoperability, parser fuzzing and crash/power-loss qualification.
No production-security claim follows from writing these documents or passing the old spike.
