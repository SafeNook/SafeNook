# SN-003B1 — typed payloads and authenticated in-memory vault state

Date: 2026-11-12. Scope authorised by the owner: typed schema-1 manifest/items, strict
JSON, reference validation, trusted admission and in-memory opening. No filesystem
adapter, atomic commit, backup/restore, vault CLI, sync, agent, GUI or migration is added.
The binary/wire format, crypto parameters, dependencies and ADR statuses are unchanged.

## Git and preserved work

SN-003A was committed by the owner as `aa3f5a2d18756c46a49b7a838ce198cb385d55f7` before
work began. The initial tracked tree was clean. New branch:
`feat/sn-003b1-authenticated-state`, based on that commit; HEAD is unchanged. This continues
the agreed sequential-branch workflow instead of using stale local main (`6904096`).
Local main and recorded origin/main had 0/0 divergence; no remote freshness is claimed.
No commit, push, fetch, pull, merge or rebase was performed. Existing ignored research,
build and publish artifacts were preserved.

## New files and public contracts

All Core APIs are under `SafeNook.Core.Vault`, with DTOs in its `Models` namespace.

| File | Contract |
|---|---|
| `src/SafeNook.Core/Vault/Models/VaultModels.cs` | `ManifestDto`, `ObjectReference`, common `ItemFields`, `ItemDocument`, login/note/SSH/age/file payload classes; internal wire DTO and source-generated JSON context. Required nullable fields remain required. Classes avoid record-generated secret-bearing ToString. |
| `src/SafeNook.Core/Vault/VaultPayloadJson.cs` | Strict bounded readers, source-generated writers, typed payload validation and optional authenticated-predecessor revision validation. |
| `src/SafeNook.Core/Vault/ManifestValidation.cs` | Inventory limits, canonical IDs and sorted arrays, unique write IDs, header binding, exact item inventory, exclusive live ownership and role-specific blob limits. |
| `src/SafeNook.Core/Vault/VaultAdmissionPolicy.cs` | Trusted KDF/RAM policy with shared reservation accounting and an injectable owned-buffer allocator for deterministic allocation-failure tests. |
| `src/SafeNook.Core/Vault/AuthenticatedVaultState.cs` | `IVaultObjectSource`, `AuthenticatedVaultState`, owned/reserved lazy `AdmittedPlaintext`. No storage implementation or path construction. |
| `src/SafeNook.Core/Vault/VaultDataException.cs` | Safe failure categories without raw JSON, credentials, source exception messages or inner exceptions. |
| `tests/SafeNook.Core.Tests/Vault/StateFixture.cs` | Public synthetic encrypted inventory, raw hand-authored JSON and in-memory test source; no user secrets. |
| `tests/SafeNook.Core.Tests/Vault/AuthenticatedStateTests.cs` | Positive, malformed-input, linkage, atomic-publication, resource and lifecycle tests. |
| `spikes/CoreStateAotSmoke/CoreStateAotSmoke.csproj`, `Program.cs` | Actual Core/source-generated JSON AOT smoke, separate from production CLI. |
| `docs/SN-003B1-IMPLEMENTATION.md` | This report. |

Modified documentation: `docs/ROADMAP.md`, `docs/vault-format.md`,
`docs/SN-002-VERIFICATION.md`. No previous source/test files were modified or deleted. Final Git status: 3 modified
documentation files, 11 new files, none staged; no unrelated tracked changes.

## JSON and reference rules

Input is capped before deserialisation: manifest 8 MiB, item 64 KiB. A bounded
Utf8JsonReader pass rejects duplicate decoded property names at every nesting level,
invalid UTF-8, unpaired escaped surrogates, depth above 16, and numeric tokens that are
not unsigned integer decimal values fitting UInt64. Arrays are capped at 10,000 elements
before DTO allocation; object property sets are capped at 16 (all schema-1 objects have
fewer fields, and unknown properties are rejected). JSON framing rejects BOM, comments,
trailing commas and extra root tokens. Source generation rejects unknown/missing fields;
case-sensitive names and required-nullable semantics are retained.

Payload dispatch is an explicit type switch with concrete generated JsonTypeInfo values,
not reflection-based polymorphism or a type-name fallback. Common fields, UTF-8 byte
lengths, tags, timestamps, schema/type, payload shape and tombstones are checked. Writers
validate before serialisation and refuse oversized output. Serialized plaintext returned
to a caller belongs to that caller and must be wiped when no longer needed.

Manifest checks cover header vault/epoch/generation/sequence/parent hash equality,
lexical order of canonical lower-case IDs (equivalent to raw byte order), per-array ID
uniqueness, write ID uniqueness across both inventories and the manifest object itself,
reference kinds/types, per-object and aggregate byte/count limits. Each authenticated
item must match the expected ID/type/schema/length. Every manifest blob must have exactly
one live item owner. SSH/age primary blobs are limited to 1 MiB and companions to 64 KiB;
general file blobs retain 25 MiB. Tombstones contain no payload, title, tags or blob links.

A missing referenced object is corruption. Extra *manifest references* without an owner
are rejected. Unreferenced physical objects are unreachable candidates and are ignored,
not auto-imported or rejected solely for existing; this is the explicit v1 COW contract.
The abstract source has no enumeration operation.

Revision 1 requires null previous; later revisions require a canonical hash. Opening a
single snapshot cannot establish history or prove that an earlier type/revision was
unchanged. `ValidateRevision` additionally checks ID/type, creation time, monotonic update
time, exact revision increment, overflow refusal and previous-file hash when the caller
supplies an authenticated predecessor. No unavailable historical file is invented or required.

## Opening and byte-source contract

`OpenPassword`/`OpenRecovery` accept the decoded fixed header and exactly one credential.
The existing `VaultFormat.DecodeWrapper` handles vault.json separately. The input root is
structurally checked and copied before invoking source callbacks. The selected slot and
complete header MAC authenticate before any encrypted inventory is read.

`IVaultObjectSource.Read(kind, writeId, destination, token)` copies the prefix up to the
requested destination length and returns the exact complete object length, or -1 if
missing. It must provide one stable object per call, fill the requested prefix accurately,
never retain the destination span, and never publish plaintext. A future adapter must
qualify those guarantees against the filesystem. Core owns read buffers. Separate reads
are not trusted to describe the same bytes: each full item/manifest/blob read is checked
against authenticated expected identity, exact length, hash and AEAD.

The orchestrator authenticates/decrypts the manifest, validates root binding and inventory,
authenticates/parses every current item, verifies all ownership links, then probes each
blob's 118-byte envelope and physical length. It validates blob kind, schema, algorithm,
vault/epoch/object/write context and expected size without reading blob payloads.
Only then does the method return a state. There is no progress callback carrying partial
metadata or a partially unlocked session. Failure disposes candidate key/item buffers and
releases reservations. Explicit cancellation is propagated without credential fallback.

Blob hash and AEAD are intentionally lazy: an otherwise correct root can open with a
blob whose tag is damaged, but `ReadBlob` will reject that blob without returning any
plaintext. This is an authenticated inventory/item state, not a claim that all unopened
blob bytes have already authenticated. Later blob reads recheck the full immutable
reference and content; source replacement after opening cannot bypass authentication.

State operations/disposal are serialised. `ItemIds` and `ReadItem` return detached values;
callers cannot mutate the state's private authenticated inventory or item JSON. The key
and retained item JSON are wiped on state disposal. Returned blob plaintext is independently
owned and retains its RAM reservation until disposed, even if the state is closed first.
Borrowed source lifetime remains the caller's responsibility.

## Admission, memory and limitations

Budgets come from trusted application code, never from header values. The default factory
uses trusted available physical RAM supplied by the application: min(256 MiB, one quarter
of available RAM), rounded down to MiB. Below 64 MiB it refuses; overhead can require more
than the minimum. Explicit policy may allow the existing 1 GiB KDF ceiling. Saved KDF
parameters are never lowered. No worker, calibration or hard deadline is implemented.

Reservations are shared across states using the same policy instance. Native KDF cost is
admitted before invocation. JSON/collection work is conservatively reserved at 16 times
encoded inventory/item sizes plus fixed/per-reference overhead. Blob use reserves two
payload lengths plus overhead and keeps the lease with returned plaintext. This is an
admission estimate, not a measured or guaranteed bound on process working set, GC heap
residency, provider allocation or total application memory. Applications must share the
policy and account for caller-owned input, retained returned DTOs and unrelated work.

Tests inject OutOfMemoryException at owned ciphertext buffer allocations, including after
an earlier item has authenticated, and during lazy blob use. All tested failures return
no state/plaintext and release the applicable reservations. These deterministic faults
are not real OS low-memory stress, and do not exhaust every allocation inside the runtime,
serializer or native library. Managed DTO strings and internal serializer copies cannot
be reliably wiped; the state retains wipeable item JSON rather than a permanent secret DTO
graph. Caller-retained DTOs remain the caller's lifetime responsibility. Absolute memory
erasure, protection against compromised hosts and complete rollback resistance are not claimed.

## Executed validation

Host: Windows x64, .NET 10. Restore/build use existing pinned dependencies.

| Check | Result |
|---|---|
| `dotnet restore` | Passed |
| `dotnet build -c Release` | Passed, zero warnings and errors |
| `dotnet test -c Release` / final no-build run | 122 passed, zero failures/skips; 70 existing + 52 added cases |
| MTP `--list-tests` | 122 discovered |
| `CoreStateAotSmoke` publish/run, win-x64 | Passed with static libsodium; all five source-generated payload types, both credential paths, lazy blob, allocator failure |
| CLI Native AOT publish and regressions | Passed; 165 checks for managed CLI and 165 for native CLI |
| Documentation / diff | 33 local Markdown links valid; LF/whitespace checked on all 14 changed/new files; git diff --check passed |

The new fixtures hand-author JSON and encrypt synthetic inventories with the already
KAT-tested SN-003A primitives. They reuse SN-003A independent slot vectors; root MACs are
constructed for each synthetic generation. They are orchestration tests, not newly claimed
independent cryptographic vectors. Existing independent primitive tests remain in the suite.

Negative tests cover duplicate IDs/write IDs, unsorted arrays, missing items/blobs, orphan
and shared blob references, hashes/context/types/schema/enums, malformed JSON/UTF-8/depth,
required nullable fields, tombstones/revisions, count/aggregate limits, allocation denial,
source errors without secret diagnostics, source mutation after opening, no partial state,
disposal and reservation lifetime. Logs are ignored under `artifacts/sn-003b1-*`.

Not executed: Linux/macOS/ARM64, real OOM/process memory-pressure stress, full KDF hardware
calibration, external protocol/security audit, filesystem durability/permissions/failure
injection. No support claims for untested platforms or a complete usable on-disk vault.

## SN-003B2 recommendation

Review the source/ownership/admission contracts, then implement separately authorised
filesystem adapters with bounded stable reads, no-follow/handle identity checks, locking
and owner-only permissions. Integrate immutable staging, dependency readback and single-root
COW publication with crash/failure injection; preserve mandatory recovery and explicit
recovery delivery/reauthentication rules. Do not equate successful in-memory opening with
qualified durable storage. CLI vault commands and backup/restore need explicit scope.

Suggested Conventional Commit:

```text
feat(core): validate typed manifests and open authenticated vault state
```
