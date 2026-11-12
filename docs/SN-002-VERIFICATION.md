# SN-002 — план проверки спецификации и будущей реализации

Дата: 2026-11-12. Статус: план обновлён по SN-002-R2, **не выполненные криптографические тесты**.
SN-002 не добавляет тесты, код, зависимости или CI. Ниже — критерии следующих отдельно
разрешённых задач. Связи: [угрозы](threat-model.md), [формат](vault-format.md),
[recovery](recovery-and-io.md), [транзакции](storage-protocol.md),
[решения владельца](SN-002-DECISIONS.md).

## Матрица будущих проверок

| ID | Область / traceability | Проверка и ожидаемый результат |
|---|---|---|
| V01 | Primitive KAT, Q-02/Q-05, T14 | AES-GCM NIST vectors, HKDF RFC5869 Appendix A; отдельные negative tags/AAD/nonces; точное совпадение bytes |
| V02 | KDF, Q-04, T01/T08 | NSec/libsodium p1/salt16/tag32 vs независимый reference Argon2; m/t/p/size boundaries, memory/time budgets, OOM/timeout/cancel; без downgrade |
| V03 | Credentials, Q-03, T02/T13 | Init requires RK; password change preserves recovery slot; old password lost→RK recovery; RK lost→password replacement; fail each confirmation/commit point; оба slots не исчезают |
| V04 | Parser/header, Q-02, T03/T04/T08 | Каждый byte/length/enum mutation, truncation at every boundary, oversized files/overflow, duplicate JSON and bad UTF8; reject before дорогих операций где возможно |
| V05 | Items/manifest, Q-02/Q-09, T04/T06 | Межvault/epoch/type/write substitution, missing/duplicate references, wrong hash, wrong schema, dangling blobs, total budgets; unlock fail closed |
| V06 | Whole-object blobs, Q-05, T05/T08 | Independent AES-GCM/envelope vectors, empty/max/max+1, ciphertext/tag/AAD/context/length/EOF tamper; 2L memory, OOM/cancel; ни одного plaintext byte до полной аутентификации |
| V07 | Transactions, Q-06, T09 | Process kill, short write, ENOSPC, flush/rename/ACL failure на каждом шаге; current old/new complete либо explicit recovery-required |
| V08 | Recovery/rollback, Q-03/Q-06/Q-09, T06/T07/T15 | Full/partial/mixed backups, old credentials, corrupted header, deleted objects, competing roots, full rollback; не заявлять freshness для authentic old snapshot |
| V09 | Filesystem, Q-06, T10 | Symlink/reparse/hardlink, root swap, alternate stream, competing processes, lock owner killed, unsupported fs; no unintended path mutation |
| V10 | Input/output, Q-07/Q-08, T11/T12 | TTY/non-TTY, secret argv rejection, pipe limits, JSON allowlist, ANSI injection, export overwrite/permissions/cancel, exact opaque-byte round-trip |
| V11 | Platform/AOT, all | Win/macOS/Linux AOT; семь RID before support claims, source-gen parser, static/shared native linkage, no ignored trim warnings |

## Independent vectors and fixture provenance

Use NIST CAVP AES-GCM known-answer datasets and RFC5869 SHA256 cases, pin original source,
version/checksum and licence in fixture metadata. For Argon2 retain the three spike vectors
as regression data but do not call them independent: they originate in libsodium. Produce
additional p=1, salt16, Argon2id v0x13, output32 vectors using a separately maintained
reference implementation, with empty secret/AD. Record exact password bytes (including
Unicode, embedded NUL at byte level where API allows), memory KiB and pass count; compare
reference, NSec and direct libsodium outputs. RFC9106's p4/secret/AD example does not match
this API and cannot simply be relabelled.

For vault fixtures fix all random inputs explicitly in **test-only** data: vault/epoch/
slot/generation IDs, VK/RK, salts, nonces, write IDs and synthetic plaintext. Publish every
intermediate KEK, AAD hex, wrapped VK/tag, header HMAC, object key, encrypted manifest/hash
and final header wrapper. Use only synthetic secrets and separate reference generator;
never put deterministic randomness into production code. Round-trip alone is insufficient:
compare bytes to independently produced expectations and exercise damaged inputs.

For v1 blobs generate independent whole-object AES-256-GCM vectors with the exact
118-byte envelope, HKDF info, ObjectAAD, nonce12 and tag16. Verify both directions with
a separately maintained primitive implementation. Test algorithm=2/unknown-version refusal,
not fallback. R1 PoC results are research evidence, not production envelope qualification.
Streaming interop/profile fixtures are deferred to a separately approved future format;
Tink/secretstream are not mandatory v1 dependencies or release gates.

## Structural boundary checklist

The following are specification arithmetic expectations, not cryptographic vectors:

| Structure | Expected bytes |
|---|---:|
| Header prefix | 166 |
| One slot descriptor including nonce | 60 |
| One complete slot | 108 |
| MAC input header bytes (excluding domain) | 382 |
| Complete binary header | 414 |
| Base64 header payload | 552 |
| Canonical JSON wrapper including LF | 567 |
| Generic envelope | 118 |
| Empty whole-AEAD suffix including tag | 16 |
| Empty blob total | 134 |
| Maximum 25 MiB blob total | 26,214,534 |
| Maximum separate plaintext + ciphertext arrays | 52,428,800 (50 MiB), excluding overhead |

LE32(65536) is `00 00 01 00`; LE32(3) is `03 00 00 00`.
UUID textual/network byte order must be tested
against Guid mixed-endian defaults. For each concatenation verify exact domain string
including terminal NUL; no UTF16, implicit delimiter, decimal rendering or length prefix
may sneak into fixed-width AAD. SlotAAD covers slot[0:60]; Header HMAC covers H[0:382];
ObjectAAD covers E[0:118]. Verify these with independent parser offsets, not shared structs.

Blob L values: 0, 1, 15, 16, 17, 1/5/10/25 MiB and limit+1. Expected physical size
is always 118+L+16 for supported L. Test each truncated prefix/tag boundary, appended byte,
forged L, ciphertext reorder/duplication, nonce/AAD/context changes and historical object
substitution. Empty ciphertext still requires tag verification. Verify no destination or
external plaintext before full success; no chunk-count/final-bit rules exist in v1.

Measure allocation/peak memory on representative Windows/Linux/macOS devices for separate
buffers, including metadata, provider and concurrent operations. The working payload bound
2L is not a total-process cap. Inject OOM/cancel before read/derive/encrypt/decrypt/commit,
and cancellation during a noninterruptible call: publication is withheld after completion.
Check finally cleanup of owned buffers and preservation of current root/destination.
Validate 10,000-item and aggregate memory limits before claiming support. KDF minimum64MiB/t3,
maximum1GiB/t10 and calibration0.5–1s remain working values requiring hardware checks;
worker/deadline tests apply only after a separately approved design, not by inference.

Header parser must reject wrapper>1024, decoded length!=414, unknown/duplicate properties,
noncanonical base64, nonzero flags, unsupported versions/algorithms, wrong slot order,
invalid UUIDs, duplicate slot IDs, parameter overflow and out-of-policy values **before** KDF.
Recovery parser: all symbols, separators/case, bad pad bits, checksum, prefix, overlong
input, truncated tokens; do not autocorrect ambiguous characters. Password UTF8 bytes
must be identical between interactive and framed input; neither normalisation nor trimming.

## Fault injection and state invariants

Kill before/after every write, file flush, install, directory flush, backup root write,
manifest write, root replace, readback, acknowledgement and GC deletion. Also inject disk
full/short-write/read errors and failed ACL inheritance. On reopen require exactly one of:
old authenticated complete generation, new authenticated complete generation, or explicit
recovery-required/uncertain outcome. Never accept a mixed set, empty vault after corruption,
missing recovery slot, partially written attachment, or a hidden rollback.

Separate process-crash tests from power-cut VM tests; a process kill does not empty disk
write caches. Qualify NTFS/Windows and APFS/macOS adapters and POSIX fsync/rename ordering;
record OS/filesystem/mount/storage versions. Test two concurrent processes, killed lock
holder, reader/export during writer, and unsupported shared/network filesystems. Do not
infer seven-RID filesystem guarantees from a cryptographic AOT smoke run.

For full VK rotation, interrupt every phase and test all combinations of old/new password,
old/new RK, old/new header and objects. Demonstrate that old credentials still decrypt old
backups, that slot-only replacement with a captured old VK permits new-epoch-unchanged
object decryption, and that fresh-VK objects reject old VK. Verify unconfirmed RK never
becomes sole recovery credential of committed state. Simulate loss of new RK while valid
password remains, and loss of header with valid RK but no backup: report irrecoverability.

## I/O and assurance gates

Inject secrets into every field and error condition, capture stdout/stderr/logs/exceptions/
JSON/process argv/env and assert no accidental disclosure. Test readback failure of recovery
output, output path inside vault, overwrite refusal, broken pipe, cancellation before/after
publication and strict no-plaintext-before-complete-authentication. Check exact round-trip
of SSH/age/file bytes including non-UTF8, BOM, CRLF, NUL and missing newline. No key parser
or plugin invocation is expected for opaque storage.

Before SN-003: separate owner authorisation and review of the rewritten ADR 0009;
ADRs 0007/0008 are already Accepted. Resolve KDF worker/deadline separately before any
hard-timeout promise. Before M1 acceptance: independent primitive/composition review,
V01–V05/V07–V11 appropriate to M1, filesystem qualification and verified recovery.
Before M2: V06 whole-object vectors/memory/error handling and complete opaque-type/export
checks. Before production claims:

external security review and all release gates; documentation consistency is not proof.
