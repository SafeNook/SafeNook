# SN-003A — in-memory crypto and v1 format implementation

Date: 2026-11-12. Owner-approved scope: primitives, binary parsers/encoders, key slots,
recovery encoding and whole-object codec. ADR 0009 is Accepted; ADRs 0001–0009 are now
Accepted, with the partial supersessions documented in the ADR index. This is not a
released vault, a security audit, or an implementation of the filesystem protocol.

Branch: `feat/sn-003a-crypto-core-format`, based on owner-approved R2 commit
`0ead0620caaf2c30af25ed486eff41eb143dd989`. HEAD remains that commit; no commit, fetch,
pull, push, merge or rebase was performed. Local main and recorded origin/main both
pointed to `6904096`; remote freshness was not established. Prior research and ignored
artifacts were retained. No CLI commands, CI settings or wire parameters were changed.

## Changed files

Modified: `Directory.Packages.props`, `src/SafeNook.Core/SafeNook.Core.csproj`,
`docs/ROADMAP.md`, `docs/SN-002-DECISIONS.md`, `docs/SN-002-VERIFICATION.md`,
`docs/adr/0003-aead-cipher.md`, `docs/adr/0009-streaming-aead-profile.md`,
`docs/adr/README.md`, `docs/vault-format.md`.

Created: `src/SafeNook.Core/Vault/SecretBuffer.cs`, `VaultCrypto.cs`, `VaultFormat.cs`,
`KeySlots.cs`, `RecoveryCode.cs`, `ObjectCodec.cs`;
`tests/SafeNook.Core.Tests/Vault/VaultTests.cs`, `Vectors.g.cs`, `generate_vectors.py`;
`spikes/CoreCryptoAotSmoke/CoreCryptoAotSmoke.csproj`, `Program.cs`;
`docs/SN-003A-IMPLEMENTATION.md`. No files deleted. NSec version remains unchanged;
its Core reference implements the already approved ADR 0002 dependency.

## Public contracts and ownership

All APIs are in `SafeNook.Core.Vault`. Inputs are borrowed spans: callers must keep their
contents stable for the complete call and must not mutate/dispose them concurrently.
No Core operation accesses files, Console, UI, clipboard or network.

| Component | Contract |
|---|---|
| `SecretBuffer` | Owns secret bytes, exposes a span, wipes on Dispose, rejects access after disposal. Caller must dispose returned keys/plaintext promptly and wipe any copies. No secret-bearing ToString. |
| `VaultCrypto` | BCL AES-256-GCM (key32/nonce12/tag16, support check, separate non-overlapping buffers); BCL SHA-256 HKDF Extract+Expand; NSec Argon2id v1.3/p1/salt16/output32; CSPRNG key generation. |
| `VaultFormat` | Bounded UTF-8 vault.json wrapper; exact 414-byte header, 108-byte slots, 166-byte prefix, 118-byte envelope; UUIDv4 network order; LE integers; exact EOF, algorithm/type/schema/flags/version and resource bounds. Parsing never implies authentication. |
| `KeySlots` | Build candidate header, open explicitly selected credential slot, verify entire header MAC, replace either slot while preserving the other byte-for-byte. No fallback between credentials. |
| `RecoveryCode` | Canonical 75-character SN1 encoding, ASCII-only accepted normalisation, 256-character input ceiling, exact symbols/pad bits and constant-time 40-bit checksum check. Returned string is not wipeable; no automatic printing. |
| `ObjectCodec` | Whole-object item/manifest/blob encryption, fresh write ID/nonce per attempt, per-write HKDF and exact AAD; checked limits, trusted context/write ID/hash on decryption; returns plaintext only after all checks and complete authentication. |

`CreateHeader` accepts separately generated VK/RK and staged manifest prefix. It checks
both credentials against the candidate VK and MAC before returning. It does not confirm
human recovery delivery or publish a root. Generate VK and RK with separate `GenerateKey`
calls; no deterministic production RNG or fixture injection exists.

`ReplacePassword`/`ReplaceRecovery` verify the old header MAC using supplied VK and require
a next prefix in the same vault/epoch, next sequence, fresh generation/manifest write ID,
and SHA-256 of the previous complete header. Overflow is refused. The replaced slot gets
fresh ID/salt/nonce; the new credential is read back; the other slot is unchanged. The old
input remains immutable even on failure. These are low-level candidate builders: the
future application must enforce fresh credential authentication, confirmation/delivery,
known-password policy on recovery rotation, manifest validation and atomic publication.
They do not provide revocation of old headers/copies or rollback protection.

`OpenPassword`/`OpenRecovery` return an owned cryptographic key after full header MAC
verification, not an unlocked session. Before any session, item metadata or export is
published, the future store must authenticate the referenced manifest and active items.
Header fixtures below exercise binary composition only; they are not complete vaults.

`ObjectCodec.Decrypt` requires the trusted expected context, write ID and complete-file
SHA-256 separately from input. The future store must obtain them from an authenticated
root/manifest, never from the candidate envelope itself. Hash and AEAD use the same stable
in-memory file. Payload JSON/schema semantics are explicitly outside this binary codec;
opaque SSH/age/file bytes are not interpreted here.

## Resource and cancellation policy

Argon2 wire bounds remain 65,536..1,048,576 KiB, divisible by 1,024, t=3..10, p=1.
Password bytes must be strict UTF-8, 1..1,024 bytes, without normalisation or trimming.
Trusted caller-supplied memory budget is checked before the native KDF. No fallback,
calibration, automatic physical-RAM discovery, worker or hard deadline was added. The
future admission layer must implement the documented local default budget and concurrency
policy; a header cannot consent to a larger budget.

Object bounds: item 65,536 bytes, manifest 8,388,608 bytes, blob 26,214,400 bytes.
Ciphertext file = 118 + L + 16; empty blob is 134 bytes, max blob 26,214,534 bytes.
Explicit trusted payload admission checks `2 * L` against the supplied budget; callers
must additionally budget provider/runtime/metadata overhead and concurrent operations.
Whole-object encryption/decryption uses separate arrays; ArrayPool and plaintext disk
spooling are absent. No peak-process-memory benchmark was performed for this implementation;
R1 measurements are historical and not substituted for new measurements.

Cancellation is checked before and after native KDF/AEAD work. Those calls are not
interruptible or hard-bounded by a token. A result is withheld and disposed if cancellation
is observed after the call. Managed secret buffers, stack keys and recovery scratch space
are explicitly wiped; this is not a guarantee about GC/provider/OS copies or a compromised
host. Returned plaintext/key storage belongs to the caller until disposal.

## Independent vectors and reproducibility

- SHA-256 HKDF: [RFC 5869 Appendix A.1–A.3](https://www.rfc-editor.org/rfc/rfc5869), exact
  expected outputs, including empty salt/info and 82-byte output.
- AES-256-GCM: [BoringSSL published test collection](https://raw.githubusercontent.com/google/boringssl/master/crypto/cipher/test/aes_256_gcm_tests.txt),
  empty case with key starting `e5ac4a32` and 10-byte/AAD case with key starting `80e2e561`.
  Exact values are frozen in tests. This is not a full CAVP run or certification.
- Argon2id: independent reference C implementation through
  [argon2-cffi low-level API](https://argon2-cffi.readthedocs.io/en/stable/api.html#low-level),
  version=19, p=1, salt16/output32, m=65,536 KiB, t=3 and t=4; no secret/associated data.
  The second password contains UTF-8 and NUL. Expected outputs were not generated by NSec/libsodium.
- Header, slots, intermediate KEKs/AAD/MAC keys, envelope, ciphertext and recovery code:
  deterministic public synthetic fixtures from the checked-in
  [generator](../tests/SafeNook.Core.Tests/Vault/generate_vectors.py), using
  [cryptography AESGCM](https://cryptography.io/en/latest/hazmat/primitives/aead/)
  and HKDF on OpenSSL, plus the reference Argon2 above.
  [Vectors.g.cs](../tests/SafeNook.Core.Tests/Vault/Vectors.g.cs) freezes outputs; tests do
  not regenerate expectations with the implementation being tested.

Generator environment: Python 3.14; cryptography 46.0.3, OpenSSL 3.5.4 (30 Sep 2025),
argon2-cffi 25.1.0, argon2-cffi-bindings 26.1.0, cffi 2.1.1, pycparser 3.12. Packages were
installed only into ignored `artifacts/sn-003a-vectors-venv`, not globally. Reproduce:

```powershell
python -m venv artifacts/sn-003a-vectors-venv
artifacts/sn-003a-vectors-venv/Scripts/python.exe -m pip install cryptography==46.0.3 argon2-cffi==25.1.0 argon2-cffi-bindings==26.1.0 cffi==2.1.1 pycparser==3.12
artifacts/sn-003a-vectors-venv/Scripts/python.exe tests/SafeNook.Core.Tests/Vault/generate_vectors.py
```

These are public test keys, never user credentials. Interoperability between independently
implemented encodings catches composition mistakes, but does not replace independent
review of the specified protocol or the production API boundaries.

## Executed checks

Available host: Windows x64, .NET SDK 10.0.404/runtime 10.0.15. Core uses centrally pinned
NSec.Cryptography 26.4.0 / libsodium 1.0.22 and BCL; xUnit v3 4.0.3 with MTP.

| Check | Actual result |
|---|---|
| `dotnet restore` | Passed |
| `dotnet build -c Release` | Passed, 0 warnings / 0 errors |
| `dotnet test -c Release` and final `--no-build` run | 70 passed, 0 failed, 0 skipped; includes 16 existing generator tests |
| `dotnet test -c Release --no-build --list-tests` | MTP discovered 70 tests |
| CLI `dotnet publish ... -r win-x64` | Native AOT passed, no warnings |
| `CoreCryptoAotSmoke` publish/run | Static libsodium Native AOT passed; actual Core Argon2/HKDF/GCM/header/wrapper/slots/recovery/object code executed |
| Existing `tests/Test-Cli.ps1` | 165 checks passed for managed CLI and 165 for native CLI |
| Documentation checks | Local Markdown targets validated; git diff --check passed; historical SN-001/R1 files unchanged |

Negative coverage includes every byte of the 414-byte header and every byte of the
synthetic encrypted object, wrong password/RK, altered tag/nonce/AAD/hash/context, exact
EOF/truncation/append, duplicate/unknown wrapper fields, unknown binary versions/algorithms,
slot ordering/duplicate IDs, UUID encoding, KDF bounds/budget, lengths up to UInt64.MaxValue,
sequence overflow, wrong replacement lineage, failed replacement preserving the old root,
empty/max/oversized payloads and invalid recovery characters/checksum/padding/case.
AEAD failure returns no `SecretBuffer`; disposal wipes retained spans. Error checks use
public synthetic secrets. The cancellation timing test covers cancellation around the KDF;
it does not prove that cancellation occurred inside the native call or establish a deadline.

Native crypto smoke additionally performs both credential paths, independent vector
opening, both slot replacements, empty/one-byte/max blobs and tamper rejection. Static
archive used: `artifacts/sodium-static/libsodium/x64/Release/v143/static/libsodium.lib`,
SHA-256 `62815491f5ef88e83a14194358d8e9a6cd01b7f43b646fcb59a647bd12c88621`.
Published smoke directory contains the executable and PDBs, with no shared libsodium DLL.
CLI trimming alone is not evidence for crypto compatibility; the separate smoke supplies it.

Local logs: `artifacts/sn-003a-build.log`, `sn-003a-tests.log`, `sn-003a-discovery.txt`,
`sn-003a-cli-publish.log`, `sn-003a-crypto-publish.log`. Artifacts are ignored, not committed.

## Remaining gates and SN-003B recommendation

Not run: Linux/macOS/ARM64 Native AOT, forced OOM/memory-pressure stress, representative
hardware KDF calibration, concurrent-operation admission, side-channel/security audit,
filesystem crash/durability/permission tests. No claim is made about those platforms or
about absolute memory erasure. Aggregate record/reference limits require future typed
manifest parsing/store accounting; only the applicable binary/object bounds are enforced here.

Before SN-003B, review these APIs and independent fixtures. Then implement strict typed
item/manifest payload parsing and expected-reference validation, trusted KDF/RAM admission,
and a store boundary that authenticates all required objects before publishing a session.
After that, add platform filesystem adapters, immutable staging/COW single-root commit,
locks/owner-only permissions and crash/failure injection, including mandatory recovery
readback and slot preservation. No filesystem store, vault CLI, backup/restore, sync,
SSH-agent, KDF worker or migration has been started in SN-003A. SN-003B needs separate authorisation.

Suggested commit:

```text
feat(core): implement v1 cryptography, key slots and whole-object codec
```
