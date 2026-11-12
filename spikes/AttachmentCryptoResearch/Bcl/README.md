# BCL whole-object AES-GCM research PoC

Research only for SN-002-R1; not part of the solution, Core, CLI, dependency management or CI.
No production vault implementation or approved wire-format change is implied.

Uses .NET 10 BCL AES-256-GCM, tag16/nonce12 and HKDF-SHA256 per-write key separation.
The proposed118-byte envelope is reused with blob kind2 and whole-object algorithm1;
**that blob/algorithm combination is an experimental alternative**, rejected by the
current SN-002 streaming draft. Synthetic fixed VK/IDs exist only in this PoC.
Each encryption gets independent random writeId32 and nonce12. AAD is the exact domain+
header bytes. Decrypt checks expected external IDs, exact file length and EOF; it creates
no output file until full AES-GCM authentication succeeds. Plaintext/key buffers are wiped.
COW transaction/permissions/flush-to-device implementation is intentionally absent.

## Reproduce

Run from the repository root with .NET10 SDK and Windows native build prerequisites:

```powershell
dotnet publish spikes/AttachmentCryptoResearch/Bcl/Bcl.csproj -c Release -r win-x64 -o artifacts/attachment-research/bcl-publish
$exe='./artifacts/attachment-research/bcl-publish/bcl-attachment-poc.exe'
& $exe check artifacts/attachment-research/bcl-data
& $exe measure artifacts/attachment-research/bcl-data 25 encrypt
& $exe measure artifacts/attachment-research/bcl-data 25 decrypt
```

`check` prepares synthetic files and tests0/1/5/10/25MiB, tamper/tag/AAD/context/length,
truncation, append and a public AES256-GCM known-answer vector:40 cases. The vector is
GCM specification Test Case14 (also preserved in [BoringSSL test data](https://boringssl.googlesource.com/boringssl/+/1d134eee9a7f456cc100ac450abcc67243d8fbdd/crypto/cipher/test/aes_256_gcm_fips_testonly_tests.txt)).
No corrupt ciphertext value is logged. Generated files contain only public synthetic data.

For recorded measurements, call `measure` in a fresh process for each size0/1/5/10/25,
each operation encrypt/decrypt and each of five repetitions. Warmup64KiB occurs before GC
and baseline. Input fixtures are prepared before measurements. Baseline and 1ms-sampled
working set/private bytes are process measurements; lifetime peak WS is OS process-wide,
not strictly interval-scoped. Private sampling can miss short peaks. Main-thread and total
allocated-byte deltas are separate; total includes monitoring allocations.

ElapsedMs includes file reads, allocations, HKDF, AEAD, direct-span file writes, ordinary
FileStream.Flush, disposal and plaintext/key zeroing. CryptoMs covers only AES-GCM call.
No Flush(true), durability/fsync, GC pause stress, concurrency, cold OS cache, encryption
of an entire manifest or immutable-root transaction is measured. FileStream bufferSize1
avoids an additional managed I/O buffer; OS/native caches still count toward real costs.
Two exact length arrays are live (plaintext and ciphertext), rather than MemoryStream copies.

Raw fresh-process results: [results/win-x64.json](results/win-x64.json).
Environment: [results/environment.json](results/environment.json).
Build and40 cases passed on win-x64 Native AOT, zero build warnings. Linux/macOS not executed.

A separate manual check copied the1MiB encrypted object unchanged and verified equal
SHA256, showing content-address/inventory compatibility, not crash-atomicity proof.
