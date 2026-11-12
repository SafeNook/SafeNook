# SecretStream research PoC (SN-002-R1)

Research only; not a production format, key store, vault or reusable crypto API.
The synthetic fixed key must never be used for real data. No connection to SafeNook.Core,
no solution entry and no managed package dependency. .NET10 SDK and the repository's
existing common properties apply. Build from the repository root with the already
verified libsodium1.0.22 MSVC static library:

```powershell
$lib=(Resolve-Path artifacts/sodium-static/libsodium/x64/Release/v143/static/libsodium.lib).Path
dotnet publish spikes/AttachmentCryptoResearch/SecretStream -c Release -r win-x64 -o artifacts/attachment-secretstream/publish "-p:LibsodiumStaticLib=$lib"
./artifacts/attachment-secretstream/publish/secretstream-research.exe test artifacts/attachment-secretstream/correctness
./spikes/AttachmentCryptoResearch/SecretStream/Measure.ps1 -Executable ./artifacts/attachment-secretstream/publish/secretstream-research.exe
```

The library archive SHA-256 pinned by the existing spike is
`3e03a726fac4bc09cb61d8f29d658ef7a5eca0811de59082130414f7ca2e4279`.
Do not supply an arbitrary native library. `LibraryImport` + `DirectPInvoke` statically
resolve the C API. ABI sizes are queried/checked at startup; native state is dynamically
sized and wiped before freeing. The tested ABI is Windows x64 only.

Research framing is LE64 plaintext length + libsodium header24 + fixed65536-byte plaintext
messages (each ciphertext adds17). Empty input has one empty FINAL message. Per-message
AAD is research context + LE64 total + LE32 index + LE32 chunk plaintext length. All
non-last tags are MESSAGE and last is FINAL; exact file length, final tag and EOF required.
The authenticating algorithm/state/rekey logic is libsodium, not a reimplementation.
SafeNook production framing/limits/domain labels need separate review and vectors.

Encryption streams file-to-file with one plaintext and ciphertext chunk. Decryption reads
one encrypted chunk at a time into a full-size plaintext quarantine buffer and creates
output only after every message authenticates. Failure wipes all buffered plaintext and
creates no destination. The PoC intentionally overwrites its own generated scratch paths;
it does not implement production owner-only creation, durable flush, locking or atomic
replace. File flush is normal OS caching, not power-loss durability.

`test` covers0,1,65535,65536,65537 bytes and1,5,10,25MiB; every size has round-trip and
ciphertext/tag/AAD/header/length corruption, truncation and append rejection with absent
output. Four larger cases also reject swapped first two chunks (76 checks total).
Inputs are synthetic repeated random64KiB blocks; no secrets are logged. Known-answer
vectors from a separate implementation are not included; round-trip/tamper checks do not
prove cryptographic composition security.

`Measure.ps1` uses a fresh native process for each size/operation/repetition, five repeats.
Inputs are prepared outside timing. Each child warms a64KiB round-trip, collects GC, then
measures one file-backed encrypt/decrypt including allocation, I/O and cleanup. Native-call
milliseconds are also accumulated. One sampling thread polls process working/private bytes
approximately every1ms; `PeakWorkingSet64` is the OS lifetime high-water mark, not operation
allocation, and sampled private peak can miss brief spikes. Managed allocation includes
sampler overhead and is not live retained memory. CSV distinguishes baselines, sampled peaks
and lifetime peaks. Sources/outputs use Windows filesystem cache; do not read these numbers
as cold-disk throughput or fsync/durable transaction latency. Round-trip SHA256 checks occur
after the timed children. No measurements were taken on Linux/macOS/ARM64.
