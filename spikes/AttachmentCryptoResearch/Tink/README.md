# TinkStreamingAead research PoC

Research-only harness for SN-002-R1. Not referenced by SafeNook.slnx or Core. Uses
synthetic fixed key/data, never real secrets. No production library code is copied or
modified. Package TinkStreamingAead1.0.1 is an **unaudited third-party .NET port**, not
Google's official implementation. It fixes ciphertext segments at1MiB, not ADR0009's64KiB.
The package version is intentionally local to this isolated project; root CPM is untouched.

Upstream source commit93c37582d8f436517c67fa44253c7c45e2215e8d, MIT. .NET6 asset has no
transitive NuGet dependencies. The package metadata and SHA256 are in results/environment.json.
SECURITY.md explicitly disclaims independent audit. Blocking encrypt/decrypt return internal
plaintext arrays to ArrayPool without clearing; caller quarantine/wipe does not fix this.
See https://github.com/salehalakhras/TinkStreamingAead/blob/93c37582d8f436517c67fa44253c7c45e2215e8d/SECURITY.md
and src/TinkStreamingAead/Aes256GcmHkdf1MB.cs lines226,296,306 at that commit.

From repository root, PowerShell7:

```powershell
dotnet publish spikes/AttachmentCryptoResearch/Tink/Tink.csproj -c Release -r win-x64 -o artifacts/tink-research/aot
./artifacts/tink-research/aot/tink-research.exe selftest artifacts/tink-research/data
./artifacts/tink-research/aot/tink-research.exe prepare artifacts/tink-research/data
./spikes/AttachmentCryptoResearch/Tink/Run-Benchmarks.ps1
```

Prepare writes only synthetic research data beneath artifacts. Benchmark outputs likewise
stay there. Selftest88 checks cover0/1/5/10/25MiB,1byte and exact1MiB-profile boundaries:
roundtrip, ciphertext length, changed ciphertext/tag/AAD, truncation, appended byte and
header-only input. Every failure checks that the external publication stream is empty.
Decrypt quarantines the full plaintext in a fixed-size private array and publishes only
after all tags succeed, then clears that array; upstream's internal pool retention remains.
No actual COW store or118-byte vault envelope is implemented; synthetic AAD is not wire format.

Each CSV row is a fresh AOT process for one operation/size/repetition;5 repetitions. One64KiB
warmup precedes full GC/baseline. Inputs/ciphertexts are generated outside measurement.
Elapsed includes file reads/writes, crypto, buffered Flush (not durability/fsync) and own
cleanup. Memory includes baseline WS/private, lifetime OS peak WS and1ms sampled peaks.
Sampling can miss short spikes; allocated-byte count is not live-memory peak. Measurements
are a single Windows x64 machine with warm filesystem cache; do not extrapolate other OS/RID.
The package's internal pool behaviour is left unchanged, so results describe that version.

Recorded final build: no AOT/trim warning output. Final AOT selftest passed88 checks and
all measured decrypted-file SHA256 values matched synthetic inputs. No official Tink
cross-language interoperability or Linux/macOS Native AOT run was executed.
