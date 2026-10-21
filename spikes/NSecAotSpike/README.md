# NSec native AOT spike (F-4)

A throwaway console app that answers one question for [ADR 0002](../../docs/adr/0002-crypto-library.md): does [NSec.Cryptography](https://nsec.rocks) (a .NET wrapper over libsodium) work under native AOT on every platform SafeNook targets, and how does libsodium get into the binary?

It is not part of `SafeNook.slnx` and is not shipped. The results and the decision live in the ADR.

## What it checks

The app prints `PASS`/`FAIL` for each check and exits with a non-zero code if any check fails.

- **Argon2id known-answer tests**: three vectors from the libsodium 1.0.22 test suite (`test/default/pwhash_argon2id.c` / `.exp`): Argon2id v1.3, one lane, no secret or associated data. The RFC 9106 vector needs a secret, associated data and p=4, which libsodium doesn't support. The phc-winner-argon2 vectors use an 8-byte salt, and libsodium requires 16 bytes.
- **Argon2id parameter limits**: which degrees of parallelism, memory sizes, pass counts and salt lengths NSec accepts. Each probe is compared with the expected behaviour, so a change in a future NSec release shows up as `FAIL`.
- **Ed25519**: RFC 8032 section 7.1, TEST 1. Derives the public key, signs, verifies, and checks that a tampered signature is rejected.
- **Argon2id timing**: m=64 MiB and m=256 MiB, t=3, p=1. One warm-up run, then the average of 3 runs.

AES-GCM and HKDF are out of scope: they come from the BCL ([ADR 0003](../../docs/adr/0003-aead-cipher.md)).

Lines starting with `SUMMARY` are machine-readable; the workflow copies them into the job summary.

## Running locally

```bash
# Shared libsodium from the NuGet package, copied next to the binary
dotnet publish spikes/NSecAotSpike -c Release -r <rid> -o out
./out/nsec-aot-spike

# libsodium linked statically into the binary
dotnet publish spikes/NSecAotSpike -c Release -r <rid> -o out-static -p:LibsodiumStaticLib=/path/to/libsodium.a
./out-static/nsec-aot-spike
```

For static linking, use a libsodium 1.0.22 static library: build it from the release tarball (`./configure --disable-shared --enable-static --with-pic && make`), or on Windows take `libsodium/<arch>/Release/v143/static/libsodium.lib` from the official `libsodium-1.0.22-msvc.zip`. Verify the download with minisign first; the key is in the workflow. The version matters: NSec 26.4.0 refuses to start unless the library reports version 26.4, which is libsodium 1.0.22.

## Running in CI

[`.github/workflows/spike-nsec-aot.yml`](../../.github/workflows/spike-nsec-aot.yml) runs on pull requests that touch `spikes/**` or the workflow, and manually through **Actions → Spike NSec AOT → Run workflow**.

For each of win-x64, win-arm64, linux-x64, linux-arm64, linux-musl-x64 (Alpine container), osx-arm64 and osx-x64 it does the following, once with the shared libsodium and once with libsodium linked statically:

1. publishes the spike;
2. lists the published files with sizes;
3. shows the native dependencies (`ldd`, `otool -L`, `dumpbin /dependents`);
4. runs the binary. In the static build the binary is copied alone into an empty directory first, to prove it needs nothing next to it.

Each job writes a results table to the run summary.
