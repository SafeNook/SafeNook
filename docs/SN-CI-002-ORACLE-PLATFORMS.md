# SN-CI-002 — Oracle test platform classification

Date: 2026-11-17. Existing PR branch feat/sn-003q3-real-vault-oracle, base/HEAD 21d5300.
Q3 was owner-committed; the initial working tree was clean. Per explicit request this fix stays
on that branch. No new branch/PR, commit, fetch, push, pull or other remote Git operation.
Existing ignored artifacts are preserved. Locally recorded upstream matches HEAD, but remote
freshness and a green GitHub Actions run have not been established.

## Root cause and fix

OracleTests.IndependentHostGuestProcesses unconditionally resolved and launched DurabilityOracle.exe.
The executable itself refuses non-Windows hosts and requires Windows owner-only evidence ACLs;
its denied-access scenario invokes Windows native impersonation. Selecting a Unix executable name
would not make this qualification harness portable. The test lacked a runtime platform gate.

Two test methods now use xUnit v3 Assert.SkipWhen before any transport, path or process setup:

- IndependentHostGuestProcesses: 13 discovered theory cases, Windows executable/ACL/native probe.
- NoReceiptOnFlushFailure: one Windows qualification pipe-transport case.

These are real dynamic skips with explicit reasons, not early successful returns. There is no
CI filter and no change to test discovery or Windows execution. The other 20 OracleTests cases
exercise memory streams, framing, state transitions, hash domains and synthetic evidence sinks;
they remain portable and execute on every platform.

.NET named pipes and Process.Start are not inherently Windows-only. The gate applies to the
Windows qualification contract, error/access semantics and executable used here; this task does
not qualify the Unix socket implementation as an equivalent Windows durability transport.

## Audit of related components

| Component | Platform dependency / existing protection |
|---|---|
| OracleIntegrationTests, 57 cases | Constructor already calls Assert.SkipWhen on non-Windows before either launcher; Native NTFS Storage and ApplicationQualification |
| SupportedOSPlatform attributes | Analyzer metadata only; not a test skip mechanism |
| CrashQualificationTests | Partial VaultApplicationTests; existing Windows x64 constructor skip applies |
| StoreTests | Existing Windows x64 NTFS constructor skip applies |
| DurabilityOracle executable | Explicit Windows entry guard, current-user pipe/evidence ACL and Windows native access probe |
| VirtualUart | Windows registry, kernel32 COM API and VirtualBox guest check; not used by portable protocol tests |
| ApplicationQualification | Windows entry guard and native NTFS Storage; remains an internal synthetic harness |
| CLI regression scripts / CI | Existing OS-specific nook/nook.exe selection; unchanged |

No product source, cryptography, vault/oracle schema, dependencies, CI permissions, production-write
gate or GC was modified. Tests still discover on Unix and report skips before any .exe launch.

## Platform counts and checks

| Scope | Windows x64 | Linux x64 | macOS arm64 |
|---|---:|---:|---:|
| OracleTests + OracleIntegrationTests discovery | 91 | 91 | 91 expected |
| Execute / skip in those classes | 91 / 0 actual | 20 / 71 actual | 20 / 71 expected |
| Entire suite discovery | 528 actual | 528 actual | 528 expected |
| Entire suite execute / skip | Not rerun in full for this two-line test gate | 168 / 360 actual | 168 / 360 expected |

The 360 Unix skips comprise StoreTests 91, VaultApplicationTests 198, OracleIntegrationTests 57,
and the 14 gated OracleTests cases. Portable Core 123, CLI 25 and Oracle 20 total 168. macOS
counts are static classification, not claims of successful execution; actual results follow.

Actual checks:

- Windows Release build: zero warnings/errors.
- Windows targeted MTP run: 91 passed, zero failed/skipped, 2m 20.144s; filtered discovery 91.
- Full Windows discovery: 528; unrelated Windows tests were not rerun for this two-line gate.
- Windows managed CLI and freshly published Native AOT CLI: each 165 + 22 checks passed.
- Linux x64 Docker SDK 10.0.404: restore and Release build passed, zero warnings/errors;
  full MTP run 168 passed / 360 skipped / zero failed, 1.937s; discovery 528.
- Linux log contains both explicit new skip reasons. OracleTests source bytes in the snapshot
  match the working tree; no pre-existing host binaries or obj directories were used.
- Markdown links and git diff --check passed. No additional skipped Windows cases.

The Linux image digest is
sha256:fe0fd4e93bd2fbb47c883b7a6369e5c8d3db8bf01cdc5981f6ee35fbdf3ff4fb.
Logs are under artifacts/sn-ci-002-*; Linux final logs are artifacts/sn-ci-002-linux-final/.
Only task-created containers were run/stopped; existing containers and user VM settings were not
modified. The newly created stopped containers and evidence remain available; no artifact cleanup.
Linux Native AOT CLI regression was not run; the complete CLI regression reported above is Windows.


Initial diagnostics are retained: the first Windows filter used an unsupported interior wildcard
and selected no runnable tests (handshake error); it was replaced by two exact class filters.
An offline Linux restore lacked dependencies. The pre-existing SDK 10.0.201 Docker image then failed
NuGet audit on its default ILCompiler 10.0.5 (NU1903). Audit was not disabled; Linux verification
uses an isolated SDK 10.0.404 image instead. This changes no repository SDK/package setting.
Linux uses a tracked-source snapshot including this working-tree fix, with no host bin/obj files.
The repository and host NuGet fallback cache are read-only; writable build state is container-local,
and logs/source snapshot remain under ignored artifacts/sn-ci-002-*.

macOS arm64 execution is unavailable locally. GitHub Actions must confirm its discovery/skips,
remaining tests, and native CLI regression. Local/container results do not establish green CI.

```text
fix(ci): gate Windows-only oracle process tests by platform
```
