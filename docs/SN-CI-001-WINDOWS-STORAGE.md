# SN-CI-001 — Windows Storage CI failure diagnosis

Date: 2026-11-13. **Local fix verified; green GitHub Actions for this change is not yet confirmed.**
Production writes remain disabled. SN-003C1 is not started.

## Root cause and evidence

The tests assumed that the ignored `artifacts` parent already existed. `FreshPath()` only
constructed `<repo>/artifacts/<unique-vault>`. It did not create `artifacts`, and neither
restore nor build creates that directory in a fresh checkout. WindowsFileSystem intentionally
opens each ancestor with FILE_OPEN and creates only the final vault directory with FILE_CREATE.
The first missing ancestor therefore fails in NtCreateFile, before vault ACL checks or `.lock`.
QualificationStore.Create caught and replaced that exception at line 82, hiding its native code.

Evidence:

- [Failing CI run 43452043305, Windows job](https://github.com/SafeNook/SafeNook/actions/runs/43452043305/job/131976414376)
  reports 182 tests, 56 failed, 126 passed, no skips. Core passes; the four Storage cases
  independent of creating a vault pass. Most failures have the same `create` wrapper.
- The runner log identifies Windows Server 2025 build 26100, image
  `windows-2025-vs2026` version `20261103.298.1`, checkout under `D:/a/SafeNook/SafeNook`.
  Its checkout/restore/build workflow has no test-parent provisioning step.
- `git ls-files artifacts` returns no tracked files; `.gitignore` excludes that directory.
  The local development checkout already had artifacts from earlier research and qualification.
- A local probe with an intentionally absent parent fails at **Ancestor / NtCreateFile**, with
  **Win32 2 and NTSTATUS 0xC0000034**, on the same local fixed NTFS volume where normal tests pass.
  SDK 10.0.26100.0 `shared/ntstatus.h` defines 0xC0000034 as STATUS_OBJECT_NAME_NOT_FOUND.
- Creating only that parent and repeating the identical probe succeeds: exact owner ACL,
  directory pinning, exclusive lock, file flush, directory flush and native rename all succeed.
- A fresh isolated source snapshot was built with its own `artifacts` absent. Full testing
  without a preflight that could hide the issue passes all 184 tests after the setup fix.

This establishes one shared test-infrastructure defect rather than 56 independent storage
bugs. The original CI log does not contain a native code, so its exact environment must still
be confirmed by the added preflight on the next run; no Server 2025 execution is claimed locally.

## Changes

- `tests/SafeNook.Storage.Tests/StoreTests.cs`: create the test-owned parent before choosing
  a unique, still-nonexistent vault path. Never precreate the vault or change its ACL.
  Add a missing-parent regression proving the failure code and recovery through parent setup;
  add a diagnostic redaction test. Create failures print only bounded internal diagnostic fields.
- `src/SafeNook.Storage/StorageDiagnostics.cs`: internal enum categories/stages, numerical
  Win32/NTSTATUS, filesystem classification, volume flags and observed capability booleans.
  No arbitrary exception message, path, SID, key, plaintext or ciphertext data is captured.
  IOException HResult becomes a Win32 code only for FACILITY_WIN32. Consumed file-not-found
  and sharing-retry failures are cleared, so a later successful operation is not reported failed.
- `src/SafeNook.Storage/WindowsFileSystem.cs`: record stages/native errors and volume metadata
  while preserving all existing checks, access masks, share modes and creation dispositions.
- `src/SafeNook.Storage/QualificationStore.cs`, `StorageContracts.cs`: carry the internal
  diagnostic through Create's generic wrapper. Its public message remains `create`, with no
  InnerException exposing original messages. No diagnostics are added to the product CLI.
- `spikes/StoreQualification/Program.cs`: explicit synthetic `probe` mode exercises actual
  creation, ACL validation, lock, encrypted staging, file flush, relative rename, directory
  flush and root readback. It fails with safe diagnostics; it does not waive a capability.
- `tests/Test-StorageCapabilities.ps1`: prepare only the test parent, run the probe, print
  OS/architecture, interactive/session-zero booleans and parent-existed flag. No username/SID
  or absolute test path is printed. Failed harness setup returns exit 2 without exception text.
- `.github/workflows/ci.yml`: run Windows preflight after Build. Test still executes after a
  failed preflight if Build succeeded; the failed preflight still makes the job fail. No
  continue-on-error, new permissions, security settings or skipped Storage tests were added.
- This report records reproduction and remaining remote validation.

Probe artifacts contain synthetic encrypted objects and are retained under ignored artifacts.
No workflow upload of vault data is added.

## Environment comparison

| Dimension | Local evidence | Original Actions evidence / next check |
|---|---|---|
| OS | Windows 10.0.26300.0 x64 | Server 2025 10.0.26100 x64 |
| Test parent | Previously exists; deliberate absence reproduces failure | Fresh checkout lacks ignored artifacts |
| Volume | Fixed NTFS, flags 0x03E72EFF; all probe operations pass | Next preflight records actual filesystem/flags/type, not inferred from drive letter |
| ACL/owner | Exact current-token owner and protected DACL checks pass | Same checks required; no SIDs logged or allowlist bypass |
| Session | Interactive=True, sessionZero=False | Next preflight records booleans; service/session differences are not established as a cause |
| Parallel assemblies | Core and Storage run together successfully | Both assemblies run; 122 Core cases succeed; unique vault paths avoid collisions |
| Runner temporary paths | Fixture uses repo artifacts, not ambient TEMP | Repo under D:/a; no dependency on a pre-existing TEMP tree |

## Verification

| Check | Result |
|---|---|
| Release build | Passed, zero warnings/errors. |
| Full local suite | 184 passed (122 Core + 62 Storage), zero failed/skipped. |
| Fresh source snapshot, artifacts absent before test | 184 passed, zero failed/skipped; no preflight before the suite. |
| MTP discovery | 184 tests in 2 assemblies. |
| Managed capability preflight | Passed; fixed NTFS, owner/namespace/lock/file flush/directory flush/rename checks succeed. |
| Native AOT store | win-x64 publish with existing static libsodium and real create/commit/backup/blob/reopen smoke passed. |
| Native AOT diagnostic probe | Passed; bounded diagnostics survive AOT. |
| CLI regression | 165 managed + 165 freshly published Native AOT checks passed. |
| PowerShell preflight syntax | Parsed without errors and executed successfully. |
| Git diff / whitespace | git diff --check and changed/new-file whitespace checks passed. |
| Remote Actions with this patch | Not executed; requires owner publication. |

Build/test/discovery/probe/publish logs are retained under ignored `artifacts/sn-ci-001-*`.
The clean snapshot verified the root-cause fix; the final main-tree suite additionally covers
subsequent diagnostic refinements. Local testing does not reproduce the runner's service
identity, Server 2025 image or D: device. Those facts must come from the next Actions run.
No claim of power-loss qualification follows from the capability probe.

## Required GitHub Actions follow-up

After the owner commits and publishes these changes, inspect the run for that exact head:

1. Build succeeds; Windows preflight reports STORAGE_CAPABILITIES_PASS, category=None,
   fixed NTFS and all exercised capability booleans true. Preserve safe environment output.
2. MTP/full suite reports 184 tests, 184 passed and zero skipped on Windows. Check the two
   added regression cases and the existing 11 process-crash boundaries and process lock test.
3. CLI managed/native steps and other platform jobs pass. Linux/macOS Storage cases remain
   unsupported as before; those jobs are not Windows storage qualification evidence.
4. If preflight fails, use stage/category/native code to investigate that first capability.
   Keep the job failed and keep checks intact. If required guarantees are unavailable, use a
   separately qualified Windows/NTFS integration runner; do not turn failures into skips.
5. Record the successful run URL/head before saying CI is fixed. This task did not push,
   dispatch, rerun or modify a remote workflow.

## Git and invariants

Started clean at `7e14a0ecb4c19d39516681e744df7d329c5dd9c1`, with SN-003B3 committed.
After explicit owner approval of the main-base exception, created
`fix/sn-ci-001-windows-storage`. Base and HEAD remain unchanged. Existing ignored research,
test output and work were preserved. No commit/push/fetch/pull/merge/rebase occurred. Local
tracking refs were inspected; Git synchronization freshness was not established by fetching.
Read-only GitHub APIs supplied the failing run/job logs. Final status: 6 modified tracked
files and 3 new files; nothing staged or deleted, no unrelated tracked changes.

ACL/owner validation, handle-relative traversal, no-reparse/hardlink checks, lock semantics,
AEAD and wire format are unchanged. Missing ancestors still fail in production storage;
only the test harness provisions its own parent. No recovery bypass, GC enablement or
production-write gate change is included.

Suggested Conventional Commit:

```text
fix(ci): initialize storage test parent and add safe capability diagnostics
```
