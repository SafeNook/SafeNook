# SN-003D3 — Process crash qualification and storage lab preparation

Date: 2026-11-17. **Production writes and GC remain disabled. No power-loss qualification.**

## Baseline and scope

Clean main 923c9d6 contains owner-committed SN-003D2 (PR #17). New branch:
test/sn-003d3-process-crash. Local main matched recorded origin/main; no remote freshness
check, commit, fetch, push, pull, merge or rebase. Existing artifacts are preserved.

ApplicationQualification gained a separate synthetic crash entry point, not a nook flag.
Only this isolated harness has additional Storage friend access. Real credentials cannot be
supplied: old fixture password/recovery are fixed synthetic values, fixture VK remains random.
Rotation uses the real Application random RK generation and full confirmation path. The new
RK travels through a current-user-only named pipe into controller RAM, never argv/env/stdout,
logs or a plaintext file. Mutable received RK bytes are wiped in finally.

## Process-kill matrix

Each row is a separate child process with an independently created vault containing a file
record and encrypted blob. No exception simulates a crash: the external controller calls
Process.Kill(true), waits for actual nonzero exit, then reopens and fully authenticates.

| Operation | Boundaries | Cases |
|---|---|---:|
| passwd | Authenticated, Validated, ObjectWritten, ObjectFlushed, ObjectInstalled, ManifestVerified, BackupWritten, RootWritten, RootFlushed, BeforePublish, BeforeRename, AfterPublish, BeforeReadback, RootReadback, ACK | 15 |
| recover | Same credential boundaries | 15 |
| recovery rotate | Same credential boundaries | 15 |
| backup | Authenticated, ObjectWritten, BeforePublish, BeforeRename, AfterPublish, BeforeReadback, ACK | 7 |
| restore | Credential boundaries except BackupWritten (no previous destination root) | 14 |
| backup verify | ArchiveRead, Authenticated, ACK | 3 |
| Total | Managed independent-process cases | 69 |

ArchiveRead is an internal hook after ciphertext bytes are read and before Core accepts that
object; it checks killed-reader handle release. It is not a claim to interrupt an NTFS system
call in flight. Hooks pause on the first occurrence of a repeated boundary. Random in-flight
cuts and every occurrence of a multiple-object workload are deferred, not silently claimed.
BeforeRename is a quiescent pre-syscall point; AfterPublish is after successful rename. These
bounded tests do not enumerate every scheduling point inside native rename/flush.

## Pre/post-ACK oracle and access preservation

The controller receives the original authenticated 414-byte header over its private pipe.
Before publication, exact old root and both old credentials must remain usable. Afterwards,
credential operations must expose exactly sequence 3 (baseline 2), unchanged opposite slot,
same VK/vault/epoch, complete item/blob authentication and no second implicit commit. Backup
must leave source unchanged; restore must preserve exact header, IDs and immutable ciphertext.
Every retained root is authenticated explicitly with the historical recovery credential.
Unknown/staged ciphertext is retained; no rollback, selection fallback, cleanup or GC runs.

ACK is emitted only AFTER the Application call returns success and includes SHA-256 of the
acknowledged header (or complete archive for backup/verify). The external controller records
this nonsecret hash in observer.ack, Flush(true), then kills the helper. After reopening it
requires an exact hash match as well as full cryptographic validation. This proves only the
process-crash model with the OS/storage still running; it is not evidence about device caches.

A fresh exclusive archive handle can be acquired after killed verify/restore. Reopening the
vault also verifies lock release. Tests scan the entire newly owned case directory, including
ciphertext staging and archives, for synthetic password/payload/recovery-key markers; no unknown user
files are scanned or deleted. No unexpected stdout after the one marker is accepted.

## Execution results

| Check | Actually executed |
|---|---|
| Release build, final fixture/assertions | Passed, 0 warnings/errors |
| Full MTP suite | 437 passed, 0 failed/skipped; 7m 02.959s |
| MTP discovery | 437 cases in three assemblies |
| Final exact-method crash campaign | 69 passed, 0 failed/skipped; 119.353s, after final fixture/assertion changes |
| Managed CLI regression | 165 existing/gen + 22 vault checks passed |
| Native AOT win-x64 CLI regression | Publish passed; 165 + 22 checks passed |
| Native AOT lifecycle/backup harness | Published with static libsodium; lifecycle/backup/verify/restore passed |
| Native AOT actual process kill | Backup post-ACK helper killed externally; ACK hash and native full reopen/verify passed, including final fixture |
| Lab preparation | Read-only discovery/planners executed; script syntax and no-approval refusal guards passed |
| Documentation links / git diff --check | Passed |

The full suite includes the existing 11 common COW process-kill cases as well as the 69 new
operation-specific cases. The final 69-case rerun covers the later assertion/fixture-only
changes; production code is the same as in the successful full suite. No passing result is
inferred from a zero-test filter. Logs and all synthetic cases remain under ignored artifacts/,
including sn-003d3-verified.log, sn-003d3-crash-verified.log, sn-003d3-discovery.log, native
publish logs and the retained interrupted/failed intermediate runs.

Native testing used the synthetic process controller, not a VM shutdown command. No physical
lab or quota/full-volume result is included in these pass counts.

An initial controller had a pipe handshake deadlock for rotation: the child flushed the new
RK while the parent waited for its marker before reading that RK. Timed-out cases are NOT
qualification successes. The first run was stopped by terminating only its own test controller
and child. The controller now starts the RK read concurrently before waiting for the marker,
and observes EOF for pre-confirmation kills. Original failure logs are retained. A first
filtered diagnostic run selected zero tests; it was not counted as coverage and was replaced
by the exact-method crash campaign.

A later raw-RK scan initially used a repeated ASCII A fixture key and falsely matched Base64
zero fields in header wrappers (69 assertion failures, preserved log). The fixture key was
changed to the public synthetic byte sequence 0x80..0x9f, retaining the strict raw-key scan.
Production key generation was not changed. A final complete 69-case campaign and native
post-ACK test were rerun for these fixture/assertion changes; the full 437-test suite had
already passed on the same production code.

## VirtualBox discovery and independent clone plan

Read-only local discovery: VirtualBox 7.1.4r165100 at
C:\Program Files\Oracle\VirtualBox\VBoxManage.exe. Source Win11 UUID
b147c2a7-6ed9-48f4-86d4-81774046aea4 is powered off; clean snapshot UUID
f2210738-d028-4855-a3c9-0cb202bcef31 exists. Other registered VMs were left untouched.
Win11 has an 80 GiB virtual disk with a differencing chain, shared folder VMShare and
bidirectional clipboard/drag-and-drop. All NICs and USB controllers were off. It is NOT an
isolated disposable lab. Existing snapshots/VMs were not created, modified, deleted or started.

Installed VBoxManage help for clonevm, modifyvm and clonemedium was inspected. A full
clonevm --snapshot <clean UUID> --mode machine without the link option is the proposed
independent clone. Verify every attached disk has Parent UUID=base and resides under the
new lab directory; reject source/snapshot media references. The planner disables all eight
NICs, clipboard, drag-and-drop and USB controllers/card reader, removes clone-only VMShare
and detaches inherited host DVD/VISO media. Reinspect all shared folders and USB filters
before first start; unexpected entries block provisioning. No VM start is automated.

Reserve at least 264 GiB for one 80 GiB clone, an 80 GiB forensic copy, an 80 GiB working copy,
a <=256 MiB disposable NTFS disk and at least 20 GiB host headroom. For an 8 GiB
trial disk and three copies, reserve at least 288 GiB instead. Discovery found about 360 GiB
free on C:, a volatile observation, not an allocation promise or approval to use that drive.
Multiple retained trials require more capacity. Prefer an owner-selected dedicated lab path.

Prepared scripts in [StorageLab](../spikes/StorageLab/New-LabPlan.ps1):

- New-LabPlan.ps1: read-only discovery and JSON argv plan; refuses an existing lab directory.
  Executed to produce an ignored proposal manifest; no clone/create/start commands executed.
- Invoke-LabPowerCut.ps1: future guarded controlvm poweroff only. Requires separate approval,
  rejects all three known source VM UUIDs, checks clone identity/config location, network/host
  integrations, one or two independent clone-owned disks, and writes a pre-cut evidence log.
  It never starts, repairs, reboots or restores snapshots. Use independent full copies rather
  than new differencing snapshots with this conservative guard.
- Test-NativeProcessCrash.ps1: process-only controller for the published native helper's
  backup post-ACK case, followed by native full verification. This is not VM poweroff.

Guest campaign deployment remains future work: offline read-only ISO transfer, isolated test
account, guest .NET/native binaries with recorded hashes, external observer and a protected
synthetic-credential oracle that survives guest power loss. The current named-pipe observer
runs on the same OS and is sufficient for process kills only; it must not be mistaken for an
external VM power-cut oracle. Do not expose RK in serial/console logs. Preserve a faulted disk
before reboot/repair; evaluate a working copy. No lab VM was provisioned in this task.

## Disposable NTFS quota/full-volume plan

[New-NtfsTrialPlan.ps1](../spikes/StorageLab/New-NtfsTrialPlan.ps1) emits a read-only checklist
for an explicit guest volume GUID and test-account SID. Its sample identifiers are placeholders,
not a discovered disposable disk. No quota was configured. Local fsutil quota help was read;
tracking/enforcement/modification require separate guest-only approval and recording effective
SID and resulting limits. Do not substitute host C:, a shared folder or a passthrough user disk.

[Invoke-DisposableNtfsFill.ps1](../spikes/StorageLab/Invoke-DisposableNtfsFill.ps1) is prepared,
not run beyond its early no-approval refusal. It requires VirtualBox guest identity, matching
disk unique ID, fixed NTFS labelled SAFENOOK-DISPOSABLE, VBOX HARDDISK hardware, no system/boot/
pagefile use, <=8 GiB volume/write budget, and evidence on another guest drive. It writes an
exclusive noncompressed filler file in bounded 1 MiB WriteThrough/Flush(true) steps, records
native error/free space and never cleans up. No system configuration or quota changes exist
in that script. Host free-space monitoring remains mandatory during later execution.

Run separately: (1) real byte exhaustion near dependency/manifest/retained-root/root-staging
allocation; (2) enforced quota for the exact test user; (3) many-small-files/directories and
metadata pressure; (4) flush/error observation. Metadata exhaustion is not inferred from a
free-byte threshold, and a full disk need not cause FlushFileBuffers to fail. Injected flush
errors remain a different evidence class. Keep a separate recovery disk and a manifest of
known filler paths; only those filler files may later be removed by an approved operator.
Always reauthenticate current and every retained root and compare acknowledged hashes.

## Untested scenarios and next stage

No abrupt VM poweroff, real full-volume/quota test, physical relay power cut, controller/cache
fault, physical flush failure, Linux/macOS or new remote CI run was performed. Power-loss
claims require the separate [B3 plan](SN-003B3-POWER-CUT-PLAN.md), independent observer,
protected recovery oracle and exact hardware/cache configuration. No human live TTY test.

Next stage: obtain owner approval for a particular new lab path/clone and disk, review the
prepared scripts, provision offline, verify clone independence/isolation, implement the
external VM oracle, then run boundary/occurrence and random-cut campaigns plus real NTFS
space/quota tests. Keep all faulted media and ACK evidence. Production writes and GC require
separate owner approval after qualification; this report does not open either gate.

## Changed files and Git

- `spikes/ApplicationQualification/ApplicationQualification.csproj`
- `spikes/ApplicationQualification/Program.cs`
- `src/SafeNook.Storage/BackupArchive.cs`
- `src/SafeNook.Storage/QualificationBackup.cs`
- `src/SafeNook.Storage/SafeNook.Storage.csproj`
- `src/SafeNook.Storage/StorageContracts.cs`
- `spikes/ApplicationQualification/CrashCampaign.cs`
- `spikes/StorageLab/Invoke-DisposableNtfsFill.ps1`
- `spikes/StorageLab/Invoke-LabPowerCut.ps1`
- `spikes/StorageLab/New-LabPlan.ps1`
- `spikes/StorageLab/New-NtfsTrialPlan.ps1`
- `spikes/StorageLab/Test-NativeProcessCrash.ps1`
- `tests/SafeNook.Application.Tests/CrashQualificationTests.cs`
- `docs/SN-003D3-CRASH-QUALIFICATION.md` (this report)
- `docs/ROADMAP.md`

Suggested Conventional Commit:

```text
test(storage): qualify process crashes and prepare isolated storage lab
```

Final Git: 7 modified tracked files, 8 new files, no deletions or unrelated tracked changes.
Base and HEAD remain 923c9d6; no commits or remote operations were performed.
