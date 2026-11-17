# SN-003Q2 — External durability oracle and provisioning preparation

Date: 2026-11-17. **Local process qualification only. No VM, disk or snapshot was created;
no VM was started or powered off. Production writes and GC remain disabled.**

## Scope and Git

Owner committed Q1 as 4dadb78. The working tree was clean; existing ignored artifacts were
preserved. With explicit owner permission to depart from CLAUDE.md's main-base rule, branch
feat/sn-003q2-external-durability-oracle was created from 4dadb78. No commit, fetch, pull, push,
merge, rebase or remote operation was performed. Remote freshness is not independently known.

The standalone [DurabilityOracle project](../spikes/DurabilityOracle/DurabilityOracle.csproj)
has no dependency on product Core, Storage or CLI, and no new NuGet dependency. It uses BCL
SHA-256 and Windows local IPC. It is an internal synthetic qualification executable, not a
public nook command or production-write bypass. Q1 architecture is accepted by the Q2 request;
provisioning and destructive operations remain separately prohibited.

## Components and protocol

- Protocol.cs: fixed binary frame codec, bounded reads, typed fields, domain-tagged hashes.
- Observer.cs: state machine, evidence append/flush, secret RAM custody, failure invalidation.
- GuestBridge.cs: stream-based guest adapter, secret channel and receipt validation.
- VirtualUart.cs: guest-only COM1 adapter with asynchronous I/O, 115200/8N1 and no flow control.
- Program.cs: independent host/guest process endpoints using owner-only named pipes; synthetic
  fixtures exercise all six operations. An optional operation enum selects Password, Recover,
  Rotate, Backup, Verify or Restore; credentials cannot be supplied on argv or through environment. The guest-uart mode uses the same synthetic protocol over COM1 only.
- PipeAccessProbe.cs: qualification-only synchronous anonymous-token access-denial probe.

Wire version 1 is an oracle transport schema, not a change to vault or SNBACKUP wire formats.
All integers are little-endian. A four-byte unsigned length precedes a fixed 160-byte body.
Lengths above 4096 or other than 160 are rejected before payload allocation. Exact-read semantics
support fragmented byte streams and reject EOF mid-frame.

| Body offset | Size | Field |
|---|---:|---|
| 0 | 4 | ASCII SNOR magic |
| 4 | 1 | Version 1 |
| 5 | 1 | Event / RecoveryKey / Receipt kind |
| 6 | 1 | Operation enum 1–6 |
| 7 | 1 | Boundary enum 1–7 |
| 8 | 16 | Run GUID using .NET Guid byte encoding (not network-order UUID) |
| 24 | 8 | Strict sequence starting at 1; secret frames also consume a number |
| 32 | 4 | Occurrence, starting at 1, at most 10,000 |
| 36 | 8 | Generation (ACK only) |
| 44 | 96 | Three fixed 32-byte hash slots, or constrained secret payload |
| 140 | 20 | Reserved, must be zero |

Run and operation must match host expectations. Required event order is Start → Authenticated →
BeforePublish → AfterPublish → Verified → ACK → End; Verify omits publication events. Authenticated,
BeforePublish, AfterPublish and Verified may repeat only with consecutive occurrence numbers.
Start/ACK/End are single occurrences. The schema exposes these coarse orchestration phases;
detailed Storage write/flush/install hooks must be mapped and reviewed during later VM integration.
Unknown kinds/versions/enums, duplicate sequence/ACK, skipped phase, wrong run and nonzero reserved
bytes fail closed. Protocol failure poisons the observer; no automatic reconnect or retry.

Hash slots are root wrapper, exact 414-byte header and full archive, in that order. Each hash is
SHA-256 over ASCII SNOR-v1, one domain byte (1/2/3), then exact source bytes. Header length is
checked. ArchiveDigest processes at most 2,147,483,648 bytes with a 64 KiB buffer. These tagged
hashes intentionally differ from ordinary external file SHA-256; consumers must not interchange
them. The process fixture uses synthetic byte sequences, not a real vault generation. The bridge
API accepts hashes of an actual Application-confirmed state; wiring it to real lifecycle and UART
workloads is subsequent integration work, not a claim of full vault authentication by the observer.
The host trusts the reviewed guest's state assertion; it cannot authenticate ciphertext from hashes.

## Evidence, ACK and failure semantics

Host mode requires a new dedicated directory. Existing paths and reparse ancestors are refused;
the new directory has a protected current-user DACL and owner. It creates events.bin with CreateNew,
WriteThrough and no write sharing. Within this writer, evidence is append-only; no seek/overwrite or
open-existing mode exists. It is not tamper-proof against the owner, administrator or compromised OS.
The operator must select a host location disjoint from guest disks; the planner checks disjoint
canonical paths. The generic library Evidence writer assumes its directory has already been secured.

Evidence is consecutive validated 160-byte Event records, without transport length prefixes.
RecoveryKey and Receipt records are never passed to the evidence sink. Event sequence gaps at the
single Rotate secret transfer are intentional. No arbitrary strings, exception text, paths,
passwords, payloads or RK fields are written. Errors on the executable's stderr are a fixed
"Oracle trial inconclusive." No exception chain is exposed.

ACK append followed by Flush(true) must succeed before AckDurable becomes true and before any
Receipt is sent. End is also flushed before COMPLETE. Failure in append, flush, framing, timeout
or connection clears the live eligibility state and wipes the retained key. ACK bytes may exist
on disk after a flush failure; their mere presence is NOT proof the host issued a receipt. A later
cut controller must observe successful receipt delivery/live eligibility, not scan for the word ACK.
No poweroff implementation or persistent cut authorization token is provided in this task.

The executable has a 20-second total deadline; observer sessions have a positive timeout capped at
one minute (15 seconds in the process endpoint). GuestBridge takes the harness cancellation token;
callers must supply a finite deadline, as all supplied endpoints/tests do. A missing ACK, missing
End or lost host is never successful completion. After a lost host, persisted hashes remain useful
but recovery-key assertions requiring its RAM oracle are inconclusive. Each new trial uses a new
controller-generated run GUID and evidence directory; no cross-run automatic continuation exists.

## Recovery-key custody and transport security

Rotation alone admits one 32-byte RecoveryKey frame after authentication and before publication;
the remaining 64 payload bytes must be zero. The logical secret subchannel shares the framed byte
stream but has a separate kind, validation path and storage policy. It never enters event evidence.
The sender generates the synthetic key with RandomNumberGenerator, never a replacement production
RNG. Sender/decoder temporary byte arrays and retained host mutable buffers are zeroed after use
or failure/disposal. CopyRecovery provides a bounded mutable copy to a future verifier; that caller
owns and must wipe its copy. No immutable key string, file, environment value or command argument
is created. Process termination cannot run managed wiping; OS reclaim is not a secure-erasure claim.

NamedPipeServerStream uses Asynchronous | CurrentUserOnly and one instance. The local endpoint is
restricted to the host operator; VirtualBox must run under the same user and compatible elevation.
The anonymous probe uses a separate process, synchronous ImpersonateAnonymousToken/CreateFileW,
expects ERROR_ACCESS_DENIED, then RevertToSelf. It does not create users or change system policy.
A failed identity reversion fail-fasts that probe process.

Primary sources: [Microsoft PipeOptions](https://learn.microsoft.com/en-us/dotnet/api/system.io.pipes.pipeoptions?view=net-10.0)
explains the user/elevation boundary; [named-pipe security](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
describes DACL access checks; [anonymous impersonation](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-impersonateanonymoustoken)
documents the probe API. This is not protection against another compromised process of the same
operator, host administrator, compromised guest or OS. No TCP/HTTP listener or remote command API
is added. Host SMB policy and different-account/elevation permutations are not qualified here.

GuestBridge accepts a duplex Stream: local named pipes emulate UART for tests. The adapter uses the documented [DCB layout](https://learn.microsoft.com/en-us/windows/desktop/api/Winbase/ns-winbase-dcb)
and [BuildCommDCBW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-buildcommdcbw),
explicit binary-only flags and one-second native I/O bounds. VirtualUart provides guarded COM1 opening/configuration, but its native path, baud/flow control,
VirtualBox Host Pipe client mode, disconnect behavior and
its identity interaction have NOT been run. Do not claim VirtualBox UART compatibility from the
local emulation. VM validation of the COM stream adapter and binding to real Application operation boundaries
are prerequisites to VM campaigns, with no product changes or public qualification switches.

## Provisioning preparation

[New-MinimalLabPlan.ps1](../spikes/StorageLab/New-MinimalLabPlan.ps1) is read-only: requires explicit
new VM/OS disk/trial disk/pipe UUIDs and new disjoint lab/evidence directories, rejects known
registered identifiers and reparse ancestors, reads VBox inventory, then emits JSON only. There
is deliberately no execution switch. Output describes 2 vCPU, 6144 MiB RAM, 65536 MiB OS disk,
8192 MiB trial disk, EFI/TPM 2.0/Secure Boot, no NICs, shares, clipboard, drag/drop or USB, an
owner-only pipe and synthetic non-admin guest account. Reserve Q1's 256 GiB minimum before any
future provisioning. Read-only VBoxManage help modifynvram was consulted; no NVRAM operation ran.

[Test-MinimalLabIsolation.ps1](../spikes/StorageLab/Test-MinimalLabIsolation.ps1) is inspection-only:
refuses known user VMs, checks powered-off state, CPU/RAM/EFI, integrations and two explicit base
disks of required capacities under the lab path. It does not start, modify, create or poweroff.
A pass still requires guest TPM 2.0/Secure Boot attestation, NTFS/account/ACL checks and authorization;
this script does not pretend to establish guest firmware state from a requested plan.

After separate permission: provision new identities only, apply isolation before first boot,
initialize only the new VM's UEFI store, enroll signatures/platform key and enable Secure Boot;
install licensed offline Windows with no NIC exception; create non-admin synthetic account;
verify guest TPM/Secure Boot and local NTFS; transfer reviewed binaries by read-only ISO and detach
media; test UART without faults; preserve baseline and obtain a separate destructive-trial approval.
See [Q1](SN-003Q1-LAB-ARCHITECTURE.md) for capacity, forensic copies and acceptance criteria.

## Verification results

| Check | Actual result |
|---|---|
| Restore | Passed; no new package dependencies |
| Release build, final source | Passed, 0 warnings/errors |
| Full MTP suite | 466 passed, 0 failed/skipped, 6m 34.469s |
| Expanded final oracle suite | 34 passed, 0 failed/skipped; all six operations |
| Final MTP discovery | 471 cases in three assemblies |
| Native AOT win-x64 oracle | Publish passed; separate-process smoke passed |
| Managed CLI regression | 165 gen/existing + 22 vault checks passed |
| Planner / scripts | Read-only plan generated; syntax and existing-VM refusal guard passed |
| Documentation / Git | Relative links and git diff --check passed |

The full 466-case run preceded five additional operation cases and the isolated COM adapter;
34 final oracle tests cover the changed local components. Product code did not change. The COM
native branch is included in Native AOT through the internal guest-uart entry point but was not
executed. An initial discovery invocation with -- --list-tests returned zero tests and was rejected
as evidence; the corrected dotnet test --list-tests discovered 471. Logs, synthetic evidence and
all failed intermediate runs remain under ignored artifacts/sn-003q2-*.


The initial targeted run had 27/29 passes: managed anonymous open did not provide the expected
access result, and immediate evidence reopen after kill hit a transient sharing violation. The
probe now uses native open under anonymous impersonation. The controller waits at most two seconds
only for sharing violation after confirmed process exit; other errors are never retried. The next
run had 28/29 passes and exposed unflushed End evidence; End now flushes before COMPLETE. These
failed runs are not qualification successes. ACK flush ordering was not relaxed.

No VM power-cut, quota/full-volume, physical power-loss, remote CI, Linux/macOS or cross-user login
session was tested. Existing product crypto, vault wire format, gates and GC are unchanged.

## Changed files and final state

Modified: SafeNook.slnx, docs/ROADMAP.md, spikes/StorageLab/README.md and the Application.Tests
project reference. Added: this report; DurabilityOracle.csproj, Protocol.cs, Observer.cs,
GuestBridge.cs, Program.cs, PipeAccessProbe.cs and VirtualUart.cs under spikes/DurabilityOracle;
OracleTests.cs; New-MinimalLabPlan.ps1, Test-MinimalLabIsolation.ps1 and Test-OracleProcesses.ps1.
No files were deleted. Base and HEAD remain 4dadb78. Existing ignored artifacts were preserved;
new logs/evidence/native outputs are ignored artifacts. Product src/ has no diff.

The final source has 34 passing oracle tests (19.030s), 471 discovered tests; the full 466-case
run and final targeted expansion are distinguished above. All 26 relative documentation links
were checked. Source-VM refusal was exercised before any inspection/mutation; proposed directories
were confirmed absent. Positive VM isolation checks remain unexecuted because no lab VM exists.

## Suggested commit

```text
test(lab): add external durability oracle and guarded provisioning plans
```
