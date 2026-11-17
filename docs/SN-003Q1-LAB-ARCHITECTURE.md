# SN-003Q1 — Isolated Windows storage qualification lab

Date: 2026-11-17. Status: **architecture proposed; deployment and destructive trials NOT authorized or executed**.
Production writes and GC remain disabled. This document does not change any ADR, vault wire format,
cryptographic parameter, public CLI or security invariant.

## Baseline and evidence

Owner updated main to c3be815ff76bb38336af6bc5855b613e05297d33 (SN-003D3, PR #18).
Work started on clean main and created docs/sn-003q1-isolated-storage-lab. Main matched the locally
recorded origin/main; remote freshness was not independently checked. No commit or remote Git
operation was performed. Ignored artifacts, published binaries and build outputs were preserved.

Inputs: [D3 report](SN-003D3-CRASH-QUALIFICATION.md), [B3 power-cut plan](SN-003B3-POWER-CUT-PLAN.md)
and all five scripts in [StorageLab](../spikes/StorageLab/README.md).
D3 process-kill results are historical evidence, not VM power-loss results.

Read-only discovery in this session found VirtualBox 7.1.4r165100; existing Win11 is powered off,
2 vCPU / 6655 MiB RAM. Its known disk capacity is 80 GiB with a snapshot chain. Current settings
include VMShare, bidirectional clipboard/drag-and-drop, NIC1–8 none, OHCI/EHCI off **but xHCI on**.
The earlier D3 statement that all USB controllers were off must not be used as current evidence.
No setting was changed. A USB controller being enabled does not prove a device is passed through,
but fails the proposed stricter isolation check. Source VM and snapshots are not disposable.
Host discovery: 68,406,087,680 bytes physical RAM, 16 logical processors; C: free
380,385,636,352 bytes (about 354 GiB). These are observations, not reserved capacity or permission
to use C:. Recheck capacity immediately before any future allocation.

## Configuration comparison and recommendation

| Criterion | A: independent full clone | B: new minimal Windows VM — recommended |
|---|---|---|
| Origin | Full copy of Clean Win11 snapshot; never linked clone | Owner-supplied official Windows 11 x64 media; no source VM dependency |
| Virtual disks | 80 GiB OS + 8 GiB trial disk | 64 GiB OS + 8 GiB trial disk |
| RAM / CPU | Existing 6655 MiB / 2 vCPU, record exact configuration | 6144 MiB / 2 vCPU; one lab VM running at a time |
| Host budget, one trial | 304 GiB conservative budget below | 256 GiB conservative budget below |
| Licensing | Source activation does not establish entitlement for another instance; owner must check applicable rights | Owner must supply applicable VM entitlement and supported offline provisioning/activation procedure |
| Isolation | Must audit inherited folders, media, USB, clipboard, services, accounts and scheduled tasks | Start with empty integrations, synthetic local accounts and explicit attachment allowlist |
| Reproducibility | Snapshot UUID and source provenance required; inherited software may confound results | Record ISO hash, edition/build, installation recipe, driver and patch inventory |
| Power cut | Suitable after independence and isolation gates pass | Suitable after same gates pass |
| Full/quota testing | Separate disposable local fixed NTFS disk | Same; no filling OS disk |
| Forensics | Preserve OS disk as well as trial disk; source is not an adequate copy of faulted state | Same; new VM does not eliminate forensic storage costs |

Recommend B because it avoids inherited user data and settings and reduces the per-copy OS budget.
64 GiB is a deliberately minimal supported capacity, not a claim that all updates will fit. If
installation, servicing or measured free-space needs require 80 GiB, stop and increase the budget
to 304 GiB; do not shrink Windows or bypass requirements. Use UEFI, virtual TPM 2.0 and Secure
Boot support, a supported host CPU, and a recorded SATA/AHCI controller/cache configuration.
Disable 3D acceleration and unnecessary integrations; no Guest Additions dependency is needed.
The Microsoft requirements specify 4 GB RAM, 64 GB storage and TPM 2.0; the selected 6 GiB RAM
provides additional test headroom ([Microsoft requirements](https://learn.microsoft.com/en-us/windows/whats-new/windows-11-requirements)).

A Windows Enterprise evaluation is a possible time-limited evaluation route, not an assumed
license grant or assured offline install. Microsoft describes a 90-day evaluation and hourly
shutdown after failed activation or expiration. Such shutdowns invalidate cut timing. Verify
edition terms, activation, account/setup requirements and expiry before accepting a baseline;
do not reset evaluation time through snapshots. If the owner cannot provide a supported procedure
with **no NIC at any stage**, provisioning is blocked; no automatic temporary networking exception
([Microsoft Evaluation Center](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise)).
Existing license terms and host CPU compatibility have not been established in this task.

### Capacity accounting

Budget by maximum logical capacity, not today's dynamically allocated VDI size:

- B: 3 × (64 + 8) = 216 GiB; A: 3 × (80 + 8) = 264 GiB.
- Three sets mean immutable clean baseline, trial set retained as the post-fault forensic original,
  and independent recovery working copy. The active trial becomes the forensic set; it is not a
  fourth set. Preserve all associated configuration, NVRAM/TPM state and hashes.
- Add 16 GiB bounded ISO/tool/evidence allowance and **24 GiB host free-space floor**:
  B = 256 GiB, A = 304 GiB. If ISO/evidence exceeds allowance, increase budget first.
- Each additional retained faulted set costs up to 72 GiB (B) / 88 GiB (A); keeping another
  recovery copy costs the same again. No automatic deletion or rolling retention is authorized.
- A 256 MiB trial disk can be a separate small-volume campaign, but cannot exercise every large
  archive workload. The 8 GiB plan accommodates bounded archives up to the existing 2 GiB limit.

Prefer a dedicated owner-selected host lab volume/path. No path has been allocated. Host space
exhaustion is forbidden: reserve before running, monitor during copying/filling, and stop new work
before reaching the floor. Disk expansion and all other host consumers count. The space estimate
is not a guarantee against unrelated host writes. Archive content is sequentially verified;
container capacity is not permission to allocate a 2 GiB buffer.

## Isolation acceptance checklist (must pass before first boot and every cut)

- New registered UUID and new canonical lab directory; explicitly reject every existing user VM.
- Every attached hard disk is independent (Parent UUID=base), lab-owned, under the approved path;
  reject raw disks, physical passthrough, source media, differencing chains, reparse paths and UNC.
- Exactly OS + one disposable trial disk for campaigns; no user disks. Test volume identity is
  bound to VM UUID, disk UUID/unique ID, partition and volume GUID, not a drive letter alone.
- NIC1–8 absent/none, no shared folders (including transient), clipboard/file transfer and
  drag-and-drop disabled; OHCI/EHCI/xHCI, USB filters, card reader and USB passthrough disabled.
- No host DVD/device access. Approved read-only installer/tool ISO only during provisioning;
  detach all ISO/VISO media before trial. No generic guest-control/remote desktop channel.
- Test NTFS disk has SAFENOOK-DISPOSABLE label, is fixed, non-system/non-boot/no pagefile;
  no compression/sparse filler. Record sector/cluster sizes, effective SID and ACLs.
- Synthetic credentials/data only. Test as the dedicated non-admin account; use a separate
  guest administrator only for explicitly approved lab setup/quota. No production vault import.
- Only the bounded virtual UART oracle channel described below may cross the boundary.
  It provides no host filesystem, command execution or arbitrary path API.
- Record Windows/VirtualBox versions, firmware/controller/cache settings, host volume/device,
  filter drivers and binary hashes. No changing cache/host settings as an implicit test action.

These are future checks, not claims that a lab exists or that a positive path was tested.

## External oracle design

The D3 same-OS named-pipe observer does not survive guest poweroff. Implement a separate host
controller and guest-only qualification bridge before VM trials; no public nook switch.
Use virtual UART Host Pipe mode, with a host-created named pipe restricted to the operator identity
running VirtualBox; guest connects through its virtual COM port. Do not select serial-to-file,
TCP, physical COM or unrestricted default pipe ACLs. VirtualBox documents Windows named-pipe
transport ([Oracle 7.1 manual](https://docs.oracle.com/en/virtualization/virtualbox/7.1/user/BasicConcepts.html)).
Connection mode/ACL interoperability must be tested without cutting power before deployment approval.

Separate bounded event frames from secret frames. Proposed limits: 4 KiB/frame, fixed message kinds,
strict schema, monotonic event sequence, unique run ID, operation and boundary/occurrence enum,
binary/configuration hash, expected generation/sequence, exact root-wrapper SHA-256, canonical
414-byte header SHA-256 and complete archive SHA-256 as applicable. No payload, arbitrary text,
path, password or RK field is accepted in the event logger. Reject duplicate/out-of-order/unexpected
frames, invalid lengths, timeout and EOF; none is a successful verification. Hash domains and byte
lengths must be explicit; never compare a wrapper hash with a header hash.

Host evidence is append-only per new run file, outside all guest media, with restrictive ACLs.
Record baseline inventory and hashes, phase/occurrence, BEFORE_PUBLISH, publication-attempt status,
Application success, received ACK, host receipt-flush completion, poweroff request/result and later
verification. Flush ACK evidence before sending receipt or initiating a deliberate post-ACK cut.
A guest sends ACK only after the Application operation returns confirmed success, with hashes of
that exact committed state. If host evidence write fails, stop the campaign: do not acknowledge
or cut as a post-ACK case. Missing ACK is never invented from the eventual disk contents.

A bounded secret channel carries only synthetic rotation RK to host-owned mutable RAM, before its
publication is permitted by the harness. Do not log/tee/dump raw serial frames or send credentials
via argv/env. No deterministic replacement of production RNG. Wipe buffers at trial completion;
keep the host observer alive through recovery-copy verification. Public fixed fixture credentials
can be regenerated; random rotated RK cannot. Host observer death loses the RAM oracle and makes
that credential assertion inconclusive, never a pass. Durable nonsecret evidence survives; host
failure itself is outside this VM-cut campaign. Persistent secret escrow, if later needed, requires
separate design review. No custom encryption or new vault/container format is introduced here.

Acceptance rules:

| Observed external state | Required recovery result |
|---|---|
| Known pre-publication point | Exact baseline root, both old access paths, all retained generations authenticate |
| Publication attempted but no durable host ACK | Fully authenticated old or new state, or explicit RecoveryRequired; classify separately, no mixed state or hidden rollback |
| Host durably recorded ACK | Exact acknowledged root/archive and full authentication; lost state or RecoveryRequired is a durability failure |
| Missing/broken oracle, unexplained VM stop | Inconclusive trial; retain evidence, never infer success |

Allow a later state only if the oracle records a later legitimate acknowledged operation; default
is one mutation per trial. External hashes bind a trusted run record but do not independently
prevent rollback without that trusted reference. After reboot, authenticate header MAC, manifest,
every item and **every blob AEAD tag**, all retained roots with corresponding historical credentials,
and compare inventories, slots, VK/epoch and generation. No auto retry, fallback or GC.

## Future actions, in order — none executed here

1. Owner selects B or A, new absolute host lab/evidence paths, disk budget, supported Windows
   media/license/offline setup procedure. Approve provisioning separately from destructive trials.
2. Implement/review host oracle and guest bridge; test parsing, denied ACL access, disconnect,
   secret redaction, full-buffer handling and ACK persistence with ordinary process tests.
3. Review existing scripts and create a B-specific provision plan. New-LabPlan.ps1 is a clone-only
   planner, not an implementation of this recommendation. Bind executor to approved exact UUIDs,
   media inventory and oracle readiness. Existing poweroff guard alone is insufficient authorization.
4. After explicit provisioning approval, create independent VM and disks, enforce isolation before
   first boot, install via approved ISO/offline workflow, create synthetic accounts, deploy hashed
   Release/Native AOT qualification binaries by ISO. Detach media, inspect all settings again.
5. Establish capability baseline: local fixed NTFS, owner/DACL, path/reparse protections, flush and
   rename support, normal lifecycle/backup/verify/restore and oracle handshake. Fail closed.
6. Shut down normally for a clean baseline, preserve independent baseline disks/configuration and
   hashes. Allocate one fresh trial copy; prove source VM cannot be referenced by any attachment.
7. Obtain separate approval for specific VM-cut and guest volume/quota campaigns. No script switch
   substitutes for owner authorization. Never automatically poweroff on an unrelated error.
8. Run an approved single-case dry run without a fault, then boundary and random-cut campaigns.
   Record actual native errors and phases. On cut, wait for powered-off state and closed disk handles.
9. Hash and preserve faulted media/config before first boot, repair or journal replay. Create an
   independent working copy; boot only it. Capture recovery/journal effects and full verification.
10. Retain original, working copy and oracle evidence. Repeat only with space reserved and new IDs.
    Report failures/inconclusive cases individually. No source snapshot deletion or automatic cleanup.

## Power-cut and NTFS campaign plan

Use passwd, recover, recovery rotate, backup and restore workloads; backup verify is read-only but
must release locks and never report success after interrupted authentication. Include login/note,
empty/1/5/10/25 MiB blobs, tombstones, multiple objects and retained generations. Source vault and
backup input remain separate from restore destination, which must initially not exist.

Cover D3 boundaries with occurrence counters for each repeated object: authenticated/validated,
write/flush/install, manifest verification, retained-root write, root staging/flush, before rename,
after publication attempt, readback and post-ACK. Add random delays to cut during active I/O;
a paused boundary is not an in-flight syscall test. Record random seed, occurrence and actual cut
latency. Use B3's proposed 100 repetitions per boundary/workload/configuration and 1,000 random
cuts as campaign planning targets, not statistical proof; capacity/retention approval is necessary
before adopting these counts. Never budget hundreds of retained trials as a single trial.

| NTFS scenario | Preparation and evidence | Required checks |
|---|---|---|
| Real full volume | Guest trial disk only; bounded non-sparse flushed filler, actual free bytes, native errors; controlled windows around object/manifest/root/backup staging | Old access paths before publication; no false success; full current/retained verification after recovery |
| Quota exhaustion | Separate approval; track/enforce quota for exact synthetic test SID on trial volume, verify ownership and effective limit; keep physical free space available | Distinguish quota from disk full by observed native error and quota query; no fallback identity |
| Metadata pressure | Bounded many-small-file/directory workload; capture file counts, allocation/free space and native errors; host capacity guard | Do not label MFT exhaustion merely from a failed allocation; verify evidence or report generic allocation pressure |
| Flush failure | Observe real errors if they occur; separately run injected failures | Full disk does not guarantee a flush failure; do not relabel injection as hardware evidence |
| Recovery after refusal | Preserve original; only on working copy and separately approved, release manifest-listed filler if space is needed | Never delete unknown/ciphertext files; no automatic retry, root replacement or rollback |
| Backup/restore under pressure | Put destination on trial disk; protect source on OS disk, bound source fixture space; full input authentication | Exact archive hash/content after ACK, no partial published root, source unchanged, restored IDs/slots/ciphertext preserved |

Quota controls are NTFS per-volume/per-user operations; Windows 11 is supported by the documented
command ([Microsoft fsutil quota](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-quota)).
Do not execute quota commands on host or guest OS volume. No quota/format/fill command was run here.

## Limits, checks and decisions

Actually performed: local Git inspection, source/script review, read-only VM/host inventory,
primary-source lookup, capacity arithmetic, relative Markdown link checks and git diff --check.
No executable code changed, so build/MTP/AOT were not rerun; their D3 results are not new Q1 results.
No VM/disk creation, start, poweroff, snapshot operation, quota change, disk filling or destructive
trial occurred. No new physical durability, Linux/macOS or CI claim is made.

VM poweroff leaves host/controller caches alive. It tests guest-crash behavior on the recorded
configuration, not actual loss of host/device power or dishonest flush completion. Physical claims
still require sacrificial hardware and an independent observer. Oracle implementation, positive-path
script tests, offline Windows licensing/setup, exact host path and capacity reservation remain
outstanding. Existing scripts need review for the new VM and full oracle gating before use.

Owner decision requested: approve B's architecture and 256 GiB one-trial budget, or choose A;
identify licensed offline media and dedicated locations before requesting provisioning. Architecture
approval does not authorize creating/starting VM, allocating disks, poweroff, quota or filling.
Production writes and GC require their own later approval regardless of lab results.

Suggested Conventional Commit:

```text
docs(lab): define isolated Windows storage qualification architecture
```
