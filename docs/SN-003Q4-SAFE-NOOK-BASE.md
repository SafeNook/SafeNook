# SN-003Q4 — safe-nook-base power-cut smoke preparation

Date: 2026-11-17. **ISOLATED, NOT ARMED. No VM was started or powered off.**
Production writes and GC remain disabled. After explicit owner approval, only the powered-off
safe-nook-base configuration was isolated. Guest deployment and a no-cut check remain necessary
before a poweroff request; isolation approval does not authorize a power cut.

## Git and initial observed VM

Clean local main d310992 contains merged Q3 and SN-CI-002 (PR #19), matching the recorded origin/main.
Created feat/sn-003q4-safe-nook-base-smoke from that local base. No remote freshness assertion,
commit, push, fetch, pull, merge or rebase. Existing ignored outputs/evidence are preserved.

Read-only VBoxManage showvminfo, showmediuminfo and snapshot list established:

| Property | Observed |
|---|---|
| Name / UUID | safe-nook-base / efef2867-fa7e-4e7e-9f30-477262021e73 |
| State | poweroff |
| Guest type / resources | Windows 11 x64; 2 vCPU; 6655 MiB RAM |
| Firmware | EFI; SecureBoot on (guest attestation not performed) |
| OS disk UUID | 4a012329-1d1e-4c46-8f66-2983a4734e2a |
| OS disk | C:\Users\algmi\VirtualBox VMs\safe-nook-base\safe-nook-base.vdi |
| Disk independence | Parent UUID: base; normal base VDI, no differencing parent or reported children |
| Capacity / allocated size | 81920 MiB / 20810 MiB; dynamic VDI |
| Snapshots | None (VBoxManage reports no snapshots) |
| SATA port 1 | VBoxGuestAdditions.iso from host installation |
| SATA port 2 | Win11\Unattended-b147c2a7-6ed9-48f4-86d4-81774046aea4-aux-iso.viso |
| Network | NIC1 NAT, connected; NIC2–8 none |
| Host integrations | VideoEngine shared folder → C:\VMShare\VideoEngine; clipboard/drag-and-drop bidirectional |
| USB | OHCI/EHCI off; xHCI on; USB tablet pointer; no USB filters shown |
| COM1 | uart1 off; no active host-pipe configuration |

The VDI is **not a linked clone**. Original Win11 uses another base UUID,
31f44bb6-06b7-4d6a-bc4c-3acf7a70b90e, with its own differencing child. However, this VM still
references Win11's auxiliary VISO; disk independence is not complete configuration isolation.
Do not boot with that inherited media. Win11 and its snapshots/media were not modified.
USB controller availability is not proof that an actual host USB device is passed through.

## Isolation applied with owner approval

The owner explicitly approved isolation after the initial read-only inspection. Applied only to
safe-nook-base: all NICs set to none, VideoEngine shared-folder mapping removed, clipboard and
drag-and-drop disabled, OHCI/EHCI/xHCI disabled, pointer changed to PS/2, both DVD/VISO attachments
removed. The referenced files were not deleted. COM1–4 remain off and the sole attached medium
is the same independent base VDI. VM state remains poweroff.

The read-only Invoke-SafeNookBasePowerCut.ps1 -InspectOnly preflight now PASSES. Win11.vbox SHA-256
was compared immediately before and after the changes and is unchanged. No Win11 command that
mutates state was issued; no VM/snapshot/disk was created, started, deleted or powered off.
Before/after inventories are retained in artifacts/sn-003q4-isolation-before.txt and
artifacts/sn-003q4-isolation-after.txt. These are configuration checks, not execution/durability tests.

## Minimal preparation

No new VM, disk, snapshot or external oracle service is necessary for this first smoke. Use the
existing ApplicationQualification controller and DurabilityOracle inside the guest. COM1 remains
off: UART integration is not a prerequisite for the explicitly permitted guest-local check.

The following commands were executed after owner authorization while safe-nook-base was powered
off. They document the completed change; do not blindly rerun sharedfolder removal:

```powershell
$vbox = 'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe'
$id = 'efef2867-fa7e-4e7e-9f30-477262021e73'
& $vbox modifyvm $id --nic1 none --nic2 none --nic3 none --nic4 none --nic5 none --nic6 none --nic7 none --nic8 none --clipboard-mode disabled --drag-and-drop disabled --usb-ohci off --usb-ehci off --usb-xhci off --mouse ps2
& $vbox sharedfolder remove $id --name VideoEngine
& $vbox storageattach $id --storagectl SATA --port 1 --device 0 --medium none
& $vbox storageattach $id --storagectl SATA --port 2 --device 0 --medium none
```

Check each exit code and re-read configuration; do not run the remaining commands after a failure.
Changing the pointer to PS/2 keeps input usable with USB disabled. Detaching media does not delete
files or modify Win11. Provision a reviewed executable using owner-selected read-only media, copy
it inside the guest, then detach that media before the trial. Do not re-enable shared folders as
a hidden transfer shortcut. Transfer/mounting and guest login have not been performed.

## Guest artifact and harness

Native AOT win-x64 executable prepared on the host:

`C:\Users\algmi\source\repos\SafeNook\artifacts\sn-003q4-guest\ApplicationQualification.exe`

SHA-256: `A9FFAF3DCC63BF5DE286C4EC12C606AD30AA06D1E40C97AF01DB34E9BC590B1F`.
Copy to `C:\SafeNookSmoke\bin\ApplicationQualification.exe` inside the guest and verify this hash.
It is self-contained with the existing statically linked libsodium; no SDK install in the guest
is needed. Only fixed synthetic credentials are accepted by the fixture; no argv/env secrets.

New internal scenarios use the existing real Password operation and Storage hooks:

- vm-pre: pause at real BeforePublish before root publication. Expected unchanged sequence 2.
- vm-post: pause at real AfterPublish, before namespace flush/readback completes. No ACK claim.
- vm-ack: Application success, fresh full guest verification, independent local-controller
  verification, evidence Flush(true), receipt and flushed End; then pause. Expected sequence 3.

The old oracle pre/post scenarios kill their child themselves and are NOT usable as VM-cut
pause points. The new modes leave both processes alive for up to 30 minutes. On expiry they fail
and clean up only their own processes; they never poweroff the VM or retry a commit. Do not cut
unless the displayed marker belongs to the current run and the processes are still paused.

Each run creates a fresh vault, a fully authenticated `.baseline.snbak`, and the existing owner-only
`.oracle` evidence directory. No plaintext temporary file or new vault format is introduced.
The initial baseline is sequence 2 and contains an encrypted file item/blob sentinel. Use a fresh
case directory each time; a pre-existing vault is rejected. Do not remove previous cases/evidence.

## Exact first-trial commands

Inside the guest, use a local non-admin account, local fixed NTFS and at least 1 GiB free headroom.
Do not use a shared folder, user vault or quota/fill workload. Confirm the artifact hash, clock,
OS/NTFS version and disk free space. Keep the console visible. Choose ONE new case:

```powershell
# Before publication:
& C:\SafeNookSmoke\bin\ApplicationQualification.exe C:\SafeNookSmoke\cases\pre-001\vault oracle Password vm-pre
# After native publication, before confirmed ACK:
& C:\SafeNookSmoke\bin\ApplicationQualification.exe C:\SafeNookSmoke\cases\post-001\vault oracle Password vm-post
# After fully checked and flushed ACK:
& C:\SafeNookSmoke\bin\ApplicationQualification.exe C:\SafeNookSmoke\cases\ack-001\vault oracle Password vm-ack
```

These commands create synthetic fixtures and then wait. Observe BASELINE-SHA256 and VM-READY
pre/post/ack. Record the exact phase, case path and displayed hashes OUTSIDE the guest, for example
in an operator record/screenshot. The pre/post marker carries the original raw header SHA-256;
the ack marker carries Q2's three domain hashes. Do not confuse those domains or treat the
post-publication marker as ACK. No RK or password is displayed.

Host read-only preflight:

```powershell
& 'C:\Users\algmi\source\repos\SafeNook\spikes\StorageLab\Invoke-SafeNookBasePowerCut.ps1' -InspectOnly
```

Only AFTER separate owner approval for this specific trial, while VM-READY is still valid:

```powershell
& 'C:\Users\algmi\source\repos\SafeNook\spikes\StorageLab\Invoke-SafeNookBasePowerCut.ps1' -OwnerApprovedPowerCut
```

The script is pinned to the observed name/UUID and single base disk, rejects host integrations,
network, USB, other media and dependent/reparse disk paths, and requires running state before
controlvm poweroff. It has no create/start/snapshot/retry/repair path. The flag does not replace
owner permission. It cannot observe the guest console: the operator must verify the current marker.
The older Invoke-LabPowerCut.ps1 expects another VM name and is not used for this VM.

After the approved cut, restart this VM manually. Do not restore a snapshot or repair the original
media automatically. First-smoke guest startup/journal replay is allowed but changes disk state;
this is NOT preservation of forensic originals. Run only the matching verifier:

```powershell
& C:\SafeNookSmoke\bin\ApplicationQualification.exe C:\SafeNookSmoke\cases\pre-001\vault vm-smoke-verify pre
& C:\SafeNookSmoke\bin\ApplicationQualification.exe C:\SafeNookSmoke\cases\post-001\vault vm-smoke-verify post
& C:\SafeNookSmoke\bin\ApplicationQualification.exe C:\SafeNookSmoke\cases\ack-001\vault vm-smoke-verify ack
```

The verifier does not execute a mutation or repeat the operation. It authenticates the baseline
archive, selected root/header MAC/manifest/items/all blobs, password and recovery access, retained
generations, Vault Key/epoch/lineage, and active references against baseline ciphertext. ACK mode
also compares saved ACK and raw hashes. It prints baseline SHA-256 and current domain hashes for
comparison with the host operator record. Missing/damaged evidence means refusal, never success.

Before publication requires the old state. The post mode checks the new state; if a real VM cut
loses it before ACK, preserve evidence and classify manually (old authenticated state can be an
unacknowledged outcome). The verifier does not silently select old state or roll back. After ACK,
a lost acknowledged state is a failure even if an old generation could still open.

## Changed files

Modified: ApplicationQualification Program.cs and OracleIntegration.cs, OracleIntegrationTests.cs,
and docs/ROADMAP.md. Added: Invoke-SafeNookBasePowerCut.ps1 and this report. No product src/ diff,
no deleted files. Base/HEAD d310992; no commit or remote operations.

## Checks and readiness

Release build: passed, zero warnings/errors. Native AOT publish passed. Targeted MTP integration: 61 passed, zero failed/skipped (2m 12.053s), including all 57 Q3 cases
and four new pause/reopen cases. Native AOT process-only smoke: pre/post/ack passed (sequences
2/3/3). These are local process crashes, not guest OS power cuts. The new pause modes were exercised by
killing only their own host/worker processes, never VirtualBox. No COM1 path was executed.

Poweroff script syntax passed. Its no-approval guard refused before native calls. The initial
read-only preflight correctly refused the enabled NAT; after authorized isolation it PASSED.
The VM remains powered off. No poweroff invocation or live guest test was performed.

Outstanding before requesting the first cut: deployment and hash check inside the guest and a
non-destructive pause/reopen rehearsal. Re-run isolation preflight after detaching deployment media.
Thus it is NOT yet accurate to say that only poweroff approval remains. Isolation is complete;
no extra lab VM or infrastructure is proposed.

Risks: abrupt stop affects the entire existing 80 GiB guest OS disk, not just synthetic files.
No guest data-loss guarantee or independent forensic/power-loss qualification is made. Host/device
caches remain alive during VirtualBox poweroff. Guest-local evidence can itself be lost or rolled
back; external operator records help identify mismatches but do not replace an independent oracle.
No physical/cache-controller, quota, Linux/macOS, or live VM test was run.

```text
test(lab): prepare safe-nook-base power-cut smoke scenarios
```
