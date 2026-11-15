# SN-003B3 — destructive Windows storage qualification plan

Date: 2026-11-13. **Prepared, not executed. Production gate remains closed.**

## Available equipment and scope

Read-only discovery found VirtualBox 7.1.4r165100 at
`C:\Program Files\Oracle\VirtualBox\VBoxManage.exe`, outside PATH. Registered `Win11`
is Windows 11 x64, powered off, 2 vCPUs, 6655 MiB RAM, network adapters disabled; it has
`Clean Win11` and `Android` snapshots. The clean snapshot description mentions a shared
folder. Another existing VM is present. Neither VM nor snapshots were modified/started.
No Hyper-V module/Get-VM/Get-VHD/New-VHD or QEMU command was found. No dedicated disposable
Windows qualification clone, guest test deployment, controller fault injector or physical
power-cut rig was provisioned. Existing VM ownership/data must not be presumed disposable.

VirtualBox provides `controlvm <uuid> poweroff`; its installed `VBoxManage help controlvm`
and `help clonevm` were consulted. Poweroff is distinct from savestate, pause or ACPI shutdown.
It abruptly stops the guest, but the host and host/device caches remain alive. It qualifies
only that virtual configuration's guest-crash behavior, not physical controller-cache loss.

## Prepare an isolated lab (operator steps, not executed here)

1. Record host/guest Windows versions, VirtualBox build, SDK/.NET versions, NTFS cluster size,
   guest disk/controller type, host filesystem/device/firmware, cache and flush settings,
   power-loss protection, filter/antivirus drivers and free space. Use synthetic credentials only.
2. With sufficient dedicated disk space, make a **full independent clone** of the clean
   Windows snapshot, not a linked clone of a live user disk. Example host PowerShell:

   ```powershell
   $vbox = 'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe'
   $labName = 'SafeNook-Qualification-Disposable'
   & $vbox clonevm 'Win11' --snapshot 'Clean Win11' --mode machine --name $labName --basefolder 'D:\SafeNookLab' --register
   if ($LASTEXITCODE -ne 0) { throw 'Clone failed; do not continue.' }
   & $vbox showvminfo $labName --machinereadable
   ```

   `D:\SafeNookLab` is a placeholder for a verified dedicated host directory, not a detected
   drive. Record the clone's UUID; subsequent destructive commands must use that UUID only.
3. Inspect and remove **clone-only** shared folders, shared clipboard and drag-and-drop,
   USB passthrough and all network adapters. Never test in a host shared folder or on a
   passthrough user disk. Keep source VM untouched. Disable automatic guest shutdown/save
   integrations for abrupt-stop cases. Record host I/O cache settings rather than assuming them.
4. Deploy the Release/Native AOT StoreQualification executable and necessary runtime assets
   through a read-only ISO or other isolated transfer. Use a guest-local fixed NTFS test volume
   and a test account. Build with the reviewed commit and record binary hashes.
5. Take a powered-off clean lab baseline. Allocate a fresh independent disk/run directory for
   each trial. Preserve the post-fault disk before its first reboot; do not restore the clean
   snapshot before evaluating the faulted image. Restoring a baseline is only for a new trial.

## Boundary campaign

Guest invocation (fresh path, parent directory exists):

```powershell
.\StoreQualification.exe 'C:\SafeNookLab\case-001' crash AfterPublish
```

The helper creates a synthetic empty vault, attempts a blob/item commit, prints CRASH_POINT
at the chosen boundary and waits indefinitely. It does not shut down Windows. Capture its
console/serial output outside the guest, with run ID, binary hash and boundary. On observing
the marker, an operator or host orchestrator abruptly powers off **only the clone**:

```powershell
# Replace with the recorded UUID of SafeNook-Qualification-Disposable, never Win11's UUID.
$labId = '<disposable-clone-uuid>'
& $vbox showvminfo $labId --machinereadable
# Verify UUID/name, running state, isolated disks and no shared folders before executing:
& $vbox controlvm $labId poweroff
```

Do not use `savestate`, `acpipowerbutton`, guest shutdown, host process kill, or an ordinary
snapshot as a substitute. Export/copy the powered-off virtual disks plus VM configuration
without booting them; hash and retain forensic originals. Boot a working copy, then run:

```powershell
.\StoreQualification.exe 'C:\SafeNookLab\case-001' verify
```

`VERIFIED 0` means the fixture's fully authenticated old empty generation; `VERIFIED 1`
means the fully authenticated new item/blob generation. `REFUSED ...` is an explicit
recovery-required outcome; retain all bytes for offline diagnosis. Capture root wrapper,
manifest/object file hashes, lengths and inventory, not plaintext or credentials. Verify
retained roots separately via InspectRecoveryCandidate and the retained-generation test
fixture; do not treat successful current-root verification as proof of all backups.

Repeat for Validated, ObjectWritten, ObjectFlushed, ObjectInstalled, ManifestVerified,
BackupWritten, RootWritten, RootFlushed, BeforePublish, AfterPublish, RootReadback. Current
helper pauses on the first occurrence of a repeated boundary. A full campaign must also
instrument occurrence counters to cover each item/blob/manifest, multiple-file and slot
rotation workloads; that automation is not implemented or claimed executed here.

Add unsynchronised random cuts during writes/flush/rename and cuts immediately after a host
has recorded a successful commit acknowledgement. The current paused helper covers pre-ACK
boundaries only; add an external durable ACK log and exact sequence/header-hash oracle for
post-ACK testing. Host timestamps and a marker introduce delay; random-offset trials are
needed to cover in-flight I/O rather than only quiescent boundaries.

Proposed minimum campaign, to be approved before claiming qualification: 100 trials for
each boundary/occurrence/workload/configuration plus 1,000 random-offset trials, including
empty/1/5/10/25 MiB blobs, tombstones, password/recovery replacement, many retained roots
and near-full volumes. These counts are planning targets, not statistical proof.

## Real ENOSPC / quota campaign

Inside the disposable guest only, attach a separately labelled small fixed NTFS disk (for
example 256 MiB) containing only synthetic lab data. Never fill the host C: drive, a source
VM disk or a shared folder. Record its identity and free-space baseline.

Use ordinary fully written non-sparse filler files, flush them, and verify actual free
space. Leave controlled free-space windows around object creation, manifest write, backup
write, root staging and metadata allocation. Record actual Win32/native errors and ensure
there is enough reserved recovery space in a separate guest disk. Repeat with an NTFS
per-test-user enforced quota configured only on that disposable volume; metadata-space
exhaustion differs from quota exhaustion. Keep the vault's effective user constant.

Verify pre-publication failure preserves old authenticated root and both old slots; a
failure after attempted publication must not be acknowledged or blindly retried. Release
only known filler files for recovery, retaining vault evidence. Reopen and authenticate
current and every retained generation. Injected IOException/short write tests do not count
as this campaign. No quota setting or host-volume filling was performed in SN-003B3.

## Physical/controller campaign and acceptance

For physical claims, use a sacrificial host/device with a remotely controlled power relay
or equivalent controller-fault lab, separate observer and durable ACK log. Cut actual device/
host power, not the application or guest alone. Test specified controller/firmware/cache modes,
including volatile cache and honest/failed flush completion, and repeat across intended hardware.
Preserve raw media before repair tools mutate it. Windows journal replay on a working copy
is part of the recorded recovery path; no automatic chkdsk repair on the forensic original.

For an unacknowledged operation, allow fully authenticated old state, fully authenticated new
state, or explicit RecoveryRequired; never accept mixed dependencies or silent rollback.
For an acknowledged commit, the claimed durability configuration must reopen the acknowledged
state (or a later legitimately acknowledged state). Reverting to old state/RecoveryRequired
is a durability failure even though fail-closed recovery avoids silent corruption. Check exact
password/recovery preservation and no plaintext temp files in every trial.

Report each failure and failed acknowledgement separately, retain logs/images/hashes, and
update the [readiness checklist](SN-003B3-PRODUCTION-WRITES-CHECKLIST.md). Even an all-pass
lab report requires independent review and explicit owner approval before opening writes.
