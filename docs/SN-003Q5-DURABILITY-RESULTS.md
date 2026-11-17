# SN-003Q5 — Windows VM durability smoke results

Date: 2026-11-17. Campaign: **PASS, 3/3 guest-local VM power-cut smoke trials**. Final Windows regression passed. No further cuts authorized. Production writes and GC remain disabled.

## Scope and Git

Q4 saved by owner in b4b9286. Owner explicitly requested continuing on
feat/sn-003q4-safe-nook-base-smoke rather than a new branch. No commit or remote Git
operations performed. Existing artifacts preserved. Remote freshness not checked.

Target only: safe-nook-base, UUID efef2867-fa7e-4e7e-9f30-477262021e73.
Independent base VDI: 4a012329-1d1e-4c46-8f66-2983a4734e2a.

## Deployment

Native AOT executable SHA-256:
`A9FFAF3DCC63BF5DE286C4EC12C606AD30AA06D1E40C97AF01DB34E9BC590B1F`.
Minimal read-only ISO SHA-256:
`67054F4C93FA2FF203FBF8F088D7C1B903B17507A6FEFF70FB1FE960CC6F52F2`.
Owner executed copy and both hash checks inside guest successfully. Destination:
C:\SafeNookSmoke\bin\ApplicationQualification.exe. Guest C: reported NTFS and
57,475,809,280 bytes free. ISO subsequently ejected; empty DVD drive remains.
Initial ACPI requests did not stop Windows; owner performed ordinary shutdown
for DVD attachment. No forced shutdown used during preparation.

## Isolation exception

Owner explicitly permits clipboard for manual command entry. Guard defaults still
refuse enabled clipboard; the laboratory-only OwnerApprovedClipboardForSmoke switch
permits known modes and prints a warning. Clipboard file transfers remain forbidden.
Drag-and-drop, NICs, shared folders, USB and UART remain forbidden. UUID, independent
VDI, attached media and path checks are unchanged. This is not full-isolation
qualification. No public nook switch or production gate change.

## No-cut rehearsal

Owner supplied output for rehearsal-001:

- BASELINE-SHA256: 9d2a167d26b1af1c0c97cbe79e18bd99727c9a6189ac499645f0a20b48dc4ee7
- VM-READY pre (raw original header hash): a2d2210340a2ad9f59d02e194f9ce89008210de50376d3abcc71f9f1a4346053
- Subsequent verifier: PASS, full authentication, sequence 2; identical baseline hash.
- STATE-DOMAIN-HASHES: ba0b83c6cd3c51bf8407f8f8b39ea7a56ee838530905aaf7f7dc06b7345fa3dc93dfded2cb9ed17d59f659d13ddf313922c02eddc0ea660c3add9ece21968d840000000000000000000000000000000000000000000000000000000000000000

Controller printed `Real vault oracle qualification failed.`; its exact termination
cause and exit code were not supplied. This is not a successful password-change
commit claim. The independently invoked verifier authenticated the unchanged state.
No VM shutdown occurred at the rehearsal boundary. These observations are guest-local
operator-reported results, not an independent forensic oracle.

## Campaign

| Scenario | Status |
|---|---|
| A BeforePublish | PASS: actual VM poweroff/restart; owner-run verifier fully authenticated sequence 2; exit 0; baseline matched host record |
| B AfterPublish | PASS: new sequence 3 fully authenticated after actual VM poweroff/restart; exit 0; baseline matched; this boundary was not ACK |
| C Post-ACK | PASS: sequence 3 fully authenticated; exit 0; exact baseline and all ACK domain hashes match pre-cut host record |

## Checks this stage

Guard PowerShell syntax: passed. Default enabled-clipboard refusal: passed.
Explicit clipboard exception read-only preflight: passed. git diff --check: passed.
Release build (`--no-restore`): PASS, 0 warnings/errors. Discovery: 532 tests in
three assemblies. Full MTP execution: **532 passed, 0 failed, 0 skipped**,
6m 23s 298ms; discovery and execution counts match. Managed CLI: 165 + 22 checks passed.
Native AOT win-x64 harness and CLI publish: PASS, no warnings in captured logs.
Fresh native harness execution: full init/login/note/reveal/tombstone/credential/
backup/verify/restore lifecycle passed, followed by six oracle success scenarios
(Password, Recover, Rotate, Backup, Verify, Restore). Native CLI: 165 + 22 passed.

Commands executed from the repository root (outputs retained under artifacts/sn-003q5):

```powershell
dotnet build -c Release --no-restore
dotnet test -c Release --no-build --no-restore
dotnet test -c Release --no-build --no-restore --list-tests
# For both spikes/ApplicationQualification and src/SafeNook.Cli:
dotnet publish <project> -c Release -r win-x64 --no-restore -p:PublishAot=true -p:SelfContained=true -p:LibsodiumStaticLib=<existing-static-libsodium.lib> -o <new-Q5-output>
# For both managed and newly published Native AOT nook.exe:
./tests/Test-Cli.ps1 -Executable <nook.exe>
./tests/Test-VaultCli.ps1 -Executable <nook.exe>
# Fresh unique synthetic paths for every execution:
ApplicationQualification.exe <new-vault-path>
ApplicationQualification.exe <new-vault-path> oracle <operation> success
```

Logs: build.log, suite.log, discovery.log, cli-managed.log, aot-harness.log,
aot-cli.log, native-execution.log, cli-native.log. Builds used cached packages;
no remote restore/fetch was performed. No physical host/SSD power-loss claim.

## Release decision

The campaign found **no vault data-loss or acknowledged-state mismatch defect** in
its three Password trials. Return to functional development; do not repeat lab
preparation as a prerequisite for every feature. This does not close the existing
[production-write checklist](SN-003B3-PRODUCTION-WRITES-CHECKLIST.md).

- M1 building blocks ready for synthetic qualification: crypto/strict formats,
  mandatory independent recovery slot, authenticated in-memory models, Windows NTFS
  COW store, login/note create/list/show/delete, credential lifecycle, fully verified
  encrypted backup/restore, gated CLI and Native AOT. This is not full CRUD editing
  or cross-platform writable-storage completion.
- Actual use blockers: public mutating operations deliberately refuse writes; M1's
  three-platform storage acceptance is not met. These are known release/scope
  constraints, not newly discovered data-loss bugs. KDF calibration/device limits,
  installation and supported-platform documentation still need release acceptance.
- Before controlled Windows-only writes: independent native/security sign-off;
  declared supported OS/NTFS/device/cache model; actual isolated disk-full/quota
  evidence and recovery behavior; reviewed retained-root/disk-growth policy with GC
  disabled; an explicitly approved durability claim. Three guest-local cuts do not
  replace the current checklist's host-oracle/forensic or physical-loss requirements.
  Any narrower preview criterion requires an explicit owner decision and documented
  checklist revision, followed by a separate gate-opening change. No such decision
  or code change is made here.
- Work that may stay on the stable-release track while functionality advances behind
  the closed gate: wider randomized crash campaigns, physical-controller/cache-loss
  qualification, external audit, packaging and clean-system install matrix. Deferral
  does not authorize real-secret writes or silently waive existing gate criteria.
  Linux/macOS storage requires its own implementation/qualification; exclude these
  from a Windows-only preview rather than claiming they passed.
- Recommended next functional task: Application/CLI **edit for login and secure
  note**, preserving IDs, incrementing revisions, using existing COW and fresh
  authentication, with cancellation/fault/reopen tests through the qualification
  harness and the public gate still closed. This closes the update gap in M1 CRUD.
  SSH/age/file import/export follows as M2; agent/sync/GUI remain out of scope.

Production writes and GC remain closed. No new feature implementation starts here.

Suggested commit (not executed):

```text
test(storage): complete Windows VM power-cut smoke qualification
```
## Trial A host evidence

Owner supplied fresh VM-READY pre for pre-001. Baseline SHA-256: `fbe0b28437398c337b5bc9bbb2e6452a7ac44709a345e71717e1c4a46caacca2`; original header SHA-256: `b675bbb6faf8580a330cd8cd00bd13692a55f67686f0cffa20f60dffcb07150e`. A trailing backslash in pasted baseline was excluded as a non-hash delimiter. Host record was written with Flush(true) before the cut. Both preflight and guarded checks passed with the explicit clipboard exception. VBoxManage poweroff succeeded, VMState=poweroff confirmed; startvm then succeeded. Post-restart verification passed as recorded below.

### Trial A post-restart verification

Owner supplied full guest output: `PASS: guest-local VM smoke pre; full authentication; sequence 2`, exit code 0. Baseline SHA-256 exactly matched the pre-cut host record.

STATE-DOMAIN-HASHES:
`9296c752fd831bd01976fa27394a70ef2716eaef2382d641caa276f12a9e13e61f07da3d299dd5808cad60ddd5b80c87c5ecf9140bf557847a3a70bf968663ec0000000000000000000000000000000000000000000000000000000000000000`.

The owner's pasted lines have trailing backslashes; these are recorded as text-transfer delimiters, not hash bytes. Verification was executed by the owner inside restarted Windows; no independent forensic image was acquired. The verifier's full-authentication contract covers password/recovery access, retained generations and all active blob AEAD tags. A passed under the guest-local VM-poweroff smoke model only.

## Trial B host evidence

post-001, owner-reported fresh VM-READY post. Baseline SHA-256:
`a0de5a0f3d866b7a40650c4d9f41a6071882bbfb28ecf874878e673b766a3acc`.
Original header SHA-256 (not an ACK of the new state):
`5a8af2b0f70504c5285e70dbc8151cd6e6e3fe73f2352eaed609df5eb6915d35`.
Trailing backslash excluded as a text delimiter. Host record flushed before poweroff.
Preflight and guarded checks passed with the approved clipboard exception.
Second poweroff succeeded and poweroff state was confirmed. Immediate startvm
refused with VBOX_E_INVALID_OBJECT_STATE (session still locked/unlocking).
After rechecking powered-off state, a single subsequent startvm succeeded.
No second cut, vault retry, rollback or snapshot action. Verification passed as recorded below.

### Trial B post-restart verification

Owner supplied `PASS: guest-local VM smoke post; full authentication; sequence 3`
and verifier exit code 0. Baseline exactly matched the pre-cut host record.
STATE-DOMAIN-HASHES:
`3fbd65fd2e39f31208c2bbbd78884673972a6ad4e078ac2702f2cdc5c2d1d02f85fee81b93e93b4665e278b6de7eb5264393a402f07be2b7e50fe8cc2fd0bee80000000000000000000000000000000000000000000000000000000000000000`.
The newly published generation survived this trial with password/recovery, retained
roots and blob authentication covered by the verifier. This is an observed pre-ACK
outcome, not a guarantee or assertion of an acknowledged commit at AfterPublish.
No rollback, repair or Application retry was performed.

## Trial C host evidence

ack-001, owner-reported fresh VM-READY ack after guest-local observer flush/receipt.
Baseline SHA-256: `62af4cc3fc9b6c068c666408f590a7918cdd707d53fe8a61c0197e61e32842a7`.
ACK domain hashes:
`54cdf8a703fcb9c363f5f505e8f1385797511d3aa73fe80df76c6b39c7d65edf73148106906913486a76bf5608a0d85d7b13ee6a6ae1ecd210b7605fe8f5d2cc0000000000000000000000000000000000000000000000000000000000000000`.
The third domain is zero for this Password scenario (no output archive); the baseline
archive is checked separately. Host record written with Flush(true) before poweroff.
Preflight and guarded checks passed with the owner-approved clipboard exception.
Third and final poweroff succeeded; powered-off state confirmed; startvm succeeded.
Owner subsequently supplied PASS, full authentication, sequence 3, exit code 0. Baseline and all 192 hex characters of STATE-DOMAIN-HASHES exactly match the pre-cut host record above. No additional cuts authorized.

## Findings, evidence limits and operational state

No production Core/Application/Storage/CLI code was changed. The only executable
change is the lab guard's explicitly approved clipboard exception; it defaults to
refusal, rejects clipboard file transfer and preserves all other guards. Guard
syntax, default refusal and explicit read-only success were executed. Initial live
ISO mounting failed because Q4 removed the DVD device; ordinary guest shutdown
allowed attachment. A transient VirtualBox session lock delayed B restart; inspection
and retrying VM start resolved it without retrying the vault operation.

The three actual VM cuts used the Q4 Native AOT binary with hash A9FF...90B1F above.
The fresh regression publish is a separate artifact (SHA-256
`87E30A6C98B13A022CDEBB20CDEAEF8E008513B2C3A326425A4C494FF6F4DC78`), not the deployed
binary; do not substitute its hash in the campaign evidence.

The real cut scope is Password only at BeforePublish, AfterPublish and Post-ACK.
Recover/rotation/backup/restore were not cut in this VM campaign. Backup archives
were fully verified as baselines, not subjected to interrupted archive publication.
All A/B/C verifications cover current root/header MAC, manifest/items/blob AEAD,
password/recovery access, unchanged recovery slot, VK/epoch, immutable ciphertext
references and retained roots present on disk. Retained-root enumeration cannot
prove that every historically expected retained file survived deletion; no external
pre-cut retained-root inventory was collected. The baseline archive provides an
independently stored historical recovery copy within the guest.

Host hash records were flushed before each cut under artifacts/sn-003q5/*-before-cut-*.
Guest verifiers were run by the owner and their outputs supplied in this conversation.
No automatic live marker/process liveness telemetry was used: cuts followed fresh
operator-reported markers, with no reported error/exit. This is manual smoke evidence,
not automated race-free cut coordination. The observer and guest both lived inside
the VM; COM1/host UART oracle execution and forensic disk copies were not performed.
The VM remained running after C for verification; ISO was ejected. Clipboard remains
owner-approved bidirectional; drag-and-drop/network/shared folders/USB remain off.
No source Win11 modification, snapshot change, GC, quota/fill or further cut occurred.
No host/SSD/controller power was removed. No Linux/macOS run or fresh remote CI check.

## Files and final Git scope

Modified: docs/ROADMAP.md (Q5 outcome and next functional task),
spikes/StorageLab/Invoke-SafeNookBasePowerCut.ps1 (explicit clipboard exception).
Added: this report. No deletions or product src/ changes. Existing tracked,
untracked and ignored Q4/lab evidence remains preserved. Base/current HEAD b4b9286;
no commits or remote Git operations. No VM-created user data was cleaned up.
