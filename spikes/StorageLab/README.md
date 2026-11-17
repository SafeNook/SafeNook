# Storage qualification lab scripts

Current proposed architecture: [SN-003Q1](../../docs/SN-003Q1-LAB-ARCHITECTURE.md).
**Prepared tooling, not authorization to provision or execute destructive trials.**
Production writes and GC remain closed.

| Script | Scope |
|---|---|
| New-LabPlan.ps1 | Read-only full-clone proposal for option A; does not provision the recommended new VM |
| New-NtfsTrialPlan.ps1 | Read-only quota/full-volume checklist |
| Invoke-LabPowerCut.ps1 | Future guarded VM poweroff; requires separate approval, independent disks and isolation |
| Invoke-DisposableNtfsFill.ps1 | Future bounded guest NTFS filler; requires separate approved disposable volume |
| Test-NativeProcessCrash.ps1 | Process-only Native AOT backup ACK check; not a VM power-cut oracle |

The legacy clone planner's 264 GiB estimate is historical. Use Q1's conservative complete budgets
(256 GiB new minimal VM / 304 GiB clone) and account for every additional retained trial.
No Q1 provisioning automation or host UART oracle is implemented. Do not run the poweroff script
as a substitute for the external ACK oracle or bypass its refusal for the new configuration.
The new architecture requires a separate review and positive-path validation before destructive use.
Never reuse existing user VM identifiers, disks or snapshots as disposable fixtures.

## SN-003Q2 preparation

See [oracle implementation](../../docs/SN-003Q2-ORACLE-IMPLEMENTATION.md).

- New-MinimalLabPlan.ps1: read-only JSON proposal for new independent VM; no execution mode.
- Test-MinimalLabIsolation.ps1: read-only preflight; never starts or modifies VM.
- Test-OracleProcesses.ps1: local managed/Native AOT host/guest smoke, kills only its own host process.

The host/guest oracle transport is locally emulated. Actual VirtualBox UART and the guest COM
adapter remain unqualified. No script grants provisioning or destructive-test permission.
