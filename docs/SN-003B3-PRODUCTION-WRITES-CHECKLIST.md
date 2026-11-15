# SN-003B3 — production-write readiness checklist

Date: 2026-11-13. Decision: **CLOSED**. Owner approval is required even after every technical
gate passes. `StorageSupport.ProductionWritesSupported` remains false.

- [x] Preserve SN-003B2 baseline and use a separate branch; retain previous artifacts.
- [x] Review native contracts against Microsoft documentation and installed Windows SDK.
- [x] Add regression coverage for handle lifetime, exact ACL, root/backup/namespace changes.
- [ ] Independent native/security reviewer signs off on P/Invoke, ABI, lifetimes, ACLs,
      path pinning, reparse/hardlink/mapping races, disposal failures and error handling.
- [ ] Qualify a named Windows build + NTFS + device/controller/cache/driver configuration;
      explicitly establish the directory/namespace persistence contract and flush ordering.
- [ ] Execute actual isolated NTFS quota/full-volume campaigns; retain native error codes,
      old/new root oracle and recovery evidence. Injected IOException is insufficient.
- [ ] Run VM abrupt-power-off campaigns at every boundary and random offsets, including
      after ACK, with independent host ACK logs and forensic disk copies.
- [ ] Run physical power/controller/cache-loss campaigns, or explicitly restrict supported
      deployment to an adequately justified and qualified virtual-storage configuration.
- [ ] Verify no acknowledged commit is lost under the claimed fault model; every unacknowledged
      operation yields fully authenticated old/new state or explicit RecoveryRequired.
- [ ] Validate recovery after damaged current root/manifest/blob, historical slot changes and
      damaged retained roots; no silent rollback or destructive automatic recovery.
- [x] Keep exact owner ACL and handle-relative path rules; tests cover actual NTFS failures.
- [ ] Approve a retained-root policy and safe GC proof, or explicitly approve disabled GC with
      documented disk-growth/disk-full behavior. No unknown or uncertain data is deletable.
- [x] Refuse unsupported platforms/filesystems rather than extrapolating Windows results.
- [ ] Explicitly list supported Windows builds/devices; Linux/macOS/ARM64 remain unsupported
      until their own adapters and qualification evidence exist.
- [ ] Owner explicitly authorizes opening production writes in a separate change.

Executed regression totals and detailed limits: [security review](SN-003B3-SECURITY-REVIEW.md).
Preparation/acceptance protocol: [power-cut plan](SN-003B3-POWER-CUT-PLAN.md).
This checklist is a release decision record, not a claim that checking boxes proves security.
