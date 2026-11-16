# SN-003C2 — Password and recovery management

Application adds ChangePassword, Recover and RotateRecovery. CLI exposes passwd, recover,
and recovery rotate, each requiring --vault. Public writes return 5 before interaction.
No credential argv/environment channel or public qualification factory was added.

Storage adds an internal ReadManifest overload with explicit CredentialKind. It authenticates
that slot and header MAC under the existing lock. Commit independently reauthenticates the
current root, validates the candidate, requires the same VK and epoch, and confirms delivery
of a replacement recovery key after fresh password authentication. No direct commit bypass.

Password replacement preserves recovery bytes; rotation preserves password bytes. New manifests
retain item/blob references and advance generation/sequence/parent hash. Saved KDF memory and
iteration values are copied unchanged. Owned credentials and decoded recovery buffers are wiped.
Indeterminate returns the existing application category / CLI exit 7, without retry.

Tests cover lifecycle, unchanged slot bytes and VK, old-password rejection, old-recovery rejection
on the new root, continued recovery of the old root, malformed recovery, confirmation failures,
pre-cancel, and password commit faults before/after publication with explicit reopen.
The same Storage commit path is used by all operations; operation-specific fault matrices for
recovery and rotation remain a validation limitation. Managed payload/runtime copies cannot be
reliably erased. Old vault copies retain their old credentials; rotation is not remote revocation.

Validation was performed on Windows x64 only. Native AOT CLI and synthetic lifecycle harness
published and ran successfully. Managed/native CLI regression: 165 existing + 22 vault checks.
New command gate cases are also covered by MTP tests. Logs: ignored artifacts/sn-003c2-*.
No live human TTY, Linux/macOS, power-loss test or new remote CI run was performed.
ProductionWritesSupported remains false; real-secret use is not qualified.

Base and HEAD: 1269003. Branch: feat/sn-003c2-password-recovery. No commit or remote Git operation.

Suggested commit: feat(cli): add password and recovery management

Final Release build: 0 warnings/errors. Full MTP run: 218 passed, 0 failed/skipped.
Final git diff --check passed. Ten tracked files modified and this report added; no deletions.
