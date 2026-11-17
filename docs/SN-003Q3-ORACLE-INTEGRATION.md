# SN-003Q3 — Real vault durability oracle integration

Date: 2026-11-17. **Windows x64 local NTFS/process-crash qualification only.** No VM creation,
start, poweroff, virtual disk, snapshot, quota, GC or production-write change.

## Baseline and architecture

Owner saved Q2 in 8c32842. Initial working tree was clean; ignored artifacts were preserved.
With explicit approval to use the saved Q2 base instead of stale main, the new branch is
feat/sn-003q3-real-vault-oracle. Base/HEAD remain 8c32842; no commits or remote Git operations.
Locally recorded refs do not prove remote freshness.

[OracleIntegration.cs](../spikes/ApplicationQualification/OracleIntegration.cs) extends the existing
internal ApplicationQualification executable. The controller creates a synthetic encrypted vault
at sequence 1, commits a file record/blob at sequence 2, and prepares an archive for verify/restore.
It starts a separate guest process running the real VaultApplication APIs with internal Storage
qualification access. No new public nook command, environment switch, friend assembly, dependency,
vault format, cryptography or Storage mutation API was added. ApplicationQualification references
the existing standalone DurabilityOracle project.

The fixture includes an encrypted blob with a recognizable synthetic sentinel. It is never opened
by a user before the operation. Native full verification, not opening a user-visible file, must
check its AEAD tag. All test directories and evidence are retained.

## Real event boundaries

| Event | Source and meaning |
|---|---|
| Start | Guest begins the selected Application operation; not evidence of authentication |
| Authenticated | Existing CommitStep.Authenticated hook; no fabricated successful native operation |
| BeforePublish | Existing Storage hook immediately before publication attempt/checks |
| AfterPublish | Existing Storage hook after successful native publication; does not itself prove durability |
| Verified | Application returned success AND a fresh independent full verification completed |
| ACK | Guest sends exact-state hashes/sequence; host independently verifies them before append/flush |
| End | Guest received the host receipt; host flushes terminal evidence |

For credential commits, Authenticated follows active state authentication, before the subsequent
old-manifest/all-blob loop. It must not be interpreted as the final all-blob checkpoint. Backup,
verify and restore hooks occur after full source/archive verification. Credential/restore
AfterPublish precedes root-namespace flush/readback; backup's publication method also flushes its
parent namespace before returning. Thus an AfterPublish exception remains Indeterminate and never
produces Verified or ACK. No exception simulates the process-kill scenarios.

Backup Verify is read-only: its protocol skips BeforePublish and AfterPublish. All other operations
use existing Storage hooks. Per-boundary counters preserve occurrence numbers instead of hardcoding
one; the current workloads produce one of each mapped boundary. Fine-grained repeated object I/O
is not silently represented as a root publication or additional ACK.

## ACK verification and identity

After Application success, guest Inspect performs a fresh QualificationStore.Open, which checks
header MAC, manifest, all items and all blob AEAD tags. It opens again using the appropriate recovery
credential, verifies every retained root using historical recovery credentials, and checks:

- Expected sequence (2 → 3 for credentials; 2 unchanged for backup/verify/restore).
- Unchanged vault/epoch and Vault Key.
- New generation ID and exact parent-header SHA-256 for credential mutations.
- Exact opposite key slot preservation.
- Exact original root for unchanged operations; original immutable item/blob ciphertext hashes and active manifest references against the original inventory.
- Restore target preserves original IDs, slots, header and item/blob ciphertext.

Archive operations use VerifyPortable's exact inventory/length/hash and full AEAD checks. A
read-only archive handle denies write/replacement through authentication and hashing. Its header
must equal the baseline header; independently computed raw SHA-256 must match VerifyPortable's
result. Backup verify authenticates the archive directly and does not require the original vault
in its guest verification path. The controller retains a fixture baseline for comparison.

The host reopens and performs the same full verification independently BEFORE accepting ACK.
A mismatch is not logged as an accepted ACK and gets no receipt. Root wrapper bytes decode to the
exact authenticated header. Root/manifest cryptographic binding also binds the generation ID;
the ACK generation field is the numeric sequence. Expected state is established independently
from the controller's pre-operation baseline, not solely from guest claims.

Q2's 160-byte oracle schema and tagged SHA-256 domains are unchanged. Slots contain exact wrapper,
414-byte header and archive domain hashes. Absent archive is zero for credential operations;
absent wrapper is zero for archive-only verify. It is not a hash of fabricated wrapper bytes.
Header and archive hashes always refer to actual bytes. Raw SHA-256 values are additionally computed
and stored by the host as a fixed 96-byte raw-sha256.bin (wrapper/header/archive order, zero for an
absent object) after independent verification; these must not be confused with Q2's prefixed hashes.
Archive hashing remains sequential with a 64 KiB buffer and existing 2 GiB ceiling.

Each run creates an owner-only sibling .oracle directory outside the vault. events.bin is the
existing append-only typed evidence, without secret frames. raw-sha256.bin is CreateNew and flushed.
It is corroborating evidence, not an acknowledgement: a failure can leave this file or even ACK
bytes without a confirmed receipt. Host ACK append and Flush(true) must succeed before receipt.
After guest process kill, the controller authenticates the state again, compares persisted ACK
with the freshly computed hashes and compares raw hashes. No automatic retry or rollback.

## Recovery-key custody

Application generates the rotation key using its existing production RNG. The actual
DisplayRecovery callback decodes it into an owned mutable buffer and sends Q2's bounded secret
frame after Storage authentication and before confirmation/publication. Confirmation uses that
same key. Both guest and host verify the new recovery key opens the published generation. The
host copies it to owned RAM for post-kill verification, then zeroes it in finally; the observer
also zeroes its custody buffer. Evidence scans reject raw old/new RK and credential/blob sentinel
bytes, and every logged frame must be an Event.

The pre-existing Application interaction API supplies an encoded recovery string; no new persistent
string field is introduced. RecoveryCode.Encode necessarily creates a transient string when
answering that existing text-input API. Mutable copies are wiped; the harness does not promise
zeroization of immutable strings, provider internals, process dumps or a compromised OS. No key is
written to a file, argv, environment, stdout or ordinary logs.

## Process matrix and failure semantics

Every case uses a fresh synthetic vault and independently spawned guest. The host controller itself
is also a separate process from the MTP runner.

| Scenario | Operations | Assertion |
|---|---|---|
| success / post-ACK kill | All six | Real Application success, guest full verify, host full verify, flushed ACK/receipt, actual guest kill, persisted ACK and full reopen |
| wrong hash | All six | Guest deliberately alters wrapper slot; host rejects against actual expected bytes, no accepted ACK |
| evidence flush failure | All six | Injected flush error; no receipt or live post-ACK authorization; published state remains inspectable |
| duplicate ACK | All six | First ACK may exist; replay is refused, no second accepted ACK/commit |
| corrupted unopened blob | All six | Vault blob or input-archive blob tag flipped; no successful ACK |
| pre-publication kill | All mutating operations | Guest paused at real hook, killed externally; exact old root and both old access paths remain; no archive/root published for new destinations |
| post-publication kill | All mutating operations | Guest paused after native publication, killed externally; new generation/archive fully authenticates, no ACK inferred |
| Indeterminate | All mutating operations | Injected exception after publication; exact INDETERMINATE result, no ACK, explicit reopen only |
| lost host channel | All mutating operations | Pipe closes at authentication; guest refuses to proceed through the loss-test barrier |
| wrong confirmation | Password/recover/rotate | No ACK; baseline state/recovery path unchanged |
| corruption after Application success | Password/recover/rotate | Fresh pre-ACK authentication catches damaged blob; method return alone is insufficient |
| actual host process kill | Password | Runner kills controller without killing child; guest detects broken pipe and exits; runner reopens baseline through password and recovery |

Total: 56 operation/scenario cases plus one real host-kill case. A confirmation failure can occur
before Storage's authentication hook; Start alone is not misreported as Authenticated. In the
host-loss test a deliberate qualification barrier makes the loss point reproducible; normal
Application/Storage is not changed to depend on the observer. Blob-corruption cases intentionally
damage only their own fixture and are not claims that arbitrary physical corruption preserves all
historical generations sharing that ciphertext.

Injected evidence/Storage errors are separate from actual process kills. No physical I/O failure,
VM shutdown, device cache loss or honest/dishonest controller flush is simulated by a pass label.

## Verification results

| Check | Result |
|---|---|
| Final Release build | Passed, 0 warnings/errors |
| Targeted integration suite | 57 passed; all 57 also included in final 528-case run |
| Full final MTP suite | 528 passed, 0 failed/skipped; 6m 43.301s |
| Final MTP discovery | 528 cases in three assemblies |
| Native AOT real integration | Six operation success cases plus Rotate hash/flush/Indeterminate/exact duplicate passed |
| Managed CLI regression, final | 165 existing/gen + 22 vault checks passed |
| Native AOT CLI regression, final | 165 existing/gen + 22 vault checks passed |
| Relative documentation links | Passed |
| git diff --check | Passed |

Final Native AOT results include the active-manifest-reference assertion. Actual process execution,
not publish alone, produced the ten PASS records in artifacts/sn-003q3-native-qualified-smoke.log.
Final build/suite/native/CLI/discovery logs use artifacts/sn-003q3-*-qualified.*.
Discovery and final execution both contain exactly 528 cases across three assemblies. All 57 new
integration cases passed on the final source, including exact ACK replay and active references.
A separate scan checked 18 evidence files from 10 native cases for fixed schemas and synthetic
credential/blob markers; the mutable new RK is checked in-process before wiping. No COM1 execution occurred.


The initial 56-case integration matrix passed. A later 57-case matrix also passed. Full runs on
intermediate harnesses were stopped after final review added an explicit active-manifest-reference
comparison and then replaced a malformed second ACK with an exact valid ACK replay; those runs
are not counted as the final suite. Only that owned test process/tree was stopped.
The final full run uses the completed assertions.

Adding a test that calls Windows Storage directly
required a SupportedOSPlatform annotation; the first build rejected that missing annotation. A
subsequent stale-binary test launch was stopped together with its own child processes and is not
counted as final coverage. No existing user process or artifact was removed.

The first native harness publish hit NETSDK1150 because a self-contained executable referenced a
non-self-contained oracle executable. Publish uses explicit PublishAot=true and SelfContained=true
for the graph, plus the existing static libsodium library; no package/crypto change is involved.

## Limitations and next step

No VirtualBox UART/COM1 execution, VM poweroff, quota/full-volume or physical durability result is
claimed. The real integration currently runs over local protected named pipes; future VM work must
bind the reviewed COM adapter to this harness and validate transport/ACK behavior in an isolated
VM without initially cutting power. The present controller independently reads the same local
filesystem as its guest process. That cannot be carried into the isolated VM by enabling shared
folders: VM qualification needs a separately reviewed ciphertext/evidence extraction and offline
verification path. Merely swapping the stream for COM1 does not implement that path. Host and
guest currently share a Windows OS, so host-level power loss is not covered. Same-user/OS compromise remains outside the threat model.

Production writes and GC stay closed. The owner must separately approve provisioning and later
destructive trials. Retained synthetic artifacts remain available for review.

## Changed files and suggested commit

- spikes/ApplicationQualification/ApplicationQualification.csproj: reference existing oracle.
- spikes/ApplicationQualification/Program.cs: isolated controller/guest dispatch.
- spikes/ApplicationQualification/OracleIntegration.cs: real-operation integration and verifier.
- tests/SafeNook.Application.Tests/OracleIntegrationTests.cs: independent-process matrix.
- docs/ROADMAP.md and this report.

Final Git: three tracked modifications and three new files, no deletions or unrelated tracked
changes. Existing ignored evidence/build outputs are preserved. No product src/ diff. Final
relative-link and whitespace checks passed; base and HEAD remain 8c32842.

```text
test(lab): bind durability oracle to authenticated vault operations
```
