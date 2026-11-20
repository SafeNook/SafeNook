# SN-005A — Interactive Windows synthetic preview

Date: 2026-11-19. Windows 11 x64 interactive smoke and final regression passed.
**Synthetic data only. Do not store real credentials, private keys or personal files.**
Production writes in ordinary nook.exe and GC remain disabled.

## Architecture and boundary

spikes/SafeNook.Preview is an explicit standalone project, outside SafeNook.slnx and
normal CI/release artifact paths. Assembly/apphost/native executable: nook-preview.
It references existing CLI and invokes the same Program.Run, ConsoleVaultInteraction,
ConsoleSecretTerminal, parser, metadata escaping and error mapping. No duplicate
command implementation, fixed UI password or replacement crypto/storage code.

Application and CLI grant InternalsVisibleTo only to the distinct nook-preview
assembly. Preview invokes the existing internal ForQualification factory with the
same dynamically admitted WindowsMemory.Policy used by ordinary reads. Storage does
not gain a new friend or public mutating API. Ordinary nook assembly is not an
Application friend and its Main still creates public VaultApplication, preserving
the closed gate. No --unsafe, environment bypass, conditional Release gate or plugin.
Friend assembly names are a compilation boundary, not protection from hostile code
loaded on a compromised OS; the existing qualification tools already share this trust.

The executable prints an unmistakable warning on stderr on every invocation and
rejects non-Windows/non-x64. Console prompts require actual interactive stdin/stdout/
stderr; redirected operations refuse rather than reading supplied bytes. Every command
has Ctrl+C cancellation handling in the Preview entrypoint. Real credentials are not
technically distinguishable from synthetic ones: this is an operator restriction,
not a claim of automatic classification. Preview can read the same format as ordinary
nook: choose a separate synthetic vault path, never an existing real vault.

Only project friend declarations and the new Preview project enable this path.
No crypto/wire format, KDF parameters, ACL, recovery requirement, authentication, COW,
GC or production-write constant is changed. Preview is not an installer or production
release and is not included in the solution or ordinary binary upload patterns.

## Build and launch

From C:\Users\algmi\source\repos\SafeNook (PowerShell, .NET 10 SDK):

```powershell
dotnet restore spikes/SafeNook.Preview
dotnet build spikes/SafeNook.Preview -c Release
$preview = '.\spikes\SafeNook.Preview\bin\Release\net10.0\nook-preview.exe'
& $preview --help
```

For Native AOT (Windows x64 C++ build tools required):

```powershell
dotnet publish spikes/SafeNook.Preview -c Release -r win-x64 -o artifacts/preview-win-x64
$preview = '.\artifacts\preview-win-x64\nook-preview.exe'
& $preview --help
```

Keep the entire published directory together, including libsodium.dll when present.
Do not copy only the EXE or mix it with ordinary publish output. The task's actual
native output is artifacts/sn-005a-native-preview; it was executed successfully.
The task used cached restore (--source local NuGet cache) and --no-restore builds;
Native AOT invocation additionally supplied the repository's existing
-p:LibsodiumStaticLib=<existing libsodium.lib>. Published output still includes
libsodium.dll: no single-file/static-dependency deployment guarantee is asserted.

## Manual sequence

Use an ordinary Windows terminal, not a pipe, redirected file or IDE output panel.
All passwords/keys/content are prompted without echo. No credential argv/env values.
Use your own temporary synthetic values and preserve the shown synthetic recovery
key separately. init requires complete re-entry of the key before publication.
Do not redirect recovery display to a log. Terminal recording can capture that screen.

```powershell
$vault = 'C:\SafeNookSynthetic\demo.vault'
# Create its parent first. Use an absolute path; the vault itself must not exist.
New-Item -ItemType Directory C:\SafeNookSynthetic -Force | Out-Null
& $preview init --vault $vault
& $preview add --vault $vault --type login
& $preview add --vault $vault --type note
& $preview ls --vault $vault
# Substitute the ID returned by add/ls:
$id = '<32-character-lowercase-ID>'
& $preview show $id --vault $vault
& $preview edit --vault $vault --id $id
& $preview passwd --vault $vault
& $preview recover --vault $vault
& $preview recovery rotate --vault $vault
& $preview rm $id --vault $vault
```

show displays safe metadata; only explicit --reveal displays payload. Edits offer
Enter to keep / yes to replace, and final yes to publish; passwords/note text require
full repeated input. Multiline input ends with Ctrl+D. Esc/Ctrl+C cancels. rm requires
the full ID; it creates a tombstone. Indeterminate (exit 7) requires explicit reopen,
not repeating the mutation. Error categories/codes are identical to normal CLI.

```powershell
& $preview backup --vault $vault --output C:\SafeNookSynthetic\demo.snbak
& $preview backup verify --input C:\SafeNookSynthetic\demo.snbak
& $preview restore --input C:\SafeNookSynthetic\demo.snbak --vault C:\SafeNookSynthetic\restored.vault
& $preview ls --vault C:\SafeNookSynthetic\restored.vault
```

Backup output and restore vault must not exist. --credential recovery explicitly
selects the recovery prompt where supported; no automatic slot switching.

For file export, prepare a separate private output directory. This changes only the
new synthetic folder's ACL; do not apply it to a user directory or system root:

```powershell
$out = 'C:\SafeNookSynthetic\private-output'
if (Test-Path -LiteralPath $out) { throw 'Use a new folder; preserve existing data' }
New-Item -ItemType Directory $out | Out-Null
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
try {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner($identity.User)
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $identity.User, [Security.AccessControl.FileSystemRights]::FullControl,
        [Security.AccessControl.AccessControlType]::Allow))
    Set-Acl -LiteralPath $out -AclObject $acl
} finally { $identity.Dispose() }
```

```powershell
& $preview file add --vault $vault --input C:\SafeNookSynthetic\synthetic.bin
& $preview file extract --vault $vault --id '<file-ID>' --output "$out\file.bin"
& $preview ssh add --vault $vault --input C:\SafeNookSynthetic\synthetic-private --public-input C:\SafeNookSynthetic\synthetic-public
& $preview ssh extract --vault $vault --id '<ssh-ID>' --output "$out\private"
& $preview ssh extract --vault $vault --id '<ssh-ID>' --public-output "$out\public"
& $preview age add --vault $vault --input C:\SafeNookSynthetic\synthetic-identity --recipient-input C:\SafeNookSynthetic\synthetic-recipient
& $preview age extract --vault $vault --id '<age-ID>' --output "$out\identity"
& $preview age extract --vault $vault --id '<age-ID>' --recipient-output "$out\recipient"
```

These inputs must contain synthetic bytes only; companions are optional. SSH/age are
opaque unvalidated storage with explicit yes acknowledgement, no key generation,
matching check, plugin execution or agent. General files <=25 MiB; private/identity
<=1 MiB; companion <=64 KiB. One extraction per command, no overwrite. Stored names
are not used as destinations. Export requires a local fixed NTFS private directory,
fully authenticates the blob, then uses approved private plaintext staging and
no-replace rename. Crash/Indeterminate can leave sensitive .sn-export files; no
automatic scavenging or secure erase promise. [I/O policy](SN-004B-FILE-SSH-AGE.md).

## Executed Windows terminal smoke

Host Windows 11 Home Single Language x64, version 10.0.26300. Commands were executed
by the agent in an actual Windows PTY (tty=true), using Console.ReadKey and real
ConsoleVaultInteraction. No synthetic interaction adapter or fixed credential in
Preview code. One-time synthetic inputs were typed into the PTY; values are omitted
from this report. The recovery screen was explicitly exercised and re-entered.
This is an automated real-console smoke, not an owner-attended usability study.

- Managed: init with password/RK confirmation; login/note add, ls, safe show,
  title edit (revision 2), confirmed note rm; subsequent processes reopened state.
- Native AOT: passwd, recover with full RK, recovery rotate with fresh production RNG
  and full confirmation; subsequent commands used the updated password.
- Native: file/SSH/age import and five extract variants (including companions), with
  exact binary comparison of BOM, NUL, non-UTF8 and mixed newline synthetic bytes.
  All five outputs matched source byte-for-byte.
- Native: backup, full verify, restore into a new path, and ls on restored state.
  All three archive operations returned the same SHA-256:
  618c66aaddd6c63a505bf5a8f76dc9ab49d21dadabc252816a1d86dbcf4b7d70.
  Restored list contained login revision 2 and the three blob-backed records; deleted
  note did not reappear.
- Native real-console cancellation: Esc at password prompt returned exit 130, with
  no new vault. Ordinary native add immediately returned exit 5 without prompting.
- Test-PreviewCli.ps1: 23 checks passed for managed and 23 for native: command help
  and banner, redirected init refused before creation (exit 6), --unsafe rejected,
  ordinary nook init remains exit 5 with no output or created vault.
- Ordinary managed/native CLI regressions: each 165 general/gen + 27 vault checks PASS.

Synthetic state remains under artifacts/sn-005a-interactive.vault, sn-005a-restored.vault
and sn-005a-external. No artifacts were deleted. Host hash comparisons and a redacted
smoke summary are retained under artifacts/. No physical/VM/quota tests in this task.

## Build/regression results

Managed solution and explicit Preview Release build: 0 warnings/errors.
Native AOT Preview and ordinary nook publish: passed. Full MTP: **582 passed,
0 failed, 0 skipped**, 6m 48s 760ms; discovery **582** in three assemblies. Preview deliberately adds no MTP project to the
normal solution; separate boundary script and console smoke validate its entrypoint.
Windows-only result, no Linux/macOS run or remote CI freshness assertion.

## Limits and transition to ordinary Release

Preview preserves the current Windows x64/local fixed NTFS support boundary and all
existing durability limits. It is allowed only for synthetic experiments. Warnings
are on stderr even for help/gen; ordinary nook behavior is unchanged. Managed strings,
terminal recording, swap and private export remnants remain known limits.

A normal writable Windows release requires a separate owner decision and change:
independent native/security review, qualified named OS/NTFS/cache model, actual isolated
disk-full/quota/recovery evidence, accepted durability claim, retained-root/disk-growth
policy with GC off, supported install/dependency packaging and clean-system tests.
[Current gate checklist](SN-003B3-PRODUCTION-WRITES-CHECKLIST.md) remains authoritative.
Do not transfer Preview's friend factory into public CLI. Gate opening is not implied
by preview success; any narrower preview-to-release criteria need explicit approval.

## Git and files

Base/current HEAD 1e6fadf includes owner-saved SN-004B. Created
feat/sn-005a-windows-interactive-preview from clean local main; recorded upstream
matched but no network Git performed. Existing ignored evidence preserved. No commit,
push/fetch/pull/merge/rebase or VM changes. Added standalone Preview project/entrypoint,
Test-PreviewCli.ps1, this report; modified two friend declarations and ROADMAP only.

```text
feat(preview): add isolated Windows interactive synthetic preview
```

Final doc-link and git diff --check validation passed. Build/restore/AOT, MTP and
boundary logs remain under artifacts/sn-005a-*. The archive hash above was checked
directly with Get-FileHash; a wrapped PTY transcription error was corrected before
completion. No claim of an archive-content failure follows from that transcription.
