param([Parameter(Mandatory)][string] $Executable)
$ErrorActionPreference = 'Stop'
$Executable = (Resolve-Path -LiteralPath $Executable).Path
$checks = 0
function Invoke-VaultCli([string[]] $Arguments) {
    $info = [System.Diagnostics.ProcessStartInfo]::new($Executable)
    $info.UseShellExecute = $false
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    # These values must have no effect: the CLI has no environment credential or bypass channel.
    $info.Environment['SAFENOOK_PASSWORD'] = 'synthetic-env-secret'
    $info.Environment['SAFENOOK_QUALIFICATION'] = 'true'
    foreach ($argument in $Arguments) { $info.ArgumentList.Add($argument) }
    $process = [System.Diagnostics.Process]::Start($info)
    try {
        $process.StandardInput.Close()
        $out = $process.StandardOutput.ReadToEndAsync()
        $err = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(30000)) { $process.Kill($true); throw 'Vault CLI timeout.' }
        return @{ Code=$process.ExitCode; Out=$out.GetAwaiter().GetResult(); Err=$err.GetAwaiter().GetResult() }
    } finally { $process.Dispose() }
}
$vault = Join-Path ([System.IO.Path]::GetTempPath()) ('sn-cli-refused-' + [guid]::NewGuid().ToString('N'))
foreach ($name in @('init','ls','show','add','rm')) {
    $help = Invoke-VaultCli @($name,'--help')
    if ($help.Code -ne 0 -or $help.Out -notmatch '--vault') { throw 'Command help contract failed.' }; $checks++
}
foreach ($case in @(
    @{ Args=@('init','--vault',$vault); Code=5 },
    @{ Args=@('add','--vault',$vault,'--type','login'); Code=5 },
    @{ Args=@('rm',('a'*32),'--vault',$vault); Code=5 },
    @{ Args=@('ls','--vault',$vault); Code=6 },
    @{ Args=@('show',('a'*32),'--vault',$vault,'--reveal'); Code=6 },
    @{ Args=@('init','--vault',$vault,'--password','synthetic-argv-secret'); Code=1 },
    @{ Args=@('init','--vault',$vault,'--unsafe'); Code=1 },
    @{ Args=@('show',('a'*32),'--vault',$vault,'--json'); Code=1 }
)) {
    $r = Invoke-VaultCli $case.Args
    if ($r.Code -ne $case.Code -or $r.Out.Length -ne 0) { throw 'Vault refusal contract failed.' }; $checks++
    if (($r.Out+$r.Err) -match 'synthetic-(argv|env)-secret|SN1-') { throw 'Secret appeared in output.' }; $checks++
}
if (Test-Path -LiteralPath $vault) { throw 'Refused command created a vault.' }; $checks++
Write-Output "Vault CLI checks passed: $checks"
