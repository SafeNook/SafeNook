param([Parameter(Mandatory)][string] $Preview,[Parameter(Mandatory)][string] $Ordinary)
$ErrorActionPreference='Stop'
function Invoke-Checked([string] $Executable,[string[]] $Arguments) {
    $info=[Diagnostics.ProcessStartInfo]::new((Resolve-Path -LiteralPath $Executable).Path)
    $info.UseShellExecute=$false;$info.RedirectStandardInput=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    foreach($arg in $Arguments){$info.ArgumentList.Add($arg)}
    $p=[Diagnostics.Process]::Start($info)
    try {
        $p.StandardInput.Close();$stdout=$p.StandardOutput.ReadToEndAsync();$stderr=$p.StandardError.ReadToEndAsync()
        if(-not $p.WaitForExit(30000)){$p.Kill($true);throw 'Preview CLI timed out'}
        return @{Code=$p.ExitCode;Out=$stdout.GetAwaiter().GetResult();Err=$stderr.GetAwaiter().GetResult()}
    } finally {$p.Dispose()}
}
$checks=0
foreach($argsList in @(
    @('--help'),@('init','--help'),@('ls','--help'),@('show','--help'),@('add','--help'),@('edit','--help'),@('rm','--help'),
    @('passwd','--help'),@('recover','--help'),@('recovery','rotate','--help'),@('backup','--help'),@('backup','verify','--help'),@('restore','--help'),
    @('file','add','--help'),@('file','extract','--help'),@('ssh','add','--help'),@('ssh','extract','--help'),@('age','add','--help'),@('age','extract','--help')
)) {
    $r=Invoke-Checked $Preview $argsList
    if($r.Code -ne 0 -or $r.Err -notmatch 'SYNTHETIC DATA ONLY' -or $r.Out.Length -eq 0){throw 'Preview help/warning failed'};$checks++
}
$vault=Join-Path ([IO.Path]::GetTempPath()) ('preview-refused-'+[guid]::NewGuid().ToString('N'))
$r=Invoke-Checked $Preview @('init','--vault',$vault)
if($r.Code -ne 6 -or $r.Err -notmatch 'interactive terminal' -or (Test-Path -LiteralPath $vault)){throw 'Preview redirected input was not refused'};$checks++
foreach($exe in @($Preview,$Ordinary)) {
    $r=Invoke-Checked $exe @('init','--vault',$vault,'--unsafe','NEVER_ECHO')
    if($r.Code -ne 1 -or ($r.Out+$r.Err) -match 'NEVER_ECHO'){throw 'Unsafe switch accepted/echoed'};$checks++
}
$r=Invoke-Checked $Ordinary @('init','--vault',$vault)
if($r.Code -ne 5 -or $r.Out.Length -ne 0 -or (Test-Path -LiteralPath $vault)){throw 'Ordinary gate changed'};$checks++
"Preview boundary checks passed: $checks"
