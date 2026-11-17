param([Parameter(Mandatory)][string] $Executable,[Parameter(Mandatory)][string] $EvidenceRoot)
$ErrorActionPreference='Stop'
$Executable=(Resolve-Path -LiteralPath $Executable).Path
if(-not (Test-Path -LiteralPath $EvidenceRoot -PathType Container)) {throw 'Existing owner-selected evidence parent required.'}
function Start-Helper([string[]] $Arguments) {
    $info=[Diagnostics.ProcessStartInfo]::new($Executable)
    $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    foreach($arg in $Arguments) {$info.ArgumentList.Add($arg)}
    return [Diagnostics.Process]::Start($info)
}
$run=[guid]::NewGuid().ToString('N');$pipe=[guid]::NewGuid().ToString('N')
$directory=Join-Path $EvidenceRoot ('oracle-native-'+$run)
$hostProcess=Start-Helper @('host',$pipe,$run,$directory);$guestProcess=$null
$timeout=[Threading.CancellationTokenSource]::new(30000)
try {
    if($hostProcess.StandardOutput.ReadLineAsync($timeout.Token).AsTask().GetAwaiter().GetResult() -ne 'READY') {throw 'Host not ready.'}
    $guestProcess=Start-Helper @('guest',$pipe,$run,'synthetic')
    if($guestProcess.StandardOutput.ReadLineAsync($timeout.Token).AsTask().GetAwaiter().GetResult() -ne 'RECEIPT') {throw 'No durable ACK receipt.'}
    if($hostProcess.StandardOutput.ReadLineAsync($timeout.Token).AsTask().GetAwaiter().GetResult() -ne 'COMPLETE') {throw 'Host incomplete.'}
    $hostProcess.Kill($true);if(-not $hostProcess.WaitForExit(5000)) {throw 'Host did not terminate.'}
    if(-not $guestProcess.WaitForExit(5000) -or $guestProcess.ExitCode -ne 0) {throw 'Guest failed.'}
    $bytes=$null
    for($attempt=0;$attempt -lt 21;$attempt++) {
        try {$bytes=[IO.File]::ReadAllBytes((Join-Path $directory 'events.bin'));break}
        catch [IO.IOException] {if(($_.Exception.HResult -band 65535) -ne 32 -or $attempt -eq 20) {throw};Start-Sleep -Milliseconds 100}
    }
    if($bytes.Length -ne 1120) {throw 'Incomplete evidence.'}
    $ack=0
    for($i=0;$i -lt 7;$i++) {
        $offset=$i*160
        if([Text.Encoding]::ASCII.GetString($bytes,$offset,4) -ne 'SNOR' -or $bytes[$offset+5] -ne 1) {throw 'Invalid evidence record.'}
        if($bytes[$offset+7] -eq 6) {$ack++}
    }
    if($ack -ne 1 -or $hostProcess.StandardError.ReadToEnd() -ne '' -or $guestProcess.StandardError.ReadToEnd() -ne '') {throw 'Invalid result.'}
    'PASS: independent oracle host killed after flushed ACK; evidence retained; no secret frames logged.'
} finally {
    foreach($process in @($hostProcess,$guestProcess)) {if($null -ne $process) {if(-not $process.HasExited) {$process.Kill($true);$process.WaitForExit()};$process.Dispose()}}
    $timeout.Dispose()
}
