param([Parameter(Mandatory)][string] $Executable,[Parameter(Mandatory)][string] $CaseDirectory)
$ErrorActionPreference='Stop'
$Executable=(Resolve-Path -LiteralPath $Executable).Path
if([IO.Path]::GetFileName($Executable) -ne 'ApplicationQualification.exe' -or (Test-Path -LiteralPath $CaseDirectory)) {throw 'Use the isolated harness and a new synthetic case directory.'}
[IO.Directory]::CreateDirectory([IO.Path]::GetFullPath($CaseDirectory)) | Out-Null
$vault=Join-Path ([IO.Path]::GetFullPath($CaseDirectory)) 'vault'
$pipeName='safenook-native-crash-'+[guid]::NewGuid().ToString('N')
$pipe=[IO.Pipes.NamedPipeServerStream]::new($pipeName,[IO.Pipes.PipeDirection]::In,1,[IO.Pipes.PipeTransmissionMode]::Byte,([IO.Pipes.PipeOptions]::Asynchronous -bor [IO.Pipes.PipeOptions]::CurrentUserOnly))
$timeout=[Threading.CancellationTokenSource]::new(120000)
$info=[Diagnostics.ProcessStartInfo]::new($Executable);$info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
foreach($arg in @($vault,'crash','backup','ACK',$pipeName)) {$info.ArgumentList.Add($arg)}
$child=[Diagnostics.Process]::Start($info)
try {
    $pipe.WaitForConnectionAsync($timeout.Token).GetAwaiter().GetResult()
    $header=[byte[]]::new(414);$pipe.ReadExactlyAsync([Memory[byte]]::new($header),$timeout.Token).AsTask().GetAwaiter().GetResult()
    $marker=$child.StandardOutput.ReadLineAsync($timeout.Token).AsTask().GetAwaiter().GetResult()
    if($marker -notmatch '^ACK [0-9a-f]{64}$') {throw 'No valid ACK received.'}
    $ack=[IO.FileStream]::new((Join-Path $CaseDirectory 'observer.ack'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write)
    try {$bytes=[Text.Encoding]::ASCII.GetBytes($marker);$ack.Write($bytes);$ack.Flush($true)} finally {$ack.Dispose()}
    $child.Kill($true);if(-not $child.WaitForExit(30000)) {throw 'Child did not terminate.'}
    if($child.ExitCode -eq 0 -or $child.StandardError.ReadToEnd() -ne '') {throw 'Unexpected helper outcome.'}
    $hash=[Convert]::ToHexStringLower([Security.Cryptography.SHA256]::HashData([IO.File]::ReadAllBytes($vault+'.snbak')))
    if($marker -ne ('ACK '+$hash)) {throw 'Post-ACK hash mismatch.'}
    & $Executable $vault verify-crash-backup
    if($LASTEXITCODE -ne 0) {throw 'Native reopen/verification failed.'}
    Write-Output 'PASS: native helper forcibly killed after ACK; exact archive hash and full authentication preserved.'
} finally {if(-not $child.HasExited) {$child.Kill($true);$child.WaitForExit()};$child.Dispose();$pipe.Dispose();$timeout.Dispose()}
