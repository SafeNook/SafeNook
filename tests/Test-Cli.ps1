param(
    [Parameter(Mandatory)][string] $Executable
)

$ErrorActionPreference = 'Stop'
$Executable = (Resolve-Path -LiteralPath $Executable).Path
$script:checks = 0

function Invoke-Nook([string[]] $Arguments) {
    $start = [System.Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Executable
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $process = [System.Diagnostics.Process]::Start($start)
    try {
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(30000)) {
            $process.Kill($true)
            throw 'CLI timed out.'
        }
        return @{ Code = $process.ExitCode; Out = $stdout.GetAwaiter().GetResult(); Err = $stderr.GetAwaiter().GetResult() }
    } finally { $process.Dispose() }
}

function Assert-Check([bool] $Condition, [string] $Description) {
    if (-not $Condition) { throw $Description }
    $script:checks++
}

# Never include generated passwords in diagnostics, including assertion failures.
foreach ($case in @(
    @{ Args = @('gen'); Length = 20; Count = 1 },
    @{ Args = @('gen', '-l', '32', '-n', '3'); Length = 32; Count = 3 },
    @{ Args = @('gen', '--length', '8', '--count', '100'); Length = 8; Count = 100 },
    @{ Args = @('gen', '--length', '128'); Length = 128; Count = 1 },
    @{ Args = @('gen', '--no-symbols', '--exclude-similar', '--entropy'); Length = 20; Count = 1 }
)) {
    $result = Invoke-Nook $case.Args
    Assert-Check ($result.Code -eq 0) 'Valid generation must succeed.'
    $lines = @($result.Out.TrimEnd("`r", "`n") -split '\r?\n')
    Assert-Check ($lines.Count -eq $case.Count) 'Incorrect password count.'
    foreach ($line in $lines) { Assert-Check ($line.Length -eq $case.Length) 'Incorrect password length.' }
    if ($case.Args -contains '--entropy') {
        Assert-Check ($result.Err -match '^entropy: ~\d+ bits\r?\n$') 'Entropy must be on stderr.'
        Assert-Check ($lines[0] -cmatch '^[A-HJ-NP-Za-km-np-z2-9]+$') 'Character restrictions were not honored.'
    } else { Assert-Check ($result.Err -eq '') 'Valid generation must have empty stderr.' }
}

foreach ($arguments in @(
    @('gen', '--length', '3'), @('gen', '--length', '129'),
    @('gen', '--count', '0'), @('gen', '--count', '101')
)) {
    $result = Invoke-Nook $arguments
    Assert-Check ($result.Code -eq 1) 'Policy errors must return exit code 1.'
    Assert-Check ($result.Out -eq '') 'Policy errors must not generate passwords.'
    Assert-Check ($result.Err.StartsWith('error: ')) 'Policy errors must be on stderr.'
}

foreach ($arguments in @(
    @('gen', '--length', 'abc'), @('gen', '--length'),
    @('gen', '--count', '2147483648'), @('gen', '--unknown'),
    @('missing-command'), @('gen', 'unexpected')
)) {
    $result = Invoke-Nook $arguments
    Assert-Check ($result.Code -eq 1) 'Parser errors must return exit code 1.'
    Assert-Check (-not [string]::IsNullOrWhiteSpace($result.Err)) 'Parser errors must produce stderr.'
    # System.CommandLine may also write usage to stdout; never a generated password.
    Assert-Check (($result.Out -eq '') -or ($result.Out -match 'Usage:')) 'Parser stdout must contain only usage.'
}

foreach ($arguments in @(@('--help'), @('gen', '--help'), @('--version'))) {
    $result = Invoke-Nook $arguments
    Assert-Check ($result.Code -eq 0) 'Help/version must succeed.'
    Assert-Check ($result.Err -eq '') 'Help/version must have empty stderr.'
    if ($arguments -contains '--version') {
        Assert-Check ($result.Out -match '^0\.1\.0-alpha') 'Unexpected application version.'
    } else {
        Assert-Check ($result.Out -match 'Usage:') 'Missing help usage.'
        Assert-Check ($result.Out -match 'gen') 'Missing command help.'
    }
}

$result = Invoke-Nook @()
Assert-Check ($result.Code -eq 1) 'Missing command must return exit code 1.'
Assert-Check ($result.Out -match 'Usage:') 'Missing command must print usage.'
Write-Output "CLI regression checks passed: $script:checks"
