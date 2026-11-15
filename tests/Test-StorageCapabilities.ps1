# Synthetic qualification only; never prints paths, SIDs, credentials or exception text.
param([string] $Configuration = 'Release')
$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'Storage capability probe requires Windows.' }
try {
    $repo = Split-Path -Parent $PSScriptRoot
    $parent = Join-Path $repo 'artifacts'
    $parentExisted = Test-Path -LiteralPath $parent -PathType Container
    $process = [System.Diagnostics.Process]::GetCurrentProcess()
    try { $sessionZero = $process.SessionId -eq 0 } finally { $process.Dispose() }
    Write-Output ("STORAGE_ENV os={0}; arch={1}; interactive={2}; sessionZero={3}; parentExisted={4}" -f [Environment]::OSVersion.Version, [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture, [Environment]::UserInteractive, $sessionZero, $parentExisted)
    $null = [System.IO.Directory]::CreateDirectory($parent)
    $probePath = Join-Path $parent ('storage-capabilities-' + [guid]::NewGuid().ToString('N'))
    $executable = Join-Path $repo "spikes/StoreQualification/bin/$Configuration/net10.0/StoreQualification.exe"
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) { throw 'Probe executable unavailable.' }
    & $executable $probePath probe
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} catch {
    Write-Output 'STORAGE_CAPABILITIES_FAIL stage=Harness; category=Setup'
    exit 2
}
