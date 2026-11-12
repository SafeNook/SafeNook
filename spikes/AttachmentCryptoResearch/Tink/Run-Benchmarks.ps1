param(
    [string] $Executable = './artifacts/tink-research/aot/tink-research.exe',
    [string] $DataDirectory = './artifacts/tink-research/data',
    [string] $Output = './spikes/AttachmentCryptoResearch/Tink/results/windows-x64.csv'
)
$ErrorActionPreference = 'Stop'
'Variant,Operation,SizeBytes,Iteration,ElapsedMs,AllocatedBytes,BaselineWorkingSetBytes,LifetimePeakWorkingSetBytes,SampledPeakWorkingSetBytes,BaselinePrivateBytes,SampledPeakPrivateBytes' | Set-Content -LiteralPath $Output
foreach ($size in @(0, 1048576, 5242880, 10485760, 26214400)) {
    foreach ($operation in @('encrypt', 'decrypt')) {
        foreach ($repetition in 1..5) {
            $row = & $Executable measure $DataDirectory $operation $size $repetition
            if ($LASTEXITCODE -ne 0) { throw 'Benchmark child failed.' }
            $row | Add-Content -LiteralPath $Output
        }
    }
}
