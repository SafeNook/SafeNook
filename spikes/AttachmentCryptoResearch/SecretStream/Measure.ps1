param([Parameter(Mandatory)][string] $Executable)
$ErrorActionPreference='Stop'
$Executable=(Resolve-Path -LiteralPath $Executable).Path
$root=Join-Path $PSScriptRoot '../../../artifacts/attachment-secretstream/benchmark'
New-Item -ItemType Directory -Path $root -Force | Out-Null
$rows=[Collections.Generic.List[string]]::new()
$rows.Add('sizeMiB,repetition,operation,inputBytes,totalMs,primitiveMs,baselineWorkingSet,sampledPeakWorkingSet,baselinePrivateBytes,sampledPeakPrivateBytes,lifetimePeakBefore,lifetimePeakAfter,managedAllocatedBytes')
foreach($size in @(0,1,5,10,25)) {
    $plain=Join-Path $root "input-$size.bin"
    & $Executable prepare $plain ($size*1MB)
    if($LASTEXITCODE -ne 0) { throw 'Input preparation failed' }
    for($repeat=1; $repeat -le 5; $repeat++) {
        $cipher=Join-Path $root "cipher-$size-$repeat.bin"
        $output=Join-Path $root "output-$size-$repeat.bin"
        $row=& $Executable bench encrypt $plain $cipher
        if($LASTEXITCODE -ne 0) { throw 'Encryption benchmark failed' }
        $rows.Add("$size,$repeat,$row")
        $row=& $Executable bench decrypt $cipher $output
        if($LASTEXITCODE -ne 0) { throw 'Decryption benchmark failed' }
        $rows.Add("$size,$repeat,$row")
        if((Get-FileHash $plain).Hash -ne (Get-FileHash $output).Hash) { throw 'Benchmark round-trip failed' }
    }
}
$rows | Set-Content -LiteralPath (Join-Path $PSScriptRoot 'results-win-x64.csv') -Encoding utf8
Write-Output "Measured $($rows.Count-1) isolated operations; round-trip hashes matched."
