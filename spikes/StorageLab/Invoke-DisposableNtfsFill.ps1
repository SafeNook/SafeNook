param(
    [Parameter(Mandatory)][guid] $VolumeGuid,
    [Parameter(Mandatory)][string] $ExpectedDiskUniqueId,
    [Parameter(Mandatory)][long] $MaximumBytes,
    [Parameter(Mandatory)][string] $EvidenceDirectory,
    [switch] $OwnerApprovedDisposableVolume
)
# Prepared only; not executed. No quota/format/remove/system-setting commands.
$ErrorActionPreference='Stop'
if(-not $OwnerApprovedDisposableVolume) {throw 'Separate owner approval for this disposable guest volume is required.'}
if((Get-CimInstance Win32_ComputerSystem).Model -ne 'VirtualBox') {throw 'Only a disposable VirtualBox guest is allowed.'}
if($MaximumBytes -le 0 -or $MaximumBytes -gt 8GB) {throw 'Explicit bound must be within 1..8 GiB.'}
$volumePath='\\?\Volume{'+$VolumeGuid.ToString()+'}\'
$volume=Get-Volume -UniqueId $volumePath
$partition=$volume | Get-Partition
$disk=$partition | Get-Disk
if(@($volume).Count -ne 1 -or @($partition).Count -ne 1 -or @($disk).Count -ne 1) {throw 'Ambiguous volume identity.'}
if($volume.FileSystem -ne 'NTFS' -or $volume.FileSystemLabel -ne 'SAFENOOK-DISPOSABLE' -or $volume.Size -gt 8GB -or $volume.DriveType -ne 'Fixed') {throw 'Wrong disposable volume.'}
if($partition.IsBoot -or $partition.IsSystem -or $disk.IsBoot -or $disk.IsSystem -or $disk.UniqueId -ne $ExpectedDiskUniqueId) {throw 'Protected or unexpected disk.'}
$hardware=Get-CimInstance Win32_DiskDrive | Where-Object Index -eq $disk.Number
if($hardware.Model -notmatch '^VBOX HARDDISK') {throw 'Disk is not an isolated VirtualBox virtual disk.'}
if(Get-CimInstance Win32_PageFileUsage | Where-Object {$_.Name.StartsWith([string]$partition.DriveLetter+':',[StringComparison]::OrdinalIgnoreCase)}) {throw 'Pagefile volume forbidden.'}
if(-not (Test-Path -LiteralPath $EvidenceDirectory -PathType Container)) {throw 'Pre-create evidence directory on a different guest disk.'}
if(-not [IO.Path]::IsPathFullyQualified($EvidenceDirectory) -or $EvidenceDirectory.StartsWith('\\') -or [IO.Path]::GetPathRoot($EvidenceDirectory).TrimEnd('\').Equals(([string]$partition.DriveLetter+':'),[StringComparison]::OrdinalIgnoreCase)) {throw 'Evidence must use a different guest drive letter.'}
$caseId=[guid]::NewGuid().ToString('N');$directory=$volumePath+'sn-fill-'+$caseId
[IO.Directory]::CreateDirectory($directory) | Out-Null
$attributes=[IO.File]::GetAttributes($directory)
if(($attributes -band ([IO.FileAttributes]::ReparsePoint -bor [IO.FileAttributes]::Compressed)) -ne 0) {throw 'Compressed/reparse filler directory forbidden.'}
$filler=Join-Path $directory 'filler.bin';$written=0L;$nativeError=0
$buffer=[byte[]]::new(1MB);[Array]::Fill[byte]($buffer,165)
$stream=[IO.FileStream]::new($filler,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None,1MB,[IO.FileOptions]::WriteThrough)
try {
    while($written -lt $MaximumBytes) {
        $count=[int][Math]::Min($buffer.Length,$MaximumBytes-$written)
        try {$stream.Write($buffer,0,$count);$stream.Flush($true);$written+=$count}
        catch [IO.IOException] {$nativeError=$_.Exception.HResult -band 65535;break}
    }
} finally {$stream.Dispose()}
@{caseId=$caseId;volume=$volumePath;diskUniqueId=$disk.UniqueId;filler=$filler;bytesAcknowledged=$written;nativeError=$nativeError;freeBytes=(Get-Volume -UniqueId $volumePath).SizeRemaining;status='Retain filler and vault evidence; no cleanup performed'} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $EvidenceDirectory ($caseId+'.json'))
