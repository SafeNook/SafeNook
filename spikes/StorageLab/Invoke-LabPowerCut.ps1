param(
    [Parameter(Mandatory)][string] $CloneUuid,
    [Parameter(Mandatory)][string] $LabDirectory,
    [Parameter(Mandatory)][string] $EvidenceDirectory,
    [switch] $OwnerApprovedPowerCut,
    [string] $VBoxManage='C:\Program Files\Oracle\VirtualBox\VBoxManage.exe'
)
# Prepared only. Never invoked during SN-003D3. No start/create/restore/delete operations.
$ErrorActionPreference='Stop'
if(-not $OwnerApprovedPowerCut) {throw 'Separate owner approval for destructive lab power cuts is required.'}
if($CloneUuid -notmatch '^[0-9a-fA-F-]{36}$' -or $CloneUuid -in @('b147c2a7-6ed9-48f4-86d4-81774046aea4','ce6cdb38-2e64-4b55-97e3-166b5ccacab8','e326df28-7df4-489f-b6dd-2048144acf43')) {throw 'Not a disposable clone UUID.'}
$info=& $VBoxManage showvminfo $CloneUuid --machinereadable
if($LASTEXITCODE -ne 0) {throw 'VM inspection failed.'}
function Value([string]$key) { $line=$info | Where-Object {$_.StartsWith($key+'=')}; if(@($line).Count -ne 1) {throw 'Missing or duplicate VM field.'}; return $line.Substring($key.Length+1).Trim('"').Replace('\\','\') }
if((Value 'name') -ne 'SafeNook-Qualification-Disposable' -or (Value 'VMState') -ne 'running') {throw 'Unexpected clone identity/state.'}
function AssertPlainPath([string]$path) {
    $cursor=[IO.Path]::GetFullPath($path)
    while($cursor) {
        $entry=Get-Item -LiteralPath $cursor -Force
        if(($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {throw 'Reparse path forbidden in disposable lab.'}
        $parent=[IO.Directory]::GetParent($cursor);if($null -eq $parent) {break};$cursor=$parent.FullName
    }
}
AssertPlainPath $LabDirectory
$lab=[IO.Path]::GetFullPath($LabDirectory).TrimEnd('\')+'\'
if(-not ([IO.Path]::GetFullPath((Value 'CfgFile'))).StartsWith($lab,[StringComparison]::OrdinalIgnoreCase)) {throw 'VM configuration outside disposable lab.'}
foreach($n in 1..8) {if((Value "nic$n") -ne 'none') {throw 'Network not isolated.'}}
if((Value 'clipboard') -ne 'disabled' -or (Value 'draganddrop') -ne 'disabled' -or ($info -match '^SharedFolder')) {throw 'Host integration not isolated.'}
foreach($key in @('usb','ehci','xhci')) {if((Value $key) -ne 'off') {throw 'USB not isolated.'}}
if($info -match '^USBFilter') {throw 'USB filters remain.'}
$media=$info | Where-Object {$_ -match '^"[^"=]+-ImageUUID-[0-9]+-[0-9]+"='}
if(@($media).Count -lt 1 -or @($media).Count -gt 2) {throw 'Require one OS disk and at most one disposable NTFS disk; detach other media.'}
foreach($medium in $media) {
$id=$medium.Split('=')[1].Trim('"')
$disk=& $VBoxManage showmediuminfo disk $id
if($LASTEXITCODE -ne 0 -or -not ($disk -match '^Parent UUID:\s+base$')) {throw 'Disk is not independent.'}
$location=($disk | Where-Object {$_ -match '^Location:'}) -replace '^Location:\s*',''
AssertPlainPath $location
if(-not ([IO.Path]::GetFullPath($location)).StartsWith($lab,[StringComparison]::OrdinalIgnoreCase)) {throw 'Disk outside disposable lab.'}
}
if(-not (Test-Path -LiteralPath $EvidenceDirectory -PathType Container)) {throw 'Pre-create a dedicated evidence directory.'}
$log=Join-Path $EvidenceDirectory ([guid]::NewGuid().ToString('N')+'.pre-cut.txt')
[IO.File]::WriteAllLines($log,$info)
& $VBoxManage controlvm $CloneUuid poweroff
if($LASTEXITCODE -ne 0) {throw 'Poweroff failed; preserve evidence and inspect manually.'}
# Do not reboot, repair, snapshot-restore or delete the faulted media here.
