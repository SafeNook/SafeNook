param([Parameter(Mandatory)][guid] $VmId,[Parameter(Mandatory)][string] $LabDirectory,
    [Parameter(Mandatory)][guid] $OsDiskId,[Parameter(Mandatory)][guid] $TrialDiskId,
    [string] $VBoxManage='C:\Program Files\Oracle\VirtualBox\VBoxManage.exe')
# Inspection only. A pass is not permission to start/cut a VM.
$ErrorActionPreference='Stop'
if($OsDiskId -eq $TrialDiskId -or $OsDiskId -eq [guid]::Empty -or $TrialDiskId -eq [guid]::Empty) {throw 'Require two distinct disk identifiers.'}
if($VmId -eq [guid]::Empty -or $VmId.ToString() -in @('b147c2a7-6ed9-48f4-86d4-81774046aea4','ce6cdb38-2e64-4b55-97e3-166b5ccacab8','e326df28-7df4-489f-b6dd-2048144acf43')) {throw 'Existing user VM refused.'}
if(-not [IO.Path]::IsPathFullyQualified($LabDirectory) -or $LabDirectory.StartsWith('\\')) {throw 'Local lab path required.'}
$lab=[IO.Path]::GetFullPath($LabDirectory).TrimEnd('\')+'\'
$info=& $VBoxManage showvminfo $VmId.ToString() --machinereadable
if($LASTEXITCODE -ne 0) {throw 'Inspection failed.'}
function Value([string] $Key) {
    $values=@($info | Where-Object {$_.StartsWith($Key+'=')})
    if($values.Count -ne 1) {throw 'Missing or duplicated property.'}
    return $values[0].Substring($Key.Length+1).Trim('"').Replace('\\','\')
}
if((Value 'cpus') -ne '2' -or (Value 'memory') -ne '6144' -or (Value 'firmware') -notmatch '^EFI' -or (Value 'VMState') -ne 'poweroff') {throw 'Hardware/state mismatch.'}
if(-not ([IO.Path]::GetFullPath((Value 'CfgFile'))).StartsWith($lab,[StringComparison]::OrdinalIgnoreCase)) {throw 'Configuration outside lab.'}
foreach($i in 1..8) {if((Value "nic$i") -ne 'none') {throw 'Network enabled.'}}
foreach($key in @('usb','ehci','xhci')) {if((Value $key) -ne 'off') {throw 'USB enabled.'}}
if((Value 'clipboard') -ne 'disabled' -or (Value 'draganddrop') -ne 'disabled' -or ($info -match '^(SharedFolder|USBFilter)')) {throw 'Host integration enabled.'}
$media=@($info | Where-Object {$_ -match '^"[^"=]+-ImageUUID-[0-9]+-[0-9]+"='})
if($media.Count -ne 2) {throw 'Exactly two disks required; detach ISO.'}
$expected=@($OsDiskId.ToString(),$TrialDiskId.ToString())
foreach($entry in $media) {
    $id=$entry.Split('=')[1].Trim('"');if($id -notin $expected) {throw 'Unexpected medium.'}
    $disk=& $VBoxManage showmediuminfo disk $id
    if($LASTEXITCODE -ne 0 -or -not ($disk -match '^Parent UUID:\s+base$')) {throw 'Dependent disk refused.'}
    $location=($disk | Where-Object {$_ -match '^Location:'}) -replace '^Location:\s*',''
    if(-not ([IO.Path]::GetFullPath($location)).StartsWith($lab,[StringComparison]::OrdinalIgnoreCase)) {throw 'Disk outside lab.'}
    $capacity=if($id -eq $OsDiskId.ToString()) {65536} else {8192}
    if(-not ($disk -match ('^Capacity:\s+'+$capacity+' MBytes$'))) {throw 'Disk capacity mismatch.'}
    $cursor=Get-Item -LiteralPath $location
    while($null -ne $cursor) {if(($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {throw 'Reparse ancestor refused.'};$cursor=if($cursor -is [IO.FileInfo]) {$cursor.Directory} else {$cursor.Parent}}
}
'CONFIGURATION CHECKED; still require guest TPM 2.0/Secure Boot attestation, account/NTFS checks and separate execution approval.'
