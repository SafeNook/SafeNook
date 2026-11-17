param([switch] $OwnerApprovedPowerCut,[switch] $InspectOnly)
# Exact existing VM only. No creation, start, mutation of settings, snapshot or recovery actions.
$ErrorActionPreference='Stop'
$vbox='C:\Program Files\Oracle\VirtualBox\VBoxManage.exe'
$id='efef2867-fa7e-4e7e-9f30-477262021e73'
if(-not $InspectOnly -and -not $OwnerApprovedPowerCut) {throw 'Separate owner approval for this poweroff is required.'}
$info=& $vbox showvminfo $id --machinereadable
if($LASTEXITCODE -ne 0) {throw 'VM inspection failed.'}
function Value([string] $key) {
    $lines=@($info | Where-Object {$_.StartsWith($key+'=')})
    if($lines.Count -ne 1) {throw 'Missing/duplicate VM property.'}
    return $lines[0].Substring($key.Length+1).Trim('"').Replace('\\','\')
}
if((Value 'name') -ne 'safe-nook-base' -or (Value 'UUID') -ne $id) {throw 'Wrong VM identity.'}
foreach($n in 1..8) {if((Value "nic$n") -ne 'none') {throw 'Network must be disabled before trials.'}}
if(($info -match '^SharedFolder') -or ($info -match '^USBFilter') -or (Value 'clipboard') -ne 'disabled' -or (Value 'draganddrop') -ne 'disabled') {throw 'Host integrations must be disabled.'}
foreach($key in @('usb','ehci','xhci')) {if((Value $key) -ne 'off') {throw 'USB must be disabled.'}}
foreach($n in 1..4) {if((Value "uart$n") -ne 'off') {throw 'Guest-local smoke requires disabled host UART integrations.'}}
$media=@($info | Where-Object {$_ -match '^"[^"=]+-ImageUUID-[0-9]+-[0-9]+"='})
if($media.Count -ne 1 -or $media[0].Split('=')[1].Trim('"') -ne '4a012329-1d1e-4c46-8f66-2983a4734e2a') {throw 'Expected one independent disk; detach ISO/VISO.'}
$disk=& $vbox showmediuminfo disk '4a012329-1d1e-4c46-8f66-2983a4734e2a'
if($LASTEXITCODE -ne 0 -or -not ($disk -match '^Parent UUID:\s+base$')) {throw 'Dependent disk refused.'}
$location=($disk | Where-Object {$_ -match '^Location:'}) -replace '^Location:\s*',''
$expected=Join-Path $env:USERPROFILE 'VirtualBox VMs\safe-nook-base\safe-nook-base.vdi'
if(-not [IO.Path]::GetFullPath($location).Equals([IO.Path]::GetFullPath($expected),[StringComparison]::OrdinalIgnoreCase)) {throw 'Unexpected disk path.'}
$entry=Get-Item -LiteralPath $location
while($null -ne $entry) {if(($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {throw 'Reparse disk path refused.'};$entry=if($entry -is [IO.FileInfo]) {$entry.Directory} else {$entry.Parent}}
if($InspectOnly) {'PASS: identity and isolation inspected; no poweroff authorization implied.';return}
if((Value 'VMState') -ne 'running') {throw 'VM is not running.'}
& $vbox controlvm $id poweroff
if($LASTEXITCODE -ne 0) {throw 'Poweroff failed; inspect manually, no retry.'}
