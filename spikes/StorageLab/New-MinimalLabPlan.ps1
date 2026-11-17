param(
    [Parameter(Mandatory)][guid] $VmId,
    [Parameter(Mandatory)][guid] $OsDiskId,
    [Parameter(Mandatory)][guid] $TrialDiskId,
    [Parameter(Mandatory)][guid] $PipeId,
    [Parameter(Mandatory)][string] $LabDirectory,
    [Parameter(Mandatory)][string] $EvidenceDirectory,
    [string] $VBoxManage='C:\Program Files\Oracle\VirtualBox\VBoxManage.exe'
)
# Read-only planner. No create/modify/start/poweroff/quota command is executed.
$ErrorActionPreference='Stop'
$ids=@($VmId,$OsDiskId,$TrialDiskId,$PipeId)
if(($ids | Select-Object -Unique).Count -ne 4 -or $ids -contains [guid]::Empty) {throw 'Require four distinct explicit identifiers.'}
foreach($path in @($LabDirectory,$EvidenceDirectory)) {
    if(-not [IO.Path]::IsPathFullyQualified($path) -or $path.StartsWith('\\') -or (Test-Path -LiteralPath $path)) {throw 'Require new absolute local directories.'}
    $cursor=[IO.Directory]::GetParent([IO.Path]::GetFullPath($path))
    while($null -ne $cursor) {
        if($cursor.Exists -and (($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {throw 'Reparse ancestor refused.'}
        $cursor=$cursor.Parent
    }
}
$lab=[IO.Path]::GetFullPath($LabDirectory).TrimEnd('\')+'\'
$evidence=[IO.Path]::GetFullPath($EvidenceDirectory).TrimEnd('\')+'\'
if($lab.StartsWith($evidence,[StringComparison]::OrdinalIgnoreCase) -or $evidence.StartsWith($lab,[StringComparison]::OrdinalIgnoreCase)) {throw 'Evidence and guest media must be disjoint.'}
$registered=& $VBoxManage list vms
if($LASTEXITCODE -ne 0) {throw 'VM inventory failed.'}
$media=& $VBoxManage list hdds
if($LASTEXITCODE -ne 0) {throw 'Media inventory failed.'}
foreach($id in $ids[0..2]) {if(($registered+$media) -match [regex]::Escape($id.ToString())) {throw 'Identifier already registered.'}}
@{
 schema=1;status='PLAN-ONLY-NOT-AUTHORIZED';vmId=$VmId;osDiskId=$OsDiskId;trialDiskId=$TrialDiskId
 labDirectory=$lab;evidenceDirectory=$evidence;minimumFreeGiB=256
 hardware=@{cpus=2;memoryMiB=6144;osDiskMiB=65536;trialDiskMiB=8192;firmware='efi';tpm='2.0';secureBoot=$true}
 isolation=@{nic1='none';nic2='none';nic3='none';nic4='none';nic5='none';nic6='none';nic7='none';nic8='none';sharedFolders=@();clipboard='disabled';dragAndDrop='disabled';ohci=$false;ehci=$false;xhci=$false;usbFilters=@();rawDisks=$false}
 uart=@{mode='client';endpoint=('\\.\pipe\safenook-oracle-'+$PipeId.ToString('N'));hostCreatesOwnerOnlyPipe=$true;serialFileLogging=$false}
 futureSteps=@('Separate owner approval before provisioning','Create only the new UUID with independent base disks at the approved paths','Apply and re-read all isolation settings before first start','Initialize UEFI variable store only on the new empty VM; enroll Microsoft signatures and platform key; enable Secure Boot','Verify SecureBoot and TPM 2.0 inside guest after approved offline installation','Use licensed offline media; no temporary NIC exception','Create dedicated non-admin synthetic test account; no credentials in plan','Detach installer and tool ISO before campaign','Verify named-pipe ACL and UART protocol without a cut','Separate approval before any destructive trial')
 blockers=@('No execution mode in this script','Positive-path provisioning and VirtualBox UART remain untested','No VM/disk/snapshot/start/poweroff/quota operations authorized')
} | ConvertTo-Json -Depth 6
