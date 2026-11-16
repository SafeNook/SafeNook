param(
    [Parameter(Mandatory)][string] $LabDirectory,
    [string] $VBoxManage = 'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe'
)
# Read-only planner: emits JSON, never creates/starts/modifies VMs or directories.
$ErrorActionPreference='Stop'
$source='b147c2a7-6ed9-48f4-86d4-81774046aea4'
$snapshot='f2210738-d028-4855-a3c9-0cb202bcef31'
if(-not [IO.Path]::IsPathFullyQualified($LabDirectory)) { throw 'Choose an absolute dedicated lab directory.' }
if(Test-Path -LiteralPath $LabDirectory) { throw 'Lab directory must be new; no existing evidence may be overwritten.' }
$info=& $VBoxManage showvminfo $source --machinereadable
if($LASTEXITCODE -ne 0 -or $info -notcontains 'VMState="poweroff"') {throw 'Source must be powered off; planner never changes its state.'}
$snapshots=& $VBoxManage snapshot $source list --machinereadable
if($LASTEXITCODE -ne 0 -or -not ($snapshots -match [regex]::Escape($snapshot))) {throw 'Approved source snapshot unavailable.'}
$target=[guid]::NewGuid().ToString()
$commands=@(
    @{args=@('clonevm',$source,'--snapshot',$snapshot,'--mode','machine','--name','SafeNook-Qualification-Disposable','--uuid',$target,'--basefolder',$LabDirectory,'--register')},
    @{args=@('modifyvm',$target,'--nic1','none','--nic2','none','--nic3','none','--nic4','none','--nic5','none','--nic6','none','--nic7','none','--nic8','none','--clipboard-mode','disabled','--drag-and-drop','disabled','--usb-ohci','off','--usb-ehci','off','--usb-xhci','off','--usb-card-reader','off')},
    @{args=@('sharedfolder','remove',$target,'--name','VMShare')},
    @{args=@('storageattach',$target,'--storagectl','SATA','--port','1','--device','0','--medium','none')},
    @{args=@('storageattach',$target,'--storagectl','SATA','--port','2','--device','0','--medium','none')}
)
@{schema=1;status='PREPARED-NOT-EXECUTED';ownerApprovalRequired=$true;sourceUuid=$source;snapshotUuid=$snapshot;cloneUuid=$target;labDirectory=$LabDirectory;minimumFreeGiB=264;commands=$commands;preStartChecks=@('All clone hard disks have Parent UUID=base and paths under labDirectory','No source/snapshot disks attached','All NICs none; clipboard and drag-and-drop disabled','No shared folders, host DVD/VISO, USB filters or passthrough','Clone remains powered off; no automatic start command','Host free-space reserve >=20 GiB during every trial')} | ConvertTo-Json -Depth 8
