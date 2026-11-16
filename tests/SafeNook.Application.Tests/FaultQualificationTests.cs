using SafeNook.Application;
using SafeNook.ApplicationTestData;
using SafeNook.Core.Vault;
using SafeNook.Storage;
namespace SafeNook.Application.Tests;
public sealed partial class VaultApplicationTests
{
    public static IEnumerable<object[]> FaultCases()
    {
        foreach(var operation in new[]{"passwd","recover","rotate","backup","verify","restore"})
        foreach(var failure in new[]{"pre-cancel","wrong","cancel","oom","short","full","file-flush","directory-flush","before","rename","after","readback","oom-after","post-directory-flush"})
        { if(operation=="backup" && failure=="post-directory-flush") continue; if(operation=="verify" && failure is not ("pre-cancel" or "wrong" or "cancel" or "oom")) continue;yield return [operation,failure]; }
        foreach(var step in new[]{CommitStep.Validated,CommitStep.ObjectWritten,CommitStep.ObjectFlushed,CommitStep.ObjectInstalled,CommitStep.ManifestVerified,CommitStep.RootWritten,CommitStep.RootFlushed,CommitStep.BeforePublish,CommitStep.AfterPublish,CommitStep.BeforeReadback,CommitStep.RootReadback}) yield return ["restore","cancel:"+step];
    }
    [Theory] [MemberData(nameof(FaultCases))]
    public void OperationFaultMatrixPreservesRecovery(string operation,string failure)
    {
        var path=PathForTest();var ui=new SyntheticInteraction();var normal=App(ui);normal.Init(path,Token);normal.Add(path,"note",Token);
        var original=File.ReadAllBytes(Path.Combine(path,"vault.json"));var header=VaultFormat.DecodeWrapper(original);var recovery=ui.Recovery!;
        var archive=path+".snbak";if(operation is "verify" or "restore") normal.Backup(path,archive,false,Token);
        var target=path+"-restored";using var cancel=CancellationTokenSource.CreateLinkedTokenSource(Token);
        var faults=new MatrixFault(failure,cancel);var app=App(ui,faults);ui.ConfirmPassword=ui.NewPassword;
        if(failure=="pre-cancel") cancel.Cancel();
        if(failure=="wrong") {ui.Password="wrong synthetic";ui.DisplayRecovery(RecoveryCode.Encode(new byte[32]),"");}
        var error=Assert.Throws<VaultOperationException>(()=>
        {
            switch(operation)
            {
                case "passwd": app.ChangePassword(path,cancel.Token);break;
                case "recover": app.Recover(path,cancel.Token);break;
                case "rotate": app.RotateRecovery(path,cancel.Token);break;
                case "backup": app.Backup(path,archive,false,cancel.Token);break;
                case "verify": app.VerifyBackup(archive,false,cancel.Token);break;
                default: app.Restore(archive,target,false,cancel.Token);break;
            }
        });
        var cancelledPublished=failure is "cancel:AfterPublish" or "cancel:BeforeReadback" or "cancel:RootReadback";
        var attempted=cancelledPublished || failure is "oom-after" or "post-directory-flush" || failure is "rename" or "after" or "readback" || operation=="backup" && failure=="directory-flush";
        if(attempted) Assert.Equal(VaultApplicationError.Indeterminate,error.Error);
        if((failure is "cancel" or "pre-cancel" || failure.StartsWith("cancel:",StringComparison.Ordinal)) && !attempted) Assert.Equal(VaultApplicationError.Cancelled,error.Error);
        if(failure=="wrong") Assert.Equal(VaultApplicationError.AuthenticationOrCorruption,error.Error);
        if(failure=="oom") Assert.Equal(VaultApplicationError.ResourceLimit,error.Error);
        Assert.DoesNotContain("synthetic",error.ToString());Assert.Null(error.InnerException);
        Assert.InRange(faults.Publications,0,1);
        var published=cancelledPublished || failure is "oom-after" or "post-directory-flush" || failure is "after" or "readback" || operation=="backup" && failure=="directory-flush";
        if(operation is "passwd" or "recover" or "rotate")
        {
            var current=VaultFormat.DecodeWrapper(File.ReadAllBytes(Path.Combine(path,"vault.json")));
            if(!published) Assert.Equal(original,File.ReadAllBytes(Path.Combine(path,"vault.json")));
            var unchanged=operation=="rotate"?166:274;Assert.Equal(header.AsSpan(unchanged,108).ToArray(),current.AsSpan(unchanged,108).ToArray());
            Assert.Equal(header.AsSpan(12,32).ToArray(),current.AsSpan(12,32).ToArray());
            using var oldRecovery=RecoveryCode.Decode(recovery.AsSpan());using var oldKey=KeySlots.OpenRecovery(header,oldRecovery.Span,Token);
            var currentPassword=published && operation!="rotate"?ui.NewPassword:"synthetic master password";
            using var key=KeySlots.OpenPassword(current,System.Text.Encoding.UTF8.GetBytes(currentPassword),65536,Token);Assert.Equal(oldKey.Span.ToArray(),key.Span.ToArray());
            var currentRecovery=published && operation=="rotate"?ui.Recovery!:recovery;using var rk=RecoveryCode.Decode(currentRecovery.AsSpan());
            using var opened=QualificationStore.Open(path,CredentialKind.Recovery,rk.Span,new(65536,536870912),Token);Assert.Single(opened.ItemIds);
        }
        else
        {
            Assert.Equal(original,File.ReadAllBytes(Path.Combine(path,"vault.json")));
            ui.Password="synthetic master password";Assert.Single(normal.List(path,Token).Items);
            if(operation=="backup") {Assert.Equal(published,File.Exists(archive));if(published) normal.VerifyBackup(archive,false,Token);}
            if(operation=="restore") {Assert.Equal(published,File.Exists(Path.Combine(target,"vault.json")));if(published) Assert.Single(normal.List(target,Token).Items);}
        }
        Assert.All(ui.Issued,b=>Assert.All(b,value=>Assert.Equal((byte)0,value)));
    }
    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void ArchiveHandleBlocksSubstitutionDuringUse(bool restore)
    {
        var path=PathForTest();var ui=new SyntheticInteraction();var app=App(ui);app.Init(path,Token);app.Add(path,"note",Token);
        var archive=path+".snbak";var hash=app.Backup(path,archive,false,Token);var faults=new SubstituteArchive(archive);
        var checkedApp=App(ui,faults);Assert.Equal(hash,restore?checkedApp.Restore(archive,path+"-restored",false,Token):checkedApp.VerifyBackup(archive,false,Token));Assert.True(faults.Checked);
    }
    [Fact]
    public void ExistingBackupIsPreservedOnNativeRenameFailure()
    {
        var path=PathForTest();var ui=new SyntheticInteraction();var app=App(ui);app.Init(path,Token);
        var archive=path+".snbak";var original=app.Backup(path,archive,false,Token);app.Add(path,"note",Token);
        Assert.Equal(VaultApplicationError.Indeterminate,Assert.Throws<VaultOperationException>(()=>app.Backup(path,archive,false,Token)).Error);
        Assert.Equal(original,app.VerifyBackup(archive,false,Token));Assert.Single(app.List(path,Token).Items);
    }
    private sealed class SubstituteArchive(string path):IStoreFaults
    {
        public bool Checked {get;private set;}
        public void At(CommitStep step)
        {
            if(step!=CommitStep.Authenticated) return;
            Assert.Throws<IOException>(()=>File.Move(path,path+"-substituted"));
            Assert.Throws<IOException>(()=>File.WriteAllBytes(path,[0]));Checked=true;
        }
    }
    [Theory]
    [InlineData("passwd")] [InlineData("recover")] [InlineData("rotate")] [InlineData("backup")] [InlineData("verify")] [InlineData("restore")]
    public void AllocatorRefusalDoesNotMasqueradeAsCorruption(string operation)
    {
        var path=PathForTest();var ui=new SyntheticInteraction();var normal=App(ui);normal.Init(path,Token);var archive=path+".snbak";normal.Backup(path,archive,false,Token);
        var root=File.ReadAllBytes(Path.Combine(path,"vault.json"));var policy=new VaultAdmissionPolicy(65536,536870912,new RefuseAllocation());var app=VaultApplication.ForQualification(ui,policy);
        var error=Assert.Throws<VaultOperationException>(()=>
        {
            switch(operation)
            {case "passwd":app.ChangePassword(path,Token);break;case "recover":app.Recover(path,Token);break;case "rotate":app.RotateRecovery(path,Token);break;case "backup":app.Backup(path,path+"-new.snbak",false,Token);break;case "verify":app.VerifyBackup(archive,false,Token);break;default:app.Restore(archive,path+"-restored",false,Token);break;}
        });
        Assert.Equal(VaultApplicationError.ResourceLimit,error.Error);Assert.Equal(0,policy.ReservedBytes);Assert.Equal(root,File.ReadAllBytes(Path.Combine(path,"vault.json")));
    }
    private sealed class RefuseAllocation:IVaultBufferAllocator
    {public byte[] Allocate(int length)=>throw new OutOfMemoryException("synthetic sensitive allocator failure");}
    public static IEnumerable<object[]> CorruptionCases()
    {foreach(var operation in new[]{"passwd","recover","rotate","backup","verify","restore"}) foreach(var kind in new[]{0,1,2,3}) yield return [operation,kind];}
    [Theory] [MemberData(nameof(CorruptionCases))]
    public void CorruptionPreventsEveryOperation(string operation,int kind)
    {
        var path=PathForTest();using var fixture=new SafeNook.StoreTestData.GenerationFixture();
        using(var store=QualificationStore.Create(path,fixture.Initial(),SafeNook.StoreTestData.GenerationFixture.Password,fixture.Recovery.Span,()=>fixture.Recovery.Span.ToArray(),new(65536,536870912),new NoStoreFaults(),Token))
        {Assert.Equal(CommitOutcome.Committed,store.Commit(fixture.Next(store.Header,includeBlob:true),CredentialKind.Password,SafeNook.StoreTestData.GenerationFixture.Password,[],null,new NoStoreFaults(),Token).Outcome);}
        var ui=new SyntheticInteraction {Password=System.Text.Encoding.UTF8.GetString(SafeNook.StoreTestData.GenerationFixture.Password)};ui.DisplayRecovery(RecoveryCode.Encode(fixture.Recovery.Span),"");var normal=App(ui);var archive=path+".snbak";normal.Backup(path,archive,false,Token);
        if(operation is "verify" or "restore")
        {var bytes=File.ReadAllBytes(archive);if(kind==0) bytes[24+382]^=1;else {using var input=new MemoryStream(bytes);var parsed=new BackupArchive(input,Token);var entry=parsed.Entries.Single(e=>e.Key.Kind==kind).Value;bytes[(int)(entry.Offset+entry.Length-1)]^=1;}File.WriteAllBytes(archive,bytes);}
        else
        {var file=kind==0?Path.Combine(path,"vault.json"):Directory.GetFiles(Path.Combine(path,kind==1?"items":kind==2?"blobs":"manifests")).OrderByDescending(File.GetLastWriteTimeUtc).First();var bytes=File.ReadAllBytes(file);bytes[^1]^=1;File.WriteAllBytes(file,bytes);}
        var root=File.ReadAllBytes(Path.Combine(path,"vault.json"));
        Assert.Throws<VaultOperationException>(()=>
        {
            switch(operation)
            {case "passwd":normal.ChangePassword(path,Token);break;case "recover":normal.Recover(path,Token);break;case "rotate":normal.RotateRecovery(path,Token);break;case "backup":normal.Backup(path,path+"-new.snbak",false,Token);break;case "verify":normal.VerifyBackup(archive,false,Token);break;default:normal.Restore(archive,path+"-restored",false,Token);break;}
        });
        Assert.Equal(root,File.ReadAllBytes(Path.Combine(path,"vault.json")));Assert.False(File.Exists(Path.Combine(path+"-restored","vault.json")));
    }
    [Fact]
    public void DamagedCurrentRootRequiresRecoveryWithoutHiddenRollback()
    {
        var path=PathForTest();var ui=new SyntheticInteraction();App(ui).Init(path,Token);App(ui).Add(path,"note",Token);
        var original=VaultFormat.DecodeWrapper(File.ReadAllBytes(Path.Combine(path,"vault.json")));ui.ConfirmPassword=ui.NewPassword;
        var error=Assert.Throws<VaultOperationException>(()=>App(ui,new DamageRoot(path)).ChangePassword(path,Token));
        Assert.Equal(VaultApplicationError.AuthenticationOrCorruption,error.Error);
        Assert.Equal(new byte[]{0},File.ReadAllBytes(Path.Combine(path,"vault.json")));
        using var rk=RecoveryCode.Decode(ui.Recovery!.AsSpan());
        Assert.Equal(2ul,QualificationStore.InspectRecoveryCandidate(path,Convert.ToHexStringLower(original.AsSpan(44,16)),CredentialKind.Recovery,rk.Span,new(65536,536870912),Token));
    }
    private sealed class DamageRoot(string path):IStoreFaults
    {public void At(CommitStep step) {if(step==CommitStep.BeforePublish) File.WriteAllBytes(Path.Combine(path,"vault.json"),[0]);}}
    private sealed class MatrixFault(string failure,CancellationTokenSource cancel):IStoreFaults
    {
        public int Publications {get;private set;}
        public void At(CommitStep step)
        {
            if(step==CommitStep.AfterPublish) Publications++;
            if(failure=="cancel:"+step) {cancel.Cancel();cancel.Token.ThrowIfCancellationRequested();}
            if(failure=="oom-after" && step==CommitStep.AfterPublish) throw new OutOfMemoryException("synthetic secret");
            if(step==CommitStep.Authenticated && failure=="cancel") {cancel.Cancel();cancel.Token.ThrowIfCancellationRequested();}
            if(step==CommitStep.Authenticated && failure=="oom") throw new OutOfMemoryException("synthetic secret");
            if((failure=="before" && step==CommitStep.BeforePublish)||(failure=="rename" && step==CommitStep.BeforeRename)||(failure=="after" && step==CommitStep.AfterPublish)||(failure=="readback" && step==CommitStep.BeforeReadback)) throw new IOException("synthetic secret");
        }
        public int WriteLength(int requested)=>failure=="full"?throw new IOException("synthetic disk full"):failure=="short"?requested/2:requested;
        public void BeforeFlush(bool directory)
        {if(failure=="post-directory-flush" && directory && Publications>0 || failure==(directory?"directory-flush":"file-flush")) throw new IOException("synthetic flush");}
    }
}
