using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using SafeNook.Core.Vault;
using SafeNook.Storage;
using SafeNook.StoreTestData;

namespace SafeNook.Storage.Tests;

[SupportedOSPlatform("windows")]
public sealed class StoreTests
{
    public StoreTests() => Assert.SkipWhen(!OperatingSystem.IsWindows() || RuntimeInformation.ProcessArchitecture != Architecture.X64, "Windows x64 NTFS qualification only.");
    private static CancellationToken Token=>TestContext.Current.CancellationToken;
    private static readonly string Repo=FindRepo();
    private static string FindRepo()
    {
        var d=new DirectoryInfo(AppContext.BaseDirectory);
        while(d is not null && !File.Exists(Path.Combine(d.FullName,"SafeNook.slnx"))) d=d.Parent;
        return d?.FullName??throw new InvalidOperationException("Test workspace unavailable.");
    }
    private static string FreshPath()=>Path.Combine(Repo,"artifacts","sn-003b2-test-"+Guid.NewGuid().ToString("N"));
    private static QualificationStore Create(string path,GenerationFixture f,IStoreFaults? faults=null)
        =>QualificationStore.Create(path,f.Initial(),GenerationFixture.Password,f.Recovery.Span,()=>f.Recovery.Span.ToArray(),GenerationFixture.Policy(),faults??new NoStoreFaults(),Token);
    private static QualificationStore Open(string path)=>QualificationStore.Open(path,CredentialKind.Password,GenerationFixture.Password,GenerationFixture.Policy(),Token);
    private static QualificationCommit Commit(QualificationStore store,EncryptedGeneration next,IStoreFaults? faults=null,CancellationToken? token=null)
        =>store.Commit(next,CredentialKind.Password,GenerationFixture.Password,[],null,faults??new NoStoreFaults(),token??Token);

    [Fact]
    public void ProductionModeIsExplicitlyBlocked()
    { Assert.False(StorageSupport.ProductionWritesSupported); Assert.Throws<PlatformNotSupportedException>(StorageSupport.RequireProductionWrites); }

    [Fact]
    public void CreateEditTombstoneReopenAndRetainedDependencies()
    {
        var path=FreshPath(); using var f=new GenerationFixture(); byte[] first;
        using(var store=Create(path,f))
        {
            first=store.Header; Assert.Empty(store.ItemIds);
            Assert.Equal(CommitOutcome.Committed,Commit(store,f.Next(store.Header)).Outcome);
            var firstItemFiles=Directory.GetFiles(Path.Combine(path,"items")); Assert.Single(firstItemFiles);
            Assert.Equal(CommitOutcome.Committed,Commit(store,f.Next(store.Header,2)).Outcome);
            Assert.Equal(2ul,store.ReadItem(f.ItemId.ToString("N")).Fields.Revision);
            Assert.Equal(CommitOutcome.Committed,Commit(store,f.Next(store.Header,3,true)).Outcome);
            Assert.True(store.ReadItem(f.ItemId.ToString("N")).Fields.Deleted);
            Assert.True(File.Exists(firstItemFiles[0]));
            store.VerifyBackup(Convert.ToHexStringLower(first.AsSpan(44,16)),CredentialKind.Password,GenerationFixture.Password,Token);
            Assert.StartsWith("Refused:",store.GarbageCollectionStatus);
        }
        using var opened=Open(path); Assert.True(opened.ReadItem(f.ItemId.ToString("N")).Fields.Deleted);
        Assert.True(File.Exists(Path.Combine(path,".lock")));
    }

    [Fact]
    public void RecoveryConfirmationAndSlotPreservation()
    {
        using var f=new GenerationFixture(); var initial=f.Initial(); var rejected=FreshPath();
        var e=Assert.Throws<StoreException>(()=>QualificationStore.Create(rejected,initial,GenerationFixture.Password,f.Recovery.Span,()=>new byte[32],GenerationFixture.Policy(),new NoStoreFaults(),Token));
        Assert.Equal(CommitOutcome.RejectedBeforePublication,e.Outcome); Assert.False(File.Exists(Path.Combine(rejected,"vault.json")));
        var path=FreshPath();
        using(var store=QualificationStore.Create(path,initial,GenerationFixture.Password,f.Recovery.Span,()=>f.Recovery.Span.ToArray(),GenerationFixture.Policy(),new NoStoreFaults(),Token))
        {
            var before=store.Header;
            var next=f.Next(before,password:GenerationFixture.NextPassword);
            var result=store.Commit(next,CredentialKind.Password,GenerationFixture.Password,GenerationFixture.NextPassword,null,new NoStoreFaults(),Token);
            Assert.Equal(CommitOutcome.Committed,result.Outcome); Assert.False(result.PowerLossQualified);
            Assert.Equal(before.AsSpan(274,108).ToArray(),store.Header.AsSpan(274,108).ToArray());
        }
        using(var recovery=QualificationStore.Open(path,CredentialKind.Recovery,f.Recovery.Span,GenerationFixture.Policy(),Token)) Assert.Empty(recovery.ItemIds);
        using var newRecovery=VaultCrypto.GenerateKey();
        using(var store=QualificationStore.Open(path,CredentialKind.Password,GenerationFixture.NextPassword,GenerationFixture.Policy(),Token))
        {
            var before=store.Header; var next=f.Next(before,recovery:newRecovery.Span.ToArray());
            var denied=store.Commit(next,CredentialKind.Password,GenerationFixture.NextPassword,newRecovery.Span,()=>new byte[32],new NoStoreFaults(),Token);
            Assert.Equal(CommitOutcome.RejectedBeforePublication,denied.Outcome); Assert.Equal(before,store.Header);
            var result=store.Commit(next,CredentialKind.Password,GenerationFixture.NextPassword,newRecovery.Span,()=>newRecovery.Span.ToArray(),new NoStoreFaults(),Token);
            Assert.Equal(CommitOutcome.Committed,result.Outcome); Assert.Equal(before.AsSpan(166,108).ToArray(),store.Header.AsSpan(166,108).ToArray());
        }
        using var reopened=QualificationStore.Open(path,CredentialKind.Recovery,newRecovery.Span,GenerationFixture.Policy(),Token); Assert.Empty(reopened.ItemIds);
    }

    [Theory]
    [InlineData((int)CommitStep.Validated)] [InlineData((int)CommitStep.ObjectWritten)] [InlineData((int)CommitStep.ObjectFlushed)]
    [InlineData((int)CommitStep.ObjectInstalled)] [InlineData((int)CommitStep.ManifestVerified)] [InlineData((int)CommitStep.BackupWritten)]
    [InlineData((int)CommitStep.RootWritten)] [InlineData((int)CommitStep.RootFlushed)] [InlineData((int)CommitStep.BeforePublish)]
    [InlineData((int)CommitStep.AfterPublish)] [InlineData((int)CommitStep.RootReadback)]
    public void FaultAtEveryCommitBoundary(int stepValue)
    {
        var step=(CommitStep)stepValue;
        var path=FreshPath(); using var f=new GenerationFixture();
        using(var store=Create(path,f))
        {
            var result=Commit(store,f.Next(store.Header),new FailAt(step));
            Assert.Equal(step is CommitStep.AfterPublish or CommitStep.RootReadback?CommitOutcome.Indeterminate:CommitOutcome.RejectedBeforePublication,result.Outcome);
            if(result.Outcome==CommitOutcome.Indeterminate) Assert.Throws<StoreException>(()=>_ = store.ItemIds);
        }
        using var reopened=Open(path); Assert.Equal(step is CommitStep.AfterPublish or CommitStep.RootReadback?1:0,reopened.ItemIds.Length);
        AssertEncryptedStaging(path);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void ShortWriteAndDiskFullAreNotCommits(bool diskFull)
    {
        var path=FreshPath(); using var f=new GenerationFixture();
        using(var store=Create(path,f)) Assert.Equal(CommitOutcome.RejectedBeforePublication,Commit(store,f.Next(store.Header),new WriteFailure(diskFull)).Outcome);
        using var reopened=Open(path); Assert.Empty(reopened.ItemIds); AssertEncryptedStaging(path);
    }

    [Fact]
    public void RealAtomicRenameSharingFailureIsUncertainWithoutRetry()
    {
        var path=FreshPath(); using var f=new GenerationFixture();
        using(var store=Create(path,f))
        {
            using var blocker=File.Open(Path.Combine(path,"vault.json"),FileMode.Open,FileAccess.Read,FileShare.Read);
            var result=Commit(store,f.Next(store.Header)); Assert.Equal(CommitOutcome.Indeterminate,result.Outcome);
            Assert.Throws<StoreException>(()=>Commit(store,f.Next(store.Header,reuse:true)));
        }
        using var reopened=Open(path); Assert.Empty(reopened.ItemIds);
    }

    [Fact]
    public void CancellationAndOrphansLeaveOldGeneration()
    {
        var path=FreshPath(); using var f=new GenerationFixture();
        using(var store=Create(path,f))
        {
            Assert.Equal(CommitOutcome.RejectedBeforePublication,Commit(store,f.Next(store.Header),token:new CancellationToken(true)).Outcome);
            Assert.Equal(CommitOutcome.RejectedBeforePublication,Commit(store,f.Next(store.Header),new FailAt(CommitStep.ObjectInstalled)).Outcome);
            Assert.Empty(store.ItemIds); Assert.StartsWith("Refused:",store.GarbageCollectionStatus);
        }
        Assert.NotEmpty(Directory.GetFiles(Path.Combine(path,"items"))); using var reopened=Open(path); Assert.Empty(reopened.ItemIds);
    }

    [Theory]
    [InlineData("root")] [InlineData("manifest")] [InlineData("item")] [InlineData("blob")]
    public void CorruptCurrentGenerationNeverFallsBack(string part)
    {
        var path=FreshPath(); using var f=new GenerationFixture(); byte[] header;
        using(var store=Create(path,f)) { Assert.Equal(CommitOutcome.Committed,Commit(store,f.Next(store.Header,includeBlob:true)).Outcome); header=store.Header; }
        var file=part switch
        {
            "root"=>Path.Combine(path,"vault.json"),
            "manifest"=>Path.Combine(path,"manifests",Convert.ToHexStringLower(header.AsSpan(100,32))+".manifest"),
            "item"=>Directory.GetFiles(Path.Combine(path,"items")).Single(),
            _=>Directory.GetFiles(Path.Combine(path,"blobs")).Single(),
        };
        var bytes=File.ReadAllBytes(file); bytes[^1]^=1; File.WriteAllBytes(file,bytes);
        var error=Assert.Throws<StoreException>(()=>Open(path)); Assert.Equal(CommitOutcome.RecoveryRequired,error.Outcome);
        Assert.NotEmpty(Directory.GetFiles(Path.Combine(path,".backup")));
    }

    [Fact]
    public void BackupCorruptionBlocksVerificationAndGcNeverDeletes()
    {
        var path=FreshPath(); using var f=new GenerationFixture(); string generation;
        using(var store=Create(path,f)) { generation=Convert.ToHexStringLower(store.Header.AsSpan(44,16)); Assert.Equal(CommitOutcome.Committed,Commit(store,f.Next(store.Header)).Outcome); }
        var backup=Path.Combine(path,".backup",generation+".json"); var bytes=File.ReadAllBytes(backup); bytes[0]^=1; File.WriteAllBytes(backup,bytes);
        using var opened=Open(path); var count=Directory.GetFiles(path,"*",SearchOption.AllDirectories).Length;
        Assert.Throws<StoreException>(()=>opened.VerifyBackup(generation,CredentialKind.Password,GenerationFixture.Password,Token));
        Assert.StartsWith("Refused:",opened.GarbageCollectionStatus); Assert.Equal(count,Directory.GetFiles(path,"*",SearchOption.AllDirectories).Length);
    }

    [Fact]
    public void LockedDirectoryCannotBeSubstitutedAndPathsCannotTraverse()
    {
        var path=FreshPath(); using var f=new GenerationFixture(); using var store=Create(path,f);
        // Both paths are inside this test's newly created absolute vault directory.
        var source=Path.GetFullPath(Path.Combine(path,"items")); var target=Path.GetFullPath(Path.Combine(path,"items-moved"));
        Assert.StartsWith(path+Path.DirectorySeparatorChar,source); Assert.StartsWith(path+Path.DirectorySeparatorChar,target);
        Assert.Throws<IOException>(()=>Directory.Move(source,target));
        Assert.Throws<StoreException>(()=>new WindowsFileSystem(path+"\\..\\escape",false,Token));
        Assert.Throws<StoreException>(()=>store.VerifyBackup("..\\outside",CredentialKind.Password,GenerationFixture.Password,Token));
    }

    [Fact]
    public async Task JunctionRootIsRejected()
    {
        var target=FreshPath(); using var f=new GenerationFixture(); using(var store=Create(target,f)) { }
        var link=FreshPath();
        using var command=Start("cmd.exe",["/c","mklink","/J",link,target]);
        await command.WaitForExitAsync(Token); Assert.Equal(0,command.ExitCode);
        Assert.True((File.GetAttributes(link)&FileAttributes.ReparsePoint)!=0);
        Assert.Throws<StoreException>(()=>Open(link));
    }

    [Fact]
    public void HardLinkedRootAndInappropriateFileAreRejected()
    {
        var path=FreshPath(); using var f=new GenerationFixture(); using(var store=Create(path,f)) { }
        var root=Path.Combine(path,"vault.json"); var alias=Path.Combine(path,"root-alias");
        Assert.True(CreateHardLink(alias,root,0)); Assert.Throws<StoreException>(()=>Open(path));
        var other=FreshPath(); using(var store=Create(other,f)) { }
        var otherRoot=Path.Combine(other,"vault.json"); File.Delete(otherRoot); Directory.CreateDirectory(otherRoot);
        Assert.Throws<StoreException>(()=>Open(other));
    }

    [Fact]
    public async Task TwoProcessesContendAndTerminationReleasesLock()
    {
        var path=FreshPath(); using var f=new GenerationFixture(); using(var store=Create(path,f)) { }
        using var holder=StartHelper(path,"hold");
        try
        {
            Assert.Equal("LOCKED",await holder.StandardOutput.ReadLineAsync(Token).AsTask().WaitAsync(TimeSpan.FromSeconds(20),Token));
            using var cancellation=new CancellationTokenSource(TimeSpan.FromMilliseconds(150));
            Assert.Throws<OperationCanceledException>(()=>new WindowsFileSystem(path,false,cancellation.Token));
            using var waiter=StartHelper(path,"wait");
            try
            {
                await Task.Delay(200,Token); Assert.False(waiter.HasExited); holder.Kill(true); await holder.WaitForExitAsync(Token);
                Assert.Equal("ACQUIRED",await waiter.StandardOutput.ReadLineAsync(Token).AsTask().WaitAsync(TimeSpan.FromSeconds(20),Token));
                await waiter.WaitForExitAsync(Token); Assert.Equal(0,waiter.ExitCode);
            }
            finally { if(!waiter.HasExited) waiter.Kill(true); }
        }
        finally { if(!holder.HasExited) holder.Kill(true); }
        Assert.True(File.Exists(Path.Combine(path,".lock"))); using var reopened=Open(path); Assert.Empty(reopened.ItemIds);
    }

    [Theory]
    [InlineData((int)CommitStep.Validated)] [InlineData((int)CommitStep.ObjectWritten)] [InlineData((int)CommitStep.ObjectFlushed)]
    [InlineData((int)CommitStep.ObjectInstalled)] [InlineData((int)CommitStep.ManifestVerified)] [InlineData((int)CommitStep.BackupWritten)]
    [InlineData((int)CommitStep.RootWritten)] [InlineData((int)CommitStep.RootFlushed)] [InlineData((int)CommitStep.BeforePublish)]
    [InlineData((int)CommitStep.AfterPublish)] [InlineData((int)CommitStep.RootReadback)]
    public async Task IndependentProcessCrashAtCommitBoundary(int stepValue)
    {
        var step=(CommitStep)stepValue;
        var path=FreshPath(); TestContext.Current.TestOutputHelper?.WriteLine("Crash artifact: "+path); using var process=StartHelper(path,"crash",step.ToString());
        try
        {
            Assert.Equal("CRASH_POINT",await process.StandardOutput.ReadLineAsync(Token).AsTask().WaitAsync(TimeSpan.FromSeconds(30),Token));
            process.Kill(true); await process.WaitForExitAsync(Token);
        }
        finally { if(!process.HasExited) process.Kill(true); }
        using var reopened=Open(path); Assert.Equal(step is CommitStep.AfterPublish or CommitStep.RootReadback?1:0,reopened.ItemIds.Length);
        AssertEncryptedStaging(path);
    }

    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)]
    public void FileAndNamespaceFlushFailuresAreNotAcknowledged(int mode)
    {
        var path=FreshPath(); using var f=new GenerationFixture();
        using(var store=Create(path,f))
        {
            var result=Commit(store,f.Next(store.Header),new FlushFailure(mode));
            Assert.Equal(mode==2?CommitOutcome.Indeterminate:CommitOutcome.RejectedBeforePublication,result.Outcome);
        }
        using var reopened=Open(path); Assert.Equal(mode==2?1:0,reopened.ItemIds.Length);
    }
    private sealed class FlushFailure(int mode):IStoreFaults
    {
        private bool _published;
        public void At(CommitStep step) { if(step==CommitStep.AfterPublish) _published=true; }
        public void BeforeFlush(bool directory)
        {
            if((mode==0 && !directory) || (mode==1 && directory) || (mode==2 && _published)) throw new IOException("injected flush failure");
        }
    }

    [Fact]
    public async Task BroadenedVaultAclIsRejected()
    {
        var path=FreshPath(); using var f=new GenerationFixture(); using(var store=Create(path,f)) { }
        using var command=Start("icacls.exe",[path,"/grant","*S-1-1-0:(RX)"]);
        await command.WaitForExitAsync(Token); Assert.Equal(0,command.ExitCode);
        var error=Assert.Throws<StoreException>(()=>Open(path)); Assert.Contains("unsafe-acl",error.Code);
    }

    [Fact]
    public void FailedPasswordPublicationPreservesBothOldSlots()
    {
        var path=FreshPath(); using var f=new GenerationFixture(); byte[] previous;
        using(var store=Create(path,f))
        {
            previous=store.Header; var candidate=f.Next(previous,password:GenerationFixture.NextPassword);
            var result=store.Commit(candidate,CredentialKind.Password,GenerationFixture.Password,GenerationFixture.NextPassword,null,new FailAt(CommitStep.RootFlushed),Token);
            Assert.Equal(CommitOutcome.RejectedBeforePublication,result.Outcome); Assert.Equal(previous,store.Header);
        }
        using var recovered=QualificationStore.Open(path,CredentialKind.Recovery,f.Recovery.Span,GenerationFixture.Policy(),Token);
        Assert.Equal(previous,recovered.Header);
    }

    [Fact]
    public async Task TransientReadSharingViolationIsRetriedButPersistentOneFailsClosed()
    {
        var path=FreshPath(); using var f=new GenerationFixture(); using(var store=Create(path,f)) { }
        using(var blocker=File.Open(Path.Combine(path,"vault.json"),FileMode.Open,FileAccess.ReadWrite,FileShare.Read))
        {
            var opening=Task.Run(()=>Open(path),Token);
            await Task.Delay(100,Token); blocker.Dispose();
            using var opened=await opening.WaitAsync(TimeSpan.FromSeconds(10),Token); Assert.Empty(opened.ItemIds);
        }
        using var persistent=File.Open(Path.Combine(path,"vault.json"),FileMode.Open,FileAccess.ReadWrite,FileShare.Read);
        var error=Assert.Throws<StoreException>(()=>Open(path)); Assert.Equal(CommitOutcome.RecoveryRequired,error.Outcome);
        Assert.Contains("native-open-32",error.Code);
    }

    [Fact]
    public void BackupFilenameMustMatchAuthenticatedGeneration()
    {
        var path=FreshPath(); using var f=new GenerationFixture(); string first,second;
        using(var store=Create(path,f))
        {
            first=Convert.ToHexStringLower(store.Header.AsSpan(44,16)); Assert.Equal(CommitOutcome.Committed,Commit(store,f.Next(store.Header)).Outcome);
            second=Convert.ToHexStringLower(store.Header.AsSpan(44,16)); Assert.Equal(CommitOutcome.Committed,Commit(store,f.Next(store.Header,2)).Outcome);
        }
        File.WriteAllBytes(Path.Combine(path,".backup",second+".json"),File.ReadAllBytes(Path.Combine(path,".backup",first+".json")));
        using var opened=Open(path);
        Assert.Throws<StoreException>(()=>opened.VerifyBackup(second,CredentialKind.Password,GenerationFixture.Password,Token));
    }

    [Fact]
    public void PostPublicationDependencyDamageIsUncertainAndBackupRequiresExplicitSelection()
    {
        var path=FreshPath(); using var f=new GenerationFixture(); string previous;
        using(var store=Create(path,f))
        {
            previous=Convert.ToHexStringLower(store.Header.AsSpan(44,16)); var candidate=f.Next(store.Header);
            var manifest=Path.Combine(path,"manifests",Convert.ToHexStringLower(candidate.Header.AsSpan(100,32))+".manifest");
            var result=Commit(store,candidate,new CorruptAfterPublish(manifest)); Assert.Equal(CommitOutcome.Indeterminate,result.Outcome);
        }
        Assert.Throws<StoreException>(()=>Open(path)); var rootBytes=File.ReadAllBytes(Path.Combine(path,"vault.json"));
        Assert.Equal(1ul,QualificationStore.InspectRecoveryCandidate(path,previous,CredentialKind.Password,GenerationFixture.Password,GenerationFixture.Policy(),Token));
        Assert.Equal(rootBytes,File.ReadAllBytes(Path.Combine(path,"vault.json")));
    }
    private sealed class CorruptAfterPublish(string manifest):IStoreFaults
    {
        public void At(CommitStep step) { if(step==CommitStep.AfterPublish) { var bytes=File.ReadAllBytes(manifest); bytes[^1]^=1; File.WriteAllBytes(manifest,bytes); } }
    }

    [Fact]
    public void CorruptCurrentDependencyDuringCommitRequiresRecoveryButWrongPasswordDoesNot()
    {
        var path=FreshPath(); using var f=new GenerationFixture(); using var store=Create(path,f);
        var candidate=f.Next(store.Header);
        var wrong=store.Commit(candidate,CredentialKind.Password,"wrong"u8,[],null,new NoStoreFaults(),Token);
        Assert.Equal(CommitOutcome.RejectedBeforePublication,wrong.Outcome); Assert.Empty(store.ItemIds);
        Assert.Equal(CommitOutcome.Committed,Commit(store,candidate).Outcome);
        var next=f.Next(store.Header,2); var selectedRoot=File.ReadAllBytes(Path.Combine(path,"vault.json"));
        var item=Directory.GetFiles(Path.Combine(path,"items")).Single(); var damaged=File.ReadAllBytes(item); damaged[^1]^=1; File.WriteAllBytes(item,damaged);
        Assert.Equal(CommitOutcome.RecoveryRequired,Commit(store,next).Outcome);
        Assert.Throws<StoreException>(()=>_ = store.ItemIds); Assert.Equal(selectedRoot,File.ReadAllBytes(Path.Combine(path,"vault.json")));
    }

    private static void AssertEncryptedStaging(string path)
    {
        foreach(var file in Directory.GetFiles(Path.Combine(path,".tmp")))
        {
            var bytes=File.ReadAllBytes(file);
            Assert.False(bytes.AsSpan().IndexOf("synthetic payload"u8)>=0);
            Assert.False(bytes.AsSpan().IndexOf(GenerationFixture.Password)>=0);
            if(bytes.Length>=8) Assert.True(bytes.AsSpan(0,8).SequenceEqual("SNOBJ001"u8) || bytes[0]=='{');
        }
    }
#if DEBUG
    private const string BuildConfiguration="Debug";
#else
    private const string BuildConfiguration="Release";
#endif
    private static Process StartHelper(string path,params string[] args)=>Start(Path.Combine(Repo,"spikes","StoreQualification","bin",BuildConfiguration,"net10.0","StoreQualification.exe"),[path,..args]);
    private static Process Start(string executable,string[] args)
    {
        var info=new ProcessStartInfo(executable){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
        foreach(var arg in args) info.ArgumentList.Add(arg); return Process.Start(info)!;
    }
    private sealed class FailAt(CommitStep step):IStoreFaults { public void At(CommitStep value) { if(value==step) throw new IOException("synthetic fault"); } }
    private sealed class WriteFailure(bool full):IStoreFaults
    { public void At(CommitStep step) { } public int WriteLength(int requested)=>full?throw new IOException("synthetic disk full"):requested/2; }
    [DllImport("kernel32.dll",EntryPoint="CreateHardLinkW",CharSet=CharSet.Unicode,SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CreateHardLink(string fileName,string existing,nint security);
}
