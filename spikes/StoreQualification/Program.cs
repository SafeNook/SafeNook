using SafeNook.Core.Vault;
using SafeNook.Storage;
using SafeNook.StoreTestData;
if(!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
var path=args[0];
if(args.Length>1 && args[1]=="verify")
{
    try { using var checkedStore=QualificationStore.Open(path,CredentialKind.Password,GenerationFixture.Password,GenerationFixture.Policy(),CancellationToken.None); Console.WriteLine("VERIFIED "+checkedStore.ItemIds.Length); }
    catch(StoreException e) { Console.WriteLine("REFUSED "+e.Code); Environment.ExitCode=2; }
    return;
}
if(args.Length>1 && args[1]=="hold")
{
    using var held=new WindowsFileSystem(path,false,CancellationToken.None); Console.WriteLine("LOCKED"); Console.Out.Flush();
    Thread.Sleep(Timeout.Infinite); return;
}
if(args.Length>1 && args[1]=="wait")
{
    using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(10));
    using var waiting=new WindowsFileSystem(path,false,timeout.Token); Console.WriteLine("ACQUIRED"); return;
}
using var fixture=new GenerationFixture(); var policy=GenerationFixture.Policy();
using(var store=QualificationStore.Create(path,fixture.Initial(),GenerationFixture.Password,fixture.Recovery.Span,()=>fixture.Recovery.Span.ToArray(),policy,new NoStoreFaults(),CancellationToken.None))
{
    if(store.ItemIds.Length!=0) throw new InvalidOperationException("Initial inventory mismatch.");
    var old=store.Header;
    var next=fixture.Next(old,includeBlob:true);
    IStoreFaults faults=args.Length>2 && args[1]=="crash"?new CrashFault(Enum.Parse<CommitStep>(args[2])):new NoStoreFaults();
    var result=store.Commit(next,CredentialKind.Password,GenerationFixture.Password,[],null,faults,CancellationToken.None);
    if(result.Outcome!=CommitOutcome.Committed) throw new InvalidOperationException("Commit failed: "+result.Outcome);
    using var blob=store.ReadBlob(fixture.BlobId.ToString("N"),CancellationToken.None);
    if(!blob.Span.SequenceEqual(new byte[]{0,255,13,10})) throw new InvalidOperationException("Blob mismatch.");
    store.VerifyBackup(Convert.ToHexStringLower(old.AsSpan(44,16)),CredentialKind.Password,GenerationFixture.Password,CancellationToken.None);
    Console.WriteLine("PASS: NTFS COW create/commit, backup verification, blob AEAD; directoryFlush="+result.DirectoryFlushSucceeded+"; powerLossQualified="+result.PowerLossQualified);
}
using(var reopened=QualificationStore.Open(path,CredentialKind.Password,GenerationFixture.Password,policy,CancellationToken.None))
    if(reopened.ItemIds.Length!=1) throw new InvalidOperationException("Reopen mismatch.");
Console.WriteLine("PASS: reopen; production writable mode remains blocked");
internal sealed class CrashFault(CommitStep step):IStoreFaults
{
    public void At(CommitStep current) { if(current==step) { Console.WriteLine("CRASH_POINT"); Console.Out.Flush(); Thread.Sleep(Timeout.Infinite); } }
}
