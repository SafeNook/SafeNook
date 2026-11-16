using System.Buffers.Binary;
using SafeNook.Storage;
using SafeNook.StoreTestData;
namespace SafeNook.Storage.Tests;
public sealed partial class StoreTests
{
    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(26214400)]
    public void PortableAttachmentBoundaries(int length)
    {
        var path=FreshPath();var archive=FreshPath()+".snbak";var restored=FreshPath();using var f=new GenerationFixture();
        using(var store=Create(path,f))
        { Assert.Equal(CommitOutcome.Committed,Commit(store,f.Next(store.Header,includeBlob:true,blobBytes:new byte[length])).Outcome);store.BackupPortable(archive,CredentialKind.Password,GenerationFixture.Password,new NoStoreFaults(),Token); }
        QualificationStore.RestorePortable(archive,restored,CredentialKind.Recovery,f.Recovery.Span,GenerationFixture.Policy(),new NoStoreFaults(),Token);
        using var reopened=Open(restored);using var blob=reopened.ReadBlob(f.BlobId.ToString("N"),Token);Assert.Equal(length,blob.Span.Length);
    }
    [Fact]
    public void RestoreCancellationAndFlushFailureLeaveNoRoot()
    {
        var path=FreshPath();var archive=FreshPath()+".snbak";using var f=new GenerationFixture();
        using(var store=Create(path,f)) store.BackupPortable(archive,CredentialKind.Password,GenerationFixture.Password,new NoStoreFaults(),Token);
        var target=FreshPath();using var cancel=new CancellationTokenSource();cancel.Cancel();
        Assert.Throws<StoreException>(()=>QualificationStore.RestorePortable(archive,target,CredentialKind.Password,GenerationFixture.Password,GenerationFixture.Policy(),new NoStoreFaults(),cancel.Token));Assert.False(File.Exists(Path.Combine(target,"vault.json")));
        Assert.Throws<StoreException>(()=>QualificationStore.RestorePortable(archive,target,CredentialKind.Password,GenerationFixture.Password,GenerationFixture.Policy(),new BackupFlushFailure(),Token));Assert.False(File.Exists(Path.Combine(target,"vault.json")));
    }
    private sealed class BackupFlushFailure:IStoreFaults
    { public void At(CommitStep step) {} public void BeforeFlush(bool directory)=>throw new IOException("synthetic flush failure"); }
    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)] [InlineData(4)]
    public void ArchiveInventoryAndLengthBounds(int mode)
    {
        var path=FreshPath();var archive=FreshPath()+".snbak";using var f=new GenerationFixture();
        using(var store=Create(path,f)) {Commit(store,f.Next(store.Header,includeBlob:true));store.BackupPortable(archive,CredentialKind.Password,GenerationFixture.Password,new NoStoreFaults(),Token);}
        var bytes=File.ReadAllBytes(archive);using var input=new MemoryStream(bytes);var parsed=new BackupArchive(input,Token);
        if(mode==0) { var last=parsed.Entries.Last().Value;bytes=bytes[..checked((int)last.Offset-16)];BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(12),2);BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(16),(ulong)bytes.Length); }
        if(mode==1) {var last=parsed.Entries.Last().Value;bytes=bytes.Concat(bytes.AsSpan((int)last.Offset-16,last.Length+16).ToArray()).ToArray();BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(12),4);BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(16),(ulong)bytes.Length);}
        if(mode==4) {var last=parsed.Entries.Last().Value;var extra=bytes.AsSpan((int)last.Offset-16,last.Length+16).ToArray();extra.AsSpan(16+60,32).Fill(255);bytes=bytes.Concat(extra).ToArray();BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(12),4);BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(16),(ulong)bytes.Length);}
        if(mode==2) BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(16),2147483649);
        if(mode==3) BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(446),ulong.MaxValue);
        File.WriteAllBytes(archive,bytes);Assert.ThrowsAny<Exception>(()=>QualificationStore.VerifyPortable(archive,CredentialKind.Password,GenerationFixture.Password,GenerationFixture.Policy(),Token));
    }
    [Fact]
    public void PortableBlobRoundTripAndRecovery()
    {
        var path=FreshPath();var archive=FreshPath()+".snbak";var restored=FreshPath();using var f=new GenerationFixture();byte[] header;string hash;
        using(var store=Create(path,f))
        { Assert.Equal(CommitOutcome.Committed,Commit(store,f.Next(store.Header,includeBlob:true)).Outcome);header=store.Header;hash=store.BackupPortable(archive,CredentialKind.Password,GenerationFixture.Password,new NoStoreFaults(),Token); }
        Assert.Equal(hash,QualificationStore.VerifyPortable(archive,CredentialKind.Recovery,f.Recovery.Span,GenerationFixture.Policy(),Token));
        Assert.Equal(hash,QualificationStore.RestorePortable(archive,restored,CredentialKind.Password,GenerationFixture.Password,GenerationFixture.Policy(),new NoStoreFaults(),Token));
        using var reopened=Open(restored);Assert.Equal(header,reopened.Header);using var blob=reopened.ReadBlob(f.BlobId.ToString("N"),Token);Assert.Equal(new byte[]{0,255,13,10},blob.Span.ToArray());
        Assert.ThrowsAny<Exception>(()=>QualificationStore.VerifyPortable(archive,CredentialKind.Password,"wrong"u8,GenerationFixture.Policy(),Token));
        Assert.Throws<StoreException>(()=>QualificationStore.RestorePortable(archive,restored,CredentialKind.Password,GenerationFixture.Password,GenerationFixture.Policy(),new NoStoreFaults(),Token));
    }
    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)] [InlineData(4)] [InlineData(5)] [InlineData(6)] [InlineData(7)]
    public void PortableCorruptionRejected(int mode)
    {
        var path=FreshPath();var archive=FreshPath()+".snbak";using var f=new GenerationFixture();
        using(var store=Create(path,f)) { Commit(store,f.Next(store.Header,includeBlob:true));store.BackupPortable(archive,CredentialKind.Password,GenerationFixture.Password,new NoStoreFaults(),Token); }
        var bytes=File.ReadAllBytes(archive);
        if(mode==0) bytes[24+382]^=1;
        if(mode==1) bytes[8]=2;
        if(mode==2) bytes[438+1]=1;
        if(mode==3) bytes=bytes[..^1];
        if(mode==4) bytes=bytes.Concat(new byte[]{0}).ToArray();
        if(mode>=5) {using var stream=new MemoryStream(bytes);var parsed=new BackupArchive(stream,Token);var entry=parsed.Entries.Single(e=>e.Key.Kind==mode-4).Value;bytes[(int)(entry.Offset+entry.Length-1)]^=1;}
        File.WriteAllBytes(archive,bytes);
        var target=FreshPath();Assert.ThrowsAny<Exception>(()=>QualificationStore.RestorePortable(archive,target,CredentialKind.Password,GenerationFixture.Password,GenerationFixture.Policy(),new NoStoreFaults(),Token));Assert.False(File.Exists(Path.Combine(target,"vault.json")));
    }
    [Theory]
    [InlineData((int)CommitStep.ObjectWritten)] [InlineData((int)CommitStep.ObjectFlushed)] [InlineData((int)CommitStep.ObjectInstalled)]
    [InlineData((int)CommitStep.ManifestVerified)] [InlineData((int)CommitStep.RootWritten)] [InlineData((int)CommitStep.RootFlushed)]
    [InlineData((int)CommitStep.BeforePublish)] [InlineData((int)CommitStep.AfterPublish)] [InlineData((int)CommitStep.RootReadback)]
    public void RestorePublicationFaults(int boundary)
    {
        var path=FreshPath();var archive=FreshPath()+".snbak";var target=FreshPath();using var f=new GenerationFixture();
        using(var store=Create(path,f)) store.BackupPortable(archive,CredentialKind.Password,GenerationFixture.Password,new NoStoreFaults(),Token);
        var error=Assert.Throws<StoreException>(()=>QualificationStore.RestorePortable(archive,target,CredentialKind.Password,GenerationFixture.Password,GenerationFixture.Policy(),new FailAt((CommitStep)boundary),Token));
        var published=(CommitStep)boundary is CommitStep.AfterPublish or CommitStep.RootReadback;
        Assert.Equal(published?CommitOutcome.Indeterminate:CommitOutcome.RejectedBeforePublication,error.Outcome);
        Assert.Equal(published,File.Exists(Path.Combine(target,"vault.json")));if(published) {using var reopened=Open(target);Assert.Empty(reopened.ItemIds);}
    }
    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void BackupWriteFailureAndCancellation(bool full)
    {
        var path=FreshPath();var archive=FreshPath()+".snbak";using var f=new GenerationFixture();using var store=Create(path,f);
        Assert.Throws<StoreException>(()=>store.BackupPortable(archive,CredentialKind.Password,GenerationFixture.Password,new WriteFailure(full),Token));Assert.False(File.Exists(archive));
        using var cancel=new CancellationTokenSource();cancel.Cancel();Assert.Throws<StoreException>(()=>store.BackupPortable(archive,CredentialKind.Password,GenerationFixture.Password,new NoStoreFaults(),cancel.Token));Assert.False(File.Exists(archive));
    }
}
