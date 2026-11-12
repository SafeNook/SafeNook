using System.Security.Cryptography;
using System.Text;
using SafeNook.Core.Vault;
using SafeNook.Core.Vault.Models;
using SafeNook.StateTestData;

namespace SafeNook.Core.Tests.Vault;

public sealed class AuthenticatedStateTests
{
    private static CancellationToken Token => TestContext.Current.CancellationToken;
    private static byte[] Bytes(string value) => Encoding.UTF8.GetBytes(value);
    private static AuthenticatedVaultState Open(StateFixture f, VaultAdmissionPolicy p) => AuthenticatedVaultState.OpenRecovery(f.Header, StateFixture.Recovery, f.Source, p, Token);

    [Fact]
    public void CompleteStateBothSlotsAndLazyBlobs()
    {
        var f = StateFixture.Build(); var policy = StateFixture.Policy();
        using (var state = Open(f, policy))
        {
            Assert.Equal(new[] { StateFixture.ItemId }, state.ItemIds); Assert.Equal(1ul, state.Sequence);
            Assert.IsType<FilePayload>(state.ReadItem(StateFixture.ItemId).Payload);
            Assert.All(f.Source.Reads.Where(r => r.Kind == 2), r => Assert.Equal(118, r.Size));
            using var blob = state.ReadBlob(StateFixture.BlobId, Token); Assert.Equal(new byte[] { 0, 255, 13, 10, 0 }, blob.Span.ToArray());
            Assert.True(policy.ReservedBytes > 0);
            var ids = state.ItemIds; ids[0] = "changed"; Assert.Equal(StateFixture.ItemId, state.ItemIds[0]);
        }
        Assert.Equal(0, policy.ReservedBytes);
        using var passwordState = AuthenticatedVaultState.OpenPassword(f.Header, StateFixture.Password, f.Source, policy, Token);
        Assert.Equal(StateFixture.ItemId, passwordState.ItemIds[0]);
    }

    [Theory]
    [InlineData(1, "{\"username\":\"u\",\"password\":\"synthetic-secret\",\"urls\":[\"https://example.test\"],\"notes\":\"n\"}")]
    [InlineData(2, "{\"text\":\"note 😀\"}")]
    [InlineData(3, "{\"privateBlobId\":\"22222222333344448555666666666666\",\"publicBlobId\":null,\"format\":\"opaque-ssh\",\"originalName\":\"key\"}")]
    [InlineData(4, "{\"identityBlobId\":\"22222222333344448555666666666666\",\"recipientBlobId\":null,\"format\":\"opaque-age\",\"originalName\":\"key\"}")]
    public void TypedPayloadsAndSourceGeneratedWriters(ushort type, string payload)
    {
        var raw = StateFixture.Item(type, payload); var f = StateFixture.Build(raw, includeBlob: type >= 3, type: type);
        using var state = Open(f, StateFixture.Policy()); var item = state.ReadItem(StateFixture.ItemId);
        var encoded = VaultPayloadJson.WriteItem(item);
        try { Assert.Equal(type, VaultPayloadJson.ReadItem(encoded, StateFixture.ItemId, type).Fields.Type); }
        finally { CryptographicOperations.ZeroMemory(encoded); }
        var manifest = VaultPayloadJson.ReadManifest(Bytes(f.ManifestJson));
        Assert.Equal(manifest.VaultId, VaultPayloadJson.ReadManifest(VaultPayloadJson.WriteManifest(manifest)).VaultId);
    }

    [Theory]
    [InlineData("\"schema\":1", "\"schema\":2")]
    [InlineData("\"schema\":1", "\"schema\":1,\"schema\":1")]
    [InlineData("\"schema\":1", "\"schema\":1,\"sch\\u0065ma\":1")]
    [InlineData("\"schema\":1", "\"schema\":1,\"secret-unknown\":0")]
    [InlineData("\"schema\":1", "\"schema\":1.0")]
    [InlineData("\"schema\":1", "\"schema\":1e0")]
    [InlineData("\"revision\":1", "\"revision\":0")]
    [InlineData("\"revision\":1", "\"revision\":-1")]
    [InlineData("\"revision\":1", "\"revision\":18446744073709551616")]
    [InlineData("\"type\":5", "\"type\":6")]
    [InlineData("\"title\":\"synthetic-secret-title\"", "\"title\":null")]
    [InlineData("\"title\":\"synthetic-secret-title\"", "\"title\":\"\\ud800\"")]
    [InlineData("\"title\":\"synthetic-secret-title\"", "\"title\":\"\\udc00\"")]
    [InlineData("\"tags\":[]", "\"tags\":[\"x\",\"x\"]")]
    [InlineData("\"tags\":[]", "\"tags\":[\"\"]")]
    [InlineData("\"previous\":null", "\"previous\":\"invalid\"")]
    [InlineData("\"previous\":null,", "")]
    [InlineData("\"createdAt\":0", "\"createdAt\":1")]
    [InlineData("\"updatedAt\":0", "\"updatedAt\":253402300800000")]
    [InlineData("\"blobId\":", "\"unknownBlobId\":")]
    [InlineData("\"mediaType\":\"application/octet-stream\"", "\"mediaType\":\"x\",\"mediaType\":\"y\"")]
    public void StrictItemRejections(string before, string after)
    {
        var json = StateFixture.Item().Replace(before, after, StringComparison.Ordinal);
        var exception = Assert.Throws<VaultDataException>(() => VaultPayloadJson.ReadItem(Bytes(json), StateFixture.ItemId, 5));
        Assert.DoesNotContain("synthetic-secret", exception.ToString());
    }

    [Fact]
    public void JsonFramingEncodingDepthAndSize()
    {
        var json = Bytes(StateFixture.Item());
        foreach (var invalid in new[] { new byte[] { 255 }, new byte[] { 239, 187, 191 }.Concat(json).ToArray(), json[..^1], json.Concat("{}"u8.ToArray()).ToArray(), Bytes("/*comment*/"+StateFixture.Item()), Bytes(StateFixture.Item()[..^1]+",}"), new byte[65537] })
            Assert.Throws<VaultDataException>(() => VaultPayloadJson.ReadItem(invalid, StateFixture.ItemId, 5));
        Assert.Throws<VaultDataException>(() => VaultPayloadJson.ReadManifest(new byte[8388609]));
        var deep = StateFixture.Item().Replace("\"tags\":[]", "\"tags\":"+new string('[', 17)+"0"+new string(']', 17));
        Assert.Throws<VaultDataException>(() => VaultPayloadJson.ReadItem(Bytes(deep), StateFixture.ItemId, 5));
        var oversizedText = StateFixture.Item(2, "{\"text\":\""+new string('x',32769)+"\"}");
        Assert.Throws<VaultDataException>(() => VaultPayloadJson.ReadItem(Bytes(oversizedText), StateFixture.ItemId, 2));
        var utf8Limit = StateFixture.Item().Replace("synthetic-secret-title", new string('é',513));
        Assert.Throws<VaultDataException>(() => VaultPayloadJson.ReadItem(Bytes(utf8Limit), StateFixture.ItemId, 5));
    }

    [Theory]
    [InlineData("vaultId", "00112233445546778899aabbccddeeff", "33333333444445558666777777777777")]
    [InlineData("epochId", "102132435465476889abbcdef0123456", "33333333444445558666777777777777")]
    [InlineData("generationId", "20314253647548699abccdef01234567", "33333333444445558666777777777777")]
    public void ManifestHeaderContextMismatch(string field, string before, string after)
        => Fails(StateFixture.Build(alterManifest: s => s.Replace("\""+field+"\":\""+before, "\""+field+"\":\""+after)));

    [Fact]
    public void SequenceSchemaAndParentMismatch()
    {
        foreach (var alter in new Func<string,string>[] { s=>s.Replace("\"sequence\":1","\"sequence\":2"), s=>s.Replace("\"schema\":1","\"schema\":2"), s=>s.Replace(new string('0',64),new string('1',64)) })
            Fails(StateFixture.Build(alterManifest:alter));
    }

    [Theory]
    [InlineData("missing-item")] [InlineData("missing-blob")] [InlineData("item-hash")]
    [InlineData("manifest-hash")] [InlineData("item-type")] [InlineData("blob-context")]
    [InlineData("blob-size")]
    public void ObjectFailuresDoNotPublish(string kind)
    {
        var f=StateFixture.Build();
        switch(kind)
        {
            case "missing-item": f.Source.Files.Remove((1,f.ItemWrite)); break;
            case "missing-blob": f.Source.Files.Remove((2,f.BlobWrite)); break;
            case "item-hash": f.Source.Files[(1,f.ItemWrite)][^1]^=1; break;
            case "manifest-hash": f.Source.Files.Single(x=>x.Key.Kind==3).Value[^1]^=1; break;
            case "item-type": f.Source.Files[(1,f.ItemWrite)][92]=2; break;
            case "blob-context": f.Source.Files[(2,f.BlobWrite)][12]^=1; break;
            case "blob-size": f.Source.Files[(2,f.BlobWrite)]=f.Source.Files[(2,f.BlobWrite)][..^1]; break;
        }
        Fails(f);
    }

    [Fact]
    public void BlobTamperIsDeferredButNeverReleased()
    {
        var f=StateFixture.Build(); f.Source.Files[(2,f.BlobWrite)][^1]^=1; var p=StateFixture.Policy();
        using var state=Open(f,p); var baseline=p.ReservedBytes; AdmittedPlaintext? output=null;
        Assert.Throws<VaultDataException>(()=>output=state.ReadBlob(StateFixture.BlobId,Token));
        Assert.Null(output); Assert.Equal(baseline,p.ReservedBytes);
        // Later replacement with a valid unrelated immutable blob is also rejected.
        f.Source.Files[(2,f.BlobWrite)]=ObjectCodec.Encrypt(StateFixture.Key,StateFixture.Context(StateFixture.BlobId,2,0),new byte[5],100,Token);
        Assert.Throws<VaultDataException>(()=>state.ReadBlob(StateFixture.BlobId,Token));
    }

    [Fact]
    public void ReferencesDuplicatesOrderAndLimits()
    {
        var f=StateFixture.Build(); var m=VaultPayloadJson.ReadManifest(Bytes(f.ManifestJson)); var r=m.Items[0]; var b=m.Blobs[0];
        foreach(var items in new[] { new[]{r,r}, new[]{Ref(StateFixture.OtherId,r),r}, Enumerable.Repeat(r,10001).ToArray(),new[]{Ref(r.Id,r,length:65537)},new[]{Ref(r.Id,r,type:0)} })
            Assert.Throws<VaultDataException>(()=>ManifestValidation.ValidateInventory(Clone(m,items:items)));
        Assert.Throws<VaultDataException>(()=>ManifestValidation.ValidateInventory(Clone(m,blobs:[Ref(b.Id,b,write:r.WriteId)])));
        Assert.Throws<VaultDataException>(()=>ManifestValidation.ValidateInventory(Clone(m,blobs:[b,b])));
        Assert.Throws<VaultDataException>(()=>ManifestValidation.ValidateInventory(Clone(m,blobs:[Ref(b.Id,b,length:26214401)])));
        var aggregate=Enumerable.Range(1,42).Select(i=>new ObjectReference {Id=i.ToString("x8")+"000040008000000000000000",WriteId=i.ToString("x64"),Type=0,Length=26214400,Sha256=new string('0',64)}).ToArray();
        Assert.Throws<VaultDataException>(()=>ManifestValidation.ValidateInventory(Clone(m,blobs:aggregate)));
        var allItems=Enumerable.Range(1,4097).Select(i=>new ObjectReference {Id=i.ToString("x8")+"000040008000000000000000",WriteId=i.ToString("x64"),Type=2,Length=65536,Sha256=new string('0',64)}).ToArray();
        Assert.Throws<VaultDataException>(()=>ManifestValidation.ValidateInventory(Clone(m,items:allItems,blobs:[])));
    }

    [Fact]
    public void MissingUnownedAndSharedBlobReferences()
    {
        Fails(StateFixture.Build(includeBlob:false));
        Fails(StateFixture.Build(StateFixture.Item().Replace(StateFixture.BlobId,StateFixture.OtherId)));
        Fails(StateFixture.Build(StateFixture.Item(2,"{\"text\":\"note\"}"),type:2));
        var ssh=StateFixture.Item(3,"{\"privateBlobId\":\""+StateFixture.BlobId+"\",\"publicBlobId\":\""+StateFixture.BlobId+"\",\"format\":\"opaque-ssh\",\"originalName\":\"key\"}");
        Fails(StateFixture.Build(ssh,type:3));
        var f=StateFixture.Build(); var m=VaultPayloadJson.ReadManifest(Bytes(f.ManifestJson));
        var item=VaultPayloadJson.ReadItem(Bytes(ssh),StateFixture.ItemId,3);
        var large=Clone(m,items:[Ref(m.Items[0].Id,m.Items[0],type:3)],blobs:[Ref(m.Blobs[0].Id,m.Blobs[0],length:1048577)]);
        Assert.Throws<VaultDataException>(()=>ManifestValidation.ValidateLinks(large,[item]));
        // Physical extras are unreachable candidates, not extra manifest references.
        f.Source.Files[(2,new string('f',64))]=new byte[1]; using var state=Open(f,StateFixture.Policy());
        Assert.Throws<VaultDataException>(()=>state.ReadBlob(StateFixture.OtherId,Token));
    }

    [Fact]
    public void TombstonesAndRevisions()
    {
        var raw=StateFixture.Item().Replace("\"revision\":1","\"revision\":2").Replace("\"previous\":null","\"previous\":\""+new string('a',64)+"\"");
        var live=VaultPayloadJson.ReadItem(Bytes(raw),StateFixture.ItemId,5);
        var tomb=raw[..raw.IndexOf("\"payload\":",StringComparison.Ordinal)]+"\"payload\":null}";
        tomb=tomb.Replace("\"deleted\":false","\"deleted\":true").Replace("synthetic-secret-title","");
        using var state=Open(StateFixture.Build(tomb,includeBlob:false),StateFixture.Policy()); Assert.True(state.ReadItem(StateFixture.ItemId).Fields.Deleted);
        Fails(StateFixture.Build(tomb)); // Tombstone cannot own inventory blobs.
        foreach(var invalid in new[]{tomb.Replace("\"title\":\"\"","\"title\":\"leak\""),tomb.Replace("\"tags\":[]","\"tags\":[\"tag\"]"),raw.Replace("\"deleted\":false","\"deleted\":true"),raw.Replace("\"revision\":2","\"revision\":1")})
            Assert.Throws<VaultDataException>(()=>VaultPayloadJson.ReadItem(Bytes(invalid),StateFixture.ItemId,5));
        var first=VaultPayloadJson.ReadItem(Bytes(StateFixture.Item()),StateFixture.ItemId,5);
        VaultPayloadJson.ValidateRevision(first,live,new string('a',64));
        Assert.Throws<VaultDataException>(()=>VaultPayloadJson.ValidateRevision(first,live,new string('b',64)));
        Assert.Throws<VaultDataException>(()=>VaultPayloadJson.ValidateRevision(live,live,new string('a',64)));
    }

    [Theory]
    [InlineData(1)] [InlineData(2)]
    public void AllocationFailureCleansReservationsAndDoesNotPublish(int failAt)
    {
        var f=StateFixture.Build(); var p=StateFixture.Policy(new FailingAllocator(failAt)); AuthenticatedVaultState? state=null;
        var e=Assert.Throws<VaultDataException>(()=>state=Open(f,p)); Assert.Equal(VaultDataError.ResourceLimit,e.Error);
        Assert.Null(state); Assert.Equal(0,p.ReservedBytes); Assert.DoesNotContain("secret",e.ToString());
    }

    [Fact]
    public void LazyAllocationFailureAndLifetimeAccounting()
    {
        var f=StateFixture.Build(); var p=StateFixture.Policy(new FailingAllocator(3)); using(var state=Open(f,p))
        { var baseline=p.ReservedBytes; Assert.Throws<VaultDataException>(()=>state.ReadBlob(StateFixture.BlobId,Token)); Assert.Equal(baseline,p.ReservedBytes); }
        Assert.Equal(0,p.ReservedBytes);
        p=StateFixture.Policy(); var s=Open(f,p); var blob=s.ReadBlob(StateFixture.BlobId,Token); var span=blob.Span;
        s.Dispose(); Assert.True(p.ReservedBytes>0); blob.Dispose(); Assert.Equal(0,p.ReservedBytes); Assert.True(span.IndexOfAnyExcept((byte)0)<0);
        Assert.Throws<ObjectDisposedException>(()=>s.ReadItem(StateFixture.ItemId));
    }

    [Fact]
    public void TrustedPolicyAndSourceErrors()
    {
        var f=StateFixture.Build(); var small=new VaultAdmissionPolicy(65536,8192); Fails(f,small);
        Assert.Equal(65536u,VaultAdmissionPolicy.FromAvailableMemory(268435456).KdfMemoryKiB);
        Assert.Equal(262144u,VaultAdmissionPolicy.FromAvailableMemory(8L*1073741824).KdfMemoryKiB);
        Assert.Throws<VaultDataException>(()=>VaultAdmissionPolicy.FromAvailableMemory(1024));
        var p=StateFixture.Policy(); f.Source.Failure=new OutOfMemoryException("synthetic-secret"); Fails(f,p);
        f.Source.Failure=new InvalidOperationException("synthetic-secret"); Fails(f,p);
        f.Source.Failure=new ObjectDisposedException("synthetic-secret"); Fails(f,p);
        f.Source.Failure=null;
        Assert.Throws<OperationCanceledException>(()=>AuthenticatedVaultState.OpenRecovery(f.Header,StateFixture.Recovery,f.Source,p,new CancellationToken(true)));
        Assert.Equal(0,p.ReservedBytes);
        using var state=Open(f,p); var held=p.ReservedBytes;
        var onlyOne=new VaultAdmissionPolicy(65536,held+4096); using var first=Open(f,onlyOne);
        Fails(f,onlyOne,expectedReservation:held);
    }

    [Fact]
    public void FailureAfterFirstAuthenticatedItemIsStillAtomic()
    {
        var f=StateFixture.Build(secondItem:true); var p=StateFixture.Policy(new FailingAllocator(3));
        Fails(f,p); Assert.Equal(0,p.ReservedBytes);
        var second=f.Source.Files.Single(x=>x.Key.Kind==1 && x.Key.Write!=f.ItemWrite).Value; second[^1]^=1;
        Fails(f);
    }

    [Fact]
    public void EmptyInventoryAndManifestWriteCollision()
    {
        var f=StateFixture.Build(alterManifest:s=>
        {
            var m=VaultPayloadJson.ReadManifest(Bytes(s)); return Encoding.UTF8.GetString(VaultPayloadJson.WriteManifest(Clone(m,items:[],blobs:[])));
        });
        using var state=Open(f,StateFixture.Policy()); Assert.Empty(state.ItemIds);
        var regular=StateFixture.Build(); var m=VaultPayloadJson.ReadManifest(Bytes(regular.ManifestJson));
        var collided=Clone(m,items:[Ref(m.Items[0].Id,m.Items[0],write:Convert.ToHexStringLower(regular.Header.AsSpan(100,32)))]);
        Assert.Throws<VaultDataException>(()=>ManifestValidation.ValidateHeaderBinding(collided,regular.Header));
    }

    [Fact]
    public void ManifestLengthsHashesEnumsAndUnknownFields()
    {
        foreach(var transform in new Func<string,string>[]
        {
            s=>s.Replace("\"length\":5","\"length\":6"),
            s=>s.Replace("\"type\":0","\"type\":1"),
            s=>s.Replace("\"blobs\":[","\"unexpected\":0,\"blobs\":["),
            s=>s.Replace("\"sequence\":1","\"sequence\":1.0"),
        }) Fails(StateFixture.Build(alterManifest:transform));
        var wrongPayload=StateFixture.Item(2,"{\"text\":\"note\"}");
        Fails(StateFixture.Build(wrongPayload,type:5));
        var badFormat=StateFixture.Item(3,"{\"privateBlobId\":\""+StateFixture.BlobId+"\",\"publicBlobId\":null,\"format\":\"unknown\",\"originalName\":\"key\"}");
        Fails(StateFixture.Build(badFormat,type:3));
    }

    [Fact]
    public void NullableRequiredFieldsAndPrimitiveKinds()
    {
        foreach(var raw in new[] { StateFixture.Item().Replace("\"tags\":[]","\"tags\":null"),
            StateFixture.Item().Replace("\"deleted\":false","\"deleted\":0"),
            StateFixture.Item().Replace("\"type\":5","\"type\":\"5\""),
            StateFixture.Item().Replace("\"mediaType\":\"application/octet-stream\"","\"mediaType\":null") })
            Assert.Throws<VaultDataException>(()=>VaultPayloadJson.ReadItem(Bytes(raw),StateFixture.ItemId,5));
        var ssh=StateFixture.Item(3,"{\"privateBlobId\":\""+StateFixture.BlobId+"\",\"format\":\"opaque-ssh\",\"originalName\":\"key\"}");
        Assert.Throws<VaultDataException>(()=>VaultPayloadJson.ReadItem(Bytes(ssh),StateFixture.ItemId,3));
    }

    [Fact]
    public void PrevalidationCapsCollectionsBeforeDtoAllocation()
    {
        var tooManyTags=StateFixture.Item().Replace("\"tags\":[]","\"tags\":["+string.Join(',',Enumerable.Repeat("0",10001))+"]");
        Assert.Throws<VaultDataException>(()=>VaultPayloadJson.ReadItem(Bytes(tooManyTags),StateFixture.ItemId,5));
        var manifest=StateFixture.Build().ManifestJson;
        var tooManyObjects=manifest.Replace("\"items\":[","\"items\":["+string.Concat(Enumerable.Repeat("{},",10001)));
        Assert.Throws<VaultDataException>(()=>VaultPayloadJson.ReadManifest(Bytes(tooManyObjects)));
        var wide=StateFixture.Item()[..^1]+","+string.Join(',',Enumerable.Range(0,17).Select(i=>"\"unknown"+i+"\":0"))+"}";
        Assert.Throws<VaultDataException>(()=>VaultPayloadJson.ReadItem(Bytes(wide),StateFixture.ItemId,5));
    }

    [Fact]
    public void StateRejectsWrongCredentialBeforeReadingSource()
    {
        var f=StateFixture.Build(); var policy=StateFixture.Policy();
        Assert.Throws<VaultDataException>(()=>AuthenticatedVaultState.OpenRecovery(f.Header,new byte[32],f.Source,policy,Token));
        Assert.Empty(f.Source.Reads); Assert.Equal(0,policy.ReservedBytes);
        Assert.Throws<VaultDataException>(()=>AuthenticatedVaultState.OpenPassword(f.Header,"incorrect"u8,f.Source,policy,Token));
        Assert.Empty(f.Source.Reads); Assert.Equal(0,policy.ReservedBytes);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(f.Header.AsSpan(186),131072);
        var denied=Assert.Throws<VaultDataException>(()=>AuthenticatedVaultState.OpenPassword(f.Header,StateFixture.Password,f.Source,policy,Token));
        Assert.Equal(VaultDataError.ResourceLimit,denied.Error); Assert.Empty(f.Source.Reads); Assert.Equal(0,policy.ReservedBytes);
    }

    private static void Fails(StateFixture f,VaultAdmissionPolicy? policy=null,long expectedReservation=0)
    {
        policy??=StateFixture.Policy(); AuthenticatedVaultState? state=null;
        var e=Assert.Throws<VaultDataException>(()=>state=Open(f,policy)); Assert.Null(state); Assert.Equal(expectedReservation,policy.ReservedBytes);
        Assert.DoesNotContain("synthetic-secret",e.ToString());
    }
    private sealed class FailingAllocator(int failAt):IVaultBufferAllocator
    {
        private int _count;
        public byte[] Allocate(int length) => ++_count==failAt ? throw new OutOfMemoryException("synthetic-secret") : new byte[length];
    }
    private static ObjectReference Ref(string id,ObjectReference source,ulong? length=null,ushort? type=null,string? write=null)=>new()
    {Id=id,WriteId=write??source.WriteId,Type=type??source.Type,Length=length??source.Length,Sha256=source.Sha256};
    private static ManifestDto Clone(ManifestDto m,ObjectReference[]? items=null,ObjectReference[]? blobs=null)=>new()
    {Schema=m.Schema,VaultId=m.VaultId,EpochId=m.EpochId,GenerationId=m.GenerationId,Sequence=m.Sequence,ParentHeaderHash=m.ParentHeaderHash,Items=items??m.Items,Blobs=blobs??m.Blobs};
}
