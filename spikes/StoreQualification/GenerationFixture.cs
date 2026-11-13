using System.Buffers.Binary;
using System.Security.Cryptography;
using SafeNook.Core.Vault;
using SafeNook.Core.Vault.Models;
using SafeNook.Storage;

namespace SafeNook.StoreTestData;

// Synthetic credentials only. No secrets are passed on command lines or environment variables.
internal sealed class GenerationFixture:IDisposable
{
    internal static readonly byte[] Password="synthetic qualification password"u8.ToArray();
    internal static readonly byte[] NextPassword="synthetic replacement password"u8.ToArray();
    internal SecretBuffer Key { get; }=VaultCrypto.GenerateKey();
    internal SecretBuffer Recovery { get; }=VaultCrypto.GenerateKey();
    internal Guid VaultId { get; }=VaultFormat.NewId();
    internal Guid EpochId { get; }=VaultFormat.NewId();
    internal Guid ItemId { get; }=VaultFormat.NewId();
    internal Guid BlobId { get; }=VaultFormat.NewId();
    internal static VaultAdmissionPolicy Policy()=>new(65536,536870912);
    internal ObjectReference? ItemReference { get; private set; }
    internal ObjectReference? BlobReference { get; private set; }
    internal EncryptedGeneration Initial()
    {
        var manifest=Manifest(1,new byte[32],VaultFormat.NewId(),[],[]);
        var file=EncryptManifest(manifest); var prefix=Prefix(manifest,file);
        var header=KeySlots.CreateHeader(prefix,Key.Span,Password,Recovery.Span,65536,3,65536);
        return new(header,[file]);
    }
    internal EncryptedGeneration Next(byte[] oldHeader, int revision=1, bool deleted=false, bool includeBlob=false, bool reuse=false,
        byte[]? password=null,byte[]? recovery=null)
    {
        var files=new List<byte[]>();
        if(!reuse && password is null && recovery is null)
        {
            ItemPayload? payload=deleted?null:new NotePayload{Text="synthetic payload - never plaintext on disk"};
            if(includeBlob && !deleted)
            {
                var bytes=ObjectCodec.Encrypt(Key.Span,new(VaultId,EpochId,BlobId,2,0),new byte[]{0,255,13,10},1024);
                files.Add(bytes); BlobReference=Reference(BlobId,0,bytes);
                payload=new FilePayload {BlobId=BlobId.ToString("N"),OriginalName="synthetic.bin",MediaType="application/octet-stream"};
            }
            var type=ItemReference?.Type??(includeBlob?(ushort)5:(ushort)2);
            var item=new ItemDocument(new ItemFields {Schema=1,Id=ItemId.ToString("N"),Type=type,Revision=(ulong)revision,
                CreatedAt=0,UpdatedAt=(ulong)revision,Title=deleted?"":"synthetic title",Tags=[],Deleted=deleted,Previous=revision==1?null:ItemReference!.Sha256},payload);
            var plaintext=VaultPayloadJson.WriteItem(item); byte[] encrypted;
            try { encrypted=ObjectCodec.Encrypt(Key.Span,new(VaultId,EpochId,ItemId,1,type),plaintext,131072); }
            finally { CryptographicOperations.ZeroMemory(plaintext); }
            files.Add(encrypted); ItemReference=Reference(ItemId,type,encrypted);
            if(deleted || !includeBlob) BlobReference=null;
        }
        var manifest=Manifest(BinaryPrimitives.ReadUInt64LittleEndian(oldHeader.AsSpan(60))+1,SHA256.HashData(oldHeader),VaultFormat.NewId(),
            ItemReference is null?[]:[ItemReference],BlobReference is null?[]:[BlobReference]);
        var manifestFile=EncryptManifest(manifest); files.Add(manifestFile); var prefix=Prefix(manifest,manifestFile);
        byte[] header;
        if(password is not null) header=KeySlots.ReplacePassword(oldHeader,prefix,Key.Span,password,65536,3,65536);
        else if(recovery is not null) header=KeySlots.ReplaceRecovery(oldHeader,prefix,Key.Span,recovery);
        else
        {
            header=VaultFormat.EncodeHeader(prefix,oldHeader.AsSpan(166,108),oldHeader.AsSpan(274,108),new byte[32]);
            Span<byte> macKey=stackalloc byte[32];
            try
            {
                HKDF.DeriveKey(HashAlgorithmName.SHA256,Key.Span,macKey,header.AsSpan(12,16),"SafeNook/v1/header-mac\0"u8.ToArray().Concat(header.AsSpan(28,16).ToArray()).ToArray());
                HMACSHA256.HashData(macKey,"SafeNook/v1/header\0"u8.ToArray().Concat(header[..382]).ToArray(),header.AsSpan(382));
            }
            finally { CryptographicOperations.ZeroMemory(macKey); }
        }
        return new(header,files);
    }
    private ManifestDto Manifest(ulong sequence,byte[] parent,Guid generation,ObjectReference[] items,ObjectReference[] blobs)=>new()
    {Schema=1,VaultId=VaultId.ToString("N"),EpochId=EpochId.ToString("N"),GenerationId=generation.ToString("N"),Sequence=sequence,ParentHeaderHash=Convert.ToHexStringLower(parent),Items=items,Blobs=blobs};
    private byte[] EncryptManifest(ManifestDto manifest)
    {
        var bytes=VaultPayloadJson.WriteManifest(manifest);
        try { return ObjectCodec.Encrypt(Key.Span,new(VaultId,EpochId,Guid.ParseExact(manifest.GenerationId,"N"),3,0),bytes,16777216); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    private byte[] Prefix(ManifestDto m,byte[] file)=>VaultFormat.EncodePrefix(VaultId,EpochId,Guid.ParseExact(m.GenerationId,"N"),m.Sequence,Convert.FromHexString(m.ParentHeaderHash),file.AsSpan(60,32),SHA256.HashData(file));
    private static ObjectReference Reference(Guid id,ushort type,byte[] file)=>new() {Id=id.ToString("N"),Type=type,WriteId=Convert.ToHexStringLower(file.AsSpan(60,32)),Length=(ulong)(file.Length-134),Sha256=Convert.ToHexStringLower(SHA256.HashData(file))};
    public void Dispose() { Key.Dispose(); Recovery.Dispose(); }
}
