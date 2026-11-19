using System.Security.Cryptography;
using SafeNook.Core.Vault;
using SafeNook.Core.Vault.Models;
using SafeNook.Storage;

namespace SafeNook.Application;

internal static class GenerationBuilder
{
    internal static EncryptedGeneration Initial(ReadOnlySpan<byte> key, ReadOnlySpan<byte> password, ReadOnlySpan<byte> recovery, VaultAdmissionPolicy policy, CancellationToken token)
    {
        var manifest=new ManifestDto { Schema=1,VaultId=VaultFormat.NewId().ToString("N"),EpochId=VaultFormat.NewId().ToString("N"),
            GenerationId=VaultFormat.NewId().ToString("N"),Sequence=1,ParentHeaderHash=new string('0',64),Items=[],Blobs=[] };
        var encrypted=EncryptManifest(manifest,key,token);
        byte[] header;
        using(policy.ReserveTransientBytes(67108864+4096))
            header=KeySlots.CreateHeader(Prefix(manifest,encrypted),key,password,recovery,65536,3,policy.KdfMemoryKiB,token);
        return new(header,[encrypted]);
    }
    internal static EncryptedGeneration Change(byte[] oldHeader, ManifestDto old, ReadOnlySpan<byte> key, ItemDocument item, CancellationToken token, ObjectReference[]? addedBlobs=null, byte[][]? blobFiles=null)
    {
        var plaintext=VaultPayloadJson.WriteItem(item); byte[] encrypted;
        try { encrypted=ObjectCodec.Encrypt(key,new(Guid.ParseExact(old.VaultId,"N"),Guid.ParseExact(old.EpochId,"N"),Guid.ParseExact(item.Fields.Id,"N"),1,item.Fields.Type),plaintext,131072,token); }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
        var reference=new ObjectReference { Id=item.Fields.Id,Type=item.Fields.Type,WriteId=Convert.ToHexStringLower(encrypted.AsSpan(60,32)),
            Length=(ulong)(encrypted.Length-134),Sha256=Convert.ToHexStringLower(SHA256.HashData(encrypted)) };
        var manifest=new ManifestDto { Schema=1,VaultId=old.VaultId,EpochId=old.EpochId,GenerationId=VaultFormat.NewId().ToString("N"),
            Sequence=checked(old.Sequence+1),ParentHeaderHash=Convert.ToHexStringLower(SHA256.HashData(oldHeader)),
            Items=old.Items.Where(r=>r.Id!=reference.Id).Append(reference).OrderBy(r=>r.Id,StringComparer.Ordinal).ToArray(),Blobs=old.Blobs.Concat(addedBlobs??[]).OrderBy(r=>r.Id,StringComparer.Ordinal).ToArray() };
        var manifestFile=EncryptManifest(manifest,key,token);
        return new(KeySlots.AdvanceHeader(oldHeader,Prefix(manifest,manifestFile),key),[encrypted,manifestFile,..blobFiles??[]]);
    }
    internal static EncryptedGeneration Credentials(byte[] header,ManifestDto old,ReadOnlySpan<byte> key,ReadOnlySpan<byte> replacement,bool recovery,VaultAdmissionPolicy policy,CancellationToken token)
    {
        var manifest=new ManifestDto {Schema=1,VaultId=old.VaultId,EpochId=old.EpochId,GenerationId=VaultFormat.NewId().ToString("N"),Sequence=checked(old.Sequence+1),ParentHeaderHash=Convert.ToHexStringLower(SHA256.HashData(header)),Items=old.Items,Blobs=old.Blobs};
        var file=EncryptManifest(manifest,key,token); var prefix=Prefix(manifest,file);
        var next=recovery?KeySlots.ReplaceRecovery(header,prefix,key,replacement,token):KeySlots.ReplacePassword(header,prefix,key,replacement,System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(186)),System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(190)),policy.KdfMemoryKiB,token);
        return new(next,[file]);
    }
    private static byte[] EncryptManifest(ManifestDto manifest,ReadOnlySpan<byte> key,CancellationToken token)
    {
        var json=VaultPayloadJson.WriteManifest(manifest);
        try { return ObjectCodec.Encrypt(key,new(Guid.ParseExact(manifest.VaultId,"N"),Guid.ParseExact(manifest.EpochId,"N"),Guid.ParseExact(manifest.GenerationId,"N"),3,0),json,16777216,token); }
        finally { CryptographicOperations.ZeroMemory(json); }
    }
    private static byte[] Prefix(ManifestDto m,byte[] file)=>VaultFormat.EncodePrefix(Guid.ParseExact(m.VaultId,"N"),Guid.ParseExact(m.EpochId,"N"),
        Guid.ParseExact(m.GenerationId,"N"),m.Sequence,Convert.FromHexString(m.ParentHeaderHash),file.AsSpan(60,32),SHA256.HashData(file));
}
