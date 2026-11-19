using System.Buffers.Binary;
using System.Security.Cryptography;
using SafeNook.Core.Vault;
using SafeNook.Core.Vault.Models;
using SafeNook.Storage;

namespace SafeNook.Application;

public sealed partial class VaultApplication
{
    /// <summary>Imports exact opaque bytes; production writes remain gated.</summary>
    public VaultReply ImportFile(string path,string input,CancellationToken token=default)=>Import(path,input,null,5,token);
    /// <summary>Stores an unvalidated private key and optional public companion without parsing or normalization.</summary>
    public VaultReply ImportSshKey(string path,string input,string? publicInput=null,CancellationToken token=default)=>Import(path,input,publicInput,3,token);
    /// <summary>Stores an unvalidated identity and optional recipient companion.</summary>
    public VaultReply ImportAgeIdentity(string path,string input,string? recipientInput=null,CancellationToken token=default)=>Import(path,input,recipientInput,4,token);
    public VaultReply ExportFile(string path,string id,string output,CancellationToken token=default)=>Export(path,id,output,5,false,token);
    public VaultReply ExportSshKey(string path,string id,string output,bool publicKey=false,CancellationToken token=default)=>Export(path,id,output,3,publicKey,token);
    public VaultReply ExportAgeIdentity(string path,string id,string output,bool recipient=false,CancellationToken token=default)=>Export(path,id,output,4,recipient,token);
    private static void ExternalPath(string vault,string file)
    {
        if(!Path.IsPathFullyQualified(file)) Fail(VaultApplicationError.InvalidArguments);
        var root=Path.TrimEndingDirectorySeparator(Path.GetFullPath(vault));var full=Path.GetFullPath(file);
        if(full.Equals(root,StringComparison.OrdinalIgnoreCase) || full.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase)) Fail(VaultApplicationError.InvalidArguments);
    }
    private VaultReply Import(string path,string input,string? companion,ushort type,CancellationToken token)=>Run(()=>
    {
        Guard(path,true,token);if(!OperatingSystem.IsWindows()) throw new VaultOperationException(VaultApplicationError.UnsupportedPlatform);
        ExternalPath(path,input);if(companion is not null) ExternalPath(path,companion);
        using var password=Input(SecretPrompt.Password,1024,token);
        using var store=QualificationStore.Open(path,CredentialKind.Password,password.Bytes,Policy,token);
        var manifest=store.ReadManifest(password.Bytes,token);var header=store.Header;
        using var memory=Policy.ReserveTransientBytes(4L*26214400+67108864);
        using var key=KeySlots.OpenPassword(header,password.Bytes,Policy.KdfMemoryKiB,token);
        var refs=new List<ObjectReference>();var files=new List<byte[]>();
        string Blob(string source,int limit)
        {
            using var fs=new WindowsFileSystem(Path.GetDirectoryName(source)!,false,token,archiveParent:true);
            var bytes=fs.ImportBytes(Path.GetFileName(source),limit,token);
            try
            {
                var id=VaultFormat.NewId().ToString("N");
                var file=ObjectCodec.Encrypt(key.Span,new(Guid.ParseExact(manifest.VaultId,"N"),Guid.ParseExact(manifest.EpochId,"N"),Guid.ParseExact(id,"N"),2,0),bytes,52428800,token);
                files.Add(file);refs.Add(new ObjectReference {Id=id,Type=0,WriteId=Convert.ToHexStringLower(file.AsSpan(60,32)),Length=(ulong)bytes.Length,Sha256=Convert.ToHexStringLower(SHA256.HashData(file))});return id;
            }
            finally {CryptographicOperations.ZeroMemory(bytes);}
        }
        if(type!=5 && (_interaction is not IVaultFileInteraction approval || !approval.ConfirmUnvalidatedKey(type==4,token))) Fail(VaultApplicationError.Cancelled);
        var primary=Blob(input,type==5?26214400:1048576);var secondary=companion is null?null:Blob(companion,65536);
        var name=Path.GetFileName(input);var now=checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        ItemPayload payload=type switch {3=>new SshPayload {PrivateBlobId=primary,PublicBlobId=secondary,Format="opaque-ssh",OriginalName=name},4=>new AgePayload {IdentityBlobId=primary,RecipientBlobId=secondary,Format="opaque-age",OriginalName=name},_=>new FilePayload {BlobId=primary,OriginalName=name,MediaType="application/octet-stream"}};
        var item=new ItemDocument(new ItemFields {Schema=1,Id=VaultFormat.NewId().ToString("N"),Type=type,Revision=1,CreatedAt=now,UpdatedAt=now,Title=name,Tags=[],Deleted=false,Previous=null},payload);
        var candidate=GenerationBuilder.Change(header,manifest,key.Span,item,token,refs.ToArray(),files.ToArray());
        memory.Dispose();var result=store.Commit(candidate,CredentialKind.Password,password.Bytes,[],null,_faults,token).Outcome;
        if(result==CommitOutcome.Indeterminate) Fail(VaultApplicationError.Indeterminate);
        if(result!=CommitOutcome.Committed) {token.ThrowIfCancellationRequested();Fail(VaultApplicationError.Rejected);}
        return new VaultReply([Summary(item)]);
    },token);
    private VaultReply Export(string path,string id,string output,ushort type,bool companion,CancellationToken token)=>Run(()=>
    {
        Guard(path,true,token);if(!OperatingSystem.IsWindows()) throw new VaultOperationException(VaultApplicationError.UnsupportedPlatform);
        Id(id);ExternalPath(path,output);
        using var password=Input(SecretPrompt.Password,1024,token);using var store=QualificationStore.Open(path,CredentialKind.Password,password.Bytes,Policy,token);
        var item=Find(store,id);if(item.Fields.Type!=type) Fail(VaultApplicationError.UnsupportedItem);
        var blob=item.Payload switch {FilePayload f=>f.BlobId,SshPayload s=>companion?s.PublicBlobId:s.PrivateBlobId,AgePayload a=>companion?a.RecipientBlobId:a.IdentityBlobId,_=>null};
        if(blob is null) Fail(VaultApplicationError.NotFound);
        using var plaintext=store.ReadBlob(blob,token);
        using var fs=new WindowsFileSystem(Path.GetDirectoryName(output)!,false,token,archiveParent:true);
        fs.ExportBytes(Path.GetFileName(output),plaintext.Span,_faults,token);
        return new VaultReply([]);
    },token);
}
