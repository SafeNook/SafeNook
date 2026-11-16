using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using SafeNook.Core.Vault;
using SafeNook.Core.Vault.Models;
using SafeNook.Storage;

namespace SafeNook.Application;

/// <summary>User operations. Public construction never grants qualification write access.</summary>
public sealed class VaultApplication
{
    private readonly IVaultInteraction _interaction;
    private readonly bool _qualification;
    private readonly IStoreFaults _faults;
    private VaultAdmissionPolicy? _policy;
    private static readonly UTF8Encoding Utf8=new(false,true);
    public VaultApplication(IVaultInteraction interaction) : this(interaction,false,null,new NoStoreFaults()) { }
    private VaultApplication(IVaultInteraction interaction,bool qualification,VaultAdmissionPolicy? policy,IStoreFaults faults)
    { _interaction=interaction; _qualification=qualification; _policy=policy; _faults=faults; }
    internal static VaultApplication ForQualification(IVaultInteraction interaction,VaultAdmissionPolicy policy,IStoreFaults? faults=null)
        =>new(interaction,true,policy,faults??new NoStoreFaults());
    private VaultAdmissionPolicy Policy=>_policy??=WindowsMemory.Policy();

    public string Backup(string path,string output,bool recovery=false,CancellationToken token=default)
        =>ArchiveOperation(path,output,0,recovery,token);
    public string VerifyBackup(string input,bool recovery=false,CancellationToken token=default)
        =>ArchiveOperation(input,null,1,recovery,token);
    public string Restore(string input,string destination,bool recovery=false,CancellationToken token=default)
        =>ArchiveOperation(input,destination,2,recovery,token);
    private string ArchiveOperation(string path,string? destination,int operation,bool recovery,CancellationToken token)
    {
        string hash="";
        Run(()=>
        {
            Guard(path,operation!=1,token);
            if(!OperatingSystem.IsWindows()) throw new VaultOperationException(VaultApplicationError.UnsupportedPlatform);
            if(destination is not null && !Path.IsPathFullyQualified(destination)) Fail(VaultApplicationError.InvalidArguments);
            if(operation==0 && (Path.GetFullPath(destination!).StartsWith(Path.TrimEndingDirectorySeparator(Path.GetFullPath(path))+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase) || string.Equals(Path.GetFullPath(destination!),Path.GetFullPath(path),StringComparison.OrdinalIgnoreCase))) Fail(VaultApplicationError.InvalidArguments);
            using var credential=recovery?RecoveryInput(SecretPrompt.Recovery,token):Input(SecretPrompt.Password,1024,token);
            var kind=recovery?CredentialKind.Recovery:CredentialKind.Password;
            if(operation==0)
            { using var store=QualificationStore.Open(path,kind,credential.Bytes,Policy,token);hash=store.BackupPortable(destination!,kind,credential.Bytes,_faults,token); }
            else if(operation==1) hash=QualificationStore.VerifyPortable(path,kind,credential.Bytes,Policy,token,_faults);
            else hash=QualificationStore.RestorePortable(path,destination!,kind,credential.Bytes,Policy,_faults,token);
            return new VaultReply([]);
        },token);
        return hash;
    }
    public VaultReply ChangePassword(string path,CancellationToken token=default)=>Credentials(path,false,false,token);
    public VaultReply Recover(string path,CancellationToken token=default)=>Credentials(path,true,false,token);
    public VaultReply RotateRecovery(string path,CancellationToken token=default)=>Credentials(path,false,true,token);
    private OwnedInput RecoveryInput(SecretPrompt prompt,CancellationToken token)
    {
        using var input=Input(prompt,256,token); var chars=Utf8.GetChars(input.Bytes);
        try { using var decoded=RecoveryCode.Decode(chars); return new OwnedInput(decoded.Span.ToArray()); }
        finally { CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(chars.AsSpan())); }
    }
    private VaultReply Credentials(string path,bool recover,bool rotate,CancellationToken token)=>Run(()=>
    {
        Guard(path,true,token);
        if(!OperatingSystem.IsWindows()) throw new VaultOperationException(VaultApplicationError.UnsupportedPlatform);
        using var credential=recover?RecoveryInput(SecretPrompt.Recovery,token):Input(SecretPrompt.Password,1024,token);
        var kind=recover?CredentialKind.Recovery:CredentialKind.Password;
        using var store=QualificationStore.Open(path,kind,credential.Bytes,Policy,token);
        var header=store.Header; var manifest=store.ReadManifest(kind,credential.Bytes,token);
        using var reservation=Policy.ReserveTransientBytes(checked((long)BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(186))*1024+4096));
        using var key=recover?KeySlots.OpenRecovery(header,credential.Bytes,token):KeySlots.OpenPassword(header,credential.Bytes,Policy.KdfMemoryKiB,token);
        using var generated=rotate?VaultCrypto.GenerateKey():null;
        using var replacement=rotate?new OwnedInput(generated!.Span.ToArray()):Input(SecretPrompt.NewPassword,1024,token);
        if(!rotate)
        {
            using var confirmation=Input(SecretPrompt.ConfirmPassword,1024,token);
            if(!CryptographicOperations.FixedTimeEquals(replacement.Bytes,confirmation.Bytes)) Fail(VaultApplicationError.Rejected);
        }
        var candidate=GenerationBuilder.Credentials(header,manifest,key.Span,replacement.Bytes,rotate,Policy,token);
        reservation.Dispose();
        byte[] Confirm()
        {
            token.ThrowIfCancellationRequested();
            _interaction.DisplayRecovery(RecoveryCode.Encode(replacement.Bytes),Convert.ToHexStringLower(header.AsSpan(12,16)));
            using var entered=RecoveryInput(SecretPrompt.ConfirmRecovery,token); return entered.Bytes.ToArray();
        }
        var outcome=store.Commit(candidate,kind,credential.Bytes,replacement.Bytes,rotate?Confirm:null,_faults,token).Outcome;
        if(outcome==CommitOutcome.Committed) return new VaultReply([]);
        if(outcome==CommitOutcome.Indeterminate) Fail(VaultApplicationError.Indeterminate);
        token.ThrowIfCancellationRequested(); Fail(outcome==CommitOutcome.RecoveryRequired?VaultApplicationError.AuthenticationOrCorruption:VaultApplicationError.Rejected); return null!;
    },token);

    public VaultReply Init(string path,CancellationToken token=default)=>Run(()=>
    {
        Guard(path,true,token);
        if(!OperatingSystem.IsWindows()) throw new VaultOperationException(VaultApplicationError.UnsupportedPlatform);
        using var password=Input(SecretPrompt.Password,1024,token);
        using(var confirmation=Input(SecretPrompt.ConfirmPassword,1024,token))
            if(!CryptographicOperations.FixedTimeEquals(password.Bytes,confirmation.Bytes)) Fail(VaultApplicationError.Rejected);
        using var key=VaultCrypto.GenerateKey(); using var recovery=VaultCrypto.GenerateKey();
        var generation=GenerationBuilder.Initial(key.Span,password.Bytes,recovery.Span,Policy,token);
        using var store=QualificationStore.Create(path,generation,password.Bytes,recovery.Span,()=>
        {
            token.ThrowIfCancellationRequested();
            _interaction.DisplayRecovery(RecoveryCode.Encode(recovery.Span),Convert.ToHexStringLower(generation.Header.AsSpan(12,16)));
            using var entered=Input(SecretPrompt.ConfirmRecovery,256,token);
            var chars=Utf8.GetChars(entered.Bytes);
            try { using var decoded=RecoveryCode.Decode(chars); return decoded.Span.ToArray(); }
            finally { CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(chars.AsSpan())); }
        },Policy,_faults,token);
        return new VaultReply([]);
    },token);

    public VaultReply List(string path,CancellationToken token=default)=>Run(()=>
    {
        Guard(path,false,token); if(!OperatingSystem.IsWindows()) throw new VaultOperationException(VaultApplicationError.UnsupportedPlatform); using var password=Input(SecretPrompt.Password,1024,token);
        using var store=QualificationStore.Open(path,CredentialKind.Password,password.Bytes,Policy,token);
        var result=new List<ItemSummary>();
        foreach(var id in store.ItemIds)
        {
            token.ThrowIfCancellationRequested(); var item=store.ReadItem(id);
            if(!item.Fields.Deleted) result.Add(Summary(item));
        }
        token.ThrowIfCancellationRequested(); return new VaultReply(result.ToArray());
    },token);

    public VaultReply Show(string path,string id,bool reveal=false,CancellationToken token=default)=>Run(()=>
    {
        Guard(path,false,token); if(!OperatingSystem.IsWindows()) throw new VaultOperationException(VaultApplicationError.UnsupportedPlatform); Id(id); using var password=Input(SecretPrompt.Password,1024,token);
        using var store=QualificationStore.Open(path,CredentialKind.Password,password.Bytes,Policy,token);
        var item=Find(store,id); token.ThrowIfCancellationRequested();
        RevealedItem? payload=null;
        if(reveal) payload=item.Payload switch
        {
            LoginPayload login=>new(login.Username,login.Password,login.Urls,login.Notes),
            NotePayload note=>new(null,null,[],note.Text),
            _=>throw new VaultOperationException(VaultApplicationError.UnsupportedItem)
        };
        return new VaultReply([Summary(item)],payload);
    },token);

    public VaultReply Add(string path,string type,CancellationToken token=default)=>Run(()=>
    {
        Guard(path,true,token);
        if(!OperatingSystem.IsWindows()) throw new VaultOperationException(VaultApplicationError.UnsupportedPlatform);
        if(type is not "login" and not "note") Fail(VaultApplicationError.InvalidArguments);
        using var password=Input(SecretPrompt.Password,1024,token);
        using var store=QualificationStore.Open(path,CredentialKind.Password,password.Bytes,Policy,token);
        var title=Text(SecretPrompt.Title,1024,token);
        ItemPayload payload;
        if(type=="login")
        {
            var username=Text(SecretPrompt.Username,4096,token); var secret=Text(SecretPrompt.LoginPassword,4096,token);
            var url=Text(SecretPrompt.Url,2048,token); var notes=Text(SecretPrompt.Notes,32768,token);
            payload=new LoginPayload {Username=username,Password=secret,Urls=url.Length==0?[]:[url],Notes=notes};
        }
        else payload=new NotePayload {Text=Text(SecretPrompt.Note,32768,token)};
        var now=checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        var item=new ItemDocument(new ItemFields {Schema=1,Id=VaultFormat.NewId().ToString("N"),Type=type=="login"?(ushort)1:(ushort)2,
            Revision=1,CreatedAt=now,UpdatedAt=now,Title=title,Tags=[],Deleted=false,Previous=null},payload);
        Change(store,password.Bytes,item,token); return new VaultReply([Summary(item)]);
    },token);

    public VaultReply Remove(string path,string id,CancellationToken token=default)=>Run(()=>
    {
        Guard(path,true,token);
        if(!OperatingSystem.IsWindows()) throw new VaultOperationException(VaultApplicationError.UnsupportedPlatform); Id(id); using var password=Input(SecretPrompt.Password,1024,token);
        using var store=QualificationStore.Open(path,CredentialKind.Password,password.Bytes,Policy,token);
        var old=Find(store,id);
        if(old.Fields.Type is not 1 and not 2) Fail(VaultApplicationError.UnsupportedItem);
        if(!_interaction.ConfirmRemoval(id,token)) Fail(VaultApplicationError.Cancelled);
        var manifest=store.ReadManifest(password.Bytes,token);
        var reference=manifest.Items.Single(r=>r.Id==id);
        var now=Math.Max(old.Fields.UpdatedAt,checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()));
        var tombstone=new ItemDocument(new ItemFields {Schema=1,Id=id,Type=old.Fields.Type,Revision=checked(old.Fields.Revision+1),
            CreatedAt=old.Fields.CreatedAt,UpdatedAt=now,Title="",Tags=[],Deleted=true,Previous=reference.Sha256},null);
        Change(store,password.Bytes,tombstone,token); return new VaultReply([]);
    },token);

    [SupportedOSPlatform("windows")]
    private void Change(QualificationStore store,ReadOnlySpan<byte> password,ItemDocument item,CancellationToken token)
    {
        var header=store.Header; var manifest=store.ReadManifest(password,token);
        using var reservation=Policy.ReserveTransientBytes(checked((long)BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(186))*1024+4096));
        using var key=KeySlots.OpenPassword(header,password,Policy.KdfMemoryKiB,token);
        var candidate=GenerationBuilder.Change(header,manifest,key.Span,item,token);
        reservation.Dispose();
        token.ThrowIfCancellationRequested();
        var outcome=store.Commit(candidate,CredentialKind.Password,password,[],null,_faults,token).Outcome;
        if(outcome==CommitOutcome.Committed) return;
        if(outcome==CommitOutcome.Indeterminate) Fail(VaultApplicationError.Indeterminate);
        token.ThrowIfCancellationRequested();
        Fail(outcome==CommitOutcome.RecoveryRequired?VaultApplicationError.AuthenticationOrCorruption:VaultApplicationError.Rejected);
    }
    private void Guard(string path,bool write,CancellationToken token)
    {
        // Gate before credentials, interaction, KDF, filesystem or candidate creation.
        if(write && !_qualification && !StorageSupport.ProductionWritesSupported) Fail(VaultApplicationError.WritesDisabled);
        token.ThrowIfCancellationRequested();
        if(!OperatingSystem.IsWindows() || RuntimeInformation.ProcessArchitecture!=Architecture.X64) Fail(VaultApplicationError.UnsupportedPlatform);
        if(string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path)) Fail(VaultApplicationError.InvalidArguments);
        if(!_interaction.IsInteractive) Fail(VaultApplicationError.InteractiveRequired);
    }
    private OwnedInput Input(SecretPrompt prompt,int max,CancellationToken token,bool empty=false)
    {
        token.ThrowIfCancellationRequested(); var bytes=_interaction.ReadSecret(prompt,max,token);
        var result=new OwnedInput(bytes);
        try { if(bytes is null || bytes.Length>max || (!empty && bytes.Length==0)) Fail(VaultApplicationError.InvalidArguments); Utf8.GetCharCount(bytes!); token.ThrowIfCancellationRequested(); return result; }
        catch { result.Dispose(); throw; }
    }
    private string Text(SecretPrompt prompt,int max,CancellationToken token)
    { using var input=Input(prompt,max,token,true); return Utf8.GetString(input.Bytes); }
    [SupportedOSPlatform("windows")]
    private static ItemDocument Find(QualificationStore store,string id)
    {
        if(!store.ItemIds.Contains(id,StringComparer.Ordinal)) Fail(VaultApplicationError.NotFound);
        var item=store.ReadItem(id); if(item.Fields.Deleted) Fail(VaultApplicationError.NotFound); return item;
    }
    private static ItemSummary Summary(ItemDocument item)=>new(item.Fields.Id,item.Fields.Type,item.Fields.Revision,item.Fields.Title,item.Fields.Tags.ToArray());
    private static void Id(string id)
    { if(id is null || id.Length!=32 || id.Any(c=>!(c is >= '0' and <= '9' or >= 'a' and <= 'f'))) Fail(VaultApplicationError.InvalidArguments); }
    private static VaultReply Run(Func<VaultReply> operation,CancellationToken token)
    {
        try { return operation(); }
        catch(VaultOperationException) { throw; }
        catch(OperationCanceledException) { throw new VaultOperationException(VaultApplicationError.Cancelled); }
        catch(StoreException e)
        {
            if(e.Outcome==CommitOutcome.Indeterminate) throw new VaultOperationException(VaultApplicationError.Indeterminate);
            if(token.IsCancellationRequested) throw new VaultOperationException(VaultApplicationError.Cancelled);
            throw new VaultOperationException(VaultApplicationError.AuthenticationOrCorruption);
        }
        catch(VaultDataException e) { throw new VaultOperationException(e.Error==VaultDataError.ResourceLimit?VaultApplicationError.ResourceLimit:VaultApplicationError.AuthenticationOrCorruption); }
        catch(CryptographicException) { throw new VaultOperationException(VaultApplicationError.AuthenticationOrCorruption); }
        catch(OutOfMemoryException) { throw new VaultOperationException(VaultApplicationError.ResourceLimit); }
        catch { throw new VaultOperationException(VaultApplicationError.Rejected); }
    }
    [System.Diagnostics.CodeAnalysis.DoesNotReturn] private static void Fail(VaultApplicationError error)=>throw new VaultOperationException(error);
    private sealed class OwnedInput(byte[] bytes):IDisposable
    { internal byte[] Bytes { get; }=bytes; public void Dispose() { if(Bytes is not null) CryptographicOperations.ZeroMemory(Bytes); } }
}
