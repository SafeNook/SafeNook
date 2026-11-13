using System.Buffers.Binary;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using SafeNook.Core.Vault;
using SafeNook.Core.Vault.Models;

namespace SafeNook.Storage;

internal enum CredentialKind { Password, Recovery }
internal readonly record struct QualificationCommit(CommitOutcome Outcome, bool DirectoryFlushSucceeded, bool PowerLossQualified = false);

/// <summary>Internal process-crash qualification API, not a production writable API. Holds the OS lock for its lifetime.</summary>
[SupportedOSPlatform("windows")]
internal sealed class QualificationStore : IDisposable
{
    private readonly object _gate = new();
    private readonly WindowsFileSystem _files;
    private readonly VaultAdmissionPolicy _policy;
    private AuthenticatedVaultState? _state;
    private byte[] _header;
    private bool _faulted;
    private QualificationStore(WindowsFileSystem files, VaultAdmissionPolicy policy, byte[] header, AuthenticatedVaultState state)
    { _files=files; _policy=policy; _header=header; _state=state; }
    internal byte[] Header { get { lock(_gate) return _header.ToArray(); } }
    internal string[] ItemIds { get { lock(_gate) { EnsureUsable(); return _state!.ItemIds; } } }
    internal ItemDocument ReadItem(string id) { lock(_gate) { EnsureUsable(); return _state!.ReadItem(id); } }
    internal AdmittedPlaintext ReadBlob(string id,CancellationToken token) { lock(_gate) { EnsureUsable(); return _state!.ReadBlob(id,token); } }

    internal static QualificationStore Open(string path,CredentialKind kind,ReadOnlySpan<byte> credential,VaultAdmissionPolicy policy,CancellationToken token)
    {
        WindowsFileSystem? files=null; AuthenticatedVaultState? state=null;
        try
        {
            files=new WindowsFileSystem(path,false,token); var header=files.ReadRoot(token);
            state=Authenticate(header,kind,credential,files,policy,token);
            using var key=OpenKey(header,kind,credential,policy,token); var manifest=Manifest(header,key.Span,files,policy,token);
            AllBlobs(state,manifest,token);
            var result=new QualificationStore(files,policy,header,state); files=null; state=null; return result;
        }
        catch(OperationCanceledException) { throw; }
        catch(StoreException e) { throw new StoreException(CommitOutcome.RecoveryRequired,"open-selected-root/"+e.Code); }
        catch(VaultDataException e) { throw new StoreException(CommitOutcome.RecoveryRequired,"open-selected-root/"+e.Error); }
        catch { throw new StoreException(CommitOutcome.RecoveryRequired,"open-selected-root"); }
        finally { state?.Dispose(); files?.Dispose(); }
    }

    internal static QualificationStore Create(string path,EncryptedGeneration input,ReadOnlySpan<byte> password,ReadOnlySpan<byte> recovery,
        Func<byte[]> confirmRecovery,VaultAdmissionPolicy policy,IStoreFaults faults,CancellationToken token)
    {
        WindowsFileSystem? files=null; AuthenticatedVaultState? state=null; var attempted=false;
        try
        {
            ArgumentNullException.ThrowIfNull(confirmRecovery);
            using var snapshot=new Snapshot(input,policy);
            VaultFormat.ValidateHeader(snapshot.Header);
            if(BinaryPrimitives.ReadUInt64LittleEndian(snapshot.Header.AsSpan(60))!=1) Fail("initial-sequence");
            using var passwordKey=OpenKey(snapshot.Header,CredentialKind.Password,password,policy,token);
            using var recoveryKey=OpenKey(snapshot.Header,CredentialKind.Recovery,recovery,policy,token);
            if(!CryptographicOperations.FixedTimeEquals(passwordKey.Span,recoveryKey.Span)) Fail("slot-key-mismatch");
            Confirm(confirmRecovery,recovery);
            files=new WindowsFileSystem(path,true,token);
            var overlay=new OverlaySource(snapshot,files);
            state=Authenticate(snapshot.Header,CredentialKind.Password,password,overlay,policy,token);
            var manifest=Manifest(snapshot.Header,passwordKey.Span,overlay,policy,token);
            if(manifest.Items.Length!=0 || manifest.Blobs.Length!=0) Fail("initial-inventory-must-be-empty");
            CheckSupplied(snapshot,manifest); faults.At(CommitStep.Validated);
            Install(snapshot,files,faults,token);
            state.Dispose(); state=Authenticate(snapshot.Header,CredentialKind.Password,password,files,policy,token);
            faults.At(CommitStep.ManifestVerified);
            var staged=files.StageRoot(snapshot.Header,faults,token);
            using(staged.Handle)
            {
                token.ThrowIfCancellationRequested(); faults.At(CommitStep.BeforePublish); attempted=true;
                files.PublishRoot(staged.Handle,false); faults.At(CommitStep.AfterPublish);
            }
            files.FlushRootNamespace(faults); var readback=files.ReadRoot(token);
            if(!readback.AsSpan().SequenceEqual(snapshot.Header)) Fail("root-readback");
            state.Dispose(); state=Authenticate(readback,CredentialKind.Password,password,files,policy,token);
            faults.At(CommitStep.RootReadback);
            var result=new QualificationStore(files,policy,readback,state); files=null; state=null; return result;
        }
        catch(Exception) { throw new StoreException(attempted?CommitOutcome.Indeterminate:CommitOutcome.RejectedBeforePublication,"create"); }
        finally { state?.Dispose(); files?.Dispose(); }
    }

    internal QualificationCommit Commit(EncryptedGeneration input,CredentialKind authentication,ReadOnlySpan<byte> credential,
        ReadOnlySpan<byte> replacementCredential,Func<byte[]>? recoveryConfirmation,IStoreFaults faults,CancellationToken token)
    {
        lock(_gate) return CommitCore(input,authentication,credential,replacementCredential,recoveryConfirmation,faults,token);
    }

    private QualificationCommit CommitCore(EncryptedGeneration input,CredentialKind authentication,ReadOnlySpan<byte> credential,
        ReadOnlySpan<byte> replacementCredential,Func<byte[]>? recoveryConfirmation,IStoreFaults faults,CancellationToken token)
    {
        EnsureUsable(); var attempted=false; var checkingCurrent=true; AuthenticatedVaultState? candidate=null;
        try
        {
            var current=_files.ReadRoot(token);
            if(!current.AsSpan().SequenceEqual(_header)) { Invalidate(); return new(CommitOutcome.RecoveryRequired,_files.DirectoryFlushAvailable); }
            checkingCurrent=false; // A wrong supplied credential alone does not establish storage corruption.
            using var oldKey=OpenKey(current,authentication,credential,_policy,token);
            checkingCurrent=true;
            using var currentCheck=Authenticate(current,authentication,credential,_files,_policy,token);
            var oldManifest=Manifest(current,oldKey.Span,_files,_policy,token); AllBlobs(currentCheck,oldManifest,token);
            checkingCurrent=false;
            using var snapshot=new Snapshot(input,_policy); VaultFormat.ValidateHeader(snapshot.Header);
            var next=snapshot.Header;
            var oldSequence=BinaryPrimitives.ReadUInt64LittleEndian(current.AsSpan(60));
            if(oldSequence==ulong.MaxValue || BinaryPrimitives.ReadUInt64LittleEndian(next.AsSpan(60))!=oldSequence+1 ||
                !next.AsSpan(12,32).SequenceEqual(current.AsSpan(12,32)) || next.AsSpan(44,16).SequenceEqual(current.AsSpan(44,16)) ||
                !next.AsSpan(68,32).SequenceEqual(SHA256.HashData(current))) Fail("generation-lineage");
            var passwordChanged=!next.AsSpan(166,108).SequenceEqual(current.AsSpan(166,108));
            var recoveryChanged=!next.AsSpan(274,108).SequenceEqual(current.AsSpan(274,108));
            if(passwordChanged && recoveryChanged) Fail("full-rekey-out-of-scope");
            var nextKind=passwordChanged?CredentialKind.Password:recoveryChanged?CredentialKind.Recovery:authentication;
            var nextCredential=passwordChanged||recoveryChanged?replacementCredential:credential;
            if(recoveryChanged)
            {
                // A known password is established by explicit fresh password authentication in this API.
                if(authentication!=CredentialKind.Password || recoveryConfirmation is null) Fail("password-reauthentication-required");
                Confirm(recoveryConfirmation!,replacementCredential);
            }
            using var nextKey=OpenKey(next,nextKind,nextCredential,_policy,token);
            if(!CryptographicOperations.FixedTimeEquals(oldKey.Span,nextKey.Span)) Fail("epoch-key-change");
            var overlay=new OverlaySource(snapshot,_files);
            candidate=Authenticate(next,nextKind,nextCredential,overlay,_policy,token);
            var manifest=Manifest(next,nextKey.Span,overlay,_policy,token);
            CheckSupplied(snapshot,manifest); CheckRevisions(currentCheck,candidate,oldManifest,manifest); AllBlobs(candidate,manifest,token);
            faults.At(CommitStep.Validated); Install(snapshot,_files,faults,token);
            candidate.Dispose(); candidate=Authenticate(next,nextKind,nextCredential,_files,_policy,token); AllBlobs(candidate,manifest,token);
            faults.At(CommitStep.ManifestVerified); _files.SaveBackup(current,faults,token);
            var staged=_files.StageRoot(next,faults,token);
            using(staged.Handle)
            {
                if(!_files.ReadRoot(token).AsSpan().SequenceEqual(current)) Fail("root-changed-before-publish");
                token.ThrowIfCancellationRequested(); faults.At(CommitStep.BeforePublish); attempted=true;
                _files.PublishRoot(staged.Handle,true); faults.At(CommitStep.AfterPublish);
            }
            _files.FlushRootNamespace(faults); var readback=_files.ReadRoot(token);
            if(!readback.AsSpan().SequenceEqual(next)) Fail("root-readback");
            KeySlots.VerifyHeader(readback,nextKey.Span);
            candidate.Dispose(); candidate=null;
            candidate=Authenticate(readback,nextKind,nextCredential,_files,_policy,token); AllBlobs(candidate,manifest,token);
            faults.At(CommitStep.RootReadback);
            _state!.Dispose(); _state=candidate; candidate=null; _header=readback;
            return new(CommitOutcome.Committed,_files.DirectoryFlushAvailable);
        }
        catch(Exception e)
        {
            var corruptCurrent=checkingCurrent && e is not OperationCanceledException and not OutOfMemoryException &&
                !(e is VaultDataException data && data.Error==VaultDataError.ResourceLimit);
            var outcome=attempted?CommitOutcome.Indeterminate:corruptCurrent?CommitOutcome.RecoveryRequired:CommitOutcome.RejectedBeforePublication;
            if(attempted || corruptCurrent) Invalidate();
            return new(outcome,_files.DirectoryFlushAvailable);
        }
        finally { candidate?.Dispose(); }
    }

    // Explicit, read-only selection; usable even when the live root cannot authenticate. No restore or fallback.
    internal static ulong InspectRecoveryCandidate(string path,string generationId,CredentialKind kind,ReadOnlySpan<byte> credential,VaultAdmissionPolicy policy,CancellationToken token)
    {
        WindowsFileSystem.Hex(generationId,32);
        try
        {
            using var files=new WindowsFileSystem(path,false,token); var header=files.ReadBackup(generationId+".json",token);
            using var state=Authenticate(header,kind,credential,files,policy,token);
            using var key=OpenKey(header,kind,credential,policy,token); AllBlobs(state,Manifest(header,key.Span,files,policy,token),token);
            return state.Sequence;
        }
        catch { throw new StoreException(CommitOutcome.RecoveryRequired,"selected-backup-verification"); }
    }

    internal void VerifyBackup(string generationId,CredentialKind kind,ReadOnlySpan<byte> credential,CancellationToken token)
    {
        lock(_gate) VerifyBackupCore(generationId,kind,credential,token);
    }
    private void VerifyBackupCore(string generationId,CredentialKind kind,ReadOnlySpan<byte> credential,CancellationToken token)
    {
        EnsureUsable(); WindowsFileSystem.Hex(generationId,32);
        try
        {
            var header=_files.ReadBackup(generationId+".json",token);
            using var state=Authenticate(header,kind,credential,_files,_policy,token);
            using var key=OpenKey(header,kind,credential,_policy,token); AllBlobs(state,Manifest(header,key.Span,_files,_policy,token),token);
        }
        catch { throw new StoreException(CommitOutcome.RecoveryRequired,"backup-verification"); }
    }
    internal string GarbageCollectionStatus => "Refused: durability and retained-root reachability are not qualified; no files deleted.";
    private static void Confirm(Func<byte[]> confirmation,ReadOnlySpan<byte> expected)
    {
        byte[]? entered=null;
        try { entered=confirmation(); if(entered is null || !CryptographicOperations.FixedTimeEquals(entered,expected)) Fail("recovery-not-confirmed"); }
        finally { if(entered is not null) CryptographicOperations.ZeroMemory(entered); }
    }
    private static void CheckRevisions(AuthenticatedVaultState oldState,AuthenticatedVaultState nextState,ManifestDto oldManifest,ManifestDto next)
    {
        var nextReferences=next.Items.ToDictionary(r=>r.Id,StringComparer.Ordinal);
        var oldReferences=oldManifest.Items.ToDictionary(r=>r.Id,StringComparer.Ordinal);
        foreach(var old in oldManifest.Items)
        {
            if(!nextReferences.TryGetValue(old.Id,out var changed)) Fail("missing-tombstone");
            if(old.WriteId==changed!.WriteId)
            { if(old.Sha256!=changed.Sha256 || old.Type!=changed.Type || old.Length!=changed.Length) Fail("immutable-reference-change"); }
            else VaultPayloadJson.ValidateRevision(oldState.ReadItem(old.Id),nextState.ReadItem(old.Id),old.Sha256);
        }
        foreach(var fresh in next.Items.Where(r=>!oldReferences.ContainsKey(r.Id)))
            if(nextState.ReadItem(fresh.Id).Fields.Revision!=1) Fail("new-item-revision");
    }
    private static void CheckSupplied(Snapshot snapshot,ManifestDto manifest)
    {
        var expected=new HashSet<(byte,string)>(manifest.Items.Select(r=>((byte)1,r.WriteId)).Concat(manifest.Blobs.Select(r=>((byte)2,r.WriteId))));
        var manifestWrite=Convert.ToHexStringLower(snapshot.Header.AsSpan(100,32)); expected.Add((3,manifestWrite));
        if(!snapshot.Files.ContainsKey((3,manifestWrite)) || snapshot.Files.Keys.Any(k=>!expected.Contains(k))) Fail("unreachable-supplied-object");
    }
    private static void Install(Snapshot snapshot,WindowsFileSystem files,IStoreFaults faults,CancellationToken token)
    { foreach(var entry in snapshot.Files.OrderBy(e=>e.Key.Kind==3?1:0)) files.InstallObject(entry.Value,faults,token); }
    private static AuthenticatedVaultState Authenticate(byte[] header,CredentialKind kind,ReadOnlySpan<byte> credential,IVaultObjectSource source,VaultAdmissionPolicy policy,CancellationToken token)
        => kind==CredentialKind.Password?AuthenticatedVaultState.OpenPassword(header,credential,source,policy,token):AuthenticatedVaultState.OpenRecovery(header,credential,source,policy,token);
    private static SecretBuffer OpenKey(byte[] header,CredentialKind kind,ReadOnlySpan<byte> credential,VaultAdmissionPolicy policy,CancellationToken token)
    {
        VaultFormat.ValidateHeader(header);
        using var lease=policy.ReserveTransientBytes(kind==CredentialKind.Password ? checked((long)BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(186))*1024+4096) : 4096);
        return kind==CredentialKind.Password?KeySlots.OpenPassword(header,credential,policy.KdfMemoryKiB,token):KeySlots.OpenRecovery(header,credential,token);
    }
    private static ManifestDto Manifest(byte[] header,ReadOnlySpan<byte> key,IVaultObjectSource source,VaultAdmissionPolicy policy,CancellationToken token)
    {
        var write=Convert.ToHexStringLower(header.AsSpan(100,32)); Span<byte> envelope=stackalloc byte[118];
        var length=source.Read(3,write,envelope,token); VaultFormat.ValidateEnvelope(envelope,length);
        using var lease=policy.ReserveTransientBytes(checked(length*16)); var file=new byte[checked((int)length)];
        if(source.Read(3,write,file,token)!=length) Fail("manifest-length");
        var context=new ObjectContext(VaultFormat.ReadId(header.AsSpan(12,16)),VaultFormat.ReadId(header.AsSpan(28,16)),VaultFormat.ReadId(header.AsSpan(44,16)),3,0);
        using var plaintext=ObjectCodec.Decrypt(key,context,header.AsSpan(100,32),header.AsSpan(132,32),file,checked((int)length*2),token);
        var result=VaultPayloadJson.ReadManifest(plaintext.Span); ManifestValidation.ValidateHeaderBinding(result,header); return result;
    }
    private static void AllBlobs(AuthenticatedVaultState state,ManifestDto manifest,CancellationToken token)
    { foreach(var blob in manifest.Blobs) { using var plaintext=state.ReadBlob(blob.Id,token); } }
    private void Invalidate() { _faulted=true; _state?.Dispose(); _state=null; }
    private void EnsureUsable() { if(_faulted || _state is null) throw new StoreException(CommitOutcome.RecoveryRequired,"reopen-required"); }
    private static void Fail(string code)=>throw new StoreException(CommitOutcome.RejectedBeforePublication,code);
    public void Dispose() { lock(_gate) { _state?.Dispose(); _state=null; _files.Dispose(); } }

    private sealed class Snapshot : IDisposable
    {
        internal byte[] Header { get; }
        internal Dictionary<(byte Kind,string Write),byte[]> Files { get; }=[];
        private readonly IDisposable _reservation;
        internal Snapshot(EncryptedGeneration source,VaultAdmissionPolicy policy)
        {
            VaultFormat.ValidateHeader(source.Header);
            if(source.Objects.Count>20001) Fail("object-count"); long total=4096;
            foreach(var file in source.Objects)
            { VaultFormat.ValidateEnvelope(file.AsSpan(0,Math.Min(file.Length,118)),file.Length); total=checked(total+file.Length*2L+1024); }
            _reservation=policy.ReserveTransientBytes(total);
            try
            {
                Header=source.Header.ToArray();
                foreach(var file in source.Objects)
                { var copy=file.ToArray(); if(!Files.TryAdd((copy[10],Convert.ToHexStringLower(copy.AsSpan(60,32))),copy)) Fail("duplicate-object"); }
            }
            catch { _reservation.Dispose(); throw; }
        }
        public void Dispose() { Files.Clear(); _reservation.Dispose(); }
    }
    private sealed class OverlaySource(Snapshot snapshot,WindowsFileSystem files):IVaultObjectSource
    {
        public long Read(byte kind,string writeId,Span<byte> destination,CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if(!snapshot.Files.TryGetValue((kind,writeId),out var bytes)) return files.Read(kind,writeId,destination,token);
            bytes.AsSpan(0,Math.Min(bytes.Length,destination.Length)).CopyTo(destination); return bytes.Length;
        }
    }
}
