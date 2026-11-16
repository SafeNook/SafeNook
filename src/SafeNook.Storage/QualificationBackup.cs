using System.Buffers.Binary;
using System.Runtime.Versioning;
using SafeNook.Core.Vault;
using SafeNook.Core.Vault.Models;

namespace SafeNook.Storage;

[SupportedOSPlatform("windows")]
internal sealed partial class QualificationStore
{
    private static ManifestDto VerifyArchive(BackupArchive archive,CredentialKind kind,ReadOnlySpan<byte> credential,VaultAdmissionPolicy policy,CancellationToken token)
    {
        using var key=OpenKey(archive.Header,kind,credential,policy,token);
        using var state=Authenticate(archive.Header,kind,credential,archive,policy,token);
        var manifest=Manifest(archive.Header,key.Span,archive,policy,token);
        var expected=manifest.Items.Select(r=>((byte)1,r.WriteId)).Concat(manifest.Blobs.Select(r=>((byte)2,r.WriteId))).Append(((byte)3,Convert.ToHexStringLower(archive.Header.AsSpan(100,32)))).ToHashSet();
        if(!expected.SetEquals(archive.Entries.Keys)) Fail("backup-inventory");
        AllBlobs(state,manifest,token);return manifest;
    }
    internal static string VerifyPortable(string input,CredentialKind kind,ReadOnlySpan<byte> credential,VaultAdmissionPolicy policy,CancellationToken token,IStoreFaults? faults=null)
    {
        using var parent=new WindowsFileSystem(Path.GetDirectoryName(input)!,false,token,archiveParent:true);
        using var metadata=policy.ReserveTransientBytes(20001L*256);
        using var stream=parent.OpenArchive(Path.GetFileName(input),false);var archive=new BackupArchive(stream,token);
        VerifyArchive(archive,kind,credential,policy,token);faults?.At(CommitStep.Authenticated);return archive.Hash(token);
    }
    internal string BackupPortable(string output,CredentialKind kind,ReadOnlySpan<byte> credential,IStoreFaults faults,CancellationToken token)
    {
        lock(_gate)
        {
            EnsureUsable();var attempted=false;
            try
            {
                using var key=OpenKey(_header,kind,credential,_policy,token);
                using var state=Authenticate(_header,kind,credential,_files,_policy,token);
                var manifest=Manifest(_header,key.Span,_files,_policy,token);AllBlobs(state,manifest,token);faults.At(CommitStep.Authenticated);
                var entries=new List<(byte Kind,string Write)> { (3,Convert.ToHexStringLower(_header.AsSpan(100,32))) };
                entries.AddRange(manifest.Items.OrderBy(r=>r.WriteId,StringComparer.Ordinal).Select(r=>((byte)1,r.WriteId)));
                entries.AddRange(manifest.Blobs.OrderBy(r=>r.WriteId,StringComparer.Ordinal).Select(r=>((byte)2,r.WriteId)));
                var lengths=entries.Select(e=>_files.Read(e.Kind,e.Write,Span<byte>.Empty,token)).ToArray();
                long total=checked(438+16L*entries.Count+lengths.Sum());if(total>BackupArchive.MaximumLength) Fail("backup-limit");
                using var parent=new WindowsFileSystem(Path.GetDirectoryName(output)!,false,token,archiveParent:true);
                using var stream=parent.OpenArchive(Guid.NewGuid().ToString("N")+".tmp",true);
                void Write(byte[] data)
                { token.ThrowIfCancellationRequested();var n=faults.WriteLength(data.Length);if(n<0 || n>data.Length) Fail("write-contract");stream.Write(data,0,n);if(n!=data.Length) Fail("short-write");faults.At(CommitStep.ObjectWritten); }
                var prefix=new byte[24];"SNBACKUP"u8.CopyTo(prefix);BinaryPrimitives.WriteUInt16LittleEndian(prefix.AsSpan(8),1);BinaryPrimitives.WriteUInt32LittleEndian(prefix.AsSpan(12),(uint)entries.Count);BinaryPrimitives.WriteUInt64LittleEndian(prefix.AsSpan(16),(ulong)total);Write(prefix);Write(_header);
                for(var i=0;i<entries.Count;i++)
                {
                    using var lease=_policy.ReserveTransientBytes(lengths[i]);var bytes=new byte[checked((int)lengths[i])];
                    if(_files.Read(entries[i].Kind,entries[i].Write,bytes,token)!=bytes.Length) Fail("changed-length");
                    var frame=new byte[16];frame[0]=entries[i].Kind;BinaryPrimitives.WriteUInt64LittleEndian(frame.AsSpan(8),(ulong)bytes.Length);Write(frame);Write(bytes);
                }
                stream.Flush();var archive=new BackupArchive(stream,token);VerifyArchive(archive,kind,credential,_policy,token);var hash=archive.Hash(token);
                if(!_files.ReadRoot(token).AsSpan().SequenceEqual(_header)) Fail("source-changed");_files.ValidateNamespace();
                faults.BeforeFlush(false);stream.Flush(true);faults.At(CommitStep.BeforePublish);token.ThrowIfCancellationRequested();attempted=true;
                parent.PublishArchive(stream,Path.GetFileName(output),faults);faults.At(CommitStep.AfterPublish);
                faults.At(CommitStep.BeforeReadback);VerifyArchive(new BackupArchive(stream,token),kind,credential,_policy,token);return hash;
            }
            catch(Exception e) when(!attempted && IsResourceFailure(e)) { throw; }
            catch { throw new StoreException(attempted?CommitOutcome.Indeterminate:CommitOutcome.RejectedBeforePublication,"backup"); }
        }
    }
    internal static string RestorePortable(string input,string destination,CredentialKind kind,ReadOnlySpan<byte> credential,VaultAdmissionPolicy policy,IStoreFaults faults,CancellationToken token)
    {
        var attempted=false;
        try
        {
            using var parent=new WindowsFileSystem(Path.GetDirectoryName(input)!,false,token,archiveParent:true);
            using var metadata=policy.ReserveTransientBytes(20001L*256);
            using var stream=parent.OpenArchive(Path.GetFileName(input),false);var archive=new BackupArchive(stream,token);
            var manifest=VerifyArchive(archive,kind,credential,policy,token);var hash=archive.Hash(token);faults.At(CommitStep.Authenticated);faults.At(CommitStep.Validated);
            using var files=new WindowsFileSystem(destination,true,token);
            foreach(var entry in archive.Entries)
            { using var lease=policy.ReserveTransientBytes(entry.Value.Length);files.InstallObject(archive.Object(entry.Key,token),faults,token); }
            using(var state=Authenticate(archive.Header,kind,credential,files,policy,token)) AllBlobs(state,manifest,token);
            faults.At(CommitStep.ManifestVerified);var staged=files.StageRoot(archive.Header,faults,token);
            using(staged.Handle)
            { files.ValidateNamespace();faults.At(CommitStep.BeforePublish);token.ThrowIfCancellationRequested();attempted=true;files.PublishRoot(staged.Handle,false,faults);faults.At(CommitStep.AfterPublish); }
            files.FlushRootNamespace(faults);files.ValidateNamespace();faults.At(CommitStep.BeforeReadback);var root=files.ReadRoot(token);
            if(!root.AsSpan().SequenceEqual(archive.Header)) Fail("root-readback");
            using(var state=Authenticate(root,kind,credential,files,policy,token)) AllBlobs(state,manifest,token);
            faults.At(CommitStep.RootReadback);return hash;
        }
        catch(Exception e) when(!attempted && IsResourceFailure(e)) { throw; }
        catch { throw new StoreException(attempted?CommitOutcome.Indeterminate:CommitOutcome.RejectedBeforePublication,"restore"); }
    }
}
