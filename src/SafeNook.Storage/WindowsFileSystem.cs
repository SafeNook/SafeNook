using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using SafeNook.Core.Vault;

namespace SafeNook.Storage;

/// <summary>Qualification-only Windows/NTFS adapter. All child opens/renames are relative to pinned directory handles.</summary>
[SupportedOSPlatform("windows")]
internal sealed unsafe class WindowsFileSystem : IVaultObjectSource, IDisposable
{
    private readonly List<SafeFileHandle> _pinned = [];
    private readonly Dictionary<string, SafeFileHandle> _directories = new(StringComparer.Ordinal);
    private readonly string _owner = CurrentOwner();
    private nint _descriptor;
    private SafeFileHandle? _lock;
    private readonly string _path;
    internal bool DirectoryFlushAvailable { get; private set; } = true;

    private static string CurrentOwner() { using var identity=WindowsIdentity.GetCurrent(); return identity.User!.Value; }

    internal WindowsFileSystem(string path, bool create, CancellationToken token)
    {
        if (RuntimeInformation.ProcessArchitecture != Architecture.X64) throw new PlatformNotSupportedException("Only Windows x64 has a qualification adapter.");
        if (path.Length < 4 || !char.IsAsciiLetter(path[0]) || path[1] != ':' || path[2] != '\\' || path.Contains('/')) Fail("invalid-root-path");
        _path = path.TrimEnd('\\');
        var names = _path[3..].Split('\\'); foreach (var name in names) Component(name);
        try
        {
            if (!WindowsNative.ConvertDescriptor("O:"+_owner+"D:P(A;;FA;;;"+_owner+")", 1, out _descriptor, out _)) Fail("security-descriptor");
            if(WindowsNative.GetDriveType(path[..3])!=3) Fail("unqualified-drive-type");
            var drive = WindowsNative.CreateFile("\\\\?\\"+path[..3], 0x80020000, 3, 0, 3, 0x02200000, 0);
            if (drive.IsInvalid) { drive.Dispose(); Fail("open-volume-root"); }
            _pinned.Add(drive); Validate(drive, true, false);
            char* fs = stackalloc char[32];
            if (!WindowsNative.VolumeInfo(drive, null, 0, out _, out _, out _, fs, 32) || new string(fs) != "NTFS") Fail("unqualified-filesystem");
            var parent = drive;
            for (var i = 0; i < names.Length; i++)
            {
                var last = i == names.Length - 1;
                var next = OpenRelative(parent, names[i], true, last && create ? 2u : 1u, last, false, 3, last);
                _pinned.Add(next); parent = next;
            }
            _directories.Add("", parent);
            foreach (var name in new[] { "items", "blobs", "manifests", ".backup", ".tmp" })
            {
                var directory = OpenRelative(parent, name, true, create ? 2u : 1u, true, share: 3);
                _pinned.Add(directory); _directories.Add(name, directory);
            }
            _lock = OpenRelative(parent, ".lock", false, create ? 2u : 1u, true, false, 3);
            var overlapped = new WindowsNative.Overlapped();
            while (!WindowsNative.LockFileEx(_lock, 3, 0, uint.MaxValue, uint.MaxValue, ref overlapped))
            {
                if (Marshal.GetLastPInvokeError() != 33) Fail("lock-unavailable");
                token.ThrowIfCancellationRequested();
                if (token.WaitHandle.WaitOne(20)) token.ThrowIfCancellationRequested();
            }
            token.ThrowIfCancellationRequested();
        }
        catch { Dispose(); throw; }
    }

    private SafeFileHandle OpenRelative(SafeFileHandle parent, string name, bool directory, uint disposition,
        bool writable = false, bool rename = false, uint share = 1, bool securityCheck = true)
    {
        Component(name);
        fixed (char* chars = name)
        {
            var unicode = new WindowsNative.UnicodeString { Length = checked((ushort)(name.Length * 2)), MaximumLength = checked((ushort)(name.Length * 2)), Buffer = chars };
            var attributes = new WindowsNative.ObjectAttributes { Length = (uint)sizeof(WindowsNative.ObjectAttributes), RootDirectory = parent.DangerousGetHandle(),
                ObjectName = &unicode, Attributes = 0x1040, SecurityDescriptor = disposition == 1 ? 0 : _descriptor };
            var access = 0x80120000u | (writable ? 0x40000000u : 0) | (rename ? 0x10000u : 0);
            var status = WindowsNative.NtCreateFile(out var raw, access, ref attributes, out _, 0, 0x80, share, disposition,
                0x00200020u | (directory ? 1u : 0x40u), 0, 0);
            if (status < 0)
                throw new StoreException(CommitOutcome.RejectedBeforePublication, "native-open-"+WindowsNative.RtlNtStatusToDosError(status));
            var handle = new SafeFileHandle(raw, true);
            try { Validate(handle, directory, securityCheck); return handle; }
            catch { handle.Dispose(); throw; }
        }
    }

    private void Validate(SafeFileHandle handle, bool directory, bool checkSecurity = true)
    {
        if (WindowsNative.GetFileType(handle) != 1) Fail("file-type");
        if (!WindowsNative.GetFileInformationByHandle(handle, out var info)) Fail("file-info");
        if ((info.Attributes & 0x400) != 0 || ((info.Attributes & 0x10) != 0) != directory || (!directory && info.Links != 1)) Fail("link-or-file-type");
        if (!checkSecurity) return;
        if (WindowsNative.GetSecurityInfo(handle, 1, 5, out _, out _, out _, out _, out var descriptor) != 0) Fail("read-security");
        try
        {
            var size=WindowsNative.GetSecurityDescriptorLength(descriptor); if(size is 0 or >65536) Fail("security-size");
            var data = new byte[size]; Marshal.Copy(descriptor, data, 0, data.Length);
            var security = new RawSecurityDescriptor(data, 0);
            if (security.Owner?.Value != _owner || (security.ControlFlags & ControlFlags.DiscretionaryAclProtected) == 0 || security.DiscretionaryAcl is not { Count: 1 }) Fail("unsafe-acl");
            if (security.DiscretionaryAcl![0] is not CommonAce ace || ace.AceQualifier != AceQualifier.AccessAllowed || ace.SecurityIdentifier.Value != _owner || ace.AccessMask != 0x1f01ff || ace.AceFlags != AceFlags.None) Fail("unsafe-acl");
        }
        finally { WindowsNative.LocalFree(descriptor); }
    }

    public long Read(byte kind, string writeId, Span<byte> destination, CancellationToken cancellationToken)
    {
        Hex(writeId, 64); var (directory, extension) = Location(kind);
        return ReadNamed(directory, writeId+extension, destination, cancellationToken);
    }
    internal byte[] ReadRoot(CancellationToken token)
    {
        var data = new byte[1024]; var length = ReadNamed("", "vault.json", data, token);
        if (length < 0 || length > data.Length) Fail("root-length");
        return VaultFormat.DecodeWrapper(data.AsSpan(0, (int)length));
    }
    internal byte[] ReadBackup(string name, CancellationToken token)
    {
        if (!name.EndsWith(".json", StringComparison.Ordinal)) Fail("backup-name"); Hex(name[..^5], 32);
        var data = new byte[1024]; var length = ReadNamed(".backup", name, data, token);
        if (length < 0 || length > data.Length) Fail("backup-length");
        var header=VaultFormat.DecodeWrapper(data.AsSpan(0, (int)length));
        if(Convert.ToHexStringLower(header.AsSpan(44,16))!=name[..^5]) Fail("backup-identity");
        return header;
    }
    internal string[] BackupNames() => Directory.EnumerateFiles(Path.Combine(_path, ".backup")).Select(Path.GetFileName).Select(s => s!).ToArray();
    private SafeFileHandle OpenRead(string directory,string name,CancellationToken token)
    {
        // Windows may release a killed process's lock before completing all file-handle cleanup.
        // Retry only a bounded, read-only open while holding our OS lock. Never retry publication.
        for(var attempt=0;;attempt++)
        {
            token.ThrowIfCancellationRequested();
            try { return OpenRelative(_directories[directory],name,false,1); }
            catch(StoreException e) when(e.Code=="native-open-32" && attempt<50)
            { if(token.WaitHandle.WaitOne(10)) token.ThrowIfCancellationRequested(); }
        }
    }

    private long ReadNamed(string directory, string name, Span<byte> destination, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        using var handle = OpenRead(directory,name,token);
        var length = RandomAccess.GetLength(handle);
        if (!WindowsNative.GetFileInformationByHandle(handle, out var before)) Fail("read-identity");
        var wanted = (int)Math.Min(length, destination.Length); var offset = 0;
        while (offset < wanted)
        {
            token.ThrowIfCancellationRequested(); var read = RandomAccess.Read(handle, destination.Slice(offset, wanted-offset), offset);
            if (read == 0) Fail("short-read"); offset += read;
        }
        Span<byte> extra = stackalloc byte[1];
        if (RandomAccess.Read(handle, extra, length) != 0 || RandomAccess.GetLength(handle) != length) Fail("changed-length");
        Validate(handle, false); if (!WindowsNative.GetFileInformationByHandle(handle, out var after)) Fail("read-identity");
        if (before.Volume != after.Volume || before.IndexLow != after.IndexLow || before.IndexHigh != after.IndexHigh) Fail("changed-identity");
        return length;
    }

    internal void InstallObject(byte[] file, IStoreFaults faults, CancellationToken token)
    {
        VaultFormat.ValidateEnvelope(file.AsSpan(0, Math.Min(118,file.Length)), file.Length);
        var (directory, extension) = Location(file[10]); var name = Convert.ToHexStringLower(file.AsSpan(60,32))+extension;
        // Existing immutable identities are always collisions; caller omits reused objects.
        var temp = Stage(file, faults, false, token);
        using (temp.Handle) Rename(temp.Handle, _directories[directory], name, false);
        FlushDirectory(".tmp",faults); FlushDirectory(directory,faults); faults.At(CommitStep.ObjectInstalled);
    }
    internal void SaveBackup(byte[] header, IStoreFaults faults, CancellationToken token)
    {
        var name = Convert.ToHexStringLower(header.AsSpan(44,16))+".json";
        if (BackupNames().Contains(name, StringComparer.Ordinal))
        {
            if (!ReadBackup(name,token).AsSpan().SequenceEqual(header)) Fail("backup-collision");
            return;
        }
        var temp = Stage(VaultFormat.EncodeWrapper(header), faults, false, token);
        using (temp.Handle) Rename(temp.Handle, _directories[".backup"], name, false);
        FlushDirectory(".backup",faults); faults.At(CommitStep.BackupWritten);
    }
    internal (SafeFileHandle Handle, string Name) StageRoot(byte[] header, IStoreFaults faults, CancellationToken token)
        => Stage(VaultFormat.EncodeWrapper(header), faults, true, token);
    private (SafeFileHandle Handle, string Name) Stage(byte[] bytes, IStoreFaults faults, bool root, CancellationToken token)
    {
        token.ThrowIfCancellationRequested(); var name = Convert.ToHexStringLower(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16))+".tmp";
        var handle = OpenRelative(_directories[".tmp"], name, false, 2, true, true);
        try
        {
            var count = faults.WriteLength(bytes.Length);
            if (count < 0 || count > bytes.Length) Fail("write-contract");
            RandomAccess.Write(handle, bytes.AsSpan(0,count), 0);
            faults.At(root ? CommitStep.RootWritten : CommitStep.ObjectWritten);
            if (count != bytes.Length || RandomAccess.GetLength(handle) != bytes.Length) Fail("short-write");
            faults.BeforeFlush(false);
            if (!WindowsNative.FlushFileBuffers(handle)) Fail("file-flush");
            faults.At(root ? CommitStep.RootFlushed : CommitStep.ObjectFlushed);
            var readback = new byte[bytes.Length]; var offset=0;
            while(offset<readback.Length) { var n=RandomAccess.Read(handle,readback.AsSpan(offset),offset); if(n==0) Fail("short-readback"); offset+=n; }
            if (!readback.AsSpan().SequenceEqual(bytes)) Fail("write-readback");
            Validate(handle,false); token.ThrowIfCancellationRequested(); return(handle,name);
        }
        catch { handle.Dispose(); throw; } // Keep encrypted staging evidence; no destructive cleanup.
    }
    internal void PublishRoot(SafeFileHandle staged, bool replace) => Rename(staged,_directories[""],"vault.json",replace);
    internal void FlushRootNamespace(IStoreFaults faults) { FlushDirectory(".tmp",faults); FlushDirectory("",faults); }
    private void FlushDirectory(string name,IStoreFaults faults)
    {
        // Success is not power-loss qualification; failure must still abort or make publication uncertain.
        faults.BeforeFlush(true);
        if (!WindowsNative.FlushFileBuffers(_directories[name])) { DirectoryFlushAvailable=false; Fail("directory-flush"); }
    }
    private static void Rename(SafeFileHandle file, SafeFileHandle destination, string name, bool replace)
    {
        Component(name); var size=checked(20+name.Length*2); var info=Marshal.AllocHGlobal(size);
        try
        {
            new Span<byte>((void*)info,size).Clear(); Marshal.WriteByte(info,replace?(byte)1:(byte)0);
            Marshal.WriteIntPtr(info,8,destination.DangerousGetHandle()); Marshal.WriteInt32(info,16,name.Length*2);
            name.AsSpan().CopyTo(new Span<char>((void*)(info+20),name.Length));
            var status=WindowsNative.NtSetInformationFile(file,out _,info,(uint)size,10);
            if(status<0) throw new StoreException(CommitOutcome.Indeterminate,"native-rename-"+WindowsNative.RtlNtStatusToDosError(status));
        }
        finally { Marshal.FreeHGlobal(info); }
    }
    private static (string,string) Location(byte kind) => kind switch { 1=>("items",".item"),2=>("blobs",".blob"),3=>("manifests",".manifest"),_=>throw new StoreException(CommitOutcome.RejectedBeforePublication,"object-kind") };
    internal static void Hex(string name,int length) { if(name.Length!=length || name.Any(c=>!(c is >= '0' and <= '9' or >= 'a' and <= 'f'))) Fail("invalid-identifier"); }
    private static void Component(string name)
    {
        if(name.Length is <1 or >255 || name is "." or ".." || name.EndsWith('.') || name.EndsWith(' ') || name.IndexOfAny(['\\','/',':','\0','*','?','"','<','>','|'])>=0) Fail("invalid-component");
    }
    [System.Diagnostics.CodeAnalysis.DoesNotReturn] private static void Fail(string code) => throw new StoreException(CommitOutcome.RejectedBeforePublication,code);
    public void Dispose()
    {
        _lock?.Dispose(); _lock=null;
        for(var i=_pinned.Count-1;i>=0;i--) _pinned[i].Dispose(); _pinned.Clear(); _directories.Clear();
        if(_descriptor!=0) { WindowsNative.LocalFree(_descriptor); _descriptor=0; }
    }
}
