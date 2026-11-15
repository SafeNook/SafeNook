using System.Globalization;

namespace SafeNook.Storage;

internal enum StorageStage { Input, KeySlots, RecoveryConfirmation, SecurityDescriptor, DriveType, VolumeRoot, VolumeInfo, Ancestor, VaultDirectory, ChildDirectory, Lock, FileOpen, FileValidation, ObjectWrite, FileFlush, Rename, DirectoryFlush, Authentication, Publication }
internal enum StorageFailure { None, Native, AccessControl, UnsupportedVolume, InvalidInput, Cancelled, ResourceLimit, Authentication, Io, Unknown }
internal enum StorageFileSystem { Unknown, Ntfs, Other }

// Internal, bounded diagnostics: no exception messages, paths, SID values or data buffers.
internal sealed class StorageDiagnostics
{
    internal StorageStage Stage { get; set; }
    internal StorageFailure Failure { get; private set; }
    internal uint? Win32 { get; private set; }
    internal int? NtStatus { get; private set; }
    internal uint DriveType { get; set; }
    internal StorageFileSystem FileSystem { get; set; }
    internal uint VolumeFlags { get; set; }
    internal bool NamespaceValidated { get; set; }
    internal bool LockAcquired { get; set; }
    internal bool FileFlushed { get; set; }
    internal bool DirectoryFlushed { get; set; }
    internal bool Renamed { get; set; }
    internal void Native(uint code, int? status = null)
    { Failure=StorageFailure.Native; Win32=code; NtStatus=status; }
    internal void ClearExpectedNativeFailure() { Failure=StorageFailure.None; Win32=null; NtStatus=null; }
    internal void Capture(Exception error)
    {
        if(Failure!=StorageFailure.None) return;
        Failure=error switch
        {
            OperationCanceledException=>StorageFailure.Cancelled,
            OutOfMemoryException=>StorageFailure.ResourceLimit,
            UnauthorizedAccessException=>StorageFailure.AccessControl,
            IOException=>StorageFailure.Io,
            SafeNook.Core.Vault.VaultDataException=>StorageFailure.Authentication,
            StoreException e when e.Code is "unsafe-acl" or "security-size" or "read-security" or "security-descriptor"=>StorageFailure.AccessControl,
            StoreException e when e.Code is "unqualified-drive-type" or "unqualified-filesystem"=>StorageFailure.UnsupportedVolume,
            StoreException=>StorageFailure.InvalidInput,
            _=>StorageFailure.Unknown
        };
        if(error is IOException && (unchecked((uint)error.HResult)&0xffff0000)==0x80070000)
            Win32=unchecked((uint)error.HResult)&0xffff;
    }
    internal string SafeSummary()=>string.Create(CultureInfo.InvariantCulture,
        $"stage={Stage}; category={Failure}; win32={Win32?.ToString(CultureInfo.InvariantCulture)??"none"}; ntstatus={(NtStatus is int status?$"0x{unchecked((uint)status):X8}":"none")}; fs={FileSystem}; volumeFlags=0x{VolumeFlags:X8}; driveType={DriveType}; namespace={NamespaceValidated}; lock={LockAcquired}; fileFlush={FileFlushed}; directoryFlush={DirectoryFlushed}; rename={Renamed}");
}
