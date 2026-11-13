using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SafeNook.Storage;

internal static unsafe partial class WindowsNative
{
    [StructLayout(LayoutKind.Sequential)] internal struct UnicodeString { internal ushort Length, MaximumLength; internal char* Buffer; }
    [StructLayout(LayoutKind.Sequential)] internal struct ObjectAttributes
    { internal uint Length; internal nint RootDirectory; internal UnicodeString* ObjectName; internal uint Attributes; internal nint SecurityDescriptor, SecurityQualityOfService; }
    [StructLayout(LayoutKind.Sequential)] internal struct IoStatus { internal nint Status; internal nuint Information; }
    [StructLayout(LayoutKind.Sequential, Pack=4)] internal struct FileInfo
    { internal uint Attributes; internal long Creation, Access, Write; internal uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow; }
    [StructLayout(LayoutKind.Sequential)] internal struct Overlapped
    { internal nuint Internal, InternalHigh; internal uint Offset, OffsetHigh; internal nint Event; }
    [LibraryImport("ntdll.dll")] internal static partial int NtCreateFile(out nint handle, uint access, ref ObjectAttributes attributes, out IoStatus status, nint size, uint fileAttributes, uint share, uint disposition, uint options, nint ea, uint eaLength);
    [LibraryImport("ntdll.dll")] internal static partial int NtSetInformationFile(SafeFileHandle handle, out IoStatus status, nint information, uint length, uint informationClass);
    [LibraryImport("ntdll.dll")] internal static partial uint RtlNtStatusToDosError(int status);
    [LibraryImport("kernel32.dll", EntryPoint="CreateFileW", StringMarshalling=StringMarshalling.Utf16, SetLastError=true)] internal static partial SafeFileHandle CreateFile(string name, uint access, uint share, nint security, uint disposition, uint flags, nint template);
    [LibraryImport("kernel32.dll", SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] internal static partial bool GetFileInformationByHandle(SafeFileHandle handle, out FileInfo info);
    [LibraryImport("kernel32.dll", EntryPoint="GetDriveTypeW", StringMarshalling=StringMarshalling.Utf16)] internal static partial uint GetDriveType(string root);
    [LibraryImport("kernel32.dll", SetLastError=true)] internal static partial uint GetFileType(SafeFileHandle handle);
    [LibraryImport("kernel32.dll", SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] internal static partial bool FlushFileBuffers(SafeFileHandle handle);
    [LibraryImport("kernel32.dll", SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] internal static partial bool LockFileEx(SafeFileHandle handle, uint flags, uint reserved, uint low, uint high, ref Overlapped overlapped);
    [LibraryImport("kernel32.dll", EntryPoint="GetVolumeInformationByHandleW", SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] internal static partial bool VolumeInfo(SafeFileHandle handle, char* volumeName, uint volumeSize, out uint serial, out uint maximumComponent, out uint flags, char* filesystem, uint filesystemSize);
    [LibraryImport("advapi32.dll", EntryPoint="ConvertStringSecurityDescriptorToSecurityDescriptorW", StringMarshalling=StringMarshalling.Utf16, SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] internal static partial bool ConvertDescriptor(string descriptor, uint revision, out nint result, out uint size);
    [LibraryImport("advapi32.dll")] internal static partial uint GetSecurityInfo(SafeFileHandle handle, uint type, uint flags, out nint owner, out nint group, out nint dacl, out nint sacl, out nint descriptor);
    [LibraryImport("advapi32.dll")] internal static partial uint GetSecurityDescriptorLength(nint descriptor);
    [LibraryImport("kernel32.dll")] internal static partial nint LocalFree(nint memory);
}
