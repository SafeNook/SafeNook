using System.Runtime.InteropServices;
using SafeNook.Core.Vault;

namespace SafeNook.Application;

internal static partial class WindowsMemory
{
    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryStatus
    {
        internal uint Length, Load;
        internal ulong TotalPhysical, AvailablePhysical, TotalPageFile, AvailablePageFile, TotalVirtual, AvailableVirtual, AvailableExtendedVirtual;
    }
    [LibraryImport("kernel32.dll", SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)]
    private static partial bool GlobalMemoryStatusEx(ref MemoryStatus status);
    internal static VaultAdmissionPolicy Policy()
    {
        if(!OperatingSystem.IsWindows()) throw new VaultOperationException(VaultApplicationError.UnsupportedPlatform);
        var status=new MemoryStatus {Length=(uint)Marshal.SizeOf<MemoryStatus>()};
        if(!GlobalMemoryStatusEx(ref status) || status.AvailablePhysical>long.MaxValue)
            throw new VaultOperationException(VaultApplicationError.ResourceLimit);
        return VaultAdmissionPolicy.FromAvailableMemory((long)status.AvailablePhysical);
    }
}
