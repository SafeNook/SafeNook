using System.IO.Pipes;
using System.Runtime.InteropServices;

namespace SafeNook.DurabilityOracle;

internal static class PipeAccessProbe
{
    [DllImport("kernel32.dll")] private static extern nint GetCurrentThread();
    [DllImport("advapi32.dll", SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ImpersonateAnonymousToken(nint thread);
    [DllImport("advapi32.dll", SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool RevertToSelf();
    [DllImport("kernel32.dll", EntryPoint="CreateFileW", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern nint CreateFile(string name,uint access,uint share,nint security,uint disposition,uint flags,nint template);
    [DllImport("kernel32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CloseHandle(nint handle);
    internal static void AssertDenied(string name)
    {
        // Synchronous only: impersonation cannot cross an await/thread switch.
        if(!ImpersonateAnonymousToken(GetCurrentThread())) throw new InvalidOperationException("Access probe unavailable.");
        try
        {
            var handle=CreateFile("\\\\.\\pipe\\"+name,0xC0000000,0,0,3,0,0);
            var error=Marshal.GetLastWin32Error();
            if(handle != -1) {CloseHandle(handle);throw new InvalidOperationException("Anonymous connection was not denied.");}
            if(error != 5) throw new InvalidOperationException("Access probe inconclusive.");
        }
        finally {if(!RevertToSelf()) Environment.FailFast("Oracle access probe could not revert identity.");}
    }
}
