using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Buffers.Binary;

namespace SafeNook.DurabilityOracle;

/// <summary>Qualification-only Windows guest COM1 byte stream; real VM behavior remains unqualified.</summary>
[SupportedOSPlatform("windows")]
public static class VirtualUart
{
    [DllImport("kernel32.dll", EntryPoint="CreateFileW", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern SafeFileHandle Open(string name,uint access,uint share,nint security,uint disposition,uint flags,nint template);
    [DllImport("kernel32.dll", SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetCommState(SafeFileHandle handle,[In,Out] byte[] dcb);
    [DllImport("kernel32.dll", EntryPoint="BuildCommDCBW", CharSet=CharSet.Unicode, SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool BuildCommDCB(string definition,[In,Out] byte[] dcb);
    [DllImport("kernel32.dll", SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetCommState(SafeFileHandle handle,[In] byte[] dcb);
    [DllImport("kernel32.dll", SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetCommTimeouts(SafeFileHandle handle,[In] uint[] timeouts);
    public static Stream OpenGuestCom1()
    {
        // Refuse physical host COM ports. Caller still requires the approved VM identity/isolation preflight.
        using var bios=Registry.LocalMachine.OpenSubKey("HARDWARE\\DESCRIPTION\\System\\BIOS");
        if(bios?.GetValue("SystemProductName") is not string model || model != "VirtualBox")
            throw new InvalidOperationException("Virtual guest required.");
        var handle=Open("\\\\.\\COM1",0xC0000000,0,0,3,0x40000000,0);
        try
        {
            // Windows DCB is 28 bytes; native API validates DCBlength. No managed bool/bitfield layout.
            var dcb=new byte[28];BinaryPrimitives.WriteUInt32LittleEndian(dcb,28);
            if(handle.IsInvalid || !GetCommState(handle,dcb) || !BuildCommDCB("baud=115200 parity=n data=8 stop=1 octs=off odsr=off xon=off dtr=off rts=off idsr=off",dcb))
                throw new IOException("Virtual UART configuration failed.");
            // fBinary only: no null stripping, parity substitution, or inherited flow-control flags.
            BinaryPrimitives.WriteUInt32LittleEndian(dcb.AsSpan(8),1);
            if(!SetCommState(handle,dcb) || !SetCommTimeouts(handle,new uint[]{0,0,1000,0,1000}))
                throw new IOException("Virtual UART configuration failed.");
            // Native one-second I/O bounds supplement the session cancellation deadline.
            return new FileStream(handle,FileAccess.ReadWrite,4096,true);
        }
        catch {handle.Dispose();throw;}
    }
}
