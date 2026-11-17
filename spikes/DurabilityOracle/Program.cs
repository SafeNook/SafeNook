using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography;
using SafeNook.DurabilityOracle;

if (!OperatingSystem.IsWindows()) return 2;
try
{
    if (args.Length is < 4 or > 5 || !Guid.TryParseExact(args[2], "N", out var run) || run == Guid.Empty ||
        !Guid.TryParseExact(args[1], "N", out _)) return 2;
    var operation=Operation.Rotate;
    if(args.Length==5 && (!Enum.TryParse(args[4],out operation) || !Enum.IsDefined(operation))) return 2;
    using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
    var pipeName = "safenook-oracle-" + args[1];
    if (args[0] == "denied" && args[3] == "synthetic")
    {
        PipeAccessProbe.AssertDenied(pipeName); Console.WriteLine("DENIED"); return 0;
    }
    if (args[0] == "host")
    {
        // New, dedicated host evidence directory, with protected owner-only DACL.
        var directory = Path.GetFullPath(args[3]);
        if (Directory.Exists(directory) || File.Exists(directory)) return 2;
        var parent = new DirectoryInfo(Path.GetDirectoryName(directory)!);
        for (var cursor = parent; cursor is not null; cursor = cursor.Parent)
            if (!cursor.Exists || (cursor.Attributes & FileAttributes.ReparsePoint) != 0) return 2;
        var sid = WindowsIdentity.GetCurrent().User!;
        var security = new DirectorySecurity(); security.SetOwner(sid); security.SetAccessRuleProtection(true,false);
        security.AddAccessRule(new FileSystemAccessRule(sid,FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
        new DirectoryInfo(directory).Create(security);
        using var evidence = new Evidence(Path.Combine(directory,"events.bin"));
        using var observer = new Observer(run,operation,evidence);
        using var pipe = new NamedPipeServerStream(pipeName,PipeDirection.InOut,1,PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous|PipeOptions.CurrentUserOnly);
        Console.WriteLine("READY");
        await pipe.WaitForConnectionAsync(deadline.Token);
        await Session.Run(pipe,observer,TimeSpan.FromSeconds(15),deadline.Token);
        Console.WriteLine("COMPLETE");
        // The controller can kill the independent host here to inspect persisted ACK evidence.
        await Task.Delay(Timeout.Infinite,deadline.Token);
    }
    else if (args[0] is "guest" or "guest-uart" && args[3] is "synthetic" or "duplicate" or "order" or "truncated" or "oversized" or "disconnect" or "timeout")
    {
        Stream stream;
        if(args[0]=="guest-uart")
        {
            if(args[3]!="synthetic") return 2;
            stream=VirtualUart.OpenGuestCom1();
        }
        else
        {
            var client=new NamedPipeClientStream(".",pipeName,PipeDirection.InOut,PipeOptions.Asynchronous);
            try {await client.ConnectAsync(deadline.Token);} catch {client.Dispose();throw;}
            stream=client;
        }
        using var pipe=stream;
        if (args[3] == "disconnect") return 0;
        if (args[3] == "timeout") { await Task.Delay(Timeout.Infinite,deadline.Token); return 2; }
        if (args[3] is "oversized" or "truncated")
        {
            await pipe.WriteAsync(args[3] == "oversized" ? new byte[]{1,16,0,0} : new byte[]{160,0,0,0,1},deadline.Token);
            return 0;
        }
        if (args[3] == "order")
        {
            await Wire.Write(pipe,new Frame {Run=run,Sequence=2,Operation=Operation.Rotate,Boundary=Boundary.Start},deadline.Token);
            return 0;
        }
        var guest = new GuestBridge(pipe,run,operation,deadline.Token);
        await guest.Event(Boundary.Start); await guest.Event(Boundary.Authenticated);
        if(operation==Operation.Rotate)
        {
            var key = RandomNumberGenerator.GetBytes(32);
            try { await guest.Recovery(key); } finally { CryptographicOperations.ZeroMemory(key); }
        }
        if(operation!=Operation.Verify) {await guest.Event(Boundary.BeforePublish); await guest.Event(Boundary.AfterPublish);}
        await guest.Event(Boundary.Verified);
        await guest.Acknowledge(1,Wire.Digest(1,"synthetic wrapper"u8),Wire.Digest(2,new byte[414]),Wire.Digest(3,"synthetic archive"u8));
        if (args[3] == "duplicate")
        {
            await Wire.Write(pipe,new Frame {Run=run,Sequence=7,Operation=Operation.Rotate,Boundary=Boundary.Ack},deadline.Token);
            return 0;
        }
        await guest.Event(Boundary.End);
        Console.WriteLine("RECEIPT");
    }
    else return 2;
    return 0;
}
catch { Console.Error.WriteLine("Oracle trial inconclusive."); return 2; }
