using System.Diagnostics;
using System.IO.Pipes;
using System.Security.Cryptography;
using SafeNook.DurabilityOracle;

namespace SafeNook.Application.Tests;

public sealed class OracleTests
{
    private static Frame F(Guid run, ulong sequence, Boundary boundary, byte[]? hashes = null, uint occurrence = 1) =>
        new() { Run=run, Sequence=sequence, Operation=Operation.Rotate, Boundary=boundary, Digests=hashes??new byte[96],
            Generation=boundary==Boundary.Ack?1ul:0ul, Occurrence=occurrence };
    private static void Ready(Observer observer, Guid run)
    {
        observer.Accept(F(run,1,Boundary.Start)); observer.Accept(F(run,2,Boundary.Authenticated));
        observer.Accept(new Frame {Run=run,Sequence=3,Operation=Operation.Rotate,Boundary=Boundary.Authenticated,
            Kind=FrameKind.RecoveryKey,Digests=new byte[96]});
        observer.Accept(F(run,4,Boundary.BeforePublish)); observer.Accept(F(run,5,Boundary.AfterPublish));
        observer.Accept(F(run,6,Boundary.Verified));
    }
    private sealed class MemoryEvidence : IEvidence
    {
        public List<byte[]> Records {get;} = [];
        public bool FailWrite {get;init;}
        public bool FailFlush {get;init;}
        public bool Flushed {get;private set;}
        public void Append(Frame f) { if(FailWrite) throw new IOException("Injected write failure."); Records.Add(f.Encode()); }
        public void Flush() { if(FailFlush) throw new IOException("Injected flush failure."); Flushed=true; }
        public void Dispose() { }
    }
    [Fact]
    public void RotationKeyNeverEntersEvidenceAndIsCleared()
    {
        var run=Guid.NewGuid(); var evidence=new MemoryEvidence(); using var observer=new Observer(run,Operation.Rotate,evidence);
        observer.Accept(F(run,1,Boundary.Start));observer.Accept(F(run,2,Boundary.Authenticated));
        var payload=new byte[96]; RandomNumberGenerator.Fill(payload.AsSpan(0,32));var expected=payload.AsSpan(0,32).ToArray();
        observer.Accept(new Frame {Run=run,Sequence=3,Operation=Operation.Rotate,Boundary=Boundary.Authenticated,Kind=FrameKind.RecoveryKey,Digests=payload});
        Assert.All(payload,b=>Assert.Equal(0,b));
        var copy=new byte[32];observer.CopyRecovery(copy);Assert.Equal(expected,copy);
        Assert.All(evidence.Records,r=>Assert.Equal(-1,r.AsSpan().IndexOf(expected)));
        observer.Abort();Assert.Throws<InvalidOperationException>(()=>observer.CopyRecovery(copy));
        CryptographicOperations.ZeroMemory(copy);CryptographicOperations.ZeroMemory(expected);
    }
    [Theory] [InlineData(false)] [InlineData(true)]
    public void EvidenceFailureNeverArmsPostAck(bool flush)
    {
        var run=Guid.NewGuid();var evidence=new MemoryEvidence {FailFlush=flush,FailWrite=!flush};
        using var observer=new Observer(run,Operation.Rotate,evidence);
        if(!flush) Assert.Throws<IOException>(()=>observer.Accept(F(run,1,Boundary.Start)));
        else {Ready(observer,run);Assert.Throws<IOException>(()=>observer.Accept(F(run,7,Boundary.Ack,Enumerable.Repeat((byte)1,96).ToArray())));}
        Assert.False(observer.AckDurable);
    }
    [Fact]
    public void AckIsFlushedAndDuplicateFailsClosed()
    {
        var run=Guid.NewGuid();var evidence=new MemoryEvidence();using var observer=new Observer(run,Operation.Rotate,evidence);
        Ready(observer,run);var ack=F(run,7,Boundary.Ack,Enumerable.Repeat((byte)1,96).ToArray());observer.Accept(ack);
        Assert.True(observer.AckDurable);Assert.True(evidence.Flushed);
        Assert.Throws<InvalidDataException>(()=>observer.Accept(ack));Assert.False(observer.AckDurable);
    }
    [Theory] [InlineData(0)] [InlineData(2)] [InlineData(4)]
    public void WrongInitialSequenceRejected(int sequence)
    {
        var run=Guid.NewGuid();using var observer=new Observer(run,Operation.Rotate,new MemoryEvidence());
        Assert.Throws<InvalidDataException>(()=>observer.Accept(F(run,(ulong)sequence,Boundary.Start)));
    }
    [Fact]
    public void WrongRunAndSkippedBoundaryRejected()
    {
        var run=Guid.NewGuid();using var first=new Observer(run,Operation.Rotate,new MemoryEvidence());
        Assert.Throws<InvalidDataException>(()=>first.Accept(F(Guid.NewGuid(),1,Boundary.Start)));
        using var second=new Observer(run,Operation.Rotate,new MemoryEvidence());second.Accept(F(run,1,Boundary.Start));
        Assert.Throws<InvalidDataException>(()=>second.Accept(F(run,2,Boundary.Ack)));
    }
    [Fact]
    public void OccurrencesMustIncreaseExactly()
    {
        var run=Guid.NewGuid();using var observer=new Observer(run,Operation.Rotate,new MemoryEvidence());
        observer.Accept(F(run,1,Boundary.Start));observer.Accept(F(run,2,Boundary.Authenticated));
        observer.Accept(F(run,3,Boundary.Authenticated,occurrence:2));
        Assert.Throws<InvalidDataException>(()=>observer.Accept(F(run,4,Boundary.Authenticated,occurrence:2)));
    }
    [Theory] [InlineData(0)] [InlineData(4)] [InlineData(5)] [InlineData(6)] [InlineData(7)] [InlineData(159)]
    public void UnknownWireFieldsRejected(int offset)
    {
        var b=F(Guid.NewGuid(),1,Boundary.Start).Encode();b[offset]=255;
        Assert.Throws<InvalidDataException>(()=>Frame.Decode(b));
    }
    [Theory] [InlineData(4097)] [InlineData(0)] [InlineData(159)]
    public async Task InvalidLengthRejectedBeforePayload(int length)
    {
        using var stream=new MemoryStream(BitConverter.GetBytes(length));
        await Assert.ThrowsAsync<InvalidDataException>(()=>Wire.Read(stream,CancellationToken.None));
    }
    [Fact]
    public async Task TruncatedFrameFails()
    {
        using var stream=new MemoryStream(new byte[]{160,0,0,0,1});
        await Assert.ThrowsAsync<EndOfStreamException>(()=>Wire.Read(stream,CancellationToken.None));
    }
    [Fact]
    public void HashDomainsCannotBeConfused()
    {
        var bytes=new byte[414];Assert.NotEqual(Wire.Digest(1,bytes),Wire.Digest(2,bytes));
        Assert.NotEqual(Wire.Digest(2,bytes),Wire.Digest(3,bytes));
        Assert.Throws<InvalidDataException>(()=>Wire.Digest(2,new byte[413]));
    }
    [Fact]
    public async Task NoReceiptOnFlushFailure()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows(), "Windows named-pipe qualification transport only.");
        var run=Guid.NewGuid();var pipeName=Guid.NewGuid().ToString("N");
        using var server=new NamedPipeServerStream(pipeName,PipeDirection.InOut,1,PipeTransmissionMode.Byte,PipeOptions.Asynchronous|PipeOptions.CurrentUserOnly);
        using var client=new NamedPipeClientStream(".",pipeName,PipeDirection.InOut,PipeOptions.Asynchronous);
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var connect=client.ConnectAsync(deadline.Token);await server.WaitForConnectionAsync(deadline.Token);await connect;
        using var observer=new Observer(run,Operation.Rotate,new MemoryEvidence {FailFlush=true});
        var task=Session.Run(server,observer,TimeSpan.FromSeconds(4),deadline.Token);
        var guest=new GuestBridge(client,run,Operation.Rotate,deadline.Token);
        await guest.Event(Boundary.Start);await guest.Event(Boundary.Authenticated);await guest.Recovery(new byte[32]);
        await guest.Event(Boundary.BeforePublish);await guest.Event(Boundary.AfterPublish);await guest.Event(Boundary.Verified);
        await Wire.Write(client,F(run,7,Boundary.Ack,Enumerable.Repeat((byte)1,96).ToArray()),deadline.Token);
        await Assert.ThrowsAsync<IOException>(()=>task);Assert.False(observer.AckDurable);
        server.Dispose();await Assert.ThrowsAnyAsync<IOException>(()=>Wire.Read(client,deadline.Token));
    }
    private static string Root()
    {
        var d=new DirectoryInfo(AppContext.BaseDirectory);while(d is not null && !File.Exists(Path.Combine(d.FullName,"SafeNook.slnx"))) d=d.Parent;
        return d!.FullName;
    }
    private static Process Start(string executable,params string[] args)
    {
        var start=new ProcessStartInfo(executable){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
        foreach(var arg in args) start.ArgumentList.Add(arg);return Process.Start(start)!;
    }
    [Theory]
    [InlineData("synthetic")] [InlineData("synthetic",Operation.Password)] [InlineData("synthetic",Operation.Recover)]
    [InlineData("synthetic",Operation.Backup)] [InlineData("synthetic",Operation.Verify)] [InlineData("synthetic",Operation.Restore)] [InlineData("duplicate")] [InlineData("order")] [InlineData("truncated")]
    [InlineData("denied")] [InlineData("oversized")] [InlineData("disconnect")] [InlineData("timeout")]
    public async Task IndependentHostGuestProcesses(string scenario, Operation operation=Operation.Rotate)
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows(), "Windows oracle executable, owner-only ACLs and native access probe required.");
        var root=Root();var exe=Path.Combine(root,"spikes","DurabilityOracle","bin","Release","net10.0","DurabilityOracle.exe");
        var path=Path.Combine(root,"artifacts","sn-003q2-"+Guid.NewGuid().ToString("N"));
        var run=Guid.NewGuid().ToString("N");var pipe=Guid.NewGuid().ToString("N");
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var host=Start(exe,"host",pipe,run,path,operation.ToString());
        Process? guest=null;
        try
        {
            Assert.Equal("READY",await host.StandardOutput.ReadLineAsync(deadline.Token));
            guest=Start(exe,scenario=="denied"?"denied":"guest",pipe,run,scenario=="denied"?"synthetic":scenario,operation.ToString());
            if(scenario=="denied")
            {
                Assert.Equal("DENIED",await guest.StandardOutput.ReadLineAsync(deadline.Token));
                await guest.WaitForExitAsync(deadline.Token);Assert.Equal(0,guest.ExitCode);return;
            }
            if(scenario=="synthetic")
            {
                Assert.Equal("RECEIPT",await guest.StandardOutput.ReadLineAsync(deadline.Token));
                Assert.Equal("COMPLETE",await host.StandardOutput.ReadLineAsync(deadline.Token));
                host.Kill(true);await host.WaitForExitAsync(deadline.Token);
                await guest.WaitForExitAsync(deadline.Token);Assert.Equal(0,guest.ExitCode);
                byte[] bytes=[];
                for(var attempt=0; ; attempt++)
                {
                    try {bytes=File.ReadAllBytes(Path.Combine(path,"events.bin"));break;}
                    catch(IOException e) when((e.HResult & 65535)==32 && attempt<20) {await Task.Delay(100,deadline.Token);}
                }var count=operation==Operation.Verify?5:7;Assert.Equal(count*Frame.Size,bytes.Length);
                var events=Enumerable.Range(0,count).Select(i=>Frame.Decode(bytes.AsSpan(i*Frame.Size,Frame.Size).ToArray())).ToArray();
                Assert.All(events,e=>{Assert.Equal(FrameKind.Event,e.Kind);Assert.Equal(Guid.ParseExact(run,"N"),e.Run);Assert.Equal(operation,e.Operation);});
                var ack=Assert.Single(events,e=>e.Boundary==Boundary.Ack);
                Assert.Equal(1ul,ack.Generation);
                Assert.Equal(Wire.Digest(1,"synthetic wrapper"u8),ack.Digests.AsSpan(0,32).ToArray());
                Assert.Equal(Wire.Digest(2,new byte[414]),ack.Digests.AsSpan(32,32).ToArray());
                Assert.Equal(Wire.Digest(3,"synthetic archive"u8),ack.Digests.AsSpan(64,32).ToArray());
                Assert.Equal("",await host.StandardError.ReadToEndAsync(deadline.Token));
                Assert.Equal("",await guest.StandardError.ReadToEndAsync(deadline.Token));
            }
            else
            {
                await host.WaitForExitAsync(deadline.Token);Assert.Equal(2,host.ExitCode);
                Assert.Equal("Oracle trial inconclusive.", (await host.StandardError.ReadToEndAsync(deadline.Token)).Trim());
                Assert.Equal("",await host.StandardOutput.ReadToEndAsync(deadline.Token));
            }
        }
        finally
        {
            if(!host.HasExited) {host.Kill(true);host.WaitForExit();}
            if(guest is not null) {if(!guest.HasExited) {guest.Kill(true);guest.WaitForExit();}guest.Dispose();}
        }
    }
}
