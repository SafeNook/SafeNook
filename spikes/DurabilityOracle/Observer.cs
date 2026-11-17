using System.Security.Cryptography;

namespace SafeNook.DurabilityOracle;

public interface IEvidence : IDisposable
{
    void Append(Frame frame);
    void Flush();
}

public sealed class Evidence : IEvidence
{
    private readonly FileStream stream;
    public Evidence(string path)
    {
        // Caller supplies a dedicated owner-only host directory, never a guest disk/share.
        stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read, 4096, FileOptions.WriteThrough);
    }
    public void Append(Frame frame)
    {
        if (frame.Kind != FrameKind.Event) throw new InvalidDataException("Non-event evidence refused.");
        var bytes = frame.Encode(); stream.Write(bytes);
    }
    public void Flush() => stream.Flush(true);
    public void Dispose() => stream.Dispose();
}

public sealed class Observer : IDisposable
{
    private readonly Guid run;
    private readonly Operation operation;
    private readonly IEvidence evidence;
    private readonly byte[] recovery = new byte[32];
    private ulong next = 1;
    private Boundary last;
    private uint occurrence;
    private bool hasRecovery;
    private bool failed;
    public bool AckDurable { get; private set; }
    public bool Complete { get; private set; }
    public Observer(Guid run, Operation operation, IEvidence evidence)
    {
        if (run == Guid.Empty || !Enum.IsDefined(operation)) throw new ArgumentException("Invalid oracle identity.");
        this.run = run; this.operation = operation; this.evidence = evidence;
    }
    public void Accept(Frame f)
    {
        try
        {
            if (failed || Complete || f.Run != run || f.Operation != operation || f.Sequence != next || f.Occurrence == 0 || f.Occurrence > 10000)
                throw new InvalidDataException("Oracle sequence rejected.");
            if (f.Kind == FrameKind.RecoveryKey)
            {
                if (operation != Operation.Rotate || last != Boundary.Authenticated || hasRecovery ||
                    f.Boundary != Boundary.Authenticated || f.Generation != 0 || f.Digests.AsSpan(32).IndexOfAnyExcept((byte)0) >= 0)
                    throw new InvalidDataException("Oracle secret channel rejected.");
                f.Digests.AsSpan(0,32).CopyTo(recovery); hasRecovery = true; next++; return;
            }
            if (f.Kind != FrameKind.Event) throw new InvalidDataException("Oracle event rejected.");
            var expected = last switch
            {
                0 => Boundary.Start,
                Boundary.Start => Boundary.Authenticated,
                Boundary.Authenticated => operation == Operation.Verify ? Boundary.Verified : Boundary.BeforePublish,
                Boundary.BeforePublish => Boundary.AfterPublish,
                Boundary.AfterPublish => Boundary.Verified,
                Boundary.Verified => Boundary.Ack,
                Boundary.Ack => Boundary.End,
                _ => throw new InvalidDataException("Oracle state rejected.")
            };
            var repeated = f.Boundary == last && last is Boundary.Authenticated or Boundary.BeforePublish or Boundary.AfterPublish or Boundary.Verified;
            if ((!repeated && (f.Boundary != expected || f.Occurrence != 1)) || (repeated && f.Occurrence != occurrence + 1) || (operation == Operation.Rotate && f.Boundary == Boundary.BeforePublish && !hasRecovery))
                throw new InvalidDataException("Oracle boundary rejected.");
            if (f.Boundary == Boundary.Ack)
            {
                if (f.Generation == 0 || f.Digests.AsSpan().IndexOfAnyExcept((byte)0) < 0)
                    throw new InvalidDataException("Oracle acknowledgement rejected.");
            }
            else if (f.Generation != 0 || f.Digests.AsSpan().IndexOfAnyExcept((byte)0) >= 0)
                throw new InvalidDataException("Oracle metadata rejected.");
            evidence.Append(f);
            if (f.Boundary == Boundary.Ack) { evidence.Flush(); AckDurable = true; }
            if (f.Boundary == Boundary.End) evidence.Flush();
            last = f.Boundary; occurrence = f.Occurrence; next++; Complete = last == Boundary.End;
        }
        catch { Abort(); throw; }
        finally { if (f.Kind == FrameKind.RecoveryKey) CryptographicOperations.ZeroMemory(f.Digests); }
    }
    public void CopyRecovery(Span<byte> destination)
    {
        if (failed || !hasRecovery || destination.Length != 32) throw new InvalidOperationException("Recovery oracle unavailable.");
        recovery.CopyTo(destination);
    }
    public void Abort() { failed = true; AckDurable = false; CryptographicOperations.ZeroMemory(recovery); }
    public void Dispose() { Abort(); evidence.Dispose(); }
}

public static class Session
{
    public static async Task Run(Stream transport, Observer observer, TimeSpan timeout, CancellationToken token)
    {
        if (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromMinutes(1)) throw new ArgumentOutOfRangeException(nameof(timeout));
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token); deadline.CancelAfter(timeout);
        try
        {
            while (!observer.Complete)
            {
                var frame = await Wire.Read(transport, deadline.Token);
                observer.Accept(frame);
                if (frame.Boundary == Boundary.Ack && frame.Kind == FrameKind.Event)
                    await Wire.Write(transport, new Frame { Run = frame.Run, Sequence = frame.Sequence, Operation = frame.Operation,
                        Boundary = Boundary.Ack, Kind = FrameKind.Receipt }, deadline.Token);
            }
        }
        catch { observer.Abort(); throw; }
    }
}
