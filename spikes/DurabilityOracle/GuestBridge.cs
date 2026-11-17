using System.Security.Cryptography;

namespace SafeNook.DurabilityOracle;

// Stream adapter: local pipe now; a reviewed virtual COM adapter can supply the same byte stream later.
public sealed class GuestBridge(Stream stream, Guid run, Operation operation, CancellationToken token)
{
    private ulong sequence;
    public async Task Event(Boundary boundary, uint occurrence = 1)
    {
        await Wire.Write(stream, new Frame { Run = run, Sequence = ++sequence, Operation = operation,
            Boundary = boundary, Occurrence = occurrence }, token);
    }
    public async Task Recovery(ReadOnlyMemory<byte> key)
    {
        if (operation != Operation.Rotate || key.Length != 32) throw new InvalidDataException("Oracle key rejected.");
        var data = new byte[96]; key.Span.CopyTo(data);
        try { await Wire.Write(stream, new Frame { Run = run, Sequence = ++sequence, Operation = operation,
            Boundary = Boundary.Authenticated, Kind = FrameKind.RecoveryKey, Digests = data }, token); }
        finally { CryptographicOperations.ZeroMemory(data); }
    }
    // Call only after Application success. Hash inputs come from the exact acknowledged generation.
    public async Task Acknowledge(ulong generation, byte[] wrapperHash, byte[] headerHash, byte[] archiveHash)
    {
        if (wrapperHash.Length != 32 || headerHash.Length != 32 || archiveHash.Length != 32)
            throw new InvalidDataException("Oracle hash rejected.");
        var hashes = new byte[96]; wrapperHash.CopyTo(hashes,0); headerHash.CopyTo(hashes,32); archiveHash.CopyTo(hashes,64);
        var sent = ++sequence;
        await Wire.Write(stream,new Frame { Run=run,Sequence=sent,Operation=operation,Boundary=Boundary.Ack,Generation=generation,Digests=hashes },token);
        var receipt=await Wire.Read(stream,token);
        if(receipt.Run!=run || receipt.Sequence!=sent || receipt.Kind!=FrameKind.Receipt || receipt.Operation!=operation ||
            receipt.Boundary!=Boundary.Ack || receipt.Occurrence!=1 || receipt.Generation!=0 || receipt.Digests.AsSpan().IndexOfAnyExcept((byte)0)>=0)
            throw new InvalidDataException("Oracle receipt rejected.");
    }
}
