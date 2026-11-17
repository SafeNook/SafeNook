using System.Buffers.Binary;
using System.Security.Cryptography;

namespace SafeNook.DurabilityOracle;

public enum Operation : byte { Password = 1, Recover, Rotate, Backup, Verify, Restore }
public enum Boundary : byte { Start = 1, Authenticated, BeforePublish, AfterPublish, Verified, Ack, End }
public enum FrameKind : byte { Event = 1, RecoveryKey, Receipt }

// Fixed fields: no strings, paths or user-controlled diagnostic text.
public sealed class Frame
{
    public const int Size = 160;
    public Guid Run { get; init; }
    public ulong Sequence { get; init; }
    public FrameKind Kind { get; init; } = FrameKind.Event;
    public Operation Operation { get; init; }
    public Boundary Boundary { get; init; }
    public uint Occurrence { get; init; } = 1;
    public ulong Generation { get; init; }
    public byte[] Digests { get; init; } = new byte[96];
    public byte[] Encode()
    {
        var b = new byte[Size];
        "SNOR"u8.CopyTo(b); b[4] = 1; b[5] = (byte)Kind; b[6] = (byte)Operation; b[7] = (byte)Boundary;
        Run.TryWriteBytes(b.AsSpan(8, 16));
        BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(24), Sequence);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(32), Occurrence);
        BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(36), Generation);
        if (Digests.Length != 96) throw new InvalidDataException("Oracle frame rejected.");
        Digests.CopyTo(b, 44);
        return b;
    }
    public static Frame Decode(byte[] b)
    {
        if (b.Length != Size || !b.AsSpan(0,4).SequenceEqual("SNOR"u8) || b[4] != 1 ||
            b[5] is < 1 or > 3 || b[6] is < 1 or > 6 || b[7] is < 1 or > 7 ||
            b.AsSpan(140).IndexOfAnyExcept((byte)0) >= 0)
            throw new InvalidDataException("Oracle frame rejected.");
        return new Frame { Run = new Guid(b.AsSpan(8,16)), Sequence = BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(24)),
            Kind = (FrameKind)b[5], Operation = (Operation)b[6], Boundary = (Boundary)b[7],
            Occurrence = BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(32)),
            Generation = BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(36)), Digests = b.AsSpan(44,96).ToArray() };
    }
}

public static class Wire
{
    public static async Task<Frame> Read(Stream stream, CancellationToken token)
    {
        var prefix = new byte[4];
        await stream.ReadExactlyAsync(prefix, token);
        var length = BinaryPrimitives.ReadUInt32LittleEndian(prefix);
        // Reject before allocating; current version admits only the fixed schema, never 4 KiB arbitrary data.
        if (length > 4096 || length != Frame.Size) throw new InvalidDataException("Oracle length rejected.");
        var bytes = new byte[Frame.Size];
        try { await stream.ReadExactlyAsync(bytes, token); return Frame.Decode(bytes); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    public static async Task Write(Stream stream, Frame frame, CancellationToken token)
    {
        var prefix = new byte[4]; BinaryPrimitives.WriteUInt32LittleEndian(prefix, Frame.Size);
        var bytes = frame.Encode();
        try { await stream.WriteAsync(prefix, token); await stream.WriteAsync(bytes, token); await stream.FlushAsync(token); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    public static async Task<byte[]> ArchiveDigest(Stream stream, CancellationToken token)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("SNOR-v1"u8); hash.AppendData(new byte[]{3});
        var buffer=new byte[65536]; long length=0;
        try
        {
            int count;
            while((count=await stream.ReadAsync(buffer,token))!=0)
            {
                length=checked(length+count);
                if(length>2147483648L) throw new InvalidDataException("Oracle archive limit exceeded.");
                hash.AppendData(buffer,0,count);
            }
            return hash.GetHashAndReset();
        }
        finally {CryptographicOperations.ZeroMemory(buffer);}
    }
    // Three independently tagged domains. Header input length is part of its contract.
    public static byte[] Digest(byte domain, ReadOnlySpan<byte> value)
    {
        if (domain is < 1 or > 3 || (domain == 2 && value.Length != 414)) throw new InvalidDataException("Oracle hash domain rejected.");
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("SNOR-v1"u8); hash.AppendData(new[]{domain}); hash.AppendData(value); return hash.GetHashAndReset();
    }
}
