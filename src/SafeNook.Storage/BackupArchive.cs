using System.Buffers.Binary;
using System.Security.Cryptography;
using SafeNook.Core.Vault;

namespace SafeNook.Storage;

/// <summary>Sequential SNBACKUP v1 framing; no archive-sized allocation or path extraction.</summary>
internal sealed class BackupArchive : IVaultObjectSource
{
    internal const long MaximumLength=2147483648;
    private readonly Stream _stream;
    internal byte[] Header { get; }
    internal Dictionary<(byte Kind,string Write),(long Offset,int Length)> Entries { get; }=[];
    internal BackupArchive(Stream stream,CancellationToken token)
    {
        _stream=stream;
        if(!stream.CanSeek || stream.Length<438 || stream.Length>MaximumLength) Fail();
        stream.Position=0;var prefix=new byte[24];ReadExact(stream,prefix,token);
        if(!prefix.AsSpan(0,8).SequenceEqual("SNBACKUP"u8) || BinaryPrimitives.ReadUInt16LittleEndian(prefix.AsSpan(8))!=1 || BinaryPrimitives.ReadUInt16LittleEndian(prefix.AsSpan(10))!=0 || BinaryPrimitives.ReadUInt64LittleEndian(prefix.AsSpan(16))!=(ulong)stream.Length) Fail();
        var count=BinaryPrimitives.ReadUInt32LittleEndian(prefix.AsSpan(12));if(count is <1 or >20001) Fail();
        Header=new byte[414];ReadExact(stream,Header,token);VaultFormat.ValidateHeader(Header);
        var frame=new byte[16];var envelope=new byte[118];var ids=new HashSet<string>(StringComparer.Ordinal);
        byte previousKind=0;string previous="";int items=0,blobs=0;
        for(uint i=0;i<count;i++)
        {
            ReadExact(stream,frame,token);var kind=frame[0];var size=BinaryPrimitives.ReadUInt64LittleEndian(frame.AsSpan(8));
            var maximum=kind switch {1=>65670,2=>26214534,3=>8388742,_=>0};
            if(frame.AsSpan(1,7).IndexOfAnyExcept((byte)0)>=0 || size<134 || size>(ulong)maximum || size>(ulong)(stream.Length-stream.Position)) Fail();
            if(i==0?kind!=3:kind is not (1 or 2) || (previousKind==2 && kind==1)) Fail();
            var offset=stream.Position;ReadExact(stream,envelope,token);VaultFormat.ValidateEnvelope(envelope,(long)size);
            var write=Convert.ToHexStringLower(envelope.AsSpan(60,32));
            if(envelope[10]!=kind || !ids.Add(write) || (kind==previousKind && StringComparer.Ordinal.Compare(previous,write)>=0)) Fail();
            if(kind==1 && ++items>10000 || kind==2 && ++blobs>10000) Fail();
            Entries.Add((kind,write),(offset,(int)size));previousKind=kind;previous=write;
            stream.Position=checked(offset+(long)size);
        }
        if(stream.Position!=stream.Length) Fail();
    }
    public long Read(byte kind,string writeId,Span<byte> destination,CancellationToken token)
    {
        if(!Entries.TryGetValue((kind,writeId),out var entry)) return -1;
        _stream.Position=entry.Offset;ReadExact(_stream,destination[..Math.Min(destination.Length,entry.Length)],token);return entry.Length;
    }
    internal byte[] Object((byte Kind,string Write) id,CancellationToken token)
    { var entry=Entries[id];var bytes=new byte[entry.Length];Read(id.Kind,id.Write,bytes,token);return bytes; }
    internal string Hash(CancellationToken token)
    {
        _stream.Position=0;using var hash=IncrementalHash.CreateHash(HashAlgorithmName.SHA256);var buffer=new byte[65536];int read;
        while((read=_stream.Read(buffer))!=0) { token.ThrowIfCancellationRequested();hash.AppendData(buffer,0,read); }
        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }
    internal static void ReadExact(Stream stream,Span<byte> bytes,CancellationToken token)
    { while(!bytes.IsEmpty) { token.ThrowIfCancellationRequested();var n=stream.Read(bytes);if(n==0) Fail();bytes=bytes[n..]; } }
    private static void Fail()=>throw new StoreException(CommitOutcome.RejectedBeforePublication,"backup-format");
}
