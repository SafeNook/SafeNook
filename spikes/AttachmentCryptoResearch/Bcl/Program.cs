using System.Buffers.Binary;
using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

// Research only. Not a vault implementation or a reviewed production format.
internal static class Program
{
    const int PrefixLength = 118;
    const int MaxLength = 25 * 1024 * 1024;
    static readonly int[] Sizes = [0, 1, 5, 10, 25];
    static readonly byte[] VaultKey = SHA256.HashData("PUBLIC SYNTHETIC BENCHMARK KEY"u8);
    static readonly byte[] VaultId = Convert.FromHexString("00112233445546778899aabbccddeeff");
    static readonly byte[] EpochId = Convert.FromHexString("112233445566478899aabbccddeeff00");
    static readonly byte[] ObjectId = Convert.FromHexString("2233445566774899aabbccddeeff0011");

    static int Main(string[] args)
    {
        try
        {
            if (!AesGcm.IsSupported) throw new PlatformNotSupportedException("AES-GCM unavailable.");
            if (args.Length < 2) throw new ArgumentException("prepare|check|measure directory [sizeMiB operation]");
            string directory = Path.GetFullPath(args[1]);
            Directory.CreateDirectory(directory);
            switch (args[0])
            {
                case "prepare": Prepare(directory); break;
                case "check": Check(directory); break;
                case "measure": Measure(directory, int.Parse(args[2], CultureInfo.InvariantCulture), args[3]); break;
                default: throw new ArgumentException("Unknown command.");
            }
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.GetType().Name + ": " + ex.Message);
            return 1;
        }
    }

    static byte[] Header(int length)
    {
        byte[] h = new byte[PrefixLength];
        "SNOBJ001"u8.CopyTo(h);
        BinaryPrimitives.WriteUInt16LittleEndian(h.AsSpan(8), 1);
        h[10] = 2;
        VaultId.CopyTo(h, 12); EpochId.CopyTo(h, 28); ObjectId.CopyTo(h, 44);
        RandomNumberGenerator.Fill(h.AsSpan(60, 32));
        BinaryPrimitives.WriteUInt16LittleEndian(h.AsSpan(94), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(h.AsSpan(96), 1);
        BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(98), (ulong)length);
        RandomNumberGenerator.Fill(h.AsSpan(106, 12));
        return h;
    }

    static int Validate(ReadOnlySpan<byte> h, long fileLength)
    {
        if (h.Length != PrefixLength || !h[..8].SequenceEqual("SNOBJ001"u8) ||
            BinaryPrimitives.ReadUInt16LittleEndian(h[8..]) != 1 || h[10] != 2 || h[11] != 0 ||
            !h.Slice(12,16).SequenceEqual(VaultId) || !h.Slice(28,16).SequenceEqual(EpochId) ||
            !h.Slice(44,16).SequenceEqual(ObjectId) || BinaryPrimitives.ReadUInt16LittleEndian(h[92..]) != 0 ||
            BinaryPrimitives.ReadUInt16LittleEndian(h[94..]) != 1 || BinaryPrimitives.ReadUInt16LittleEndian(h[96..]) != 1)
            throw new InvalidDataException("Unsupported or mismatched research envelope.");
        ulong n = BinaryPrimitives.ReadUInt64LittleEndian(h[98..]);
        if (n > MaxLength || fileLength != PrefixLength + (long)n + 16)
            throw new InvalidDataException("Invalid bounded length.");
        return (int)n;
    }

    static void Key(ReadOnlySpan<byte> h, Span<byte> key)
    {
        byte[] domain = "SafeNook/v1/object-key\0"u8.ToArray();
        byte[] info = new byte[domain.Length + 106];
        domain.CopyTo(info, 0); h[..106].CopyTo(info.AsSpan(domain.Length));
        HKDF.DeriveKey(HashAlgorithmName.SHA256, VaultKey, key, h.Slice(12,16), info);
    }

    static byte[] Aad(ReadOnlySpan<byte> h, bool corrupt = false)
    {
        byte[] domain = "SafeNook/v1/object\0"u8.ToArray();
        byte[] aad = new byte[domain.Length + PrefixLength];
        domain.CopyTo(aad,0); h.CopyTo(aad.AsSpan(domain.Length));
        if (corrupt) aad[0] ^= 1;
        return aad;
    }

    static double EncryptFile(string source, string destination)
    {
        using var input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read, 1);
        if (input.Length > MaxLength) throw new InvalidDataException("Input too large.");
        int n = checked((int)input.Length);
        byte[] plaintext = new byte[n]; byte[] ciphertext = new byte[n];
        byte[] h = Header(n); byte[] aad = Aad(h);
        Span<byte> key = stackalloc byte[32]; Span<byte> tag = stackalloc byte[16];
        try
        {
            input.ReadExactly(plaintext);
            if (input.ReadByte() != -1) throw new InvalidDataException("Input changed.");
            Key(h,key);
            using var aes = new AesGcm(key,16);
            long start = Stopwatch.GetTimestamp();
            aes.Encrypt(h.AsSpan(106,12),plaintext,ciphertext,tag,aad);
            double cryptoMs = Stopwatch.GetElapsedTime(start).TotalMilliseconds;
            using var output = new FileStream(destination,FileMode.CreateNew,FileAccess.Write,FileShare.None,1);
            output.Write(h); output.Write(ciphertext); output.Write(tag); output.Flush();
            return cryptoMs;
        }
        finally { CryptographicOperations.ZeroMemory(plaintext); CryptographicOperations.ZeroMemory(key); }
    }

    static double DecryptFile(string source, string destination, bool corruptAad = false)
    {
        using var input = new FileStream(source,FileMode.Open,FileAccess.Read,FileShare.Read,1);
        byte[] h = new byte[PrefixLength]; input.ReadExactly(h);
        int n = Validate(h,input.Length);
        byte[] ciphertext = new byte[n]; byte[] plaintext = new byte[n];
        Span<byte> key = stackalloc byte[32]; Span<byte> tag = stackalloc byte[16];
        try
        {
            input.ReadExactly(ciphertext); input.ReadExactly(tag);
            if (input.ReadByte() != -1) throw new InvalidDataException("Unexpected suffix.");
            Key(h,key);
            using var aes = new AesGcm(key,16);
            long start = Stopwatch.GetTimestamp();
            aes.Decrypt(h.AsSpan(106,12),ciphertext,tag,plaintext,Aad(h,corruptAad));
            double cryptoMs = Stopwatch.GetElapsedTime(start).TotalMilliseconds;
            // Publication gate: destination does not exist until whole-message authentication succeeds.
            using var output = new FileStream(destination,FileMode.CreateNew,FileAccess.Write,FileShare.None,1);
            output.Write(plaintext); output.Flush();
            return cryptoMs;
        }
        finally { CryptographicOperations.ZeroMemory(plaintext); CryptographicOperations.ZeroMemory(key); }
    }

    static void Prepare(string directory)
    {
        foreach (int size in Sizes)
        {
            string input = Path.Combine(directory,$"input-{size}.bin");
            if (!File.Exists(input))
            {
                using var f = File.Create(input);
                byte[] block = new byte[65536];
                for (int i=0;i<block.Length;i++) block[i]=(byte)(i*31+7);
                for (int remaining=size*1024*1024;remaining>0;remaining-=block.Length)
                    f.Write(block.AsSpan(0,Math.Min(remaining,block.Length)));
            }
            string encrypted = Path.Combine(directory,$"input-{size}.enc");
            if (!File.Exists(encrypted)) EncryptFile(input,encrypted);
        }
        Console.WriteLine("Prepared synthetic inputs.");
    }

    static void Check(string directory)
    {
        Prepare(directory);
        string run = Path.Combine(directory,"checks-"+Guid.NewGuid().ToString("N")); Directory.CreateDirectory(run);
        int cases=0;
        foreach (int size in Sizes)
        {
            string plain=Path.Combine(directory,$"input-{size}.bin"), enc=Path.Combine(directory,$"input-{size}.enc");
            string output=Path.Combine(run,$"roundtrip-{size}.bin"); DecryptFile(enc,output);
            using (var a=File.OpenRead(plain)) using(var b=File.OpenRead(output))
                if(!SHA256.HashData(a).AsSpan().SequenceEqual(SHA256.HashData(b))) throw new Exception("Round-trip mismatch.");
            cases++;
            foreach(string mode in new[]{"ciphertext","tag","aad","truncate","append","context","length"})
            {
                if(mode=="ciphertext" && size==0) continue;
                byte[] bytes=File.ReadAllBytes(enc);
                switch(mode)
                {
                    case "ciphertext": bytes[PrefixLength]^=1; break;
                    case "tag": bytes[^1]^=1; break;
                    case "context": bytes[44]^=1; break;
                    case "length": bytes[98]^=1; break;
                    case "truncate": Array.Resize(ref bytes,bytes.Length-1); break;
                    case "append": Array.Resize(ref bytes,bytes.Length+1); break;
                }
                string bad=Path.Combine(run,$"bad-{size}-{mode}.enc"), dest=Path.Combine(run,$"bad-{size}-{mode}.out");
                File.WriteAllBytes(bad,bytes); bool rejected=false;
                try { DecryptFile(bad,dest,mode=="aad"); }
                catch(Exception ex) when(ex is CryptographicException or InvalidDataException or EndOfStreamException) { rejected=true; }
                if(!rejected || File.Exists(dest)) throw new Exception("Invalid input was published: "+mode);
                cases++;
            }
        }
        // Public NIST AES256-GCM zero-key, zero-IV, one-zero-block known-answer vector.
        byte[] zeroKey=new byte[32], zeroNonce=new byte[12], zeroPlain=new byte[16], ct=new byte[16], tag=new byte[16];
        using(var aes=new AesGcm(zeroKey,16)) aes.Encrypt(zeroNonce,zeroPlain,ct,tag);
        if(!ct.AsSpan().SequenceEqual(Convert.FromHexString("cea7403d4d606b6e074ec5d3baf39d18")) ||
           !tag.AsSpan().SequenceEqual(Convert.FromHexString("d0d1c8a799996bf0265b98b5d48ab919"))) throw new Exception("AES256 GCM vector mismatch.");
        cases++;
        Console.WriteLine($"PASS {cases} cases; no output on invalid input; AES-GCM supported={AesGcm.IsSupported}");
    }

    static void Warmup()
    {
        byte[] p=new byte[65536],c=new byte[65536],tag=new byte[16],nonce=new byte[12];
        using var aes=new AesGcm(VaultKey,16);
        aes.Encrypt(nonce,p,c,tag); aes.Decrypt(nonce,c,tag,p);
        CryptographicOperations.ZeroMemory(p);
    }

    static void Measure(string directory,int size,string op)
    {
        if(!Sizes.Contains(size) || (op!="encrypt" && op!="decrypt")) throw new ArgumentException("Invalid measure selection.");
        Warmup(); GC.Collect(); GC.WaitForPendingFinalizers(); GC.Collect();
        using var monitor = new MemoryMonitor(); monitor.Start();
        long allocated=GC.GetAllocatedBytesForCurrentThread(), totalAllocated=GC.GetTotalAllocatedBytes(true);
        string input=Path.Combine(directory,$"input-{size}."+(op=="encrypt"?"bin":"enc"));
        string output=Path.Combine(directory,$"measurement-{op}-{size}-{Guid.NewGuid():N}.bin");
        long start=Stopwatch.GetTimestamp();
        double cryptoMs=op=="encrypt"?EncryptFile(input,output):DecryptFile(input,output);
        double elapsed=Stopwatch.GetElapsedTime(start).TotalMilliseconds;
        long allocatedDelta=GC.GetAllocatedBytesForCurrentThread()-allocated;
        long totalAllocatedDelta=GC.GetTotalAllocatedBytes(true)-totalAllocated;
        monitor.Stop();
        var result=new Measurement("BCL-AesGcm",Environment.Version.ToString(),System.Runtime.InteropServices.RuntimeInformation.RuntimeIdentifier,size,op,
            elapsed,cryptoMs,monitor.BaseWs,monitor.BasePrivate,monitor.PeakWs,monitor.PeakPrivate,monitor.LifetimePeakWs,allocatedDelta,totalAllocatedDelta);
        Console.WriteLine(JsonSerializer.Serialize(result,MeasureJson.Default.Measurement));
    }
}

internal sealed class MemoryMonitor : IDisposable
{
    readonly Process process=Process.GetCurrentProcess();
    readonly ManualResetEventSlim stop=new(false);
    Thread? thread;
    public long BaseWs,BasePrivate,PeakWs,PeakPrivate,LifetimePeakWs;
    public void Start()
    {
        Sample(); BaseWs=PeakWs; BasePrivate=PeakPrivate;
        thread=new Thread(()=>{while(!stop.Wait(1)) Sample();}){IsBackground=true}; thread.Start();
    }
    void Sample()
    {
        process.Refresh(); PeakWs=Math.Max(PeakWs,process.WorkingSet64); PeakPrivate=Math.Max(PeakPrivate,process.PrivateMemorySize64);
        LifetimePeakWs=Math.Max(LifetimePeakWs,process.PeakWorkingSet64);
    }
    public void Stop(){stop.Set();thread?.Join();Sample();}
    public void Dispose(){stop.Dispose();process.Dispose();}
}
internal sealed record Measurement(string Algorithm,string Runtime,string Rid,int SizeMiB,string Operation,double ElapsedMs,double CryptoMs,
    long BaselineWorkingSetBytes,long BaselinePrivateBytes,long SampledPeakWorkingSetBytes,long SampledPeakPrivateBytes,long LifetimePeakWorkingSetBytes,
    long MainThreadAllocatedBytes,long TotalAllocatedBytes);
[JsonSerializable(typeof(Measurement))]
internal partial class MeasureJson : JsonSerializerContext;
