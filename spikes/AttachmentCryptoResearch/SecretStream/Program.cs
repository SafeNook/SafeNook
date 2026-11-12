using System.Buffers.Binary;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

// Research only: synthetic key and framing, not a production wire format.
internal static unsafe partial class Program
{
    private const int Chunk = 65536;
    private const int Max = 25 * 1024 * 1024;
    private static readonly byte[] Key = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
    private static readonly byte[] Context = "SafeNook/SN-002-R1/secretstream/research-only"u8.ToArray();
    private static long primitiveTicks;

    private static int Main(string[] args)
    {
        try
        {
            if (SodiumInit() < 0 || StateBytes() != 52 || HeaderBytes() != 24 || ABytes() != 17 || KeyBytes() != 32)
                throw new InvalidOperationException("Unexpected libsodium ABI.");
            if (args[0] == "prepare") { Prepare(args[1], int.Parse(args[2], CultureInfo.InvariantCulture)); return 0; }
            if (args[0] == "test") { Tests(args[1]); return 0; }
            if (args[0] == "bench") { Bench(args[1], args[2], args[3]); return 0; }
            throw new ArgumentException("Expected prepare/test/bench.");
        }
        catch (Exception ex) { Console.Error.WriteLine(ex.GetType().Name + ": " + ex.Message); return 1; }
    }

    private static void Prepare(string path, int size)
    {
        using var file = File.Create(path);
        byte[] buffer = new byte[Chunk];
        RandomNumberGenerator.Fill(buffer);
        while (size > 0) { int n = Math.Min(size, Chunk); file.Write(buffer, 0, n); size -= n; }
        CryptographicOperations.ZeroMemory(buffer);
    }

    // Framing: LE64 plaintext size, native header24, fixed-size chunk ciphertexts.
    // Every native call binds context + total length + index + plaintext chunk length.
    private static byte[] Aad(long length, int index, int chunkLength, byte[] context)
    {
        byte[] aad = new byte[context.Length + 16];
        context.CopyTo(aad, 0);
        BinaryPrimitives.WriteInt64LittleEndian(aad.AsSpan(context.Length), length);
        BinaryPrimitives.WriteInt32LittleEndian(aad.AsSpan(context.Length + 8), index);
        BinaryPrimitives.WriteInt32LittleEndian(aad.AsSpan(context.Length + 12), chunkLength);
        return aad;
    }

    private static void Encrypt(string input, string output)
    {
        using var source = File.OpenRead(input);
        long length = source.Length;
        if (length > Max) throw new InvalidDataException("Size limit.");
        byte[] buffer = new byte[Chunk], encrypted = new byte[Chunk + 17], header = new byte[24];
        void* state = NativeMemory.Alloc(StateBytes());
        try
        {
            fixed (byte* k = Key, h = header)
                if (InitPush(state, h, k) != 0) throw new CryptographicException("Init failed.");
            using var target = File.Create(output);
            Span<byte> prefix = stackalloc byte[8]; BinaryPrimitives.WriteInt64LittleEndian(prefix, length);
            target.Write(prefix); target.Write(header);
            int count = Math.Max(1, (int)((length + Chunk - 1) / Chunk));
            for (int i = 0; i < count; i++)
            {
                int n = (int)Math.Min(Chunk, length - (long)i * Chunk);
                source.ReadExactly(buffer.AsSpan(0, n));
                byte[] aad = Aad(length, i, n, Context);
                ulong written = 0;
                fixed (byte* m = buffer, c = encrypted, a = aad)
                {
                    long start = Stopwatch.GetTimestamp();
                    int result = Push(state, c, &written, m, (ulong)n, a, (ulong)aad.Length, i == count - 1 ? (byte)3 : (byte)0);
                    primitiveTicks += Stopwatch.GetTimestamp() - start;
                    if (result != 0 || written != (ulong)n + 17) throw new CryptographicException("Encrypt failed.");
                }
                target.Write(encrypted.AsSpan(0, (int)written));
            }
            if (source.ReadByte() != -1) throw new IOException("Source changed.");
            target.Flush(); // OS cache flush only, not a durable COW transaction benchmark.
        }
        finally { CryptographicOperations.ZeroMemory(buffer); CryptographicOperations.ZeroMemory(new Span<byte>(state, (int)StateBytes())); NativeMemory.Free(state); }
    }

    private static void Decrypt(string input, string output, byte[]? differentContext = null)
    {
        using var source = File.OpenRead(input);
        Span<byte> prefix = stackalloc byte[8]; source.ReadExactly(prefix);
        long length = BinaryPrimitives.ReadInt64LittleEndian(prefix);
        if (length < 0 || length > Max) throw new InvalidDataException("Size limit.");
        int count = Math.Max(1, (int)((length + Chunk - 1) / Chunk));
        if (source.Length != 32 + length + 17L * count) throw new InvalidDataException("Exact length mismatch.");
        byte[] header = new byte[24]; source.ReadExactly(header);
        byte[] plaintext = new byte[(int)length], encrypted = new byte[Chunk + 17];
        // Ensure non-null pointer even for the required empty final message.
        byte[] empty = new byte[1];
        void* state = NativeMemory.Alloc(StateBytes());
        try
        {
            fixed (byte* k = Key, h = header)
                if (InitPull(state, h, k) != 0) throw new CryptographicException("Init failed.");
            for (int i = 0; i < count; i++)
            {
                int n = (int)Math.Min(Chunk, length - (long)i * Chunk);
                source.ReadExactly(encrypted.AsSpan(0, n + 17));
                byte[] aad = Aad(length, i, n, differentContext ?? Context);
                ulong written = 0; byte tag = 255;
                fixed (byte* p = plaintext, e = empty, c = encrypted, a = aad)
                {
                    long start = Stopwatch.GetTimestamp();
                    int result = Pull(state, n == 0 ? e : p + i * Chunk, &written, &tag, c, (ulong)n + 17, a, (ulong)aad.Length);
                    primitiveTicks += Stopwatch.GetTimestamp() - start;
                    if (result != 0 || written != (ulong)n || tag != (i == count - 1 ? 3 : 0))
                        throw new CryptographicException("Authentication failed.");
                }
            }
            if (source.ReadByte() != -1) throw new InvalidDataException("Trailing bytes.");
            // No output opened or exposed until every chunk and FINAL has authenticated.
            File.WriteAllBytes(output, plaintext);
        }
        finally { CryptographicOperations.ZeroMemory(plaintext); CryptographicOperations.ZeroMemory(new Span<byte>(state, (int)StateBytes())); NativeMemory.Free(state); }
    }

    private static void Tests(string dir)
    {
        Directory.CreateDirectory(dir);
        int checks = 0;
        foreach (int size in new[] { 0, 1, 65535, 65536, 65537, 1048576, 5242880, 10485760, 26214400 })
        {
            string plain = Path.Combine(dir, "plain"), cipher = Path.Combine(dir, "cipher"), restored = Path.Combine(dir, "restored");
            Prepare(plain, size); Encrypt(plain, cipher); Decrypt(cipher, restored);
            if (!SHA256.HashData(File.ReadAllBytes(plain)).AsSpan().SequenceEqual(SHA256.HashData(File.ReadAllBytes(restored)))) throw new Exception("Roundtrip failed.");
            checks++;
            byte[] original = File.ReadAllBytes(cipher);
            foreach (string mutation in new[] { "ciphertext", "tag", "aad", "truncate", "append", "header", "length" })
            {
                byte[] changed = (byte[])original.Clone();
                if (mutation == "ciphertext") changed[32] ^= 1;
                if (mutation == "tag") changed[^1] ^= 1;
                if (mutation == "header") changed[8] ^= 1;
                if (mutation == "length") changed[0] ^= 1;
                if (mutation == "truncate") changed = changed[..^1];
                if (mutation == "append") changed = [.. changed, (byte)0];
                string bad = Path.Combine(dir, "bad"), absent = Path.Combine(dir, "must-not-exist");
                File.WriteAllBytes(bad, changed);
                bool rejected = false;
                try { Decrypt(bad, absent, mutation == "aad" ? "Wrong context"u8.ToArray() : null); }
                catch (Exception ex) when (ex is CryptographicException or InvalidDataException or EndOfStreamException) { rejected = true; }
                if (!rejected || File.Exists(absent)) throw new Exception("Negative test exposed output: " + mutation);
                checks++;
            }
            if (size >= 2 * Chunk)
            {
                byte[] changed = (byte[])original.Clone(); int width = Chunk + 17;
                original.AsSpan(32 + width, width).CopyTo(changed.AsSpan(32, width));
                original.AsSpan(32, width).CopyTo(changed.AsSpan(32 + width, width));
                string bad = Path.Combine(dir, "reordered"), absent = Path.Combine(dir, "must-not-exist"); File.WriteAllBytes(bad, changed);
                bool rejected = false; try { Decrypt(bad, absent); } catch (CryptographicException) { rejected = true; }
                if (!rejected || File.Exists(absent)) throw new Exception("Reorder accepted."); checks++;
            }
        }
        Console.WriteLine($"PASS checks={checks}; libsodium={Marshal.PtrToStringUTF8(Version())}; statebytes={StateBytes()}; AOT={(!RuntimeFeature.IsDynamicCodeSupported)}");
    }

    private static void Bench(string operation, string input, string output)
    {
        string warm = output + ".warm", warmCipher = warm + ".enc", warmPlain = warm + ".dec";
        Prepare(warm, Chunk); Encrypt(warm, warmCipher); Decrypt(warmCipher, warmPlain);
        File.Delete(warm); File.Delete(warmCipher); File.Delete(warmPlain);
        GC.Collect(); GC.WaitForPendingFinalizers(); GC.Collect(); primitiveTicks = 0;
        using Process process = Process.GetCurrentProcess(); process.Refresh();
        long baseWs = process.WorkingSet64, basePrivate = process.PrivateMemorySize64, lifetimeBefore = process.PeakWorkingSet64;
        long peakWs = baseWs, peakPrivate = basePrivate; bool stop = false;
        Thread sampler = new(() => { using Process sampled = Process.GetCurrentProcess(); while (!Volatile.Read(ref stop)) { sampled.Refresh(); peakWs = Math.Max(peakWs, sampled.WorkingSet64); peakPrivate = Math.Max(peakPrivate, sampled.PrivateMemorySize64); Thread.Sleep(1); } });
        sampler.Start(); long allocated = GC.GetTotalAllocatedBytes(true); Stopwatch timer = Stopwatch.StartNew();
        if (operation == "encrypt") Encrypt(input, output); else if (operation == "decrypt") Decrypt(input, output); else throw new ArgumentException("Operation.");
        timer.Stop(); long allocation = GC.GetTotalAllocatedBytes(true) - allocated;
        process.Refresh(); peakWs = Math.Max(peakWs, process.WorkingSet64); peakPrivate = Math.Max(peakPrivate, process.PrivateMemorySize64);
        Volatile.Write(ref stop, true); sampler.Join();
        Console.WriteLine(string.Join(',', operation, new FileInfo(input).Length.ToString(CultureInfo.InvariantCulture), timer.Elapsed.TotalMilliseconds.ToString("F4", CultureInfo.InvariantCulture), (primitiveTicks * 1000.0 / Stopwatch.Frequency).ToString("F4", CultureInfo.InvariantCulture), baseWs, peakWs, basePrivate, peakPrivate, lifetimeBefore, process.PeakWorkingSet64, allocation));
    }

    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    [LibraryImport("libsodium", EntryPoint = "sodium_init")] private static partial int SodiumInit();
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    [LibraryImport("libsodium", EntryPoint = "sodium_version_string")] private static partial nint Version();
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    [LibraryImport("libsodium", EntryPoint = "crypto_secretstream_xchacha20poly1305_statebytes")] private static partial nuint StateBytes();
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    [LibraryImport("libsodium", EntryPoint = "crypto_secretstream_xchacha20poly1305_headerbytes")] private static partial nuint HeaderBytes();
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    [LibraryImport("libsodium", EntryPoint = "crypto_secretstream_xchacha20poly1305_abytes")] private static partial nuint ABytes();
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    [LibraryImport("libsodium", EntryPoint = "crypto_secretstream_xchacha20poly1305_keybytes")] private static partial nuint KeyBytes();
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    [LibraryImport("libsodium", EntryPoint = "crypto_secretstream_xchacha20poly1305_init_push")] private static partial int InitPush(void* state, byte* header, byte* key);
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    [LibraryImport("libsodium", EntryPoint = "crypto_secretstream_xchacha20poly1305_init_pull")] private static partial int InitPull(void* state, byte* header, byte* key);
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    [LibraryImport("libsodium", EntryPoint = "crypto_secretstream_xchacha20poly1305_push")] private static partial int Push(void* state, byte* ciphertext, ulong* ciphertextLength, byte* message, ulong length, byte* aad, ulong aadLength, byte tag);
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    [LibraryImport("libsodium", EntryPoint = "crypto_secretstream_xchacha20poly1305_pull")] private static partial int Pull(void* state, byte* message, ulong* messageLength, byte* tag, byte* ciphertext, ulong length, byte* aad, ulong aadLength);
}
