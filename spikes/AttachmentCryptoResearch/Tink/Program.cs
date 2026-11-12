using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using TinkStreamingAead;

// Research only: synthetic fixed test key. Never use this code or key for secrets.
internal static class Program
{
    private static readonly byte[] Key = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
    private static readonly int[] Sizes = [0, 1 << 20, 5 << 20, 10 << 20, 25 << 20];
    private static byte[] Aad(int size) => Encoding.ASCII.GetBytes($"SafeNook/research/tink-1MiB/file/{size.ToString(CultureInfo.InvariantCulture)}");

    private static int Main(string[] args)
    {
        if (args.Length == 0) throw new ArgumentException("Use prepare, selftest or measure.");
        string directory = Path.GetFullPath(args.Length > 1 ? args[1] : "artifacts/tink-research/data");
        Directory.CreateDirectory(directory);
        if (args[0] == "prepare")
        {
            foreach (int size in Sizes.Append(65536))
            {
                string input = Path.Combine(directory, $"{size}.input");
                using (var stream = File.Create(input))
                {
                    byte[] block = new byte[65536];
                    for (int i = 0; i < block.Length; i++) block[i] = (byte)(i * 31 + 17);
                    for (int done = 0; done < size; done += block.Length) stream.Write(block, 0, Math.Min(block.Length, size - done));
                }
                EncryptFile(directory, size, "cipher");
            }
            Console.WriteLine("Prepared synthetic files.");
            return 0;
        }
        if (args[0] == "selftest") return SelfTest();
        string op = args[2];
        int bytes = int.Parse(args[3], CultureInfo.InvariantCulture);
        int iteration = int.Parse(args[4], CultureInfo.InvariantCulture);
        if (op != "encrypt" && op != "decrypt") throw new ArgumentException("Unknown operation.");
        if (!Sizes.Contains(bytes)) throw new ArgumentException("Unsupported research size.");
        Run(op, directory, 65536, "warmup");
        GC.Collect(); GC.WaitForPendingFinalizers(); GC.Collect();
        using var process = Process.GetCurrentProcess();
        process.Refresh();
        long baselineWs = process.WorkingSet64, baselinePrivate = process.PrivateMemorySize64;
        long sampledWs = baselineWs, sampledPrivate = baselinePrivate;
        bool running = true;
        using var ready = new ManualResetEventSlim();
        var sampler = new Thread(() =>
        {
            using var sample = Process.GetCurrentProcess();
            ready.Set();
            while (Volatile.Read(ref running))
            {
                sample.Refresh();
                sampledWs = Math.Max(sampledWs, sample.WorkingSet64);
                sampledPrivate = Math.Max(sampledPrivate, sample.PrivateMemorySize64);
                Thread.Sleep(1);
            }
        });
        sampler.Start(); ready.Wait();
        long allocatedBefore = GC.GetTotalAllocatedBytes(true);
        var watch = Stopwatch.StartNew();
        Run(op, directory, bytes, "measured");
        watch.Stop();
        long allocated = GC.GetTotalAllocatedBytes(true) - allocatedBefore;
        Volatile.Write(ref running, false); sampler.Join();
        process.Refresh();
        sampledWs = Math.Max(sampledWs, process.WorkingSet64);
        sampledPrivate = Math.Max(sampledPrivate, process.PrivateMemorySize64);
        Console.WriteLine(FormattableString.Invariant($"TinkStreamingAead-1.0.1-1MiB,{op},{bytes},{iteration},{watch.Elapsed.TotalMilliseconds:F3},{allocated},{baselineWs},{process.PeakWorkingSet64},{sampledWs},{baselinePrivate},{sampledPrivate}"));
        return 0;
    }

    private static void Run(string operation, string directory, int size, string suffix)
    {
        if (operation == "encrypt") EncryptFile(directory, size, suffix);
        else DecryptFile(directory, size, suffix);
    }

    private static void EncryptFile(string directory, int size, string suffix)
    {
        using var input = new FileStream(Path.Combine(directory, $"{size}.input"), FileMode.Open, FileAccess.Read, FileShare.Read, 65536);
        using var output = new FileStream(Path.Combine(directory, $"{size}.{suffix}"), FileMode.Create, FileAccess.Write, FileShare.None, 65536);
        Aes256GcmHkdf1MB.Encrypt(Key, input, output, Aad(size));
        output.Flush();
    }

    private static void DecryptFile(string directory, int size, string suffix)
    {
        using var input = new FileStream(Path.Combine(directory, $"{size}.cipher"), FileMode.Open, FileAccess.Read, FileShare.Read, 65536);
        if (input.Length != Aes256GcmHkdf1MB.GetCiphertextLength(size)) throw new CryptographicException("Length mismatch.");
        byte[] held = new byte[size];
        try
        {
            using var quarantine = new MemoryStream(held, writable: true);
            Aes256GcmHkdf1MB.Decrypt(Key, input, quarantine, Aad(size));
            if (quarantine.Position != size) throw new CryptographicException("Length mismatch.");
            // Publish only after the complete stream authenticates. No ToArray copy.
            using var output = new FileStream(Path.Combine(directory, $"{size}.{suffix}"), FileMode.Create, FileAccess.Write, FileShare.None, 65536);
            output.Write(held); output.Flush();
        }
        finally { CryptographicOperations.ZeroMemory(held); }
        // Upstream internal pooled plaintext buffers are not cleared; see research report.
    }

    private static byte[] Encrypt(byte[] plain, byte[] aad)
    {
        using var input = new MemoryStream(plain, writable: false);
        using var output = new MemoryStream();
        Aes256GcmHkdf1MB.Encrypt(Key, input, output, aad);
        return output.ToArray();
    }

    private static bool Rejects(byte[] cipher, byte[] aad, int expectedLength)
    {
        byte[] held = new byte[expectedLength];
        using var published = new MemoryStream();
        try
        {
            using var input = new MemoryStream(cipher, writable: false);
            using var quarantine = new MemoryStream(held, writable: true);
            Aes256GcmHkdf1MB.Decrypt(Key, input, quarantine, aad);
            published.Write(held);
            return false;
        }
        catch (CryptographicException) { Require(published.Length == 0, "Failure published plaintext"); return true; }
        finally { CryptographicOperations.ZeroMemory(held); }
    }

    private static int SelfTest()
    {
        int checks = 0;
        foreach (int size in Sizes.Concat([1, 1048519, 1048520, 1048521, 2097080, 2097081]))
        {
            byte[] plain = new byte[size];
            for (int i = 0; i < size; i++) plain[i] = (byte)(i * 31 + 17);
            byte[] aad = Aad(size), cipher = Encrypt(plain, aad), held = new byte[size];
            try
            {
                using var input = new MemoryStream(cipher, writable: false);
                using var quarantine = new MemoryStream(held, writable: true);
                Aes256GcmHkdf1MB.Decrypt(Key, input, quarantine, aad);
                Require(quarantine.Position == size && plain.AsSpan().SequenceEqual(held), "Round trip"); checks++;
                Require(cipher.Length == Aes256GcmHkdf1MB.GetCiphertextLength(size), "Cipher length"); checks++;
                byte[] mutated = (byte[])cipher.Clone(); mutated[Math.Min(40, mutated.Length - 1)] ^= 1;
                Require(Rejects(mutated, aad, size), "Cipher mutation"); checks++;
                mutated = (byte[])cipher.Clone(); mutated[^1] ^= 1;
                Require(Rejects(mutated, aad, size), "Tag mutation"); checks++;
                byte[] wrongAad = (byte[])aad.Clone(); wrongAad[0] ^= 1;
                Require(Rejects(cipher, wrongAad, size), "AAD mutation"); checks++;
                Require(Rejects(cipher[..^1], aad, size), "Truncation"); checks++;
                Require(Rejects([.. cipher, 0], aad, size), "Append"); checks++;
                Require(Rejects(cipher[..40], aad, size), "Header only"); checks++;
            }
            finally { CryptographicOperations.ZeroMemory(plain); CryptographicOperations.ZeroMemory(held); }
        }
        Console.WriteLine($"SELFTEST PASS checks={checks}; fixed profile=1MiB; official Google implementation NOT tested; no external plaintext publication on failure.");
        return 0;
    }

    private static void Require(bool condition, string label)
    {
        if (!condition) throw new InvalidOperationException($"Self-test failed: {label}");
    }
}
