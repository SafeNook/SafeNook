using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;

using NSec.Cryptography;

namespace SafeNook.Spikes.NSecAot;

/// <summary>
/// Spike F-4: checks NSec.Cryptography under native AOT. Prints PASS/FAIL per check and
/// "SUMMARY key=value" lines that the workflow copies into the job summary.
/// Exit code is 0 only if every check passed.
/// </summary>
internal static partial class Program
{
    private static int s_failures;

    private static int Main()
    {
        Section("Environment", PrintEnvironment);
        Section("Argon2id known-answer tests", CheckArgon2idVectors);
        Section("Argon2id parameter limits", ProbeArgon2idParameters);
        Section("Ed25519 (RFC 8032, TEST 1)", CheckEd25519);
        Section("Argon2id timing", MeasureArgon2id);

        Console.WriteLine();
        Console.WriteLine(s_failures == 0 ? "RESULT: PASS" : $"RESULT: FAIL ({s_failures} failed)");
        Summary("result", s_failures == 0 ? "PASS" : $"FAIL ({s_failures})");
        return s_failures == 0 ? 0 : 1;
    }

    private static void PrintEnvironment()
    {
        Console.WriteLine($"rid:       {RuntimeInformation.RuntimeIdentifier}");
        Console.WriteLine($"os:        {RuntimeInformation.OSDescription}");
        Console.WriteLine($"arch:      {RuntimeInformation.ProcessArchitecture}");
        Console.WriteLine($"framework: {RuntimeInformation.FrameworkDescription}");

        var nextToBinary = Directory.GetFiles(AppContext.BaseDirectory, "*sodium*")
            .Select(Path.GetFileName)
            .ToArray();
        var linkage = nextToBinary.Length == 0 ? "static (no libsodium file next to the binary)" : string.Join(", ", nextToBinary);
        Console.WriteLine($"libsodium: {linkage}");
        Summary("libsodium-file", nextToBinary.Length == 0 ? "none" : string.Join(" ", nextToBinary));

        // Loads libsodium the same way NSec does (dynamically, or via DirectPInvoke when statically linked).
        var version = Marshal.PtrToStringAnsi(SodiumVersionString()) ?? "?";
        Console.WriteLine($"libsodium version: {version}");
        Summary("libsodium-version", version);
    }

    // Vectors from libsodium 1.0.22, test/default/pwhash_argon2id.c and pwhash_argon2id.exp:
    // https://github.com/jedisct1/libsodium/blob/1.0.22-RELEASE/test/default/pwhash_argon2id.c
    // All are Argon2id v1.3 (0x13), one lane, no secret, no associated data.
    // The RFC 9106 vector can't be used: it needs a secret, associated data and p=4, none of which
    // libsodium supports. The phc-winner-argon2 vectors use an 8-byte salt; libsodium requires 16.
    private static void CheckArgon2idVectors()
    {
        // tv(), tests[0]: expected output is line 1 of pwhash_argon2id.exp. crypto_pwhash reads only the
        // first 16 bytes of salt_hex and uses memlimit / 1024 KiB (7256678 / 1024 = 7086).
        Argon2idVector(
            "libsodium tv[0] (t=5, m=7086 KiB, 155-byte output)",
            password: Convert.FromHexString(
                "a347ae92bce9f80f6f595a4480fc9c2fe7e7d7148d371e9487d75f5c23008ffae0" +
                "65577a928febd9b1973a5a95073acdbeb6a030cfc0d79caa2dc5cd011cef02c08d" +
                "a232d76d52dfbca38ca8dcbd665b17d1665f7cf5fe59772ec909733b24de97d6f5" +
                "8d220b20c60d7c07ec1fd93c52c31020300c6c1facd77937a597c7a6"),
            salt: Convert.FromHexString("5541fbc995d5c197ba290346d2c559de"),
            memoryKiB: 7256678 / 1024,
            passes: 5,
            expectedHex:
                "18acec5d6507739f203d1f5d9f1d862f7c2cdac4f19d2bdff64487e60d969e3ced615337b9eec6ac4461c6ca07f0939741e5" +
                "7c24d0005c7ea171a0ee1e7348249d135b38f222e4dad7b9a033ed83f5ca27277393e316582033c74affe2566a2bea47f91f" +
                "0fd9fe49ece7e1f79f3ad6e9b23e0277c8ecc4b313225748dd2a80f5679534a0700e246a79a49b3f74eb89ec6205fe1eeb94" +
                "1c73b1fcf1");

        // tv3(), tests[2]: "$argon2id$v=19$m=4882,t=2,p=1$bA81arsiXysd3WbTRzmEOw$Nm8QBM+7RH1DXo9rvp5cwKEOOOfD2g6JuxlXihoNcpE"
        // with an empty password; crypto_pwhash_str_verify accepts it (not listed as a failure in the .exp file).
        Argon2idVector(
            "libsodium tv3[2] (empty password, t=2, m=4882 KiB)",
            password: [],
            salt: Convert.FromBase64String("bA81arsiXysd3WbTRzmEOw=="),
            memoryKiB: 4882,
            passes: 2,
            expectedHex: Convert.ToHexStringLower(Convert.FromBase64String("Nm8QBM+7RH1DXo9rvp5cwKEOOOfD2g6JuxlXihoNcpE=")));

        // tv3(), tests[4]: "$argon2id$v=19$m=4096,t=19,p=1$PkEgMTYtYnl0ZXMgc2FsdA$ltB/ue1kPtBMBGfsysMpPigE6hiNEKZ9vs8vLNVDQGA"
        // (salt is ">A 16-bytes salt"); crypto_pwhash_str_verify accepts it.
        Argon2idVector(
            "libsodium tv3[4] (t=19, m=4096 KiB)",
            password: "^T5H$JYt39n%K*j:W]!1s?vg!:jGi]Ax?..l7[p0v:1jHTpla9;]bUN;?bWyCbtqg "u8.ToArray(),
            salt: ">A 16-bytes salt"u8.ToArray(),
            memoryKiB: 4096,
            passes: 19,
            expectedHex: Convert.ToHexStringLower(Convert.FromBase64String("ltB/ue1kPtBMBGfsysMpPigE6hiNEKZ9vs8vLNVDQGA=")));
    }

    private static void Argon2idVector(string name, byte[] password, byte[] salt, long memoryKiB, long passes, string expectedHex)
    {
        var expected = Convert.FromHexString(expectedHex);
        var algorithm = new Argon2id(new Argon2Parameters
        {
            DegreeOfParallelism = 1,
            MemorySize = memoryKiB,
            NumberOfPasses = passes,
        });

        var actual = algorithm.DeriveBytes(password, salt, expected.Length);
        Check(name, actual.AsSpan().SequenceEqual(expected));
    }

    // NSec validates parameters in the Argon2id constructor (mirroring libsodium's pwhash_argon2id.c) and the
    // salt length in DeriveBytes. Each probe records whether NSec accepts the value and compares it with the
    // documented behaviour, so a change in a future NSec release shows up as FAIL.
    private static void ProbeArgon2idParameters()
    {
        ExpectArgon2Parameters("p=1 accepted", p: 1, m: 65536, t: 3, accepted: true);
        ExpectArgon2Parameters("p=2 rejected", p: 2, m: 65536, t: 3, accepted: false);
        ExpectArgon2Parameters("p=4 rejected", p: 4, m: 65536, t: 3, accepted: false);
        ExpectArgon2Parameters("m=8 KiB (minimum) accepted", p: 1, m: 8, t: 3, accepted: true);
        ExpectArgon2Parameters("m=7 KiB rejected", p: 1, m: 7, t: 3, accepted: false);

        var maxMemoryKiB = Environment.Is64BitProcess ? 4398046510080L / 1024 : 2147483648L / 1024;
        ExpectArgon2Parameters($"m={maxMemoryKiB} KiB (maximum) accepted", p: 1, m: maxMemoryKiB, t: 3, accepted: true);
        ExpectArgon2Parameters($"m={maxMemoryKiB + 1} KiB rejected", p: 1, m: maxMemoryKiB + 1, t: 3, accepted: false);

        ExpectArgon2Parameters("t=1 (minimum) accepted", p: 1, m: 65536, t: 1, accepted: true);
        ExpectArgon2Parameters("t=0 rejected", p: 1, m: 65536, t: 0, accepted: false);
        ExpectArgon2Parameters("t=2^32-1 (maximum) accepted", p: 1, m: 65536, t: uint.MaxValue, accepted: true);
        ExpectArgon2Parameters("t=2^32 rejected", p: 1, m: 65536, t: (long)uint.MaxValue + 1, accepted: false);

        var small = new Argon2id(new Argon2Parameters { DegreeOfParallelism = 1, MemorySize = 8, NumberOfPasses = 1 });
        foreach (var saltLength in new[] { 8, 15, 16, 17, 32 })
        {
            var accepted = Accepts(() => small.DeriveBytes("password"u8, new byte[saltLength], 32));
            Check($"salt of {saltLength} bytes {(saltLength == 16 ? "accepted" : "rejected")}", accepted == (saltLength == 16));
        }

        foreach (var outputLength in new[] { 4, 15, 16 })
        {
            var accepted = Accepts(() => small.DeriveBytes("password"u8, new byte[16], outputLength));
            Console.WriteLine($"INFO  output of {outputLength} bytes: {(accepted ? "accepted" : "rejected")}");
        }

        Summary("argon2id-limits", "p=1 only; salt=16 bytes; m=8 KiB..4 TiB (64-bit); t=1..2^32-1");
    }

    private static void ExpectArgon2Parameters(string name, int p, long m, long t, bool accepted)
    {
        var actual = Accepts(() => new Argon2id(new Argon2Parameters
        {
            DegreeOfParallelism = p,
            MemorySize = m,
            NumberOfPasses = t,
        }));
        Check(name, actual == accepted);
    }

    private static bool Accepts(Action action)
    {
        try
        {
            action();
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    // RFC 8032, section 7.1, TEST 1: https://www.rfc-editor.org/rfc/rfc8032#section-7.1
    private static void CheckEd25519()
    {
        var secretKey = Convert.FromHexString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        var expectedPublicKey = Convert.FromHexString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        var expectedSignature = Convert.FromHexString(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
        var message = Array.Empty<byte>();

        var algorithm = SignatureAlgorithm.Ed25519;
        using var key = Key.Import(algorithm, secretKey, KeyBlobFormat.RawPrivateKey);

        var publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        Check("public key derived from the secret key", publicKey.AsSpan().SequenceEqual(expectedPublicKey));

        var signature = algorithm.Sign(key, message);
        Check("signature matches RFC 8032", signature.AsSpan().SequenceEqual(expectedSignature));

        var importedPublicKey = PublicKey.Import(algorithm, expectedPublicKey, KeyBlobFormat.RawPublicKey);
        Check("reference signature verifies", algorithm.Verify(importedPublicKey, message, expectedSignature));

        var tampered = (byte[])expectedSignature.Clone();
        tampered[0] ^= 0x01;
        Check("tampered signature is rejected", !algorithm.Verify(importedPublicKey, message, tampered));
    }

    private static void MeasureArgon2id()
    {
        const int Runs = 3;
        var password = "correct horse battery staple"u8.ToArray();
        var salt = new byte[16];

        foreach (var memoryMiB in new[] { 64, 256 })
        {
            var algorithm = new Argon2id(new Argon2Parameters
            {
                DegreeOfParallelism = 1,
                MemorySize = memoryMiB * 1024L,
                NumberOfPasses = 3,
            });

            algorithm.DeriveBytes(password, salt, 32); // warm-up

            var timings = new double[Runs];
            for (var i = 0; i < Runs; i++)
            {
                var start = Stopwatch.GetTimestamp();
                algorithm.DeriveBytes(password, salt, 32);
                timings[i] = Stopwatch.GetElapsedTime(start).TotalMilliseconds;
            }

            var average = timings.Average().ToString("F0", CultureInfo.InvariantCulture);
            var runs = string.Join(", ", timings.Select(ms => ms.ToString("F0", CultureInfo.InvariantCulture)));
            Console.WriteLine($"m={memoryMiB} MiB, t=3, p=1: average {average} ms ({runs})");
            Summary($"argon2id-{memoryMiB}mib-t3-ms", average);
        }
    }

    private static void Section(string title, Action body)
    {
        Console.WriteLine();
        Console.WriteLine($"== {title}");
        try
        {
            body();
        }
        catch (Exception ex)
        {
            Check($"{title}: unexpected {ex.GetType().Name}: {ex.Message}", false);
        }
    }

    private static void Check(string name, bool passed)
    {
        Console.WriteLine($"{(passed ? "PASS" : "FAIL")}  {name}");
        if (!passed)
        {
            s_failures++;
        }
    }

    private static void Summary(string key, string value) => Console.WriteLine($"SUMMARY {key}={value}");

    [LibraryImport("libsodium", EntryPoint = "sodium_version_string")]
    private static partial IntPtr SodiumVersionString();
}
