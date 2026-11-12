using System.Security.Cryptography;
using System.Text;
using NSec.Cryptography;

namespace SafeNook.Core.Vault;

/// <summary>Approved v1 primitives. Inputs are borrowed and must remain stable during each call.</summary>
public static class VaultCrypto
{
    /// <summary>Generates an independent 256-bit secret using the operating system CSPRNG.</summary>
    public static SecretBuffer GenerateKey() => new(RandomNumberGenerator.GetBytes(32));

    /// <summary>RFC 5869 SHA-256 Extract and Expand; destination length is checked by the BCL.</summary>
    public static void Hkdf(ReadOnlySpan<byte> input, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> info, Span<byte> output)
        => HKDF.DeriveKey(HashAlgorithmName.SHA256, input, output, salt, info);

    /// <summary>Validates wire costs without performing or allocating a KDF.</summary>
    public static void ValidateArgon2(uint memoryKiB, uint iterations, uint parallelism)
    {
        if (memoryKiB is < 65536 or > 1048576 || memoryKiB % 1024 != 0 || iterations is < 3 or > 10 || parallelism != 1)
            throw new FormatException("Unsupported KDF parameters.");
        _ = checked((long)memoryKiB * 1024);
    }

    /// <summary>Argon2id v1.3/p1/salt16/output32. Budget is trusted caller policy, never read from the vault.</summary>
    public static SecretBuffer Argon2(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt,
        uint memoryKiB, uint iterations, uint localMemoryBudgetKiB, CancellationToken cancellationToken = default)
    {
        ValidateArgon2(memoryKiB, iterations, 1);
        if (password.Length is < 1 or > 1024 || salt.Length != 16)
            throw new ArgumentException("Invalid credential dimensions.");
        // Validate UTF-8 without normalising, trimming or copying the password into a string.
        try { _ = new UTF8Encoding(false, true).GetCharCount(password); }
        catch (DecoderFallbackException) { throw new ArgumentException("Invalid credential encoding."); }
        if (memoryKiB > localMemoryBudgetKiB)
            throw new InvalidOperationException("KDF exceeds the trusted local memory budget.");
        cancellationToken.ThrowIfCancellationRequested();
        var algorithm = new Argon2id(new Argon2Parameters
        {
            DegreeOfParallelism = 1, MemorySize = memoryKiB, NumberOfPasses = iterations,
        });
        var result = new SecretBuffer(algorithm.DeriveBytes(password, salt, 32));
        try { cancellationToken.ThrowIfCancellationRequested(); return result; }
        catch { result.Dispose(); throw; }
    }

    /// <summary>AES-256-GCM with a 12-byte nonce and 16-byte tag. No overlapping buffers.</summary>
    public static void Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> aad, Span<byte> ciphertext, Span<byte> tag)
    {
        CheckAes(key, nonce, tag.Length);
        if (plaintext.Length != ciphertext.Length || plaintext.Overlaps(ciphertext) || plaintext.Overlaps(tag) || ciphertext.Overlaps(tag) ||
            key.Overlaps(ciphertext) || key.Overlaps(tag) || nonce.Overlaps(ciphertext) || nonce.Overlaps(tag) ||
            aad.Overlaps(ciphertext) || aad.Overlaps(tag))
            throw new ArgumentException("Invalid encryption buffers.");
        using var aes = new AesGcm(key, 16);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);
    }

    /// <summary>Returns owned plaintext only after successful authentication. Failure wipes the output.</summary>
    public static SecretBuffer Decrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag, ReadOnlySpan<byte> aad, CancellationToken cancellationToken = default)
    {
        CheckAes(key, nonce, tag.Length);
        cancellationToken.ThrowIfCancellationRequested();
        var result = new SecretBuffer(new byte[ciphertext.Length]);
        try
        {
            using var aes = new AesGcm(key, 16);
            aes.Decrypt(nonce, ciphertext, tag, result.Span, aad);
            cancellationToken.ThrowIfCancellationRequested();
            return result;
        }
        catch { result.Dispose(); throw; }
    }

    internal static byte[] Domain(string label) => Encoding.ASCII.GetBytes("SafeNook/v1/" + label + "\0");
    internal static byte[] Join(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second)
    {
        var result = new byte[checked(first.Length + second.Length)];
        first.CopyTo(result); second.CopyTo(result.AsSpan(first.Length)); return result;
    }
    internal static void KeyLength(ReadOnlySpan<byte> key)
    {
        if (key.Length != 32) throw new ArgumentException("Invalid key dimensions.");
    }
    private static void CheckAes(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, int tagLength)
    {
        KeyLength(key);
        if (nonce.Length != 12 || tagLength != 16) throw new ArgumentException("Invalid AEAD dimensions.");
        if (!AesGcm.IsSupported) throw new PlatformNotSupportedException("AES-GCM is unavailable.");
    }
}
