using System.Buffers.Binary;
using System.Security.Cryptography;

namespace SafeNook.Core.Vault;

/// <summary>Trusted logical object identity supplied by the authenticated root/manifest, not the input envelope.</summary>
public readonly record struct ObjectContext(Guid VaultId, Guid EpochId, Guid ObjectId, byte Kind, ushort Type, ushort Schema = 1);

/// <summary>Whole-object v1 codec. Payload JSON semantics and filesystem publication belong to the future store.</summary>
public static class ObjectCodec
{
    /// <summary>Creates a new immutable encrypted object with fresh random write ID and nonce.</summary>
    public static byte[] Encrypt(ReadOnlySpan<byte> vaultKey, ObjectContext context, ReadOnlySpan<byte> plaintext,
        int localPayloadBudgetBytes, CancellationToken cancellationToken = default)
    {
        VaultCrypto.KeyLength(vaultKey);
        VaultFormat.Require(plaintext.Length <= VaultFormat.Limit(context.Kind));
        Admit(plaintext.Length, localPayloadBudgetBytes);
        cancellationToken.ThrowIfCancellationRequested();
        var envelope = new byte[VaultFormat.EnvelopeSize];
        "SNOBJ001"u8.CopyTo(envelope); BinaryPrimitives.WriteUInt16LittleEndian(envelope.AsSpan(8), 1);
        envelope[10] = context.Kind;
        VaultFormat.WriteId(context.VaultId, envelope.AsSpan(12, 16));
        VaultFormat.WriteId(context.EpochId, envelope.AsSpan(28, 16));
        VaultFormat.WriteId(context.ObjectId, envelope.AsSpan(44, 16));
        do { RandomNumberGenerator.Fill(envelope.AsSpan(60, 32)); } while (VaultFormat.IsZero(envelope.AsSpan(60, 32)));
        BinaryPrimitives.WriteUInt16LittleEndian(envelope.AsSpan(92), context.Type);
        BinaryPrimitives.WriteUInt16LittleEndian(envelope.AsSpan(94), context.Schema);
        BinaryPrimitives.WriteUInt16LittleEndian(envelope.AsSpan(96), 1);
        BinaryPrimitives.WriteUInt64LittleEndian(envelope.AsSpan(98), (ulong)plaintext.Length);
        RandomNumberGenerator.Fill(envelope.AsSpan(106, 12));
        var size = checked(plaintext.Length + 134);
        VaultFormat.ValidateEnvelope(envelope, size);
        var result = new byte[size]; envelope.CopyTo(result, 0);
        Span<byte> key = stackalloc byte[32];
        try
        {
            DeriveKey(vaultKey, envelope, key);
            VaultCrypto.Encrypt(key, envelope.AsSpan(106), plaintext, VaultCrypto.Join(VaultCrypto.Domain("object"), envelope),
                result.AsSpan(118, plaintext.Length), result.AsSpan(size - 16));
            cancellationToken.ThrowIfCancellationRequested(); return result;
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    /// <summary>Authenticates the expected immutable reference and entire object before returning plaintext.</summary>
    /// <remarks>Caller owns stable input bytes and trusted expected write ID/hash; never derive expectations from this input.</remarks>
    public static SecretBuffer Decrypt(ReadOnlySpan<byte> vaultKey, ObjectContext expectedContext,
        ReadOnlySpan<byte> expectedWriteId, ReadOnlySpan<byte> expectedHash, ReadOnlySpan<byte> file,
        int localPayloadBudgetBytes, CancellationToken cancellationToken = default)
    {
        VaultCrypto.KeyLength(vaultKey);
        VaultFormat.Require(file.Length >= 134 && expectedWriteId.Length == 32 && expectedHash.Length == 32);
        var envelope = file[..118]; VaultFormat.ValidateEnvelope(envelope, file.Length);
        var actual = new ObjectContext(VaultFormat.ReadId(envelope.Slice(12, 16)), VaultFormat.ReadId(envelope.Slice(28, 16)),
            VaultFormat.ReadId(envelope.Slice(44, 16)), envelope[10], VaultFormat.U16(envelope, 92), VaultFormat.U16(envelope, 94));
        if (actual != expectedContext || !CryptographicOperations.FixedTimeEquals(expectedWriteId, envelope.Slice(60, 32)))
            throw new CryptographicException("Object context authentication failed.");
        var length = file.Length - 134; Admit(length, localPayloadBudgetBytes);
        cancellationToken.ThrowIfCancellationRequested();
        Span<byte> hash = stackalloc byte[32]; SHA256.HashData(file, hash);
        if (!CryptographicOperations.FixedTimeEquals(hash, expectedHash)) throw new CryptographicException("Object authentication failed.");
        Span<byte> key = stackalloc byte[32];
        try
        {
            DeriveKey(vaultKey, envelope, key);
            return VaultCrypto.Decrypt(key, envelope.Slice(106, 12), file.Slice(118, length), file[^16..],
                VaultCrypto.Join(VaultCrypto.Domain("object"), envelope), cancellationToken);
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    private static void DeriveKey(ReadOnlySpan<byte> key, ReadOnlySpan<byte> envelope, Span<byte> output)
        => VaultCrypto.Hkdf(key, envelope.Slice(12, 16), VaultCrypto.Join(VaultCrypto.Domain("object-key"), envelope[..106]), output);

    private static void Admit(int length, int budget)
    {
        if (budget < 0 || checked(2L * length) > budget)
            throw new InvalidOperationException("Object exceeds the trusted local payload memory budget.");
    }
}
