using System.Buffers.Binary;
using System.Security.Cryptography;

namespace SafeNook.Core.Vault;

/// <summary>In-memory candidates only. Caller must confirm recovery delivery and validate manifest/items before publication/session use.</summary>
public static class KeySlots
{
    /// <summary>Builds and verifies two independently wrapped slots and header MAC over the supplied 166-byte prefix.</summary>
    /// <remarks>Generate VK and RK independently using GenerateKey. Prefix binds the staged manifest; this method does not publish it.</remarks>
    public static byte[] CreateHeader(ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> vaultKey, ReadOnlySpan<byte> password,
        ReadOnlySpan<byte> recoveryKey, uint memoryKiB, uint iterations, uint localMemoryBudgetKiB,
        CancellationToken cancellationToken = default)
    {
        VaultFormat.ValidatePrefix(prefix); VaultCrypto.KeyLength(vaultKey); VaultCrypto.KeyLength(recoveryKey);
        var pwd = Wrap(prefix, vaultKey, password, 1, memoryKiB, iterations, localMemoryBudgetKiB, cancellationToken);
        byte[] recovery;
        do { recovery = Wrap(prefix, vaultKey, recoveryKey, 2, 0, 0, localMemoryBudgetKiB, cancellationToken); }
        while (pwd.AsSpan(0, 16).SequenceEqual(recovery.AsSpan(0, 16)));
        var header = VaultFormat.EncodeHeader(prefix, pwd, recovery, new byte[32]);
        Sign(header, vaultKey);
        using var passwordCheck = OpenPassword(header, password, localMemoryBudgetKiB, cancellationToken);
        using var recoveryCheck = OpenRecovery(header, recoveryKey, cancellationToken);
        VerifyKey(vaultKey, passwordCheck.Span); VerifyKey(vaultKey, recoveryCheck.Span);
        return header;
    }

    /// <summary>Unwraps the password slot and authenticates the complete header. Does not create an unlocked vault session.</summary>
    public static SecretBuffer OpenPassword(ReadOnlySpan<byte> header, ReadOnlySpan<byte> password,
        uint localMemoryBudgetKiB, CancellationToken cancellationToken = default)
        => Open(header, password, 1, localMemoryBudgetKiB, cancellationToken);

    /// <summary>Unwraps only the explicitly selected recovery slot and authenticates the complete header.</summary>
    public static SecretBuffer OpenRecovery(ReadOnlySpan<byte> header, ReadOnlySpan<byte> recoveryKey,
        CancellationToken cancellationToken = default) => Open(header, recoveryKey, 2, 0, cancellationToken);

    /// <summary>Replaces password slot, preserving recovery bytes. Authenticates old root using supplied VK.</summary>
    /// <remarks>Caller must enforce fresh credential authentication. Candidate prefix must be the next generation in the same epoch.</remarks>
    public static byte[] ReplacePassword(ReadOnlySpan<byte> oldHeader, ReadOnlySpan<byte> nextPrefix, ReadOnlySpan<byte> vaultKey,
        ReadOnlySpan<byte> newPassword, uint memoryKiB, uint iterations, uint localMemoryBudgetKiB,
        CancellationToken cancellationToken = default)
        => Replace(oldHeader, nextPrefix, vaultKey, newPassword, 1, memoryKiB, iterations, localMemoryBudgetKiB, cancellationToken);

    /// <summary>Replaces recovery slot, preserving password bytes. Caller confirms new RK delivery before future atomic publication.</summary>
    public static byte[] ReplaceRecovery(ReadOnlySpan<byte> oldHeader, ReadOnlySpan<byte> nextPrefix, ReadOnlySpan<byte> vaultKey,
        ReadOnlySpan<byte> newRecoveryKey, CancellationToken cancellationToken = default)
        => Replace(oldHeader, nextPrefix, vaultKey, newRecoveryKey, 2, 0, 0, 0, cancellationToken);

    /// <summary>Authenticates all 382 header bytes with constant-time MAC comparison after structural validation.</summary>
    public static void VerifyHeader(ReadOnlySpan<byte> header, ReadOnlySpan<byte> vaultKey)
    {
        VaultFormat.ValidateHeader(header); VaultCrypto.KeyLength(vaultKey);
        Span<byte> mac = stackalloc byte[32];
        try
        {
            ComputeMac(header, vaultKey, mac);
            if (!CryptographicOperations.FixedTimeEquals(mac, header[382..])) throw new CryptographicException("Header authentication failed.");
        }
        finally { CryptographicOperations.ZeroMemory(mac); }
    }

    private static byte[] Replace(ReadOnlySpan<byte> oldHeader, ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> credential, byte kind, uint memory, uint iterations, uint budget, CancellationToken cancellationToken)
    {
        VerifyHeader(oldHeader, key);
        VaultFormat.ValidatePrefix(prefix);
        VaultFormat.Require(prefix.Length == 166 && prefix.Slice(12, 32).SequenceEqual(oldHeader.Slice(12, 32)));
        VaultFormat.Require(VaultFormat.U64(oldHeader, 60) != ulong.MaxValue && VaultFormat.U64(prefix, 60) == VaultFormat.U64(oldHeader, 60) + 1);
        VaultFormat.Require(!prefix.Slice(44, 16).SequenceEqual(oldHeader.Slice(44, 16)) &&
            !prefix.Slice(100, 32).SequenceEqual(oldHeader.Slice(100, 32)) && prefix.Slice(68, 32).SequenceEqual(SHA256.HashData(oldHeader)));
        var offset = kind == 1 ? 166 : 274;
        var otherOffset = kind == 1 ? 274 : 166;
        byte[] slot;
        do { slot = Wrap(prefix, key, credential, kind, memory, iterations, budget, cancellationToken); }
        while (slot.AsSpan(0, 16).SequenceEqual(oldHeader.Slice(otherOffset, 16)) || slot.AsSpan(0, 16).SequenceEqual(oldHeader.Slice(offset, 16)));
        var result = oldHeader.ToArray(); prefix.CopyTo(result); slot.CopyTo(result, offset);
        VaultFormat.ValidateHeader(result); Sign(result, key);
        using var check = Open(result, credential, kind, budget, cancellationToken); VerifyKey(key, check.Span);
        VaultFormat.Require(result.AsSpan(otherOffset, 108).SequenceEqual(oldHeader.Slice(otherOffset, 108)));
        return result;
    }

    private static SecretBuffer Open(ReadOnlySpan<byte> header, ReadOnlySpan<byte> credential, byte kind, uint budget, CancellationToken cancellationToken)
    {
        VaultFormat.ValidateHeader(header);
        var slot = header.Slice(kind == 1 ? 166 : 274, 108);
        Span<byte> kek = stackalloc byte[32];
        try
        {
            DeriveKek(header, slot, credential, budget, kek, cancellationToken);
            var key = VaultCrypto.Decrypt(kek, slot.Slice(48, 12), slot.Slice(60, 32), slot.Slice(92, 16), Aad(header, slot), cancellationToken);
            try { VerifyHeader(header, key.Span); cancellationToken.ThrowIfCancellationRequested(); return key; }
            catch { key.Dispose(); throw; }
        }
        finally { CryptographicOperations.ZeroMemory(kek); }
    }

    private static byte[] Wrap(ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> key, ReadOnlySpan<byte> credential, byte kind,
        uint memory, uint iterations, uint budget, CancellationToken cancellationToken)
    {
        var slot = new byte[108]; VaultFormat.WriteId(VaultFormat.NewId(), slot.AsSpan(0, 16));
        slot[16] = kind; slot[17] = kind == 1 ? (byte)1 : (byte)0;
        BinaryPrimitives.WriteUInt16LittleEndian(slot.AsSpan(18), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(slot.AsSpan(20), memory);
        BinaryPrimitives.WriteUInt32LittleEndian(slot.AsSpan(24), iterations);
        BinaryPrimitives.WriteUInt32LittleEndian(slot.AsSpan(28), kind == 1 ? 1u : 0u);
        RandomNumberGenerator.Fill(slot.AsSpan(32, 28)); VaultFormat.ValidateSlot(slot, kind);
        Span<byte> kek = stackalloc byte[32];
        try
        {
            DeriveKek(prefix, slot, credential, budget, kek, cancellationToken);
            VaultCrypto.Encrypt(kek, slot.AsSpan(48, 12), key, Aad(prefix, slot), slot.AsSpan(60, 32), slot.AsSpan(92, 16));
            cancellationToken.ThrowIfCancellationRequested(); return slot;
        }
        finally { CryptographicOperations.ZeroMemory(kek); }
    }

    private static void DeriveKek(ReadOnlySpan<byte> header, ReadOnlySpan<byte> slot, ReadOnlySpan<byte> credential, uint budget,
        Span<byte> output, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (slot[16] == 1)
        {
            using var seed = VaultCrypto.Argon2(credential, slot.Slice(32, 16), VaultFormat.U32(slot, 20), VaultFormat.U32(slot, 24), budget, cancellationToken);
            VaultCrypto.Hkdf(seed.Span, header.Slice(12, 16),
                VaultCrypto.Join(VaultCrypto.Domain("password-wrap"), VaultCrypto.Join(header.Slice(28, 16), slot[..16])), output);
        }
        else
        {
            VaultCrypto.KeyLength(credential);
            VaultCrypto.Hkdf(credential, slot.Slice(32, 16),
                VaultCrypto.Join(VaultCrypto.Domain("recovery-wrap"), VaultCrypto.Join(header.Slice(12, 32), slot[..16])), output);
        }
    }

    private static byte[] Aad(ReadOnlySpan<byte> header, ReadOnlySpan<byte> slot)
        => VaultCrypto.Join(VaultCrypto.Domain("slot"), VaultCrypto.Join(new byte[] { 1, 0 }, VaultCrypto.Join(header.Slice(12, 32), slot[..60])));

    private static void ComputeMac(ReadOnlySpan<byte> header, ReadOnlySpan<byte> key, Span<byte> output)
    {
        Span<byte> macKey = stackalloc byte[32];
        try
        {
            VaultCrypto.Hkdf(key, header.Slice(12, 16), VaultCrypto.Join(VaultCrypto.Domain("header-mac"), header.Slice(28, 16)), macKey);
            HMACSHA256.HashData(macKey, VaultCrypto.Join(VaultCrypto.Domain("header"), header[..382]), output);
        }
        finally { CryptographicOperations.ZeroMemory(macKey); }
    }
    private static void Sign(Span<byte> header, ReadOnlySpan<byte> key) => ComputeMac(header, key, header[382..]);
    private static void VerifyKey(ReadOnlySpan<byte> expected, ReadOnlySpan<byte> actual)
    {
        if (!CryptographicOperations.FixedTimeEquals(expected, actual)) throw new CryptographicException("Candidate verification failed.");
    }
}
