using System.Security.Cryptography;
using System.Runtime.InteropServices;

namespace SafeNook.Core.Vault;

/// <summary>SN1 recovery text encoding. Returned strings cannot be wiped; display/export remains caller policy.</summary>
public static class RecoveryCode
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    /// <summary>Encodes 32 secret bytes into the canonical 75-character SN1 token.</summary>
    public static string Encode(ReadOnlySpan<byte> recoveryKey)
    {
        VaultCrypto.KeyLength(recoveryKey);
        Span<char> symbols = stackalloc char[60];
        Span<byte> checksum = stackalloc byte[32];
        Span<char> text = stackalloc char[75];
        try
        {
            Checksum(recoveryKey, checksum);
            Base32(recoveryKey, symbols[..52]); Base32(checksum[..5], symbols[52..]);
            "SN1-".AsSpan().CopyTo(text);
            var position = 4;
            for (var i = 0; i < 60; i++)
            {
                if (i > 0 && i % 5 == 0) text[position++] = '-';
                text[position++] = symbols[i];
            }
            return new string(text);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(symbols)); CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(text)); CryptographicOperations.ZeroMemory(checksum);
        }
    }

    /// <summary>Checks ASCII, size, canonical pad bits and checksum without echoing any input in errors.</summary>
    public static SecretBuffer Decode(ReadOnlySpan<char> text)
    {
        Span<char> symbols = stackalloc char[60];
        Span<byte> decoded = stackalloc byte[37];
        Span<byte> checksum = stackalloc byte[32];
        try
        {
            Check(text.Length is >= 3 and <= 256 && Upper(text[0]) == 'S' && Upper(text[1]) == 'N' && text[2] == '1');
            var count = 0;
            foreach (var c in text[3..])
            {
                if (c is ' ' or '\t' or '\r' or '\n' or '-') continue;
                Check(c <= 127 && count < 60);
                var upper = Upper(c); Check(Alphabet.Contains(upper)); symbols[count++] = upper;
            }
            Check(count == 60 && (Alphabet.IndexOf(symbols[51]) & 15) == 0);
            Decode32(symbols[..52], decoded[..32]); Decode32(symbols[52..], decoded[32..]);
            Checksum(decoded[..32], checksum);
            Check(CryptographicOperations.FixedTimeEquals(decoded[32..], checksum[..5]));
            return new SecretBuffer(decoded[..32].ToArray());
        }
        finally { CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(symbols)); CryptographicOperations.ZeroMemory(decoded); CryptographicOperations.ZeroMemory(checksum); }
    }

    private static char Upper(char c) => c is >= 'a' and <= 'z' ? (char)(c - 32) : c;
    private static void Check(bool condition) { if (!condition) throw new FormatException("Invalid recovery code."); }
    private static void Checksum(ReadOnlySpan<byte> key, Span<byte> output)
    {
        Span<byte> input = stackalloc byte[VaultCrypto.Domain("recovery-check").Length + 32];
        try
        {
            var domain = VaultCrypto.Domain("recovery-check"); domain.CopyTo(input); key.CopyTo(input[domain.Length..]);
            SHA256.HashData(input, output);
        }
        finally { CryptographicOperations.ZeroMemory(input); }
    }
    private static void Base32(ReadOnlySpan<byte> input, Span<char> output)
    {
        uint bits = 0; var remaining = 0; var position = 0;
        foreach (var b in input)
        {
            bits = (bits << 8) | b; remaining += 8;
            while (remaining >= 5) { remaining -= 5; output[position++] = Alphabet[(int)((bits >> remaining) & 31)]; }
        }
        if (remaining > 0) output[position] = Alphabet[(int)((bits << (5 - remaining)) & 31)];
    }
    private static void Decode32(ReadOnlySpan<char> input, Span<byte> output)
    {
        uint bits = 0; var remaining = 0; var position = 0;
        foreach (var c in input)
        {
            bits = (bits << 5) | (uint)Alphabet.IndexOf(c); remaining += 5;
            if (remaining >= 8) { remaining -= 8; output[position++] = (byte)(bits >> remaining); }
        }
    }
}
