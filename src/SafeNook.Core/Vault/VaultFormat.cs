using System.Buffers.Binary;
using System.Text.Json;

namespace SafeNook.Core.Vault;

/// <summary>Strict binary v1 validation and wrapper encoding; successful parsing is not authentication.</summary>
public static class VaultFormat
{
    /// <summary>Binary header bytes.</summary>
    public const int HeaderSize = 414;
    /// <summary>Key slot bytes.</summary>
    public const int SlotSize = 108;
    /// <summary>Object envelope bytes.</summary>
    public const int EnvelopeSize = 118;
    /// <summary>Maximum blob plaintext bytes.</summary>
    public const int MaximumBlobSize = 26214400;

    /// <summary>RFC/network-order UUIDv4. Rejects zero, other versions and invalid variants.</summary>
    public static Guid ReadId(ReadOnlySpan<byte> bytes)
    {
        Require(bytes.Length == 16 && (bytes[6] & 0xf0) == 0x40 && (bytes[8] & 0xc0) == 0x80);
        return new Guid(bytes, bigEndian: true);
    }

    /// <summary>Writes a validated UUIDv4 in RFC/network order.</summary>
    public static void WriteId(Guid id, Span<byte> output)
    {
        Require(output.Length == 16);
        id.TryWriteBytes(output, bigEndian: true, out _); _ = ReadId(output);
    }

    /// <summary>Checks a complete untrusted header before any KDF, including both slots.</summary>
    public static void ValidateHeader(ReadOnlySpan<byte> header)
    {
        Require(header.Length == HeaderSize);
        ValidatePrefix(header[..166]);
        ValidateSlot(header.Slice(166, SlotSize), 1); ValidateSlot(header.Slice(274, SlotSize), 2);
        Require(!header.Slice(166, 16).SequenceEqual(header.Slice(274, 16)));
    }

    /// <summary>Validates the fixed prefix before credential operations; values remain untrusted until MAC verification.</summary>
    public static void ValidatePrefix(ReadOnlySpan<byte> header)
    {
        Require(header.Length == 166);
        Require(header[..8].SequenceEqual("SNVLT001"u8) && U16(header, 8) == 1 && U16(header, 10) == 0);
        _ = ReadId(header.Slice(12, 16)); _ = ReadId(header.Slice(28, 16)); _ = ReadId(header.Slice(44, 16));
        var sequence = U64(header, 60);
        Require(sequence >= 1 && (IsZero(header.Slice(68, 32)) == (sequence == 1)));
        Require(!IsZero(header.Slice(100, 32)) && U16(header, 164) == 2);
    }

    /// <summary>Encodes an exact header prefix referencing a staged immutable manifest.</summary>
    public static byte[] EncodePrefix(Guid vaultId, Guid epochId, Guid generationId, ulong sequence,
        ReadOnlySpan<byte> parentHash, ReadOnlySpan<byte> manifestWriteId, ReadOnlySpan<byte> manifestHash)
    {
        Require(parentHash.Length == 32 && manifestWriteId.Length == 32 && manifestHash.Length == 32);
        var result = new byte[166]; "SNVLT001"u8.CopyTo(result);
        BinaryPrimitives.WriteUInt16LittleEndian(result.AsSpan(8), 1);
        WriteId(vaultId, result.AsSpan(12, 16)); WriteId(epochId, result.AsSpan(28, 16)); WriteId(generationId, result.AsSpan(44, 16));
        BinaryPrimitives.WriteUInt64LittleEndian(result.AsSpan(60), sequence);
        parentHash.CopyTo(result.AsSpan(68)); manifestWriteId.CopyTo(result.AsSpan(100)); manifestHash.CopyTo(result.AsSpan(132));
        BinaryPrimitives.WriteUInt16LittleEndian(result.AsSpan(164), 2); ValidatePrefix(result); return result;
    }

    /// <summary>Generates a fresh UUIDv4 using RandomNumberGenerator and RFC byte order.</summary>
    public static Guid NewId()
    {
        Span<byte> bytes = stackalloc byte[16]; System.Security.Cryptography.RandomNumberGenerator.Fill(bytes);
        bytes[6] = (byte)((bytes[6] & 15) | 64); bytes[8] = (byte)((bytes[8] & 63) | 128);
        return ReadId(bytes);
    }

    /// <summary>Validates one slot, including the caller's expected kind.</summary>
    public static void ValidateSlot(ReadOnlySpan<byte> slot, byte expectedKind)
    {
        Require(slot.Length == SlotSize && expectedKind is 1 or 2);
        _ = ReadId(slot[..16]); Require(slot[16] == expectedKind && U16(slot, 18) == 1);
        if (expectedKind == 1)
        {
            Require(slot[17] == 1);
            VaultCrypto.ValidateArgon2(U32(slot, 20), U32(slot, 24), U32(slot, 28));
        }
        else Require(slot[17] == 0 && U32(slot, 20) == 0 && U32(slot, 24) == 0 && U32(slot, 28) == 0);
    }

    /// <summary>Assembles exact binary fields without changing or canonicalising authenticated bytes.</summary>
    public static byte[] EncodeHeader(ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> passwordSlot,
        ReadOnlySpan<byte> recoverySlot, ReadOnlySpan<byte> mac)
    {
        Require(prefix.Length == 166 && passwordSlot.Length == SlotSize && recoverySlot.Length == SlotSize && mac.Length == 32);
        var result = new byte[HeaderSize]; prefix.CopyTo(result); passwordSlot.CopyTo(result.AsSpan(166));
        recoverySlot.CopyTo(result.AsSpan(274)); mac.CopyTo(result.AsSpan(382)); ValidateHeader(result); return result;
    }

    /// <summary>Parses a bounded strict JSON wrapper. No reflection-based serialisation.</summary>
    public static byte[] DecodeWrapper(ReadOnlySpan<byte> utf8)
    {
        Require(utf8.Length <= 1024);
        try
        {
            var reader = new Utf8JsonReader(utf8, new JsonReaderOptions { MaxDepth = 2 });
            Require(reader.Read() && reader.TokenType == JsonTokenType.StartObject);
            Require(reader.Read() && reader.TokenType == JsonTokenType.PropertyName && reader.ValueTextEquals("payload"u8));
            Require(reader.Read() && reader.TokenType == JsonTokenType.String);
            var encoded = reader.GetString()!;
            Require(encoded.Length == 552 && !encoded.Any(char.IsWhiteSpace));
            var result = Convert.FromBase64String(encoded);
            Require(Convert.ToBase64String(result) == encoded);
            Require(reader.Read() && reader.TokenType == JsonTokenType.EndObject && !reader.Read());
            ValidateHeader(result); return result;
        }
        catch (JsonException) { throw new FormatException("Invalid vault wrapper."); }
        catch (FormatException) { throw new FormatException("Invalid vault wrapper."); }
    }

    /// <summary>Produces canonical UTF-8 wrapper with trailing LF (567 bytes).</summary>
    public static byte[] EncodeWrapper(ReadOnlySpan<byte> header)
    {
        ValidateHeader(header);
        return System.Text.Encoding.UTF8.GetBytes("{\"payload\":\"" + Convert.ToBase64String(header) + "\"}\n");
    }

    /// <summary>Validates the 118-byte envelope and exact complete file length before allocation.</summary>
    public static void ValidateEnvelope(ReadOnlySpan<byte> envelope, long fileLength)
    {
        Require(envelope.Length == EnvelopeSize);
        Require(envelope[..8].SequenceEqual("SNOBJ001"u8) && U16(envelope, 8) == 1 && envelope[11] == 0);
        var kind = envelope[10]; Require(kind is >= 1 and <= 3);
        _ = ReadId(envelope.Slice(12, 16)); _ = ReadId(envelope.Slice(28, 16)); _ = ReadId(envelope.Slice(44, 16));
        Require(!IsZero(envelope.Slice(60, 32)));
        var type = U16(envelope, 92);
        Require(kind == 1 ? type is >= 1 and <= 5 : type == 0);
        Require(U16(envelope, 94) == 1 && U16(envelope, 96) == 1);
        var length = U64(envelope, 98);
        Require(length <= (ulong)Limit(kind));
        Require(fileLength == checked((long)length + EnvelopeSize + 16));
    }

    internal static int Limit(byte kind) => kind switch { 1 => 65536, 2 => MaximumBlobSize, 3 => 8388608, _ => throw new FormatException("Unsupported object kind.") };
    internal static ushort U16(ReadOnlySpan<byte> bytes, int offset) => BinaryPrimitives.ReadUInt16LittleEndian(bytes[offset..]);
    internal static uint U32(ReadOnlySpan<byte> bytes, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(bytes[offset..]);
    internal static ulong U64(ReadOnlySpan<byte> bytes, int offset) => BinaryPrimitives.ReadUInt64LittleEndian(bytes[offset..]);
    internal static bool IsZero(ReadOnlySpan<byte> bytes) => bytes.IndexOfAnyExcept((byte)0) < 0;
    internal static void Require(bool condition) { if (!condition) throw new FormatException("Invalid or unsupported vault format."); }
}
