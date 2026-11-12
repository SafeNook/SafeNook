using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SafeNook.Core.Vault.Models;

namespace SafeNook.Core.Vault;

/// <summary>Bounded strict schema-1 JSON parsing and source-generated serialisation.</summary>
public static class VaultPayloadJson
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    /// <summary>Parses and validates an inventory; header binding is checked separately by ManifestValidation.</summary>
    public static ManifestDto ReadManifest(ReadOnlySpan<byte> json)
    {
        try
        {
            Prevalidate(json, 8388608);
            var result = JsonSerializer.Deserialize(json, VaultJsonContext.Default.ManifestDto);
            Require(result is not null); ManifestValidation.ValidateInventory(result!); return result!;
        }
        catch (Exception e) when (IsParserError(e)) { throw new VaultDataException(VaultDataError.InvalidFormat); }
    }

    /// <summary>Parses an item with exact envelope/manifest ID, type and schema expectations.</summary>
    public static ItemDocument ReadItem(ReadOnlySpan<byte> json, string expectedId, ushort expectedType, uint expectedSchema = 1)
    {
        try
        {
            Prevalidate(json, 65536);
            var w = JsonSerializer.Deserialize(json, VaultJsonContext.Default.WireItem);
            Require(w is not null);
            var fields = new ItemFields { Schema = w!.Schema, Id = w.Id, Type = w.Type, Revision = w.Revision,
                CreatedAt = w.CreatedAt, UpdatedAt = w.UpdatedAt, Title = w.Title, Tags = w.Tags, Deleted = w.Deleted, Previous = w.Previous };
            Require(w.Id == expectedId && w.Type == expectedType && w.Schema == expectedSchema);
            ItemPayload? payload = null;
            if (!w.Deleted)
            {
                Require(w.Payload.ValueKind == JsonValueKind.Object);
                payload = w.Type switch
                {
                    1 => w.Payload.Deserialize(VaultJsonContext.Default.LoginPayload),
                    2 => w.Payload.Deserialize(VaultJsonContext.Default.NotePayload),
                    3 => w.Payload.Deserialize(VaultJsonContext.Default.SshPayload),
                    4 => w.Payload.Deserialize(VaultJsonContext.Default.AgePayload),
                    5 => w.Payload.Deserialize(VaultJsonContext.Default.FilePayload),
                    _ => throw new VaultDataException(VaultDataError.InvalidFormat),
                };
                Require(payload is not null);
            }
            else Require(w.Payload.ValueKind == JsonValueKind.Null);
            var result = new ItemDocument(fields, payload); ValidateItem(result); return result;
        }
        catch (Exception e) when (IsParserError(e)) { throw new VaultDataException(VaultDataError.InvalidFormat); }
    }

    /// <summary>Writes validated schema-1 manifest bytes. Caller owns the returned plaintext.</summary>
    public static byte[] WriteManifest(ManifestDto manifest)
    {
        ManifestValidation.ValidateInventory(manifest);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(manifest, VaultJsonContext.Default.ManifestDto);
        if (bytes.Length <= 8388608) return bytes;
        CryptographicOperations.ZeroMemory(bytes); throw new VaultDataException(VaultDataError.ResourceLimit);
    }

    /// <summary>Writes validated item bytes using explicit payload dispatch. Caller must wipe returned plaintext.</summary>
    public static byte[] WriteItem(ItemDocument item)
    {
        ValidateItem(item);
        var f = item.Fields;
        var payload = item.Payload switch
        {
            LoginPayload p => JsonSerializer.SerializeToElement(p, VaultJsonContext.Default.LoginPayload),
            NotePayload p => JsonSerializer.SerializeToElement(p, VaultJsonContext.Default.NotePayload),
            SshPayload p => JsonSerializer.SerializeToElement(p, VaultJsonContext.Default.SshPayload),
            AgePayload p => JsonSerializer.SerializeToElement(p, VaultJsonContext.Default.AgePayload),
            FilePayload p => JsonSerializer.SerializeToElement(p, VaultJsonContext.Default.FilePayload),
            _ => JsonSerializer.SerializeToElement((NotePayload?)null, VaultJsonContext.Default.NotePayload),
        };
        var wire = new WireItem { Schema = f.Schema, Id = f.Id, Type = f.Type, Revision = f.Revision, CreatedAt = f.CreatedAt,
            UpdatedAt = f.UpdatedAt, Title = f.Title, Tags = f.Tags, Deleted = f.Deleted, Previous = f.Previous, Payload = payload };
        var bytes = JsonSerializer.SerializeToUtf8Bytes(wire, VaultJsonContext.Default.WireItem);
        if (bytes.Length <= 65536) return bytes;
        CryptographicOperations.ZeroMemory(bytes); throw new VaultDataException(VaultDataError.ResourceLimit);
    }

    /// <summary>Validates a typed value independently of serialisation. No historical predecessor is assumed available.</summary>
    public static void ValidateItem(ItemDocument item)
    {
        Require(item is not null && item.Fields is not null);
        var f = item!.Fields;
        Require(f.Schema == 1 && f.Type is >= 1 and <= 5 && f.Revision >= 1);
        Id(f.Id); Require(f.CreatedAt <= f.UpdatedAt && f.UpdatedAt <= 253402300799999);
        Require((f.Revision == 1) == (f.Previous is null));
        if (f.Previous is not null) Hex(f.Previous, 64);
        Text(f.Title, 1024); Require(f.Tags is not null && f.Tags.Length <= 32);
        var tags = new HashSet<string>(StringComparer.Ordinal);
        foreach (var tag in f.Tags!) { Text(tag, 64, 1); Require(tags.Add(tag)); }
        if (f.Deleted)
        {
            Require(item.Payload is null && f.Title.Length == 0 && f.Tags.Length == 0);
            return;
        }
        switch (item.Payload)
        {
            case LoginPayload p:
                Require(f.Type == 1); Text(p.Username, 4096); Text(p.Password, 4096); Text(p.Notes, 32768);
                Require(p.Urls is not null && p.Urls.Length <= 16); foreach (var url in p.Urls!) Text(url, 2048); break;
            case NotePayload p: Require(f.Type == 2); Text(p.Text, 32768); break;
            case SshPayload p:
                Require(f.Type == 3 && p.Format == "opaque-ssh"); Id(p.PrivateBlobId); OptionalId(p.PublicBlobId); Text(p.OriginalName, 255); break;
            case AgePayload p:
                Require(f.Type == 4 && p.Format == "opaque-age"); Id(p.IdentityBlobId); OptionalId(p.RecipientBlobId); Text(p.OriginalName, 255); break;
            case FilePayload p: Require(f.Type == 5); Id(p.BlobId); Text(p.OriginalName, 255); Text(p.MediaType, 255); break;
            default: throw new VaultDataException(VaultDataError.InvalidFormat);
        }
    }

    /// <summary>Checks an edit against a supplied authenticated predecessor; opening alone cannot prove unavailable history.</summary>
    public static void ValidateRevision(ItemDocument previous, ItemDocument next, string previousFileHash)
    {
        ValidateItem(previous); ValidateItem(next); Hex(previousFileHash, 64);
        var a = previous.Fields; var b = next.Fields;
        Require(a.Id == b.Id && a.Type == b.Type && a.CreatedAt == b.CreatedAt && b.UpdatedAt >= a.UpdatedAt &&
            a.Revision != ulong.MaxValue && b.Revision == a.Revision + 1 && b.Previous == previousFileHash);
    }

    internal static void Id(string? id)
    {
        Hex(id, 32);
        try { _ = VaultFormat.ReadId(Convert.FromHexString(id!)); }
        catch (FormatException) { throw new VaultDataException(VaultDataError.InvalidFormat); }
    }
    internal static void Hex(string? text, int length, bool nonzero = false)
    {
        Require(text is not null && text.Length == length);
        foreach (var c in text!) Require(c is >= '0' and <= '9' or >= 'a' and <= 'f');
        if (nonzero) Require(text.Any(c => c != '0'));
    }
    private static void OptionalId(string? id) { if (id is not null) Id(id); }
    private static void Text(string? text, int max, int min = 0)
    {
        Require(text is not null);
        try { var size = StrictUtf8.GetByteCount(text!); Require(size >= min && size <= max); }
        catch (EncoderFallbackException) { throw new VaultDataException(VaultDataError.InvalidFormat); }
    }
    internal static void Require([System.Diagnostics.CodeAnalysis.DoesNotReturnIf(false)] bool condition)
    {
        if (!condition) throw new VaultDataException(VaultDataError.InvalidFormat);
    }
    private static bool IsParserError(Exception e) => e is JsonException or FormatException or DecoderFallbackException or InvalidOperationException or OverflowException;

    private static void Prevalidate(ReadOnlySpan<byte> json, int maximum)
    {
        Require(json.Length > 0 && json.Length <= maximum);
        _ = StrictUtf8.GetCharCount(json);
        var reader = new Utf8JsonReader(json, new JsonReaderOptions { MaxDepth = 16 });
        var properties = new Stack<HashSet<string>>();
        var arrays = new Dictionary<int, int>();
        while (reader.Read())
        {
            // Reject oversized arrays before the serializer allocates their DTO graph.
            if (reader.TokenType is JsonTokenType.StartObject or JsonTokenType.StartArray or JsonTokenType.String or
                JsonTokenType.Number or JsonTokenType.True or JsonTokenType.False or JsonTokenType.Null)
            {
                if (arrays.TryGetValue(reader.CurrentDepth - 1, out var count))
                {
                    Require(count < 10000); arrays[reader.CurrentDepth - 1] = count + 1;
                }
            }
            switch (reader.TokenType)
            {
                case JsonTokenType.StartArray: arrays.Add(reader.CurrentDepth, 0); break;
                case JsonTokenType.EndArray: arrays.Remove(reader.CurrentDepth); break;
                case JsonTokenType.StartObject: properties.Push(new HashSet<string>(StringComparer.Ordinal)); break;
                case JsonTokenType.EndObject: properties.Pop(); break;
                case JsonTokenType.PropertyName:
                    CheckEscapes(reader.ValueSpan); Require(properties.Peek().Count < 16 && properties.Peek().Add(reader.GetString()!)); break;
                case JsonTokenType.String: CheckEscapes(reader.ValueSpan); break;
                case JsonTokenType.Number:
                    foreach (var b in reader.ValueSpan) Require(b is >= (byte)'0' and <= (byte)'9');
                    Require(reader.TryGetUInt64(out _)); break;
            }
        }
    }
    private static void CheckEscapes(ReadOnlySpan<byte> raw)
    {
        for (var i = 0; i < raw.Length; i++)
        {
            if (raw[i] != '\\') continue;
            i++;
            if (raw[i] != 'u') continue;
            var value = ushort.Parse(Encoding.ASCII.GetString(raw.Slice(i + 1, 4)), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            i += 4;
            Require(value is not (>= 0xdc00 and <= 0xdfff));
            if (value is >= 0xd800 and <= 0xdbff)
            {
                Require(i + 6 < raw.Length && raw[i + 1] == '\\' && raw[i + 2] == 'u');
                var low = ushort.Parse(Encoding.ASCII.GetString(raw.Slice(i + 3, 4)), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
                Require(low is >= 0xdc00 and <= 0xdfff); i += 6;
            }
        }
    }
}
