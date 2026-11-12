using System.Text.Json;
using System.Text.Json.Serialization;

namespace SafeNook.Core.Vault.Models;

/// <summary>Schema-1 immutable-object inventory; all values remain untrusted until validation.</summary>
public sealed class ManifestDto
{
    public required uint Schema { get; init; }
    public required string VaultId { get; init; }
    public required string EpochId { get; init; }
    public required string GenerationId { get; init; }
    public required ulong Sequence { get; init; }
    public required string ParentHeaderHash { get; init; }
    public required ObjectReference[] Items { get; init; }
    public required ObjectReference[] Blobs { get; init; }
}

/// <summary>Authenticated reference to an exact immutable item or blob file.</summary>
public sealed class ObjectReference
{
    public required string Id { get; init; }
    public required string WriteId { get; init; }
    public required ushort Type { get; init; }
    public required ulong Length { get; init; }
    public required string Sha256 { get; init; }
}

/// <summary>Common item fields. Classes deliberately do not produce secret-bearing record ToString output.</summary>
public sealed class ItemFields
{
    public required uint Schema { get; init; }
    public required string Id { get; init; }
    public required ushort Type { get; init; }
    public required ulong Revision { get; init; }
    public required ulong CreatedAt { get; init; }
    public required ulong UpdatedAt { get; init; }
    public required string Title { get; init; }
    public required string[] Tags { get; init; }
    public required bool Deleted { get; init; }
    public required string? Previous { get; init; }
}

/// <summary>Typed item value. Payload dispatch is explicit and never reflection-based polymorphism.</summary>
public sealed class ItemDocument(ItemFields fields, ItemPayload? payload)
{
    public ItemFields Fields { get; } = fields;
    public ItemPayload? Payload { get; } = payload;
}

/// <summary>Marker for the five explicitly supported schema-1 payloads.</summary>
public abstract class ItemPayload;
public sealed class LoginPayload : ItemPayload
{
    public required string Username { get; init; }
    public required string Password { get; init; }
    public required string[] Urls { get; init; }
    public required string Notes { get; init; }
}
public sealed class NotePayload : ItemPayload { public required string Text { get; init; } }
public sealed class SshPayload : ItemPayload
{
    public required string PrivateBlobId { get; init; }
    public required string? PublicBlobId { get; init; }
    public required string Format { get; init; }
    public required string OriginalName { get; init; }
}
public sealed class AgePayload : ItemPayload
{
    public required string IdentityBlobId { get; init; }
    public required string? RecipientBlobId { get; init; }
    public required string Format { get; init; }
    public required string OriginalName { get; init; }
}
public sealed class FilePayload : ItemPayload
{
    public required string BlobId { get; init; }
    public required string OriginalName { get; init; }
    public required string MediaType { get; init; }
}

internal sealed class WireItem
{
    public required uint Schema { get; init; }
    public required string Id { get; init; }
    public required ushort Type { get; init; }
    public required ulong Revision { get; init; }
    public required ulong CreatedAt { get; init; }
    public required ulong UpdatedAt { get; init; }
    public required string Title { get; init; }
    public required string[] Tags { get; init; }
    public required bool Deleted { get; init; }
    public required string? Previous { get; init; }
    public required JsonElement Payload { get; init; }
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow, MaxDepth = 16)]
[JsonSerializable(typeof(ManifestDto))]
[JsonSerializable(typeof(WireItem))]
[JsonSerializable(typeof(LoginPayload))]
[JsonSerializable(typeof(NotePayload))]
[JsonSerializable(typeof(SshPayload))]
[JsonSerializable(typeof(AgePayload))]
[JsonSerializable(typeof(FilePayload))]
internal sealed partial class VaultJsonContext : JsonSerializerContext;
