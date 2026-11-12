using SafeNook.Core.Vault.Models;

namespace SafeNook.Core.Vault;

/// <summary>Schema-1 inventory and authenticated item-to-blob relationship validation.</summary>
public static class ManifestValidation
{
    /// <summary>Checks canonical identities/order, unique write IDs and fixed v1 aggregate limits.</summary>
    public static void ValidateInventory(ManifestDto manifest)
    {
        VaultPayloadJson.Require(manifest is not null);
        VaultPayloadJson.Require(manifest!.Schema == 1 && manifest.Sequence >= 1);
        VaultPayloadJson.Id(manifest.VaultId); VaultPayloadJson.Id(manifest.EpochId); VaultPayloadJson.Id(manifest.GenerationId);
        VaultPayloadJson.Hex(manifest.ParentHeaderHash, 64);
        VaultPayloadJson.Require((manifest.Sequence == 1) == manifest.ParentHeaderHash.All(c => c == '0'));
        VaultPayloadJson.Require(manifest.Items is not null && manifest.Blobs is not null && manifest.Items.Length <= 10000 && manifest.Blobs.Length <= 10000);
        var writes = new HashSet<string>(StringComparer.Ordinal);
        ValidateReferences(manifest.Items!, false, writes, 268435456);
        ValidateReferences(manifest.Blobs!, true, writes, 1073741824);
    }

    /// <summary>Binds manifest metadata and reference identities to a structurally valid authenticated root.</summary>
    public static void ValidateHeaderBinding(ManifestDto manifest, ReadOnlySpan<byte> header)
    {
        ValidateInventory(manifest); VaultFormat.ValidateHeader(header);
        Match(manifest.VaultId == Convert.ToHexStringLower(header.Slice(12, 16)) &&
            manifest.EpochId == Convert.ToHexStringLower(header.Slice(28, 16)) &&
            manifest.GenerationId == Convert.ToHexStringLower(header.Slice(44, 16)) && manifest.Sequence == VaultFormat.U64(header, 60) &&
            manifest.ParentHeaderHash == Convert.ToHexStringLower(header.Slice(68, 32)));
        var write = Convert.ToHexStringLower(header.Slice(100, 32));
        Match(!manifest.Items.Concat(manifest.Blobs).Any(r => r.WriteId == write));
    }

    /// <summary>Every manifest item must occur once; each blob has exactly one live owner and satisfies its role limit.</summary>
    public static void ValidateLinks(ManifestDto manifest, IReadOnlyCollection<ItemDocument> items)
    {
        ValidateInventory(manifest); Match(items.Count == manifest.Items.Length);
        var references = manifest.Items.ToDictionary(r => r.Id, StringComparer.Ordinal);
        var blobs = manifest.Blobs.ToDictionary(r => r.Id, StringComparer.Ordinal);
        var seen = new HashSet<string>(StringComparer.Ordinal); var owned = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in items)
        {
            VaultPayloadJson.ValidateItem(item);
            Match(seen.Add(item.Fields.Id) && references.TryGetValue(item.Fields.Id, out _));
            Match(references[item.Fields.Id].Type == item.Fields.Type);
            var count = 0;
            foreach (var (id, limit) in BlobRoles(item))
            {
                Match(++count <= 32 && owned.Add(id) && blobs.TryGetValue(id, out _) && blobs[id].Length <= limit);
            }
        }
        Match(owned.Count == blobs.Count);
    }

    private static IEnumerable<(string Id, ulong Limit)> BlobRoles(ItemDocument item)
    {
        if (item.Fields.Deleted) yield break;
        switch (item.Payload)
        {
            case SshPayload p:
                yield return (p.PrivateBlobId, 1048576); if (p.PublicBlobId is not null) yield return (p.PublicBlobId, 65536); break;
            case AgePayload p:
                yield return (p.IdentityBlobId, 1048576); if (p.RecipientBlobId is not null) yield return (p.RecipientBlobId, 65536); break;
            case FilePayload p: yield return (p.BlobId, 26214400); break;
        }
    }
    private static void ValidateReferences(ObjectReference[] entries, bool blob, HashSet<string> writes, ulong maximum)
    {
        string? previous = null; ulong total = 0;
        foreach (var r in entries)
        {
            VaultPayloadJson.Require(r is not null); VaultPayloadJson.Id(r!.Id); VaultPayloadJson.Hex(r.WriteId, 64, true); VaultPayloadJson.Hex(r.Sha256, 64);
            VaultPayloadJson.Require(previous is null || StringComparer.Ordinal.Compare(previous, r.Id) < 0); previous = r.Id;
            VaultPayloadJson.Require(writes.Add(r.WriteId));
            VaultPayloadJson.Require(blob ? r.Type == 0 && r.Length <= 26214400 : r.Type is >= 1 and <= 5 && r.Length <= 65536);
            total = checked(total + r.Length); VaultPayloadJson.Require(total <= maximum);
        }
    }
    internal static void Match(bool value) { if (!value) throw new VaultDataException(VaultDataError.CorruptGeneration); }
}
