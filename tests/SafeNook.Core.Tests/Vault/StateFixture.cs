using System.Security.Cryptography;
using System.Text;
using SafeNook.Core.Vault;
using SafeNook.Core.Vault.Models;
using SafeNook.TestVectors;

namespace SafeNook.StateTestData;

// Public synthetic data only. Raw JSON is authored independently of the new serializer.
internal sealed class StateFixture
{
    internal const string ItemId = "11111111222243338444555555555555";
    internal const string BlobId = "22222222333344448555666666666666";
    internal const string OtherId = "33333333444445558666777777777777";
    internal const string VaultId = "00112233445546778899aabbccddeeff";
    internal const string EpochId = "102132435465476889abbcdef0123456";
    internal const string GenerationId = "20314253647548699abccdef01234567";
    internal static readonly byte[] Key = Convert.FromHexString(Vectors.VaultKey);
    internal static readonly byte[] Recovery = Convert.FromHexString(Vectors.RecoveryKey);
    internal static readonly byte[] Password = Convert.FromHexString(Vectors.Password);
    internal byte[] Header { get; private set; } = [];
    internal MemorySource Source { get; } = new();
    internal string ItemWrite { get; private set; } = "";
    internal string BlobWrite { get; private set; } = "";
    internal string ManifestJson { get; private set; } = "";
    internal string ItemJson { get; private set; } = "";
    internal static string Item(ushort type = 5, string? payload = null, string? commonTail = null)
        => "{\"schema\":1,\"id\":\"" + ItemId + "\",\"type\":" + type + ",\"revision\":1,\"createdAt\":0,\"updatedAt\":0,\"title\":\"synthetic-secret-title\",\"tags\":[],\"deleted\":false,\"previous\":null,\"payload\":" +
            (payload ?? "{\"blobId\":\"" + BlobId + "\",\"originalName\":\"opaque.bin\",\"mediaType\":\"application/octet-stream\"}") + (commonTail ?? "") + "}";

    internal static StateFixture Build(string? item = null, Func<string, string>? alterManifest = null, bool includeBlob = true, ushort type = 5, bool secondItem = false)
    {
        var f = new StateFixture(); f.ItemJson = item ?? Item();
        var blob = ObjectCodec.Encrypt(Key, Context(BlobId, 2, 0), new byte[] { 0, 255, 13, 10, 0 }, 1024);
        f.BlobWrite = Convert.ToHexStringLower(blob.AsSpan(60, 32)); f.Source.Files[(2, f.BlobWrite)] = blob;
        var itemBytes = Encoding.UTF8.GetBytes(f.ItemJson);
        byte[] encrypted;
        try { encrypted = ObjectCodec.Encrypt(Key, Context(ItemId, 1, type), itemBytes, 131072); }
        finally { CryptographicOperations.ZeroMemory(itemBytes); }
        f.ItemWrite = Convert.ToHexStringLower(encrypted.AsSpan(60, 32)); f.Source.Files[(1, f.ItemWrite)] = encrypted;
        var itemRef = Reference(ItemId, f.ItemWrite, type, encrypted);
        if (secondItem)
        {
            var secondRaw = Encoding.UTF8.GetBytes(Item(2, "{\"text\":\"second synthetic secret\"}").Replace(ItemId, OtherId));
            byte[] secondFile;
            try { secondFile = ObjectCodec.Encrypt(Key, Context(OtherId, 1, 2), secondRaw, 131072); }
            finally { CryptographicOperations.ZeroMemory(secondRaw); }
            var secondWrite = Convert.ToHexStringLower(secondFile.AsSpan(60, 32));
            f.Source.Files[(1, secondWrite)] = secondFile;
            itemRef += "," + Reference(OtherId, secondWrite, 2, secondFile);
        }
        var blobRef = Reference(BlobId, f.BlobWrite, 0, blob);
        var m = "{\"schema\":1,\"vaultId\":\"" + VaultId + "\",\"epochId\":\"" + EpochId + "\",\"generationId\":\"" + GenerationId +
            "\",\"sequence\":1,\"parentHeaderHash\":\"" + new string('0', 64) + "\",\"items\":[" + itemRef + "],\"blobs\":[" + (includeBlob ? blobRef : "") + "]}";
        f.ManifestJson = alterManifest is null ? m : alterManifest(m);
        var manifestBytes = Encoding.UTF8.GetBytes(f.ManifestJson);
        byte[] manifest;
        try { manifest = ObjectCodec.Encrypt(Key, Context(GenerationId, 3, 0), manifestBytes, 16777216); }
        finally { CryptographicOperations.ZeroMemory(manifestBytes); }
        var manifestWrite = manifest.AsSpan(60, 32).ToArray(); f.Source.Files[(3, Convert.ToHexStringLower(manifestWrite))] = manifest;
        var prefix = VaultFormat.EncodePrefix(Guid.ParseExact(VaultId, "N"), Guid.ParseExact(EpochId, "N"), Guid.ParseExact(GenerationId, "N"),
            1, new byte[32], manifestWrite, SHA256.HashData(manifest));
        f.Header = VaultFormat.EncodeHeader(prefix, Convert.FromHexString(Vectors.PasswordSlot), Convert.FromHexString(Vectors.RecoverySlot), new byte[32]);
        // Existing independently generated SN-003A slots; new synthetic root signed with the fixture header key.
        HMACSHA256.HashData(Convert.FromHexString(Vectors.HeaderKey), "SafeNook/v1/header\0"u8.ToArray().Concat(f.Header[..382]).ToArray()).CopyTo(f.Header, 382);
        return f;
    }
    internal static ObjectContext Context(string id, byte kind, ushort type) => new(Guid.ParseExact(VaultId, "N"), Guid.ParseExact(EpochId, "N"), Guid.ParseExact(id, "N"), kind, type);
    private static string Reference(string id, string write, ushort type, byte[] file) =>
        "{\"id\":\""+id+"\",\"writeId\":\""+write+"\",\"type\":"+type+",\"length\":"+(file.Length-134)+",\"sha256\":\""+Convert.ToHexStringLower(SHA256.HashData(file))+"\"}";
    internal static VaultAdmissionPolicy Policy(IVaultBufferAllocator? allocator = null) => new(65536, 268435456, allocator);
}

internal sealed class MemorySource : IVaultObjectSource
{
    internal Dictionary<(byte Kind, string Write), byte[]> Files { get; } = new();
    internal List<(byte Kind, int Size)> Reads { get; } = [];
    internal Exception? Failure { get; set; }
    public long Read(byte kind, string writeId, Span<byte> destination, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (Failure is not null) throw Failure;
        Reads.Add((kind, destination.Length));
        if (!Files.TryGetValue((kind, writeId), out var bytes)) return -1;
        bytes.AsSpan(0, Math.Min(bytes.Length, destination.Length)).CopyTo(destination); return bytes.Length;
    }
}
