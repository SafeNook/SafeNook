using System.Security.Cryptography;
using SafeNook.Core.Vault.Models;

namespace SafeNook.Core.Vault;

/// <summary>Opaque immutable object source. No paths or payload metadata are used as storage locations.</summary>
public interface IVaultObjectSource
{
    /// <summary>Copies min(destination.Length, full length) bytes from offset zero and returns exact full physical length.</summary>
    /// <remarks>Return -1 for missing. Read from one stable object per call; never retain destination. Core revalidates later reads.</remarks>
    long Read(byte kind, string writeId, Span<byte> destination, CancellationToken cancellationToken);
}

/// <summary>Fully verified root/manifest/items; blobs remain lazy and must authenticate before use. Dispose to wipe keys/item JSON.</summary>
public sealed class AuthenticatedVaultState : IDisposable
{
    private readonly object _gate = new();
    private SecretBuffer? _key;
    private readonly ManifestDto _manifest;
    private readonly Dictionary<string, SecretBuffer> _items;
    private readonly List<IDisposable> _reservations;
    private readonly IVaultObjectSource _source;
    private readonly VaultAdmissionPolicy _policy;
    private AuthenticatedVaultState(SecretBuffer key, ManifestDto manifest, Dictionary<string, SecretBuffer> items,
        List<IDisposable> reservations, IVaultObjectSource source, VaultAdmissionPolicy policy)
    { _key = key; _manifest = manifest; _items = items; _reservations = reservations; _source = source; _policy = policy; }

    /// <summary>Returns detached nonsecret IDs; no mutable internal inventory is exposed.</summary>
    public string[] ItemIds { get { lock (_gate) { EnsureOpen(); return _manifest.Items.Select(r => r.Id).ToArray(); } } }
    public Guid VaultId { get { lock (_gate) { EnsureOpen(); return Guid.ParseExact(_manifest.VaultId, "N"); } } }
    public ulong Sequence { get { lock (_gate) { EnsureOpen(); return _manifest.Sequence; } } }

    /// <summary>Returns a detached typed item. Its managed strings cannot be reliably erased; caller controls their lifetime.</summary>
    public ItemDocument ReadItem(string id)
    {
        lock (_gate)
        {
            EnsureOpen();
            if (!_items.TryGetValue(id, out var json)) throw new VaultDataException(VaultDataError.CorruptGeneration);
            var reference = _manifest.Items.Single(r => r.Id == id);
            return VaultPayloadJson.ReadItem(json.Span, id, reference.Type);
        }
    }

    /// <summary>Authenticates a currently referenced blob in full. Returned bytes must be disposed by the caller.</summary>
    /// <remarks>Returned plaintext remains charged to the shared policy until disposal, even after this state is disposed.</remarks>
    public AdmittedPlaintext ReadBlob(string id, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            EnsureOpen(); IDisposable? lease = null; SecretBuffer? plaintext = null;
            try
            {
                var r = _manifest.Blobs.SingleOrDefault(r => r.Id == id);
                ManifestValidation.Match(r is not null);
                lease = _policy.Reserve(checked((long)r!.Length * 2 + 4096));
                var file = ReadFile(_source, 2, r.WriteId, checked((int)r.Length + 134), _policy, cancellationToken);
                plaintext = ObjectCodec.Decrypt(_key!.Span, Context(_manifest, r, 2), Convert.FromHexString(r.WriteId),
                    Convert.FromHexString(r.Sha256), file, checked((int)r.Length * 2), cancellationToken);
                cancellationToken.ThrowIfCancellationRequested();
                var result = new AdmittedPlaintext(plaintext, lease); plaintext = null; lease = null; return result;
            }
            catch (Exception e) when (CanSanitise(e)) { cancellationToken.ThrowIfCancellationRequested(); throw Sanitise(e); }
            finally { plaintext?.Dispose(); lease?.Dispose(); }
        }
    }

    /// <summary>Opens a complete in-memory root through the explicitly chosen password slot. Publishes no partial state.</summary>
    public static AuthenticatedVaultState OpenPassword(ReadOnlySpan<byte> header, ReadOnlySpan<byte> password,
        IVaultObjectSource source, VaultAdmissionPolicy policy, CancellationToken cancellationToken = default)
        => Open(header, password, false, source, policy, cancellationToken);

    /// <summary>Opens using the recovery slot only; never falls back from one credential path to another.</summary>
    public static AuthenticatedVaultState OpenRecovery(ReadOnlySpan<byte> header, ReadOnlySpan<byte> recoveryKey,
        IVaultObjectSource source, VaultAdmissionPolicy policy, CancellationToken cancellationToken = default)
        => Open(header, recoveryKey, true, source, policy, cancellationToken);

    private static AuthenticatedVaultState Open(ReadOnlySpan<byte> inputHeader, ReadOnlySpan<byte> credential, bool recovery,
        IVaultObjectSource source, VaultAdmissionPolicy policy, CancellationToken cancellationToken)
    {
        SecretBuffer? key = null;
        var items = new Dictionary<string, SecretBuffer>(StringComparer.Ordinal);
        var leases = new List<IDisposable>(2);
        try
        {
            ArgumentNullException.ThrowIfNull(source); ArgumentNullException.ThrowIfNull(policy);
            VaultFormat.ValidateHeader(inputHeader);
            // Copy the bounded root so source callbacks cannot change the authenticated context.
            var header = inputHeader.ToArray();
            if (!recovery && VaultFormat.U32(header.AsSpan(166, 108), 20) > policy.KdfMemoryKiB)
                throw new VaultDataException(VaultDataError.ResourceLimit);
            using (policy.Reserve(recovery ? 4096 : checked((long)VaultFormat.U32(header.AsSpan(166, 108), 20) * 1024 + 4096)))
            {
                key = recovery ? KeySlots.OpenRecovery(header, credential, cancellationToken) :
                    KeySlots.OpenPassword(header, credential, policy.KdfMemoryKiB, cancellationToken);
            }
            var manifestWrite = Convert.ToHexStringLower(header.AsSpan(100, 32));
            var manifestEnvelope = new byte[118];
            var manifestSize = ReadSource(source, 3, manifestWrite, manifestEnvelope, cancellationToken);
            VaultFormat.ValidateEnvelope(manifestEnvelope, manifestSize);
            ManifestValidation.Match(manifestEnvelope[10] == 3);
            // Conservative allowance for UTF-16 strings, JsonElement, collections, JSON prevalidation and retained inventory.
            leases.Add(policy.Reserve(checked(manifestSize * 16 + 1048576)));
            var manifestFile = ReadFile(source, 3, manifestWrite, checked((int)manifestSize), policy, cancellationToken);
            var context = new ObjectContext(VaultFormat.ReadId(header.AsSpan(12, 16)), VaultFormat.ReadId(header.AsSpan(28, 16)),
                VaultFormat.ReadId(header.AsSpan(44, 16)), 3, 0);
            ManifestDto manifest;
            using (var json = ObjectCodec.Decrypt(key.Span, context, header.AsSpan(100, 32), header.AsSpan(132, 32), manifestFile,
                checked((int)manifestSize * 2), cancellationToken))
                manifest = VaultPayloadJson.ReadManifest(json.Span);
            ManifestValidation.ValidateHeaderBinding(manifest, header);
            var totalItems = manifest.Items.Sum(r => checked((long)r.Length));
            leases.Add(policy.Reserve(checked(totalItems * 16 + manifest.Items.Length * 1024L + manifest.Blobs.Length * 1024L)));
            var parsed = new List<ItemDocument>(manifest.Items.Length);
            foreach (var r in manifest.Items)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var file = ReadFile(source, 1, r.WriteId, checked((int)r.Length + 134), policy, cancellationToken);
                SecretBuffer? json = ObjectCodec.Decrypt(key.Span, Context(manifest, r, 1), Convert.FromHexString(r.WriteId),
                    Convert.FromHexString(r.Sha256), file, checked((int)r.Length * 2), cancellationToken);
                try
                {
                    var item = VaultPayloadJson.ReadItem(json.Span, r.Id, r.Type);
                    parsed.Add(item); items.Add(r.Id, json); json = null;
                }
                finally { json?.Dispose(); }
            }
            ManifestValidation.ValidateLinks(manifest, parsed);
            var envelope = new byte[118];
            foreach (var r in manifest.Blobs)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var size = ReadSource(source, 2, r.WriteId, envelope, cancellationToken);
                VaultFormat.ValidateEnvelope(envelope, size);
                ManifestValidation.Match(size == checked((long)r.Length + 134) && envelope[10] == 2 &&
                    envelope.AsSpan(12, 16).SequenceEqual(Convert.FromHexString(manifest.VaultId)) &&
                    envelope.AsSpan(28, 16).SequenceEqual(Convert.FromHexString(manifest.EpochId)) &&
                    envelope.AsSpan(44, 16).SequenceEqual(Convert.FromHexString(r.Id)) &&
                    envelope.AsSpan(60, 32).SequenceEqual(Convert.FromHexString(r.WriteId)));
            }
            cancellationToken.ThrowIfCancellationRequested();
            var result = new AuthenticatedVaultState(key, manifest, items, leases, source, policy);
            key = null; return result;
        }
        catch (Exception e) when (CanSanitise(e)) { cancellationToken.ThrowIfCancellationRequested(); throw Sanitise(e); }
        finally
        {
            if (key is not null) { key.Dispose(); foreach (var item in items.Values) item.Dispose(); foreach (var lease in leases) lease.Dispose(); }
        }
    }

    private static long ReadSource(IVaultObjectSource source, byte kind, string writeId, Span<byte> destination, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        try
        {
            var length = source.Read(kind, writeId, destination, token);
            ManifestValidation.Match(length >= 0); return length;
        }
        catch (Exception e)
        {
            token.ThrowIfCancellationRequested();
            throw Sanitise(e);
        }
    }

    private static byte[] ReadFile(IVaultObjectSource source, byte kind, string writeId, int size, VaultAdmissionPolicy policy, CancellationToken token)
    {
        var file = policy.Allocate(size);
        ManifestValidation.Match(ReadSource(source, kind, writeId, file, token) == size); return file;
    }
    private static ObjectContext Context(ManifestDto m, ObjectReference r, byte kind)
        => new(Guid.ParseExact(m.VaultId, "N"), Guid.ParseExact(m.EpochId, "N"), Guid.ParseExact(r.Id, "N"), kind, r.Type);
    private static bool CanSanitise(Exception e) => e is not VaultDataException;
    private static VaultDataException Sanitise(Exception e) => new(e switch
    {
        OutOfMemoryException => VaultDataError.ResourceLimit,
        CryptographicException => VaultDataError.AuthenticationFailed,
        FormatException or System.Text.Json.JsonException or OverflowException => VaultDataError.InvalidFormat,
        _ => VaultDataError.CorruptGeneration,
    });
    private void EnsureOpen() { ObjectDisposedException.ThrowIf(_key is null, this); }
    public void Dispose()
    {
        lock (_gate)
        {
            if (_key is null) return;
            _key.Dispose(); _key = null;
            foreach (var item in _items.Values) item.Dispose(); _items.Clear();
            foreach (var lease in _reservations) lease.Dispose(); _reservations.Clear();
        }
    }
}

/// <summary>Owned lazy-blob plaintext with its RAM reservation. Dispose both together.</summary>
public sealed class AdmittedPlaintext : IDisposable
{
    private readonly SecretBuffer _buffer;
    private IDisposable? _reservation;
    internal AdmittedPlaintext(SecretBuffer buffer, IDisposable reservation) { _buffer = buffer; _reservation = reservation; }
    public Span<byte> Span => _buffer.Span;
    public void Dispose() { _buffer.Dispose(); Interlocked.Exchange(ref _reservation, null)?.Dispose(); }
}
