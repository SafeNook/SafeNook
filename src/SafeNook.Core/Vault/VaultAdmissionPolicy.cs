namespace SafeNook.Core.Vault;

/// <summary>Trusted allocation hook for owned encrypted read buffers; implementations must return a fresh exact-sized array.</summary>
public interface IVaultBufferAllocator { byte[] Allocate(int length); }

/// <summary>Thread-safe shared admission accounting. Budgets originate in the application, never in a vault.</summary>
public sealed class VaultAdmissionPolicy
{
    private readonly object _gate = new();
    private long _reserved;
    private readonly IVaultBufferAllocator _allocator;
    public uint KdfMemoryKiB { get; }
    public long ManagedBudgetBytes { get; }
    /// <summary>Current conservative reservations, including authenticated states until disposal.</summary>
    public long ReservedBytes { get { lock (_gate) return _reserved; } }

    public VaultAdmissionPolicy(uint kdfMemoryKiB, long managedBudgetBytes, IVaultBufferAllocator? allocator = null)
    {
        if (kdfMemoryKiB is < 65536 or > 1048576 || managedBudgetBytes <= 0)
            throw new ArgumentException("Invalid trusted admission policy.");
        KdfMemoryKiB = kdfMemoryKiB; ManagedBudgetBytes = managedBudgetBytes;
        _allocator = allocator ?? new DefaultAllocator();
    }
    /// <summary>Default: min(256 MiB, one quarter of trusted available physical RAM), rounded down to MiB.</summary>
    public static VaultAdmissionPolicy FromAvailableMemory(long availablePhysicalBytes)
    {
        if (availablePhysicalBytes < 0) throw new ArgumentException("Invalid trusted memory observation.");
        var bytes = Math.Min(268435456, availablePhysicalBytes / 4) / 1048576 * 1048576;
        if (bytes < 67108864) throw new VaultDataException(VaultDataError.ResourceLimit);
        return new VaultAdmissionPolicy((uint)(bytes / 1024), bytes);
    }
    /// <summary>Reserves trusted caller-owned operation buffers; dispose the lease after releasing those buffers.</summary>
    public IDisposable ReserveTransientBytes(long bytes) => Reserve(bytes);

    internal IDisposable Reserve(long bytes)
    {
        lock (_gate)
        {
            if (bytes < 0 || bytes > ManagedBudgetBytes - _reserved) throw new VaultDataException(VaultDataError.ResourceLimit);
            var lease = new Reservation(this, bytes); _reserved += bytes; return lease;
        }
    }
    internal byte[] Allocate(int length)
    {
        var bytes = _allocator.Allocate(length);
        if (bytes is null || bytes.Length != length) throw new VaultDataException(VaultDataError.ResourceLimit);
        return bytes;
    }
    private sealed class DefaultAllocator : IVaultBufferAllocator { public byte[] Allocate(int length) => new byte[length]; }
    private sealed class Reservation(VaultAdmissionPolicy policy, long bytes) : IDisposable
    {
        private bool _disposed;
        public void Dispose() { lock (policy._gate) { if (!_disposed) { policy._reserved -= bytes; _disposed = true; } } }
    }
}
