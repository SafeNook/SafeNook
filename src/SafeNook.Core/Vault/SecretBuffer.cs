using System.Security.Cryptography;

namespace SafeNook.Core.Vault;

/// <summary>Owns secret bytes. Dispose promptly; callers must not retain or concurrently use spans.</summary>
public sealed class SecretBuffer : IDisposable
{
    private byte[]? _bytes;
    internal SecretBuffer(byte[] bytes) => _bytes = bytes;
    /// <summary>Secret bytes, valid only until disposal. Copies belong to the caller.</summary>
    public Span<byte> Span => (_bytes ?? throw new ObjectDisposedException(nameof(SecretBuffer))).AsSpan();
    /// <summary>Wipes owned storage. Does not promise erasure of provider, GC or OS copies.</summary>
    public void Dispose()
    {
        if (_bytes is { } bytes)
        {
            CryptographicOperations.ZeroMemory(bytes);
            _bytes = null;
        }
    }
}
