using System.Security.Cryptography;
using SafeNook.Core.Vault;
using SafeNook.TestVectors;

// All fixtures are public synthetic data. Never print credentials or plaintext.
static byte[] Hex(string text) => Convert.FromHexString(text);
static void Check(bool condition) { if (!condition) throw new InvalidOperationException("Crypto smoke check failed."); }
var header = Hex(Vectors.Header);
Check(VaultFormat.DecodeWrapper(VaultFormat.EncodeWrapper(header)).AsSpan().SequenceEqual(header));
using var passwordKey = KeySlots.OpenPassword(header, Hex(Vectors.Password), 65536);
using var recoveryKey = KeySlots.OpenRecovery(header, Hex(Vectors.RecoveryKey));
Check(passwordKey.Span.SequenceEqual(Hex(Vectors.VaultKey)) && passwordKey.Span.SequenceEqual(recoveryKey.Span));
using var recoveryCode = RecoveryCode.Decode(Vectors.RecoveryText);
Check(RecoveryCode.Encode(recoveryCode.Span) == Vectors.RecoveryText);
var context = new ObjectContext(VaultFormat.ReadId(Hex(Vectors.VaultId)), VaultFormat.ReadId(Hex(Vectors.EpochId)),
    VaultFormat.ReadId(Hex(Vectors.GenerationId)), 2, 0);
using var vectorPlain = ObjectCodec.Decrypt(passwordKey.Span, context, Hex(Vectors.WriteId), Hex(Vectors.Hash), Hex(Vectors.File), 52428800);
Check(vectorPlain.Span.SequenceEqual(Hex(Vectors.Plaintext)));
foreach (var size in new[] { 0, 1, 26214400 })
{
    var plaintext = new byte[size];
    try
    {
        var file = ObjectCodec.Encrypt(passwordKey.Span, context, plaintext, 52428800);
        using var output = ObjectCodec.Decrypt(passwordKey.Span, context, file.AsSpan(60, 32), SHA256.HashData(file), file, 52428800);
        Check(output.Span.SequenceEqual(plaintext));
        file[^1] ^= 1;
        var rejected = false;
        try { using var unexpected = ObjectCodec.Decrypt(passwordKey.Span, context, file.AsSpan(60, 32), SHA256.HashData(file), file, 52428800); }
        catch (AuthenticationTagMismatchException) { rejected = true; }
        Check(rejected);
    }
    finally { CryptographicOperations.ZeroMemory(plaintext); }
}
using var vk = VaultCrypto.GenerateKey(); using var rk = VaultCrypto.GenerateKey();
var created = KeySlots.CreateHeader(Hex(Vectors.Prefix), vk.Span, Hex(Vectors.Password), rk.Span, 65536, 3, 65536);
var next = VaultFormat.EncodePrefix(context.VaultId, context.EpochId, VaultFormat.NewId(), 2, SHA256.HashData(created), RandomNumberGenerator.GetBytes(32), new byte[32]);
var replacement = KeySlots.ReplacePassword(created, next, vk.Span, "synthetic new password"u8, 65536, 3, 65536);
Check(created.AsSpan(274, 108).SequenceEqual(replacement.AsSpan(274, 108)));
using var recovered = KeySlots.OpenRecovery(replacement, rk.Span); Check(recovered.Span.SequenceEqual(vk.Span));
using var nextRk = VaultCrypto.GenerateKey();
var next2 = VaultFormat.EncodePrefix(context.VaultId, context.EpochId, VaultFormat.NewId(), 3, SHA256.HashData(replacement), RandomNumberGenerator.GetBytes(32), new byte[32]);
var rotated = KeySlots.ReplaceRecovery(replacement, next2, vk.Span, nextRk.Span);
Check(rotated.AsSpan(166, 108).SequenceEqual(replacement.AsSpan(166, 108)));
using var rotatedKey = KeySlots.OpenRecovery(rotated, nextRk.Span); Check(rotatedKey.Span.SequenceEqual(vk.Span));
Console.WriteLine("PASS: Core crypto/format Native AOT smoke; vectors, slots, recovery, empty/max blobs and authentication failure.");
