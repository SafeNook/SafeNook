using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using SafeNook.Core.Vault;
using SafeNook.TestVectors;

namespace SafeNook.Core.Tests.Vault;

public sealed class VaultTests
{
    private static byte[] Hex(string value) => Convert.FromHexString(value);
    private static readonly ObjectContext Context = new(new Guid(Hex(Vectors.VaultId), true), new Guid(Hex(Vectors.EpochId), true),
        new Guid(Hex(Vectors.GenerationId), true), 2, 0);
    private const int Budget = 2 * VaultFormat.MaximumBlobSize;

    // BoringSSL crypto/cipher/test/aes_256_gcm_tests.txt, first case and the 12-byte-nonce 10-byte case.
    // https://raw.githubusercontent.com/google/boringssl/master/crypto/cipher/test/aes_256_gcm_tests.txt
    [Theory]
    [InlineData("e5ac4a32c67e425ac4b143c83c6f161312a97d88d634afdf9f4da5bd35223f01", "5bf11a0951f0bfc7ea5c9e58", "", "", "", "d7cba289d6d19a5af45dc13857016bac")]
    [InlineData("80e2e561886eb2a953cf923aaac1653ed2db0111ee62e09cb20d9e2652bd3476", "5daf201589654da8884c3c68", "96669d2d3542a4d49c7c", "e51e5bce7cbceb660399", "4521953e7d39497e4563", "2083e3c0d84d663066bbe2961b08dcf7")]
    public void AesKnownAnswers(string key, string nonce, string input, string aad, string expected, string expectedTag)
    {
        var ciphertext = new byte[input.Length / 2]; var tag = new byte[16];
        VaultCrypto.Encrypt(Hex(key), Hex(nonce), Hex(input), Hex(aad), ciphertext, tag);
        Assert.Equal(Hex(expected), ciphertext); Assert.Equal(Hex(expectedTag), tag);
        using var plain = VaultCrypto.Decrypt(Hex(key), Hex(nonce), Hex(expected), Hex(expectedTag), Hex(aad), cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(Hex(input), plain.Span.ToArray());
    }

    // RFC 5869 Appendix A.1-A.3, SHA-256 Extract AND Expand.
    [Theory]
    [InlineData(1)] [InlineData(2)] [InlineData(3)]
    public void HkdfRfc5869(int test)
    {
        var ikm = test == 2 ? Enumerable.Range(0, 80).Select(i => (byte)i).ToArray() : Enumerable.Repeat((byte)11, 22).ToArray();
        var salt = test switch { 1 => Hex("000102030405060708090a0b0c"), 2 => Enumerable.Range(0x60, 80).Select(i => (byte)i).ToArray(), _ => [] };
        var info = test switch { 1 => Hex("f0f1f2f3f4f5f6f7f8f9"), 2 => Enumerable.Range(0xb0, 80).Select(i => (byte)i).ToArray(), _ => [] };
        var expected = test switch
        {
            1 => "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
            2 => "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
            _ => "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        };
        var output = new byte[expected.Length / 2]; VaultCrypto.Hkdf(ikm, salt, info, output); Assert.Equal(Hex(expected), output);
    }

    [Fact]
    public void Argon2MatchesIndependentReference()
    {
        using var first = VaultCrypto.Argon2(Hex(Vectors.Password), Enumerable.Range(0, 16).Select(i => (byte)i).ToArray(), 65536, 3, 65536, cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(Hex(Vectors.ArgonSeed), first.Span.ToArray());
        using var second = VaultCrypto.Argon2(Hex("c3a90074657374"), Enumerable.Range(240, 16).Reverse().Select(i => (byte)i).ToArray(), 65536, 4, 65536, cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(Hex(Vectors.ArgonSeed2), second.Span.ToArray());
    }

    [Theory]
    [InlineData(65535u, 3u, 1u)] [InlineData(65537u, 3u, 1u)] [InlineData(1049600u, 3u, 1u)]
    [InlineData(uint.MaxValue, uint.MaxValue, 1u)] [InlineData(65536u, 2u, 1u)]
    [InlineData(65536u, 11u, 1u)] [InlineData(65536u, 3u, 0u)] [InlineData(65536u, 3u, 2u)]
    public void ArgonLimitsBeforeAllocation(uint memory, uint iterations, uint parallelism)
        => Assert.Throws<FormatException>(() => VaultCrypto.ValidateArgon2(memory, iterations, parallelism));

    [Fact]
    public void KdfBudgetAndCredentialDimensions()
    {
        VaultCrypto.ValidateArgon2(1048576, 10, 1); // Validation only; do not allocate one GiB in tests.
        Assert.Throws<InvalidOperationException>(() => VaultCrypto.Argon2(Hex(Vectors.Password), new byte[16], 65536, 3, 65535, cancellationToken: TestContext.Current.CancellationToken));
        foreach (var password in new[] { Array.Empty<byte>(), new byte[1025], new byte[] { 255 } })
            Assert.Throws<ArgumentException>(() => VaultCrypto.Argon2(password, new byte[16], 65536, 3, 65536, cancellationToken: TestContext.Current.CancellationToken));
        Assert.Throws<ArgumentException>(() => VaultCrypto.Argon2("x"u8, new byte[15], 65536, 3, 65536, cancellationToken: TestContext.Current.CancellationToken));
        Assert.Throws<OperationCanceledException>(() => VaultCrypto.Argon2("x"u8, new byte[16], 65536, 3, 65536, new CancellationToken(true)));
    }

    [Fact]
    public void IndependentHeaderAndSlots()
    {
        var header = Hex(Vectors.Header); VaultFormat.ValidateHeader(header);
        using var password = KeySlots.OpenPassword(header, Hex(Vectors.Password), 65536, cancellationToken: TestContext.Current.CancellationToken);
        using var recovery = KeySlots.OpenRecovery(header, Hex(Vectors.RecoveryKey), cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(Hex(Vectors.VaultKey), password.Span.ToArray()); Assert.Equal(password.Span.ToArray(), recovery.Span.ToArray());
        KeySlots.VerifyHeader(header, Hex(Vectors.VaultKey));
        Assert.Equal(header, VaultFormat.EncodeHeader(Hex(Vectors.Prefix), Hex(Vectors.PasswordSlot), Hex(Vectors.RecoverySlot), Hex(Vectors.Mac)));
        var prefix = VaultFormat.EncodePrefix(Context.VaultId, Context.EpochId, Context.ObjectId, 1, new byte[32], Hex(Vectors.WriteId), Hex(Vectors.Hash));
        Assert.Equal(Hex(Vectors.Prefix), prefix);
        Assert.Equal(414, header.Length); Assert.Equal(108, Hex(Vectors.PasswordSlot).Length);
    }

    [Fact]
    public void EveryHeaderByteIsCoveredByValidationOrMac()
    {
        var original = Hex(Vectors.Header);
        for (var offset = 0; offset < original.Length; offset++)
        {
            var changed = original.ToArray(); changed[offset] ^= 1;
            Assert.NotNull(Record.Exception(() => KeySlots.VerifyHeader(changed, Hex(Vectors.VaultKey))));
            // Recovery must not expose VK even if its own slot is intact and the other slot/prefix/MAC is damaged.
            Assert.NotNull(Record.Exception(() => { using var key = KeySlots.OpenRecovery(changed, Hex(Vectors.RecoveryKey), cancellationToken: TestContext.Current.CancellationToken); }));
        }
    }

    [Fact]
    public void HeaderAndSlotOffsetsAreExact()
    {
        var h = Hex(Vectors.Header);
        Assert.Equal("SNVLT001", Encoding.ASCII.GetString(h, 0, 8));
        Assert.Equal(1, BinaryPrimitives.ReadUInt16LittleEndian(h.AsSpan(8)));
        Assert.Equal(0, BinaryPrimitives.ReadUInt16LittleEndian(h.AsSpan(10)));
        foreach (var field in new[] { (12, Vectors.VaultId), (28, Vectors.EpochId), (44, Vectors.GenerationId), (100, Vectors.WriteId), (132, Vectors.Hash), (166, Vectors.PasswordSlot), (274, Vectors.RecoverySlot), (382, Vectors.Mac) })
            Assert.Equal(Hex(field.Item2), h.AsSpan(field.Item1, field.Item2.Length / 2).ToArray());
        Assert.Equal(1ul, BinaryPrimitives.ReadUInt64LittleEndian(h.AsSpan(60)));
        Assert.Equal(new byte[32], h.AsSpan(68, 32).ToArray()); Assert.Equal(2, BinaryPrimitives.ReadUInt16LittleEndian(h.AsSpan(164)));
        foreach (var (offset, kind, id) in new[] { (166, 1, Vectors.PasswordSlotId), (274, 2, Vectors.RecoverySlotId) })
        {
            var s = h.AsSpan(offset, 108); Assert.Equal(Hex(id), s[..16].ToArray());
            Assert.Equal(kind, s[16]); Assert.Equal(kind == 1 ? 1 : 0, s[17]);
            Assert.Equal(1, BinaryPrimitives.ReadUInt16LittleEndian(s[18..]));
            Assert.Equal(kind == 1 ? 65536u : 0u, BinaryPrimitives.ReadUInt32LittleEndian(s[20..]));
            Assert.Equal(kind == 1 ? 3u : 0u, BinaryPrimitives.ReadUInt32LittleEndian(s[24..]));
            Assert.Equal(kind == 1 ? 1u : 0u, BinaryPrimitives.ReadUInt32LittleEndian(s[28..]));
            var salt = Enumerable.Range(kind == 1 ? 0 : 128, 16).Select(i => (byte)i).ToArray();
            var nonce = Enumerable.Range(kind == 1 ? 16 : 144, 12).Select(i => (byte)i).ToArray();
            Assert.Equal(salt, s.Slice(32, 16).ToArray()); Assert.Equal(nonce, s.Slice(48, 12).ToArray());
            var ciphertext = new byte[32]; var tag = new byte[16];
            VaultCrypto.Encrypt(Hex(kind == 1 ? Vectors.PasswordKek : Vectors.RecoveryKek), nonce, Hex(Vectors.VaultKey),
                Hex(kind == 1 ? Vectors.PasswordAad : Vectors.RecoveryAad), ciphertext, tag);
            Assert.Equal(ciphertext, s.Slice(60, 32).ToArray()); Assert.Equal(tag, s.Slice(92, 16).ToArray());
        }
    }

    [Fact]
    public void WrapperStrictnessAndCanonicalEncoding()
    {
        var header = Hex(Vectors.Header); var encoded = VaultFormat.EncodeWrapper(header);
        Assert.Equal(567, encoded.Length); Assert.Equal((byte)'\n', encoded[^1]); Assert.Equal(header, VaultFormat.DecodeWrapper(encoded));
        var payload = Convert.ToBase64String(header);
        Assert.Equal(header, VaultFormat.DecodeWrapper(Encoding.UTF8.GetBytes(" \n{ \"payload\" : \"" + payload + "\" }\t")));
        var invalid = new[] { "{}", "[]", "null", "{\"payload\":1}", "{\"payload\":\"bad\"}",
            "{\"payload\":\""+payload+"\",\"payload\":\""+payload+"\"}",
            "{\"payload\":\""+payload+"\",\"unknown\":0}", "{\"payload\":\""+payload+"\",}",
            "{\"payload\":\""+payload+"\"}null", "{\"payload\":\" "+payload+"\"}",
            "/*x*/{\"payload\":\""+payload+"\"}", "\ufeff{\"payload\":\""+payload+"\"}" };
        foreach (var input in invalid) Assert.Throws<FormatException>(() => VaultFormat.DecodeWrapper(Encoding.UTF8.GetBytes(input)));
        Assert.Throws<FormatException>(() => VaultFormat.DecodeWrapper(new byte[1025]));
        Assert.Throws<FormatException>(() => VaultFormat.ValidateHeader(header[..^1]));
        Assert.Throws<FormatException>(() => VaultFormat.ValidateHeader([.. header, 0]));
        Assert.Throws<FormatException>(() => VaultFormat.ValidateSlot(new byte[109], 1));
    }

    [Fact]
    public void IndependentEnvelopeAndEveryFieldOffset()
    {
        var file = Hex(Vectors.File); var e = Hex(Vectors.Envelope); VaultFormat.ValidateEnvelope(e, file.Length);
        Assert.Equal(118, e.Length); Assert.Equal("SNOBJ001", Encoding.ASCII.GetString(e, 0, 8));
        Assert.Equal(1, BinaryPrimitives.ReadUInt16LittleEndian(e.AsSpan(8))); Assert.Equal(2, e[10]); Assert.Equal(0, e[11]);
        foreach (var field in new[] { (12, Vectors.VaultId), (28, Vectors.EpochId), (44, Vectors.GenerationId), (60, Vectors.WriteId), (106, Vectors.Nonce) })
            Assert.Equal(Hex(field.Item2), e.AsSpan(field.Item1, field.Item2.Length / 2).ToArray());
        Assert.Equal(0, BinaryPrimitives.ReadUInt16LittleEndian(e.AsSpan(92)));
        Assert.Equal(1, BinaryPrimitives.ReadUInt16LittleEndian(e.AsSpan(94))); Assert.Equal(1, BinaryPrimitives.ReadUInt16LittleEndian(e.AsSpan(96)));
        Assert.Equal((ulong)Hex(Vectors.Plaintext).Length, BinaryPrimitives.ReadUInt64LittleEndian(e.AsSpan(98)));
        using var plaintext = ObjectCodec.Decrypt(Hex(Vectors.VaultKey), Context, Hex(Vectors.WriteId), Hex(Vectors.Hash), file, Budget, cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(Hex(Vectors.Plaintext), plaintext.Span.ToArray());
    }

    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(1024)] [InlineData(65536)] [InlineData(26214400)]
    public void BlobRoundTripAndSizes(int size)
    {
        var plain = new byte[size]; RandomNumberGenerator.Fill(plain);
        using var key = VaultCrypto.GenerateKey();
        var file = ObjectCodec.Encrypt(key.Span, Context, plain, Budget, cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(size + 134, file.Length);
        using var decoded = ObjectCodec.Decrypt(key.Span, Context, file.AsSpan(60, 32), SHA256.HashData(file), file, Budget, cancellationToken: TestContext.Current.CancellationToken);
        Assert.True(plain.AsSpan().SequenceEqual(decoded.Span));
        CryptographicOperations.ZeroMemory(plain);
    }

    [Theory]
    [InlineData((byte)1, (ushort)1, 65536)] [InlineData((byte)1, (ushort)2, 10)]
    [InlineData((byte)1, (ushort)3, 10)] [InlineData((byte)1, (ushort)4, 10)] [InlineData((byte)1, (ushort)5, 10)]
    [InlineData((byte)3, (ushort)0, 8388608)]
    public void ItemAndManifestCodec(byte kind, ushort type, int size)
    {
        var context = Context with { Kind = kind, Type = type }; var plain = new byte[size];
        var file = ObjectCodec.Encrypt(Hex(Vectors.VaultKey), context, plain, Budget, cancellationToken: TestContext.Current.CancellationToken);
        using var decoded = ObjectCodec.Decrypt(Hex(Vectors.VaultKey), context, file.AsSpan(60, 32), SHA256.HashData(file), file, Budget, cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(size, decoded.Span.Length);
    }

    [Fact]
    public void EveryObjectByteTamperFailsWithoutReturningPlaintext()
    {
        var original = Hex(Vectors.File);
        for (var offset = 0; offset < original.Length; offset++)
        {
            var file = original.ToArray(); file[offset] ^= 1; SecretBuffer? output = null;
            // Recompute hash deliberately to reach GCM/AAD checks rather than only hash rejection.
            var exception = Record.Exception(() => output = ObjectCodec.Decrypt(Hex(Vectors.VaultKey), Context, Hex(Vectors.WriteId), SHA256.HashData(file), file, Budget, cancellationToken: TestContext.Current.CancellationToken));
            Assert.NotNull(exception); Assert.Null(output);
            Assert.DoesNotContain("Synthetic blob", exception.Message);
        }
        Assert.Equal(original, Hex(Vectors.File));
    }

    [Fact]
    public void ContextHashAndFramingMismatch()
    {
        var file = Hex(Vectors.File);
        foreach (var context in new[] { Context with { VaultId = VaultFormat.NewId() }, Context with { EpochId = VaultFormat.NewId() },
            Context with { ObjectId = VaultFormat.NewId() }, Context with { Kind = 1 }, Context with { Type = 5 }, Context with { Schema = 2 } })
            Assert.Throws<CryptographicException>(() => ObjectCodec.Decrypt(Hex(Vectors.VaultKey), context, Hex(Vectors.WriteId), Hex(Vectors.Hash), file, Budget, cancellationToken: TestContext.Current.CancellationToken));
        Assert.Throws<CryptographicException>(() => ObjectCodec.Decrypt(Hex(Vectors.VaultKey), Context, new byte[32], Hex(Vectors.Hash), file, Budget, cancellationToken: TestContext.Current.CancellationToken));
        Assert.Throws<CryptographicException>(() => ObjectCodec.Decrypt(Hex(Vectors.VaultKey), Context, Hex(Vectors.WriteId), new byte[32], file, Budget, cancellationToken: TestContext.Current.CancellationToken));
        foreach (var changed in new[] { file[..^1], file[..117], Array.Empty<byte>(), file.Concat(new byte[1]).ToArray() })
            Assert.Throws<FormatException>(() => ObjectCodec.Decrypt(Hex(Vectors.VaultKey), Context, Hex(Vectors.WriteId), Hex(Vectors.Hash), changed, Budget, cancellationToken: TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData(8, 2)] [InlineData(10, 0)] [InlineData(10, 4)] [InlineData(11, 1)]
    [InlineData(92, 1)] [InlineData(94, 2)] [InlineData(96, 0)] [InlineData(96, 2)] [InlineData(96, 255)]
    public void UnknownEnvelopeFields(int offset, byte value)
    {
        var e = Hex(Vectors.Envelope); e[offset] = value;
        Assert.Throws<FormatException>(() => VaultFormat.ValidateEnvelope(e, Hex(Vectors.File).Length));
    }

    [Fact]
    public void OversizeOverflowBudgetAndFreshness()
    {
        var e = Hex(Vectors.Envelope);
        foreach (var length in new[] { 26214401ul, (ulong)long.MaxValue, ulong.MaxValue })
        {
            BinaryPrimitives.WriteUInt64LittleEndian(e.AsSpan(98), length);
            Assert.Throws<FormatException>(() => VaultFormat.ValidateEnvelope(e, long.MaxValue));
        }
        Assert.Throws<FormatException>(() => ObjectCodec.Encrypt(Hex(Vectors.VaultKey), Context, new byte[26214401], Budget, cancellationToken: TestContext.Current.CancellationToken));
        Assert.Throws<FormatException>(() => ObjectCodec.Encrypt(Hex(Vectors.VaultKey), Context with { Kind = 1, Type = 1 }, new byte[65537], Budget, cancellationToken: TestContext.Current.CancellationToken));
        Assert.Throws<FormatException>(() => ObjectCodec.Encrypt(Hex(Vectors.VaultKey), Context with { Kind = 3 }, new byte[8388609], Budget, cancellationToken: TestContext.Current.CancellationToken));
        Assert.Throws<InvalidOperationException>(() => ObjectCodec.Encrypt(Hex(Vectors.VaultKey), Context, new byte[10], 19, cancellationToken: TestContext.Current.CancellationToken));
        Assert.Throws<InvalidOperationException>(() => ObjectCodec.Decrypt(Hex(Vectors.VaultKey), Context, Hex(Vectors.WriteId), Hex(Vectors.Hash), Hex(Vectors.File), 1, cancellationToken: TestContext.Current.CancellationToken));
        var first = ObjectCodec.Encrypt(Hex(Vectors.VaultKey), Context, [], Budget, cancellationToken: TestContext.Current.CancellationToken);
        var second = ObjectCodec.Encrypt(Hex(Vectors.VaultKey), Context, [], Budget, cancellationToken: TestContext.Current.CancellationToken);
        Assert.NotEqual(first.AsSpan(60, 32).ToArray(), second.AsSpan(60, 32).ToArray());
        Assert.NotEqual(first.AsSpan(106, 12).ToArray(), second.AsSpan(106, 12).ToArray());
    }

    [Fact]
    public void WrongCredentialsAndHeaderMacNeverExposeKey()
    {
        var header = Hex(Vectors.Header);
        Assert.Throws<AuthenticationTagMismatchException>(() => KeySlots.OpenPassword(header, "wrong-password"u8, 65536, cancellationToken: TestContext.Current.CancellationToken));
        Assert.Throws<AuthenticationTagMismatchException>(() => KeySlots.OpenRecovery(header, new byte[32], cancellationToken: TestContext.Current.CancellationToken));
        header[^1] ^= 1;
        Assert.Throws<CryptographicException>(() => KeySlots.OpenPassword(header, Hex(Vectors.Password), 65536, cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public void CreationAndIndependentSlotReplacement()
    {
        using var vk = VaultCrypto.GenerateKey(); using var rk = VaultCrypto.GenerateKey();
        Assert.False(vk.Span.SequenceEqual(rk.Span));
        var header = KeySlots.CreateHeader(Hex(Vectors.Prefix), vk.Span, Hex(Vectors.Password), rk.Span, 65536, 3, 65536, cancellationToken: TestContext.Current.CancellationToken);
        var copy = header.ToArray();
        var next = NextPrefix(header);
        var changedPassword = KeySlots.ReplacePassword(header, next, vk.Span, "new-password"u8, 65536, 3, 65536, cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(copy, header); Assert.Equal(header.AsSpan(274, 108).ToArray(), changedPassword.AsSpan(274, 108).ToArray());
        Assert.NotEqual(header.AsSpan(166, 16).ToArray(), changedPassword.AsSpan(166, 16).ToArray());
        Assert.NotEqual(header.AsSpan(198, 16).ToArray(), changedPassword.AsSpan(198, 16).ToArray());
        Assert.NotEqual(header.AsSpan(214, 12).ToArray(), changedPassword.AsSpan(214, 12).ToArray());
        using var recovered = KeySlots.OpenRecovery(changedPassword, rk.Span, cancellationToken: TestContext.Current.CancellationToken); Assert.True(vk.Span.SequenceEqual(recovered.Span));
        using var password = KeySlots.OpenPassword(changedPassword, "new-password"u8, 65536, cancellationToken: TestContext.Current.CancellationToken); Assert.True(vk.Span.SequenceEqual(password.Span));
        Assert.Throws<AuthenticationTagMismatchException>(() => KeySlots.OpenPassword(changedPassword, Hex(Vectors.Password), 65536, cancellationToken: TestContext.Current.CancellationToken));
        using var newRk = VaultCrypto.GenerateKey();
        var changedRecovery = KeySlots.ReplaceRecovery(changedPassword, NextPrefix(changedPassword), vk.Span, newRk.Span, cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(changedPassword.AsSpan(166, 108).ToArray(), changedRecovery.AsSpan(166, 108).ToArray());
        using var final = KeySlots.OpenRecovery(changedRecovery, newRk.Span, cancellationToken: TestContext.Current.CancellationToken); Assert.True(vk.Span.SequenceEqual(final.Span));
        Assert.Throws<AuthenticationTagMismatchException>(() => KeySlots.OpenRecovery(changedRecovery, rk.Span, cancellationToken: TestContext.Current.CancellationToken));
        using var retainedPassword = KeySlots.OpenPassword(changedRecovery, "new-password"u8, 65536, cancellationToken: TestContext.Current.CancellationToken);
        Assert.True(vk.Span.SequenceEqual(retainedPassword.Span));
        Assert.Throws<FormatException>(() => KeySlots.ReplaceRecovery(header, Hex(Vectors.Prefix), vk.Span, newRk.Span, cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public void ReplacementRejectsWrongParentEpochAndOverflow()
    {
        var header = Hex(Vectors.Header);
        foreach (var offset in new[] { 12, 28, 44, 60, 68, 100 })
        {
            var prefix = NextPrefix(header);
            if (offset is 44 or 100) header.AsSpan(offset, offset == 44 ? 16 : 32).CopyTo(prefix.AsSpan(offset));
            else prefix[offset] ^= 1;
            Assert.NotNull(Record.Exception(() => KeySlots.ReplaceRecovery(header, prefix, Hex(Vectors.VaultKey), Hex(Vectors.RecoveryKey), cancellationToken: TestContext.Current.CancellationToken)));
        }
        // A structurally valid max-sequence root must refuse wraparound; rebuild a valid MAC independently via BCL.
        BinaryPrimitives.WriteUInt64LittleEndian(header.AsSpan(60), ulong.MaxValue); header[68] = 1;
        HMACSHA256.HashData(Hex(Vectors.HeaderKey), "SafeNook/v1/header\0"u8.ToArray().Concat(header[..382]).ToArray()).CopyTo(header, 382);
        KeySlots.VerifyHeader(header, Hex(Vectors.VaultKey));
        Assert.Throws<FormatException>(() => KeySlots.ReplaceRecovery(header, Hex(Vectors.Prefix), Hex(Vectors.VaultKey), Hex(Vectors.RecoveryKey), cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public void RecoveryCodeIndependentVectorAndNormalisation()
    {
        Assert.Equal(Vectors.RecoveryText, RecoveryCode.Encode(Hex(Vectors.RecoveryKey)));
        foreach (var text in new[] { Vectors.RecoveryText, Vectors.RecoveryText.ToLowerInvariant(), Vectors.RecoveryText.Replace("-", " \t\r\n") })
        {
            using var key = RecoveryCode.Decode(text); Assert.Equal(Hex(Vectors.RecoveryKey), key.Span.ToArray());
        }
        for (var i = 0; i < 8; i++)
        {
            using var key = VaultCrypto.GenerateKey(); using var decoded = RecoveryCode.Decode(RecoveryCode.Encode(key.Span));
            Assert.True(key.Span.SequenceEqual(decoded.Span));
        }
    }

    [Fact]
    public void RecoveryCodeRejectsMalformedAndNoncanonical()
    {
        var code = Vectors.RecoveryText;
        var compact = code[4..].Replace("-", ""); var badPad = compact.ToCharArray();
        badPad[51] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"["ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".IndexOf(badPad[51]) | 1];
        foreach (var value in new[] { "", "SN", code[..^1], code + "A", new string('A', 257), " SN1-" + compact,
            "SN2-" + compact, "SN1-0" + compact[1..], "SN1-=" + compact[1..], "SN1-é" + compact[1..],
            "SN1-" + new string(badPad), code[..^1] + (code[^1] == 'A' ? 'B' : 'A') })
        {
            var exception = Assert.Throws<FormatException>(() => RecoveryCode.Decode(value));
            Assert.Equal("Invalid recovery code.", exception.Message);
        }
    }

    [Fact]
    public void UuidNetworkOrderAndVersionValidation()
    {
        var id = VaultFormat.ReadId(Hex(Vectors.VaultId)); Assert.Equal("00112233-4455-4677-8899-aabbccddeeff", id.ToString());
        var output = new byte[16]; VaultFormat.WriteId(id, output); Assert.Equal(Hex(Vectors.VaultId), output);
        Assert.Throws<FormatException>(() => VaultFormat.ReadId(new byte[16]));
        Assert.Throws<FormatException>(() => VaultFormat.ReadId(new byte[15]));
        var invalid = Hex(Vectors.VaultId); invalid[6] = 0x10;
        Assert.Throws<FormatException>(() => VaultFormat.ReadId(invalid)); invalid[6] = 0x40; invalid[8] = 0;
        Assert.Throws<FormatException>(() => VaultFormat.ReadId(invalid));
    }

    [Fact]
    public void SecretDisposalWipesRetainedSpanAndCancellationWithholdsOutput()
    {
        var secret = VaultCrypto.GenerateKey(); var retained = secret.Span; secret.Dispose();
        Assert.True(retained.IndexOfAnyExcept((byte)0) < 0); secret.Dispose();
        Assert.Throws<ObjectDisposedException>(() => { _ = secret.Span.Length; });
        Assert.DoesNotContain(Vectors.VaultKey, secret.ToString()!);
        Assert.Throws<OperationCanceledException>(() => ObjectCodec.Encrypt(Hex(Vectors.VaultKey), Context, [], Budget, new CancellationToken(true)));
        Assert.Throws<OperationCanceledException>(() => ObjectCodec.Decrypt(Hex(Vectors.VaultKey), Context, Hex(Vectors.WriteId), Hex(Vectors.Hash), Hex(Vectors.File), Budget, new CancellationToken(true)));
    }

    [Fact]
    public void AesDimensionsAadAndAuthenticationFailure()
    {
        var key = Hex(Vectors.ObjectKey); var file = Hex(Vectors.File);
        Assert.Throws<ArgumentException>(() => VaultCrypto.Decrypt(new byte[31], new byte[12], [], new byte[16], [], cancellationToken: TestContext.Current.CancellationToken));
        Assert.Throws<ArgumentException>(() => VaultCrypto.Decrypt(key, new byte[11], [], new byte[16], [], cancellationToken: TestContext.Current.CancellationToken));
        Assert.Throws<ArgumentException>(() => VaultCrypto.Decrypt(key, new byte[12], [], new byte[15], [], cancellationToken: TestContext.Current.CancellationToken));
        SecretBuffer? output = null;
        Assert.Throws<AuthenticationTagMismatchException>(() => output = VaultCrypto.Decrypt(key, Hex(Vectors.Nonce), file.AsSpan(118, file.Length - 134), file.AsSpan(file.Length - 16), "wrong AAD"u8, cancellationToken: TestContext.Current.CancellationToken));
        Assert.Null(output);
        var same = new byte[10]; Assert.Throws<ArgumentException>(() => VaultCrypto.Encrypt(key, new byte[12], same, [], same, new byte[16]));
    }

    [Fact]
    public async Task CancellationAroundKdfWithholdsResult()
    {
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        cancellation.CancelAfter(TimeSpan.FromMilliseconds(1));
        await Assert.ThrowsAsync<OperationCanceledException>(() => Task.Run(() =>
        {
            using var output = VaultCrypto.Argon2(Hex(Vectors.Password), new byte[16], 65536, 3, 65536, cancellation.Token);
        }, TestContext.Current.CancellationToken));
    }

    [Fact]
    public void HeaderStructuralUnknownsAndSlotOrder()
    {
        foreach (var (offset, value) in new[] { (8, 2), (10, 1), (164, 1), (182, 2), (183, 0), (184, 2), (290, 1), (291, 1), (292, 2), (294, 1) })
        {
            var header = Hex(Vectors.Header); header[offset] = (byte)value;
            Assert.Throws<FormatException>(() => VaultFormat.ValidateHeader(header));
        }
        var duplicate = Hex(Vectors.Header); duplicate.AsSpan(166, 16).CopyTo(duplicate.AsSpan(274, 16));
        Assert.Throws<FormatException>(() => VaultFormat.ValidateHeader(duplicate));
        var swapped = Hex(Vectors.Header); Hex(Vectors.RecoverySlot).CopyTo(swapped, 166); Hex(Vectors.PasswordSlot).CopyTo(swapped, 274);
        Assert.Throws<FormatException>(() => VaultFormat.ValidateHeader(swapped));
        var missingWriteId = Hex(Vectors.Header); missingWriteId.AsSpan(100, 32).Clear();
        Assert.Throws<FormatException>(() => VaultFormat.ValidateHeader(missingWriteId));
    }

    [Fact]
    public void FailedReplacementPreservesOriginalAndDoesNotExposeSecrets()
    {
        var header = Hex(Vectors.Header); var original = header.ToArray();
        var error = Assert.Throws<InvalidOperationException>(() => KeySlots.ReplacePassword(header, NextPrefix(header), Hex(Vectors.VaultKey),
            Hex(Vectors.Password), 65536, 3, 65535, TestContext.Current.CancellationToken));
        Assert.Equal(original, header); Assert.DoesNotContain(Encoding.UTF8.GetString(Hex(Vectors.Password)), error.ToString());
        var damaged = header.ToArray(); damaged[^1] ^= 1;
        Assert.Throws<CryptographicException>(() => KeySlots.ReplaceRecovery(damaged, NextPrefix(header), Hex(Vectors.VaultKey), Hex(Vectors.RecoveryKey), TestContext.Current.CancellationToken));
        Assert.Equal(original, header);
    }

    private static byte[] NextPrefix(byte[] header) => VaultFormat.EncodePrefix(
        VaultFormat.ReadId(header.AsSpan(12, 16)), VaultFormat.ReadId(header.AsSpan(28, 16)), VaultFormat.NewId(),
        BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(60)) + 1, SHA256.HashData(header), RandomNumberGenerator.GetBytes(32), new byte[32]);
}
