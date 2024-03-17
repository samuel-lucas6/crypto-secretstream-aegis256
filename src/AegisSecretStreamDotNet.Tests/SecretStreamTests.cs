using System.Security.Cryptography;

namespace AegisSecretStreamDotNet.Tests;

[TestClass]
public class SecretStreamTests
{
    public static IEnumerable<object[]> EncryptParameters()
    {
        yield return
        [
            "1001000000000000000000000000000000000000000000000000000000000000",
            "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829"
        ];
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, SecretStream.KeySize);
        Assert.AreEqual(24, SecretStream.HeaderSize);
        Assert.AreEqual(33, SecretStream.TagSize);
    }

    [TestMethod]
    [DynamicData(nameof(EncryptParameters), DynamicDataSourceType.Method)]
    public void SingleChunk_Valid(string key, string plaintext, string associatedData)
    {
        Span<byte> h = stackalloc byte[SecretStream.HeaderSize];
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> c = stackalloc byte[p.Length + SecretStream.TagSize];

        using var encryption = new SecretStream(h, k, encryption: true);
        encryption.Push(c, p, SecretStream.ChunkFlag.Final);
        p.Clear();

        using var decryption = new SecretStream(h, k, encryption: false);
        var chunkFlag = decryption.Pull(p, c);

        Assert.AreEqual(SecretStream.ChunkFlag.Final, chunkFlag);
        Assert.AreEqual(plaintext, Convert.ToHexString(p).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(EncryptParameters), DynamicDataSourceType.Method)]
    public void MultipleChunks_Valid(string key, string plaintext, string associatedData)
    {
        Span<byte> h = stackalloc byte[SecretStream.HeaderSize];
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> p1 = p[..10], p2 = p[10..20], p3 = p[20..30], p4 = p[30..];
        Span<byte> c = stackalloc byte[(p1.Length + SecretStream.TagSize) * 4];
        Span<byte> c1 = c[..43], c2 = c[43..86], c3 = c[86..129], c4 = c[129..];
        Span<byte> ad = Convert.FromHexString(associatedData);

        using var encryption = new SecretStream(h, k, encryption: true);
        encryption.Push(c1, p1, SecretStream.ChunkFlag.Message);
        encryption.Rekey();
        encryption.Push(c2, p2, SecretStream.ChunkFlag.Boundary);
        encryption.Push(c3, p3, ad, SecretStream.ChunkFlag.Rekey);
        encryption.Push(c4, p4, SecretStream.ChunkFlag.Final);
        p.Clear();

        using var decryption = new SecretStream(h, k, encryption: false);
        var chunkFlag = decryption.Pull(p1, c1);
        Assert.AreEqual(SecretStream.ChunkFlag.Message, chunkFlag);
        decryption.Rekey();
        chunkFlag = decryption.Pull(p2, c2);
        Assert.AreEqual(SecretStream.ChunkFlag.Boundary, chunkFlag);
        chunkFlag = decryption.Pull(p3, c3, ad);
        Assert.AreEqual(SecretStream.ChunkFlag.Rekey, chunkFlag);
        chunkFlag = decryption.Pull(p4, c4);
        Assert.AreEqual(SecretStream.ChunkFlag.Final, chunkFlag);

        Assert.AreEqual(plaintext, Convert.ToHexString(p).ToLower());
    }

    [TestMethod]
    [DataRow("48a5c0696dd7d7a0f7cba1ee11b3ea5931603e32469e3720", "1001000000000000000000000000000000000000000000000000000000000000", "334026b2962971d3f576f14a834445c23026c84a9ecce2de620215365c6c6e4f5db58a65fbaf8e9dd35cc97322c2e2024493729e375258ee1196aa4d90bb22c87da33e32e7bbdb6034", "")]
    [DataRow("7ad32916aa5d1f7e557c04af52605b955d84ccd62a412ad3", "1001000000000000000000000000000000000000000000000000000000000000", "b4e20456fd7bec75be2c8cd3d725498505ee3022b35012d6c329d3ad4e51f2adfa8e534df3a6ce9a148f82e28ecdbfda5b37ef068fdaabaa3b88ee9b37a4cb1aae363efe366c7a1fa7", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829")]
    public void SingleChunk_Tampered(string header, string key, string ciphertext, string associatedData)
    {
        var parameters = new List<byte[]>
        {
            Convert.FromHexString(header),
            Convert.FromHexString(key),
            Convert.FromHexString(ciphertext),
            Convert.FromHexString(associatedData)
        };
        var p = new byte[parameters[2].Length - SecretStream.TagSize];

        foreach (var param in parameters.Where(param => param.Length > 0)) {
            param[0]++;
            using var decryption = new SecretStream(parameters[0], parameters[1], encryption: false);
            Assert.ThrowsException<CryptographicException>(() => decryption.Pull(p, parameters[2], parameters[3]));
            param[0]--;
        }
        Assert.IsTrue(p.SequenceEqual(new byte[p.Length]));
    }

    [TestMethod]
    [DataRow(SecretStream.HeaderSize + 1, SecretStream.KeySize, SecretStream.TagSize, 0)]
    [DataRow(SecretStream.HeaderSize - 1, SecretStream.KeySize, SecretStream.TagSize, 0)]
    [DataRow(SecretStream.HeaderSize, SecretStream.KeySize + 1, SecretStream.TagSize, 0)]
    [DataRow(SecretStream.HeaderSize, SecretStream.KeySize - 1, SecretStream.TagSize, 0)]
    [DataRow(SecretStream.HeaderSize, SecretStream.KeySize, SecretStream.TagSize, 1)]
    public void InvalidParameterSizes(int headerSize, int keySize, int ciphertextSize, int plaintextSize)
    {
        var h = new byte[headerSize];
        var k = new byte[keySize];
        var c = new byte[ciphertextSize];
        var p = new byte[plaintextSize];

        if (h.Length != SecretStream.HeaderSize || k.Length != SecretStream.KeySize) {
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => new SecretStream(h, k, encryption: true));
        }
        else {
            using var encryption = new SecretStream(h, k, encryption: true);
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => encryption.Push(c, p, SecretStream.ChunkFlag.Final));

            using var decryption = new SecretStream(h, k, encryption: false);
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => decryption.Pull(p, c));
        }
    }

    [TestMethod]
    public void InvalidOperation()
    {
        var h = new byte[SecretStream.HeaderSize];
        var k = new byte[SecretStream.KeySize];
        var p = new byte[h.Length];
        var c = new byte[p.Length + SecretStream.TagSize];

        using var encryption = new SecretStream(h, k, encryption: true);
        Assert.ThrowsException<InvalidOperationException>(() => encryption.Pull(p, c));
        encryption.Push(c, p, SecretStream.ChunkFlag.Final);
        Assert.ThrowsException<InvalidOperationException>(() => encryption.Push(c, p, SecretStream.ChunkFlag.Message));

        using var decryption = new SecretStream(h, k, encryption: false);
        Assert.ThrowsException<InvalidOperationException>(() => decryption.Push(c, p, SecretStream.ChunkFlag.Final));
        decryption.Pull(p, c);
        Assert.ThrowsException<InvalidOperationException>(() => decryption.Pull(p, c));
    }

    [TestMethod]
    [DynamicData(nameof(EncryptParameters), DynamicDataSourceType.Method)]
    public void SingleChunk_MissingRekey(string key, string plaintext, string associatedData)
    {
        var h = new byte[SecretStream.HeaderSize];
        var k = Convert.FromHexString(key);
        var p = Convert.FromHexString(plaintext);
        var c = new byte[p.Length + SecretStream.TagSize];

        using var encryption = new SecretStream(h, k, encryption: true);
        encryption.Rekey();
        encryption.Push(c, p, SecretStream.ChunkFlag.Final);

        using var decryption = new SecretStream(h, k, encryption: false);
        Assert.ThrowsException<CryptographicException>(() => decryption.Pull(p, c));
    }
}
