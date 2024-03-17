using System.Security.Cryptography;
using System.Buffers.Binary;
using Geralt;

namespace AegisSecretStreamDotNet;

public sealed class SecretStream : IDisposable
{
    public const int KeySize = AEGIS256.KeySize;
    public const int HeaderSize = XChaCha20Poly1305.NonceSize;
    public const int TagSize = AEGIS256.TagSize + FlagSize;
    private const int FlagSize = 1;

    private bool _disposed;
    private bool _encryption;
    private byte[] _key = GC.AllocateArray<byte>(AEGIS256.KeySize, pinned: true);
    private byte[] _nonce = GC.AllocateArray<byte>(AEGIS256.NonceSize, pinned: true);
    private ulong _counter = 1; // 0 is used for rekeying

    public enum ChunkFlag
    {
        Message = 0x00,
        Boundary = 0x01,
        Rekey = 0x02,
        Final = 0x03
    }

    public SecretStream(Span<byte> header, ReadOnlySpan<byte> key, bool encryption)
    {
        Validation.EqualToSize(nameof(header), header.Length, HeaderSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        _disposed = false;
        _encryption = encryption;
        if (encryption) {
            SecureRandom.Fill(header);
        }
        header.CopyTo(_nonce);
        key.CopyTo(_key);
    }

    public void Push(Span<byte> ciphertextChunk, ReadOnlySpan<byte> plaintextChunk, ChunkFlag chunkFlag)
    {
        Push(ciphertextChunk, plaintextChunk, associatedData: ReadOnlySpan<byte>.Empty, chunkFlag);
    }

    public void Push(Span<byte> ciphertextChunk, ReadOnlySpan<byte> plaintextChunk, ReadOnlySpan<byte> associatedData, ChunkFlag chunkFlag)
    {
        if (!_encryption) { throw new InvalidOperationException("Cannot push when decrypting."); }
        if (_disposed) { throw new InvalidOperationException("Cannot push after being disposed/the final chunk."); }
        Validation.EqualToSize(nameof(ciphertextChunk), ciphertextChunk.Length, plaintextChunk.Length + TagSize);

        Span<byte> plaintext = GC.AllocateArray<byte>(FlagSize + plaintextChunk.Length, pinned: true);
        plaintext[0] = (byte)chunkFlag;
        plaintextChunk.CopyTo(plaintext[FlagSize..]);

        Span<byte> nonce = _nonce.AsSpan();
        BinaryPrimitives.WriteUInt64LittleEndian(nonce[HeaderSize..], _counter);

        AEGIS256.Encrypt(ciphertextChunk, plaintext, nonce, _key, associatedData);
        CryptographicOperations.ZeroMemory(plaintext);

        Span<byte> tag = ciphertextChunk[^AEGIS256.TagSize..];
        for (int i = 0; i < HeaderSize; i++) {
            nonce[i] = (byte)(nonce[i] ^ tag[i]);
        }

        _counter++;
        if (chunkFlag == ChunkFlag.Rekey || _counter == 0) {
            Rekey();
        }

        if (chunkFlag == ChunkFlag.Final) {
            Dispose();
        }
    }

    public ChunkFlag Pull(Span<byte> plaintextChunk, ReadOnlySpan<byte> ciphertextChunk, ReadOnlySpan<byte> associatedData = default)
    {
        if (_encryption) { throw new InvalidOperationException("Cannot pull when encrypting."); }
        if (_disposed) { throw new InvalidOperationException("Cannot pull after being disposed/the final chunk."); }
        Validation.NotLessThanMin(nameof(ciphertextChunk), ciphertextChunk.Length, TagSize);
        Validation.EqualToSize(nameof(plaintextChunk), plaintextChunk.Length, ciphertextChunk.Length - TagSize);

        Span<byte> plaintext = GC.AllocateArray<byte>(FlagSize + plaintextChunk.Length, pinned: true);
        Span<byte> nonce = _nonce.AsSpan();
        BinaryPrimitives.WriteUInt64LittleEndian(nonce[HeaderSize..], _counter);
        AEGIS256.Decrypt(plaintext, ciphertextChunk, nonce, _key, associatedData);

        ReadOnlySpan<byte> tag = ciphertextChunk[^AEGIS256.TagSize..];
        for (int i = 0; i < HeaderSize; i++) {
            nonce[i] = (byte)(nonce[i] ^ tag[i]);
        }

        _counter++;
        var chunkFlag = (ChunkFlag)plaintext[0];
        if (chunkFlag == ChunkFlag.Rekey || _counter == 0) {
            Rekey();
        }

        plaintext[FlagSize..].CopyTo(plaintextChunk);
        CryptographicOperations.ZeroMemory(plaintext);

        if (chunkFlag == ChunkFlag.Final) {
            Dispose();
        }
        return chunkFlag;
    }

    public void Rekey()
    {
        if (_disposed) { throw new InvalidOperationException("Cannot rekey after being disposed/the final chunk."); }

        Span<byte> nonce = _nonce.AsSpan();
        BinaryPrimitives.WriteUInt64LittleEndian(nonce[HeaderSize..], _counter);

        Span<byte> plaintext = stackalloc byte[KeySize + HeaderSize];
        _key.CopyTo(plaintext);
        nonce[..HeaderSize].CopyTo(plaintext[KeySize..]);

        Span<byte> ciphertext = stackalloc byte[KeySize + HeaderSize + AEGIS256.TagSize];
        AEGIS256.Encrypt(ciphertext, plaintext, nonce, _key, associatedData: ReadOnlySpan<byte>.Empty);
        ciphertext[..KeySize].CopyTo(_key);
        ciphertext.Slice(KeySize, HeaderSize).CopyTo(nonce[..HeaderSize]);
        _counter = 1;

        CryptographicOperations.ZeroMemory(plaintext);
        CryptographicOperations.ZeroMemory(ciphertext);
    }

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(_key);
        CryptographicOperations.ZeroMemory(_nonce);
        _counter = 1;
        _disposed = true;
    }
}
