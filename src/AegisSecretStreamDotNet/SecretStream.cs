using System.Buffers.Binary;
using Geralt;

namespace AegisSecretStreamDotNet;

public sealed class SecretStream : IDisposable
{
    public const int KeySize = AEGIS256.KeySize;
    public const int HeaderSize = XChaCha20Poly1305.NonceSize;
    public const int TagSize = AEGIS256.TagSize + FlagSize;
    private const int FlagSize = 1;
    private readonly byte[] _key = GC.AllocateArray<byte>(AEGIS256.KeySize, pinned: true);
    private readonly byte[] _nonce = GC.AllocateArray<byte>(AEGIS256.NonceSize, pinned: true);
    private ulong _counter;
    private bool _encryption;
    private bool _finalized;
    private bool _disposed;

    public enum ChunkFlag
    {
        Message = 0x00,
        Boundary = 0x01,
        Rekey = 0x02,
        Final = 0x03
    }

    public SecretStream(Span<byte> header, ReadOnlySpan<byte> key, bool encryption)
    {
        Reinitialize(header, key, encryption);
    }

    public void Reinitialize(Span<byte> header, ReadOnlySpan<byte> key, bool encryption)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(SecretStream)); }
        Validation.EqualToSize(nameof(header), header.Length, HeaderSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        if (encryption) {
            SecureRandom.Fill(header);
        }
        header.CopyTo(_nonce);
        key.CopyTo(_key);
        _counter = 1;
        _encryption = encryption;
        _finalized = false;
    }

    public void Push(Span<byte> ciphertextChunk, ReadOnlySpan<byte> plaintextChunk, ChunkFlag chunkFlag)
    {
        Push(ciphertextChunk, plaintextChunk, associatedData: ReadOnlySpan<byte>.Empty, chunkFlag);
    }

    public void Push(Span<byte> ciphertextChunk, ReadOnlySpan<byte> plaintextChunk, ReadOnlySpan<byte> associatedData, ChunkFlag chunkFlag)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(SecretStream)); }
        if (!_encryption) { throw new InvalidOperationException("Cannot push when decrypting."); }
        if (_finalized) { throw new InvalidOperationException("Cannot push after the final chunk."); }
        Validation.EqualToSize(nameof(ciphertextChunk), ciphertextChunk.Length, plaintextChunk.Length + TagSize);

        Span<byte> plaintext = GC.AllocateArray<byte>(FlagSize + plaintextChunk.Length, pinned: true);
        plaintext[0] = (byte)chunkFlag;
        plaintextChunk.CopyTo(plaintext[FlagSize..]);

        Span<byte> nonce = _nonce.AsSpan();
        BinaryPrimitives.WriteUInt64LittleEndian(nonce[HeaderSize..], _counter);

        AEGIS256.Encrypt(ciphertextChunk, plaintext, nonce, _key, associatedData);
        SecureMemory.ZeroMemory(plaintext);

        Span<byte> tag = ciphertextChunk[^AEGIS256.TagSize..];
        for (int i = 0; i < HeaderSize; i++) {
            nonce[i] = (byte)(nonce[i] ^ tag[i]);
        }

        _counter++;
        if (chunkFlag == ChunkFlag.Rekey || _counter == 0) {
            Rekey();
        }

        if (chunkFlag == ChunkFlag.Final) {
            _finalized = true;
        }
    }

    public ChunkFlag Pull(Span<byte> plaintextChunk, ReadOnlySpan<byte> ciphertextChunk, ReadOnlySpan<byte> associatedData = default)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(SecretStream)); }
        if (_encryption) { throw new InvalidOperationException("Cannot pull when encrypting."); }
        if (_finalized) { throw new InvalidOperationException("Cannot pull after the final chunk."); }
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
        SecureMemory.ZeroMemory(plaintext);

        if (chunkFlag == ChunkFlag.Final) {
            _finalized = true;
        }
        return chunkFlag;
    }

    public void Rekey()
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(SecretStream)); }
        if (_finalized) { throw new InvalidOperationException("Cannot rekey after the final chunk."); }

        Span<byte> nonce = _nonce.AsSpan();
        BinaryPrimitives.WriteUInt64LittleEndian(nonce[HeaderSize..], _counter);

        Span<byte> ciphertext = stackalloc byte[KeySize + HeaderSize + AEGIS256.TagSize], plaintext = ciphertext[..^AEGIS256.TagSize];
        _key.CopyTo(plaintext);
        nonce[..HeaderSize].CopyTo(plaintext[KeySize..]);

        AEGIS256.Encrypt(ciphertext, plaintext, nonce, _key, associatedData: ReadOnlySpan<byte>.Empty);
        ciphertext[..KeySize].CopyTo(_key);
        ciphertext[KeySize..^AEGIS256.TagSize].CopyTo(nonce[..HeaderSize]);
        _counter = 1;
        SecureMemory.ZeroMemory(ciphertext);
    }

    public void Dispose()
    {
        if (_disposed) { return; }
        SecureMemory.ZeroMemory(_key);
        SecureMemory.ZeroMemory(_nonce);
        _counter = 0;
        _disposed = true;
    }
}
