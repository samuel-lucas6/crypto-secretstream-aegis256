# crypto-secretstream-aegis256
Libsodium's [crypto_secretstream](https://doc.libsodium.org/secret-key_cryptography/secretstream) using [AEGIS-256](https://doc.libsodium.org/secret-key_cryptography/aead/aegis-256).

## Algorithm
Initialisation doesn't derive a subkey because [nonce extension](https://soatok.blog/2021/03/12/understanding-extended-nonce-constructions/) is unnecessary with AEGIS-256 since the nonce is 256 bits. However, this implementation only randomly generates the first 192 bits (`n`), leaving the remaining 64 bits for an unsigned little-endian counter (`i`).

```
n <- CSPRNG(n.Length)
i <- 1
```

Encryption is also slightly different as it's not possible to pad the tag (`T`) without storing the encrypted padding. Therefore, the single byte tag is prepended to the message (`M`). The nonce and counter are also concatenated the other way around because there's no need to conform to the [XChaCha20 Internet-Draft](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha#section-2).

```
c || mac <- AEGIS-256(key = k, nonce = n || i, msg = T || M)
n <- n ^ mac[0..24]
i <- i + 1
if i = 0 or T = ChunkFlag.Rekey:
   Rekey()
```

As Libsodium doesn't offer a [stream cipher API](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-aegis-aead#section-7) for AEGIS-256, rekeying requires computing an authentication tag (`mac`). This data is ignored/discarded because it [shouldn't](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-aegis-aead#section-8) be used for key derivation.

```
k || n || mac <- AEGIS-256(key = key, nonce = n || i, msg = k || n)
i <- 1
```

Rekeying occurs when the counter overflows, when `ChunkFlag.Rekey` is specified, or when the `Rekey()` method is called. The `Rekey()` method doesn't store anything, so it must manually be called at the same position in the stream during decryption.
