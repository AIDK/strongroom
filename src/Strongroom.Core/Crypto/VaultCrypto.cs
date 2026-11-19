using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace Strongroom.Core.Crypto;

/// <summary>Argon2id cost settings. Stored per user so they can be raised later without breaking old accounts.</summary>
public sealed record KdfParams(int MemoryKiB, int Iterations, int Parallelism)
{
    /// <summary>64 MiB, 3 passes, 2 lanes: roughly 0.3-0.5s on a modern PC.</summary>
    public static KdfParams Default { get; } = new(65536, 3, 2);
}

/// <summary>
/// The only place that touches key material. Design:
///   master password --Argon2id(salt)--> key-encryption key (KEK)
///   random 256-bit vault key (DEK) is stored only wrapped (AES-256-GCM) by the KEK
///   every credential is one AES-256-GCM blob under the DEK.
/// A wrong master password fails the GCM tag check on the wrapped key, so no password hash is stored.
/// Blob layout: nonce(12) || ciphertext || tag(16).
/// </summary>
public static class VaultCrypto
{
    public const int KeySize = 32;
    public const int SaltSize = 16;
    private const int NonceSize = 12;
    private const int TagSize = 16;

    public static byte[] RandomBytes(int length) => RandomNumberGenerator.GetBytes(length);
    public static byte[] NewSalt() => RandomBytes(SaltSize);
    public static byte[] NewVaultKey() => RandomBytes(KeySize);

    public static byte[] DeriveKey(string password, byte[] salt, KdfParams kdf)
    {
        var pw = Encoding.UTF8.GetBytes(password.Normalize(NormalizationForm.FormKC));
        try
        {
            using var argon = new Argon2id(pw)
            {
                Salt = salt,
                MemorySize = kdf.MemoryKiB,
                Iterations = kdf.Iterations,
                DegreeOfParallelism = kdf.Parallelism,
            };
            return argon.GetBytes(KeySize);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pw);
        }
    }

    /// <param name="aad">Authenticated but not encrypted. Binds a blob to its owner/record so blobs can't be swapped in the database.</param>
    public static byte[] Encrypt(byte[] key, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> aad)
    {
        var blob = new byte[NonceSize + plaintext.Length + TagSize];
        var nonce = blob.AsSpan(0, NonceSize);
        RandomNumberGenerator.Fill(nonce);
        using var aes = new AesGcm(key, TagSize);
        aes.Encrypt(nonce, plaintext, blob.AsSpan(NonceSize, plaintext.Length), blob.AsSpan(NonceSize + plaintext.Length, TagSize), aad);
        return blob;
    }

    /// <exception cref="CryptographicException">Wrong key, tampered data, or wrong AAD.</exception>
    public static byte[] Decrypt(byte[] key, byte[] blob, ReadOnlySpan<byte> aad)
    {
        if (blob.Length < NonceSize + TagSize)
            throw new CryptographicException("Encrypted data is too short.");

        var cipherLength = blob.Length - NonceSize - TagSize;
        var plaintext = new byte[cipherLength];
        using var aes = new AesGcm(key, TagSize);
        aes.Decrypt(
            blob.AsSpan(0, NonceSize),
            blob.AsSpan(NonceSize, cipherLength),
            blob.AsSpan(NonceSize + cipherLength, TagSize),
            plaintext,
            aad);
        return plaintext;
    }

    public static byte[] KeyAad(Guid userId) => Aad("strongroom:key:v1", userId);
    public static byte[] CredentialAad(Guid userId, Guid credentialId) => Aad("strongroom:cred:v1", userId, credentialId);

    private static byte[] Aad(string label, params Guid[] ids)
    {
        var labelBytes = Encoding.UTF8.GetBytes(label);
        var result = new byte[labelBytes.Length + ids.Length * 16];
        labelBytes.CopyTo(result, 0);
        for (var i = 0; i < ids.Length; i++)
            ids[i].TryWriteBytes(result.AsSpan(labelBytes.Length + i * 16));
        return result;
    }
}
