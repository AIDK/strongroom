using System.Security.Cryptography;
using Strongroom.Core.Crypto;

namespace Strongroom.Tests;

public class VaultCryptoTests
{
    private static readonly KdfParams Fast = new(MemoryKiB: 1024, Iterations: 1, Parallelism: 1);

    [Fact]
    public void Encrypt_then_decrypt_round_trips()
    {
        var key = VaultCrypto.NewVaultKey();
        var aad = new byte[] { 1, 2, 3 };
        var blob = VaultCrypto.Encrypt(key, "hunter2"u8, aad);

        Assert.Equal("hunter2"u8.ToArray(), VaultCrypto.Decrypt(key, blob, aad));
    }

    [Fact]
    public void Same_plaintext_encrypts_differently_each_time()
    {
        var key = VaultCrypto.NewVaultKey();
        var a = VaultCrypto.Encrypt(key, "same"u8, []);
        var b = VaultCrypto.Encrypt(key, "same"u8, []);

        Assert.NotEqual(a, b); // fresh random nonce every time
    }

    [Fact]
    public void Decrypt_with_wrong_key_fails()
    {
        var blob = VaultCrypto.Encrypt(VaultCrypto.NewVaultKey(), "secret"u8, []);

        Assert.ThrowsAny<CryptographicException>(() => VaultCrypto.Decrypt(VaultCrypto.NewVaultKey(), blob, []));
    }

    [Fact]
    public void Decrypt_with_wrong_aad_fails()
    {
        var key = VaultCrypto.NewVaultKey();
        var blob = VaultCrypto.Encrypt(key, "secret"u8, new byte[] { 1 });

        Assert.ThrowsAny<CryptographicException>(() => VaultCrypto.Decrypt(key, blob, new byte[] { 2 }));
    }

    [Theory]
    [InlineData(0)]                 // nonce
    [InlineData(15)]                // ciphertext
    public void Tampering_with_any_byte_is_detected(int index)
    {
        var key = VaultCrypto.NewVaultKey();
        var blob = VaultCrypto.Encrypt(key, "secret-value"u8, []);
        blob[index] ^= 0xFF;

        Assert.ThrowsAny<CryptographicException>(() => VaultCrypto.Decrypt(key, blob, []));
    }

    [Fact]
    public void Tampering_with_the_tag_is_detected()
    {
        var key = VaultCrypto.NewVaultKey();
        var blob = VaultCrypto.Encrypt(key, "secret-value"u8, []);
        blob[^1] ^= 0xFF;

        Assert.ThrowsAny<CryptographicException>(() => VaultCrypto.Decrypt(key, blob, []));
    }

    [Fact]
    public void Truncated_blob_is_rejected()
    {
        Assert.ThrowsAny<CryptographicException>(() => VaultCrypto.Decrypt(VaultCrypto.NewVaultKey(), new byte[10], []));
    }

    [Fact]
    public void Key_derivation_is_deterministic_and_depends_on_password_and_salt()
    {
        var salt = VaultCrypto.NewSalt();
        var k1 = VaultCrypto.DeriveKey("correct horse", salt, Fast);

        Assert.Equal(32, k1.Length);
        Assert.Equal(k1, VaultCrypto.DeriveKey("correct horse", salt, Fast));
        Assert.NotEqual(k1, VaultCrypto.DeriveKey("correct horsf", salt, Fast));
        Assert.NotEqual(k1, VaultCrypto.DeriveKey("correct horse", VaultCrypto.NewSalt(), Fast));
    }

    [Fact]
    public void Key_derivation_treats_equivalent_unicode_as_the_same_password()
    {
        var salt = VaultCrypto.NewSalt();
        // "é" as one code point vs "e" + combining accent
        Assert.Equal(
            VaultCrypto.DeriveKey("café-password", salt, Fast),
            VaultCrypto.DeriveKey("café-password", salt, Fast));
    }

    [Fact]
    public void Credential_aad_differs_per_user_and_per_record()
    {
        var u1 = Guid.NewGuid(); var u2 = Guid.NewGuid(); var c = Guid.NewGuid();

        Assert.NotEqual(VaultCrypto.CredentialAad(u1, c), VaultCrypto.CredentialAad(u2, c));
        Assert.NotEqual(VaultCrypto.CredentialAad(u1, c), VaultCrypto.CredentialAad(u1, Guid.NewGuid()));
        Assert.NotEqual(VaultCrypto.KeyAad(u1), VaultCrypto.CredentialAad(u1, c));
    }
}
