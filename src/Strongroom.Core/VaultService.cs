using System.Security.Cryptography;
using System.Text.Json;
using Strongroom.Core.Crypto;
using Strongroom.Core.Storage;

namespace Strongroom.Core;

public enum RegisterResult { Created, UsernameTaken, InvalidUsername, WeakPassword }

public enum ChangePasswordResult { Changed, WrongCurrentPassword, WeakPassword, SameAsCurrent }

public sealed class VaultService
{
    public const int MinUsernameLength = 3;
    public const int MaxUsernameLength = 64;
    public const int MinPasswordLength = 12;

    private readonly VaultStore _store;
    private readonly KdfParams _kdf;

    // Used to burn the same CPU time for unknown usernames so response timing doesn't reveal who has an account.
    private readonly byte[] _dummySalt = VaultCrypto.NewSalt();

    public VaultService(VaultStore store, KdfParams? kdf = null)
    {
        _store = store;
        _kdf = kdf ?? KdfParams.Default;
    }

    public RegisterResult Register(string username, string masterPassword)
    {
        username = username?.Trim() ?? "";
        if (username.Length is < MinUsernameLength or > MaxUsernameLength) return RegisterResult.InvalidUsername;
        if ((masterPassword?.Length ?? 0) < MinPasswordLength) return RegisterResult.WeakPassword;

        var userId = Guid.NewGuid();
        var salt = VaultCrypto.NewSalt();
        var kek = VaultCrypto.DeriveKey(masterPassword!, salt, _kdf);
        var vaultKey = VaultCrypto.NewVaultKey();
        try
        {
            var wrapped = VaultCrypto.Encrypt(kek, vaultKey, VaultCrypto.KeyAad(userId));
            var user = new UserRecord(userId, username, salt, _kdf, wrapped, DateTime.UtcNow);
            return _store.TryCreateUser(user) ? RegisterResult.Created : RegisterResult.UsernameTaken;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
            CryptographicOperations.ZeroMemory(vaultKey);
        }
    }

    /// <summary>
    /// Re-wraps the vault key under a new master password (new salt, current KDF settings).
    /// Credentials are not re-encrypted because they are protected by the vault key, which does not change.
    /// </summary>
    public ChangePasswordResult ChangeMasterPassword(UnlockedVault vault, string currentPassword, string newPassword)
    {
        if ((newPassword?.Length ?? 0) < MinPasswordLength) return ChangePasswordResult.WeakPassword;
        if (newPassword == currentPassword) return ChangePasswordResult.SameAsCurrent;

        // Prove the caller knows the current password (an unlocked session alone isn't enough).
        using var proof = Unlock(vault.Username, currentPassword);
        if (proof is null) return ChangePasswordResult.WrongCurrentPassword;

        var salt = VaultCrypto.NewSalt();
        var kek = VaultCrypto.DeriveKey(newPassword!, salt, _kdf);
        var vaultKey = vault.CopyKey();
        try
        {
            var wrapped = VaultCrypto.Encrypt(kek, vaultKey, VaultCrypto.KeyAad(vault.UserId));
            _store.UpdateUserKey(vault.UserId, salt, _kdf, wrapped);
            return ChangePasswordResult.Changed;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
            CryptographicOperations.ZeroMemory(vaultKey);
        }
    }

    /// <returns>An unlocked vault, or null if the username or password is wrong (callers can't tell which).</returns>
    public UnlockedVault? Unlock(string username, string masterPassword)
    {
        var user = _store.FindUser(username?.Trim() ?? "");
        if (user is null)
        {
            VaultCrypto.DeriveKey(masterPassword ?? "", _dummySalt, _kdf);
            return null;
        }

        var kek = VaultCrypto.DeriveKey(masterPassword ?? "", user.Salt, user.Kdf);
        try
        {
            var vaultKey = VaultCrypto.Decrypt(kek, user.WrappedKey, VaultCrypto.KeyAad(user.Id));
            return new UnlockedVault(_store, user.Id, user.Username, vaultKey);
        }
        catch (CryptographicException)
        {
            return null; // GCM tag mismatch = wrong password
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }
    }
}

/// <summary>A user's vault while the vault key is held in memory. Dispose to wipe the key (this is "lock").</summary>
public sealed class UnlockedVault : IDisposable
{
    private readonly VaultStore _store;
    private byte[] _key;

    public Guid UserId { get; }
    public string Username { get; }

    internal UnlockedVault(VaultStore store, Guid userId, string username, byte[] key)
    {
        _store = store;
        UserId = userId;
        Username = username;
        _key = key;
    }

    /// <summary>A copy of the vault key for re-wrapping. The caller must zero it.</summary>
    internal byte[] CopyKey() => (byte[])_key.Clone();

    public IReadOnlyList<CredentialView> List()
    {
        var result = new List<CredentialView>();
        foreach (var row in _store.ListCredentials(UserId))
        {
            var json = VaultCrypto.Decrypt(_key, row.Blob, VaultCrypto.CredentialAad(UserId, row.Id));
            try
            {
                var d = JsonSerializer.Deserialize<CredentialData>(json)!;
                result.Add(new CredentialView(row.Id, d.Name, d.Url, d.Username, d.Password, d.Category, d.Notes, row.UpdatedUtc));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(json);
            }
        }
        return result;
    }

    public CredentialView Add(CredentialData data)
    {
        var id = Guid.NewGuid();
        var now = DateTime.UtcNow;
        _store.InsertCredential(UserId, new StoredCredential(id, Seal(id, data), now));
        return new CredentialView(id, data.Name, data.Url, data.Username, data.Password, data.Category, data.Notes, now);
    }

    public CredentialView? Update(Guid id, CredentialData data)
    {
        var now = DateTime.UtcNow;
        return _store.UpdateCredential(UserId, new StoredCredential(id, Seal(id, data), now))
            ? new CredentialView(id, data.Name, data.Url, data.Username, data.Password, data.Category, data.Notes, now)
            : null;
    }

    public bool Delete(Guid id) => _store.DeleteCredential(UserId, id);

    private byte[] Seal(Guid credentialId, CredentialData data)
    {
        var json = JsonSerializer.SerializeToUtf8Bytes(data);
        try
        {
            return VaultCrypto.Encrypt(_key, json, VaultCrypto.CredentialAad(UserId, credentialId));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(json);
        }
    }

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(_key);
        _key = [];
    }
}
