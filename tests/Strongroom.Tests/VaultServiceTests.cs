using Microsoft.Data.Sqlite;
using Strongroom.Core;
using Strongroom.Core.Crypto;
using Strongroom.Core.Storage;

namespace Strongroom.Tests;

public sealed class VaultServiceTests : IDisposable
{
    private const string GoodPassword = "a-long-master-password";
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "strongroom-tests-" + Guid.NewGuid());
    private readonly string _db;
    private readonly VaultStore _store;
    private readonly VaultService _service;

    public VaultServiceTests()
    {
        _db = Path.Combine(_dir, "test.db");
        _store = new VaultStore(_db);
        _service = new VaultService(_store, new KdfParams(1024, 1, 1));
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { /* best effort */ }
    }

    private static CredentialData Sample(string name = "Sage One") =>
        new(name, "https://sage.example", "andries", "S3cret!pw", "Work apps", "notes here");

    private UnlockedVault Login(string user = "andries", string password = GoodPassword) =>
        _service.Unlock(user, password) ?? throw new Exception("login failed");

    [Fact]
    public void Register_validates_input()
    {
        Assert.Equal(RegisterResult.InvalidUsername, _service.Register("ab", GoodPassword));
        Assert.Equal(RegisterResult.WeakPassword, _service.Register("andries", "short"));
        Assert.Equal(RegisterResult.Created, _service.Register("andries", GoodPassword));
        Assert.Equal(RegisterResult.UsernameTaken, _service.Register("ANDRIES", GoodPassword));
    }

    [Fact]
    public void Unlock_succeeds_with_correct_password_and_fails_otherwise()
    {
        _service.Register("andries", GoodPassword);

        using var ok = _service.Unlock("andries", GoodPassword);
        Assert.NotNull(ok);
        Assert.Null(_service.Unlock("andries", "the-wrong-password"));
        Assert.Null(_service.Unlock("nobody", GoodPassword));
        Assert.NotNull(_service.Unlock("ANDRIES", GoodPassword)); // usernames are case-insensitive
    }

    [Fact]
    public void Credentials_round_trip_through_the_vault()
    {
        _service.Register("andries", GoodPassword);
        using var vault = Login();

        var added = vault.Add(Sample());
        var listed = Assert.Single(vault.List());

        Assert.Equal(added.Id, listed.Id);
        Assert.Equal("Sage One", listed.Name);
        Assert.Equal("S3cret!pw", listed.Password);
        Assert.Equal("notes here", listed.Notes);
    }

    [Fact]
    public void Credentials_survive_lock_and_unlock()
    {
        _service.Register("andries", GoodPassword);
        using (var first = Login()) first.Add(Sample());

        using var second = Login();
        Assert.Equal("S3cret!pw", Assert.Single(second.List()).Password);
    }

    [Fact]
    public void Update_and_delete_work_and_report_missing_ids()
    {
        _service.Register("andries", GoodPassword);
        using var vault = Login();
        var id = vault.Add(Sample()).Id;

        var updated = vault.Update(id, Sample("Sage Renamed") with { Password = "new-pw" });
        Assert.Equal("Sage Renamed", updated!.Name);
        Assert.Equal("new-pw", Assert.Single(vault.List()).Password);

        Assert.Null(vault.Update(Guid.NewGuid(), Sample()));
        Assert.True(vault.Delete(id));
        Assert.False(vault.Delete(id));
        Assert.Empty(vault.List());
    }

    [Fact]
    public void Users_cannot_see_or_change_each_others_credentials()
    {
        _service.Register("alice", GoodPassword);
        _service.Register("bob", "bobs-own-long-password");
        using var alice = Login("alice");
        using var bob = Login("bob", "bobs-own-long-password");

        var alicesId = alice.Add(Sample("Alice only")).Id;

        Assert.Empty(bob.List());
        Assert.Null(bob.Update(alicesId, Sample("hijack")));
        Assert.False(bob.Delete(alicesId));
        Assert.Equal("Alice only", Assert.Single(alice.List()).Name);
    }

    [Fact]
    public void Database_contains_no_plaintext()
    {
        _service.Register("andries", GoodPassword);
        using (var vault = Login()) vault.Add(Sample("UniqueTitleXyz") with { Password = "UniquePasswordXyz" });

        SqliteConnection.ClearAllPools();
        var bytes = File.ReadAllBytes(_db);
        var text = System.Text.Encoding.Latin1.GetString(bytes);

        Assert.DoesNotContain("UniqueTitleXyz", text);
        Assert.DoesNotContain("UniquePasswordXyz", text);
        Assert.DoesNotContain("sage.example", text);
        Assert.DoesNotContain(GoodPassword, text);
    }

    [Fact]
    public void A_credential_moved_to_another_record_id_fails_to_decrypt()
    {
        _service.Register("andries", GoodPassword);
        using var vault = Login();
        var a = vault.Add(Sample("A"));
        vault.Add(Sample("B"));

        // Simulate an attacker with database access copying A's blob over B's row.
        var user = _store.FindUser("andries")!;
        var rows = _store.ListCredentials(user.Id);
        var rowA = rows.Single(r => r.Id == a.Id);
        var rowB = rows.Single(r => r.Id != a.Id);
        _store.UpdateCredential(user.Id, rowB with { Blob = rowA.Blob });

        Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(() => vault.List());
    }

    [Fact]
    public void Changing_the_master_password_keeps_credentials_and_swaps_which_password_works()
    {
        _service.Register("andries", GoodPassword);
        using var vault = Login();
        vault.Add(Sample());

        const string NewPassword = "a-brand-new-master-password";
        Assert.Equal(ChangePasswordResult.Changed, _service.ChangeMasterPassword(vault, GoodPassword, NewPassword));

        Assert.Null(_service.Unlock("andries", GoodPassword));
        using var again = Login(password: NewPassword);
        Assert.Equal("S3cret!pw", Assert.Single(again.List()).Password);
    }

    [Fact]
    public void Changing_the_master_password_uses_a_new_salt_and_does_not_touch_credential_blobs()
    {
        _service.Register("andries", GoodPassword);
        using var vault = Login();
        vault.Add(Sample());
        var before = _store.FindUser("andries")!;
        var blobBefore = _store.ListCredentials(before.Id).Single().Blob;

        _service.ChangeMasterPassword(vault, GoodPassword, "a-brand-new-master-password");

        var after = _store.FindUser("andries")!;
        Assert.NotEqual(before.Salt, after.Salt);
        Assert.NotEqual(before.WrappedKey, after.WrappedKey);
        Assert.Equal(blobBefore, _store.ListCredentials(after.Id).Single().Blob);
    }

    [Fact]
    public void Change_password_rejects_wrong_current_weak_and_unchanged_passwords()
    {
        _service.Register("andries", GoodPassword);
        using var vault = Login();

        Assert.Equal(ChangePasswordResult.WrongCurrentPassword, _service.ChangeMasterPassword(vault, "not-my-password", "a-brand-new-master-password"));
        Assert.Equal(ChangePasswordResult.WeakPassword, _service.ChangeMasterPassword(vault, GoodPassword, "short"));
        Assert.Equal(ChangePasswordResult.SameAsCurrent, _service.ChangeMasterPassword(vault, GoodPassword, GoodPassword));

        using var still = Login(); // original password still works after all the rejected attempts
        Assert.NotNull(still);
    }

    [Fact]
    public void Disposing_the_vault_wipes_the_key()
    {
        _service.Register("andries", GoodPassword);
        var vault = Login();
        vault.Add(Sample());
        vault.Dispose();

        Assert.ThrowsAny<Exception>(() => vault.List());
    }
}
