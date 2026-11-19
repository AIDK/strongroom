using System.Globalization;
using Microsoft.Data.Sqlite;
using Strongroom.Core.Crypto;

namespace Strongroom.Core.Storage;

/// <summary>SQLite persistence. Only ever sees ciphertext (plus the per-user KDF salt and parameters).</summary>
public sealed class VaultStore
{
    private readonly string _connectionString;

    public VaultStore(string databasePath)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(databasePath));
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        _connectionString = new SqliteConnectionStringBuilder { DataSource = databasePath, ForeignKeys = true }.ToString();
        Initialize();
    }

    private SqliteConnection Open()
    {
        var c = new SqliteConnection(_connectionString);
        c.Open();
        return c;
    }

    private void Initialize()
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS Users (
                Id          TEXT PRIMARY KEY,
                Username    TEXT NOT NULL UNIQUE COLLATE NOCASE,
                Salt        BLOB NOT NULL,
                KdfMemoryKiB INTEGER NOT NULL,
                KdfIterations INTEGER NOT NULL,
                KdfParallelism INTEGER NOT NULL,
                WrappedKey  BLOB NOT NULL,
                CreatedUtc  TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS Credentials (
                Id          TEXT PRIMARY KEY,
                UserId      TEXT NOT NULL REFERENCES Users(Id) ON DELETE CASCADE,
                Blob        BLOB NOT NULL,
                UpdatedUtc  TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS IX_Credentials_UserId ON Credentials(UserId);
            """;
        cmd.ExecuteNonQuery();
    }

    public UserRecord? FindUser(string username)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT Id, Username, Salt, KdfMemoryKiB, KdfIterations, KdfParallelism, WrappedKey, CreatedUtc FROM Users WHERE Username = $u";
        cmd.Parameters.AddWithValue("$u", username);
        using var r = cmd.ExecuteReader();
        if (!r.Read()) return null;
        return new UserRecord(
            Guid.Parse(r.GetString(0)), r.GetString(1), (byte[])r["Salt"],
            new KdfParams(r.GetInt32(3), r.GetInt32(4), r.GetInt32(5)),
            (byte[])r["WrappedKey"], ParseUtc(r.GetString(7)));
    }

    /// <returns>false if the username is already taken.</returns>
    public bool TryCreateUser(UserRecord user)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = """
            INSERT INTO Users (Id, Username, Salt, KdfMemoryKiB, KdfIterations, KdfParallelism, WrappedKey, CreatedUtc)
            VALUES ($id, $u, $salt, $m, $t, $p, $wk, $c)
            """;
        cmd.Parameters.AddWithValue("$id", user.Id.ToString());
        cmd.Parameters.AddWithValue("$u", user.Username);
        cmd.Parameters.AddWithValue("$salt", user.Salt);
        cmd.Parameters.AddWithValue("$m", user.Kdf.MemoryKiB);
        cmd.Parameters.AddWithValue("$t", user.Kdf.Iterations);
        cmd.Parameters.AddWithValue("$p", user.Kdf.Parallelism);
        cmd.Parameters.AddWithValue("$wk", user.WrappedKey);
        cmd.Parameters.AddWithValue("$c", FormatUtc(user.CreatedUtc));
        try
        {
            cmd.ExecuteNonQuery();
            return true;
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode == 19) // constraint violation
        {
            return false;
        }
    }

    /// <summary>Replaces the salt, KDF settings and wrapped vault key (used when the master password changes).</summary>
    public bool UpdateUserKey(Guid userId, byte[] salt, KdfParams kdf, byte[] wrappedKey)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = """
            UPDATE Users
            SET Salt = $salt, KdfMemoryKiB = $m, KdfIterations = $t, KdfParallelism = $p, WrappedKey = $wk
            WHERE Id = $id
            """;
        cmd.Parameters.AddWithValue("$id", userId.ToString());
        cmd.Parameters.AddWithValue("$salt", salt);
        cmd.Parameters.AddWithValue("$m", kdf.MemoryKiB);
        cmd.Parameters.AddWithValue("$t", kdf.Iterations);
        cmd.Parameters.AddWithValue("$p", kdf.Parallelism);
        cmd.Parameters.AddWithValue("$wk", wrappedKey);
        return cmd.ExecuteNonQuery() == 1;
    }

    public List<StoredCredential> ListCredentials(Guid userId)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT Id, Blob, UpdatedUtc FROM Credentials WHERE UserId = $u";
        cmd.Parameters.AddWithValue("$u", userId.ToString());
        using var r = cmd.ExecuteReader();
        var list = new List<StoredCredential>();
        while (r.Read())
            list.Add(new StoredCredential(Guid.Parse(r.GetString(0)), (byte[])r["Blob"], ParseUtc(r.GetString(2))));
        return list;
    }

    public void InsertCredential(Guid userId, StoredCredential cred)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "INSERT INTO Credentials (Id, UserId, Blob, UpdatedUtc) VALUES ($id, $u, $b, $t)";
        cmd.Parameters.AddWithValue("$id", cred.Id.ToString());
        cmd.Parameters.AddWithValue("$u", userId.ToString());
        cmd.Parameters.AddWithValue("$b", cred.Blob);
        cmd.Parameters.AddWithValue("$t", FormatUtc(cred.UpdatedUtc));
        cmd.ExecuteNonQuery();
    }

    /// <returns>false if the user has no credential with that id.</returns>
    public bool UpdateCredential(Guid userId, StoredCredential cred)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "UPDATE Credentials SET Blob = $b, UpdatedUtc = $t WHERE Id = $id AND UserId = $u";
        cmd.Parameters.AddWithValue("$id", cred.Id.ToString());
        cmd.Parameters.AddWithValue("$u", userId.ToString());
        cmd.Parameters.AddWithValue("$b", cred.Blob);
        cmd.Parameters.AddWithValue("$t", FormatUtc(cred.UpdatedUtc));
        return cmd.ExecuteNonQuery() == 1;
    }

    public bool DeleteCredential(Guid userId, Guid id)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "DELETE FROM Credentials WHERE Id = $id AND UserId = $u";
        cmd.Parameters.AddWithValue("$id", id.ToString());
        cmd.Parameters.AddWithValue("$u", userId.ToString());
        return cmd.ExecuteNonQuery() == 1;
    }

    private static string FormatUtc(DateTime t) => t.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
    private static DateTime ParseUtc(string s) => DateTime.Parse(s, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
}
