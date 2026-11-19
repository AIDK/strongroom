using System.Collections.Concurrent;
using System.Security.Cryptography;
using Strongroom.Core;

namespace Strongroom.Web.Security;

/// <summary>
/// In-memory sessions. The unlocked vault key lives only here, never on disk, and is wiped when a
/// session is locked, expires from inactivity, or the process exits.
/// </summary>
public sealed class SessionStore(TimeSpan idleTimeout)
{
    private sealed class Entry(UnlockedVault vault)
    {
        public UnlockedVault Vault { get; } = vault;
        public DateTime LastSeenUtc { get; set; } = DateTime.UtcNow;
    }

    private readonly ConcurrentDictionary<string, Entry> _sessions = new();

    public string Create(UnlockedVault vault)
    {
        Sweep();
        var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');
        _sessions[token] = new Entry(vault);
        return token;
    }

    public UnlockedVault? Get(string? token)
    {
        if (string.IsNullOrEmpty(token) || !_sessions.TryGetValue(token, out var entry)) return null;
        if (DateTime.UtcNow - entry.LastSeenUtc > idleTimeout)
        {
            Remove(token);
            return null;
        }
        entry.LastSeenUtc = DateTime.UtcNow;
        return entry.Vault;
    }

    public void Remove(string? token)
    {
        if (!string.IsNullOrEmpty(token) && _sessions.TryRemove(token, out var entry))
            entry.Vault.Dispose();
    }

    /// <summary>Locks every other session of the same user (e.g. after a master password change).</summary>
    public void RemoveOthers(Guid userId, string? keepToken)
    {
        foreach (var (token, entry) in _sessions)
            if (entry.Vault.UserId == userId && token != keepToken)
                Remove(token);
    }

    private void Sweep()
    {
        foreach (var (token, entry) in _sessions)
            if (DateTime.UtcNow - entry.LastSeenUtc > idleTimeout)
                Remove(token);
    }
}
