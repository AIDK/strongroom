using System.Collections.Concurrent;

namespace Strongroom.Web.Security;

/// <summary>Slows down password guessing: after 5 failures a username is locked out for 1, 2, 4... up to 15 minutes.</summary>
public sealed class LoginThrottle
{
    private const int FreeAttempts = 5;
    private const int MaxTrackedNames = 5000;

    private sealed record State(int Failures, DateTime LockedUntilUtc);
    private readonly ConcurrentDictionary<string, State> _state = new(StringComparer.OrdinalIgnoreCase);

    /// <returns>Seconds the caller must wait, or 0 if an attempt is allowed.</returns>
    public int SecondsLocked(string username)
    {
        if (!_state.TryGetValue(username, out var s)) return 0;
        var left = (s.LockedUntilUtc - DateTime.UtcNow).TotalSeconds;
        return left > 0 ? (int)Math.Ceiling(left) : 0;
    }

    public void RecordFailure(string username)
    {
        if (_state.Count > MaxTrackedNames) _state.Clear();
        _state.AddOrUpdate(
            username,
            _ => new State(1, DateTime.UtcNow),
            (_, old) =>
            {
                var failures = old.Failures + 1;
                if (failures < FreeAttempts) return new State(failures, DateTime.UtcNow);
                var minutes = Math.Min(Math.Pow(2, failures - FreeAttempts), 15);
                return new State(failures, DateTime.UtcNow.AddMinutes(minutes));
            });
    }

    public void RecordSuccess(string username) => _state.TryRemove(username, out _);
}
