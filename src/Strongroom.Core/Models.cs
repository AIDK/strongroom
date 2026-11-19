using Strongroom.Core.Crypto;

namespace Strongroom.Core;

/// <summary>What the user types in. Serialized to JSON and encrypted as a single blob.</summary>
public sealed record CredentialData(
    string Name,
    string Url,
    string Username,
    string Password,
    string Category,
    string Notes);

/// <summary>A decrypted credential as returned to the UI.</summary>
public sealed record CredentialView(
    Guid Id,
    string Name,
    string Url,
    string Username,
    string Password,
    string Category,
    string Notes,
    DateTime UpdatedUtc);

public sealed record UserRecord(
    Guid Id,
    string Username,
    byte[] Salt,
    KdfParams Kdf,
    byte[] WrappedKey,
    DateTime CreatedUtc);

public sealed record StoredCredential(Guid Id, byte[] Blob, DateTime UpdatedUtc);
