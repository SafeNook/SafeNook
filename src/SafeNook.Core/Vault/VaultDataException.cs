namespace SafeNook.Core.Vault;

/// <summary>Safe failure categories; messages never contain raw JSON, credentials or source exception details.</summary>
public enum VaultDataError { InvalidFormat, CorruptGeneration, AuthenticationFailed, ResourceLimit }

/// <summary>Sanitised failure from payload validation or authenticated opening.</summary>
public sealed class VaultDataException(VaultDataError error) : Exception(error switch
{
    VaultDataError.InvalidFormat => "Invalid vault payload.",
    VaultDataError.CorruptGeneration => "Inconsistent vault generation.",
    VaultDataError.AuthenticationFailed => "Vault authentication failed.",
    _ => "Vault resource admission failed.",
})
{
    public VaultDataError Error { get; } = error;
}
