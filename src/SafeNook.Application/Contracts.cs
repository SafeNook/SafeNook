namespace SafeNook.Application;

/// <summary>Fixed prompts; credential data never appears in a prompt identifier.</summary>
public enum SecretPrompt { Password, NewPassword, Recovery, ConfirmPassword, ConfirmRecovery, Title, Username, LoginPassword, Url, Notes, Note, Urls, Tags, ConfirmLoginPassword, ConfirmNotes, ConfirmNote }
/// <summary>Only an explicit interactive channel is supported in C1. Returned byte arrays transfer ownership and are wiped by the application.</summary>
public interface IVaultInteraction
{
    bool IsInteractive { get; }
    byte[] ReadSecret(SecretPrompt prompt, int maximumBytes, CancellationToken cancellationToken);
    void DisplayRecovery(string code, string vaultId);
    bool ConfirmRemoval(string id, CancellationToken cancellationToken);
}
public enum VaultApplicationError { InvalidArguments, WritesDisabled, InteractiveRequired, UnsupportedPlatform, AuthenticationOrCorruption, NotFound, Cancelled, ResourceLimit, Rejected, Indeterminate, UnsupportedItem }
/// <summary>Only a fixed category crosses the application boundary; no inner exceptions or input values.</summary>
public sealed class VaultOperationException(VaultApplicationError error) : Exception("Vault operation failed.")
{ public VaultApplicationError Error { get; } = error; }
/// <summary>Allowlisted metadata. Contains no payload, username, URL, note or password.</summary>
public sealed class ItemSummary(string id, ushort type, ulong revision, string title, string[] tags)
{
    public string Id { get; } = id;
    public ushort Type { get; } = type;
    public ulong Revision { get; } = revision;
    public string Title { get; } = title;
    public string[] Tags { get; } = tags;
}
/// <summary>Explicit reveal result; never automatically serialised or logged.</summary>
public sealed class RevealedItem(string? username, string? password, string[] urls, string? note)
{
    public string? Username { get; } = username;
    public string? Password { get; } = password;
    public string[] Urls { get; } = urls;
    public string? Note { get; } = note;
}
public sealed class VaultReply(ItemSummary[] items, RevealedItem? revealed = null)
{
    public ItemSummary[] Items { get; } = items;
    public RevealedItem? Revealed { get; } = revealed;
}

/// <summary>Edit selection never includes existing values. False preserves the field; empty replacement explicitly clears it.</summary>
public interface IVaultEditInteraction : IVaultInteraction
{
    bool ReplaceField(SecretPrompt field, CancellationToken token);
    bool ConfirmEdit(CancellationToken token);
}

/// <summary>Explicit acknowledgement of opaque, unvalidated SSH/age storage; never receives key contents.</summary>
public interface IVaultFileInteraction : IVaultInteraction
{
    bool ConfirmUnvalidatedKey(bool age, CancellationToken token);
}
