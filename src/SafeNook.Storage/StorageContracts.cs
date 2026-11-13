namespace SafeNook.Storage;

/// <summary>Publication outcome; uncertain publication must never be retried automatically.</summary>
public enum CommitOutcome { Committed, RejectedBeforePublication, Indeterminate, RecoveryRequired }
/// <summary>Safe storage diagnostic without paths, credentials or native exception text.</summary>
public sealed class StoreException(CommitOutcome outcome, string code) : Exception("Vault storage operation failed: " + code)
{
    public CommitOutcome Outcome { get; } = outcome;
    public string Code { get; } = code;
}
/// <summary>Production writes remain closed until filesystem power-loss qualification is recorded.</summary>
public static class StorageSupport
{
    public static bool ProductionWritesSupported => false;
    public static void RequireProductionWrites() => throw new PlatformNotSupportedException("No filesystem is qualified for production vault writes.");
}
internal enum CommitStep { Validated, ObjectWritten, ObjectFlushed, ObjectInstalled, ManifestVerified, BackupWritten, RootWritten, RootFlushed, BeforePublish, AfterPublish, RootReadback }
internal interface IStoreFaults
{
    void At(CommitStep step);
    int WriteLength(int requested) => requested;
    void BeforeFlush(bool directory) { }
}
internal sealed class NoStoreFaults : IStoreFaults { public void At(CommitStep step) { } }
internal sealed class EncryptedGeneration(byte[] header, IReadOnlyList<byte[]> objects)
{
    internal byte[] Header { get; } = header;
    internal IReadOnlyList<byte[]> Objects { get; } = objects;
}
