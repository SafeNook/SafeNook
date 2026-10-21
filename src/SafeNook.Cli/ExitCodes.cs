namespace SafeNook.Cli;

/// <summary>
/// Process exit codes. Part of the CLI contract for scripts; see docs/ROADMAP.md, stage 1.
/// </summary>
internal static class ExitCodes
{
    public const int Success = 0;
    public const int Error = 1;
    public const int InvalidArguments = 1;
    public const int AmbiguousOrNotFound = 2;
    public const int WrongPassword = 3;
    public const int VaultLocked = 4;
}
