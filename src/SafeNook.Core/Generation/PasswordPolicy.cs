namespace SafeNook.Core.Generation;

/// <summary>
/// Rules for generating a random password.
/// </summary>
public sealed record PasswordPolicy
{
    /// <summary>Shortest allowed password length.</summary>
    public const int MinLength = 8;

    /// <summary>Longest allowed password length.</summary>
    public const int MaxLength = 128;

    /// <summary>Length used when none is specified.</summary>
    public const int DefaultLength = 20;

    /// <summary>Symbols used when none are specified. Avoids quotes, backslash and space, which often break shells and forms.</summary>
    public const string DefaultSymbols = "!#$%&()*+,-./:;<=>?@[]^_{|}~";

    /// <summary>Password length, between <see cref="MinLength"/> and <see cref="MaxLength"/>.</summary>
    public int Length { get; init; } = DefaultLength;

    /// <summary>Character classes to use. The generated password contains at least one character from each selected class.</summary>
    public CharacterClasses Classes { get; init; } = CharacterClasses.All;

    /// <summary>Exclude characters that are easy to confuse when read: <c>0 O o 1 l I |</c>.</summary>
    public bool ExcludeSimilar { get; init; }

    /// <summary>Symbols used when <see cref="CharacterClasses.Symbols"/> is selected.</summary>
    public string Symbols { get; init; } = DefaultSymbols;
}
