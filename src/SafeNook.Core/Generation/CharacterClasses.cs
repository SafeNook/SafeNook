namespace SafeNook.Core.Generation;

/// <summary>
/// Character classes a generated password can draw from.
/// </summary>
[Flags]
public enum CharacterClasses
{
    /// <summary>No characters.</summary>
    None = 0,

    /// <summary>Lowercase Latin letters a–z.</summary>
    Lowercase = 1,

    /// <summary>Uppercase Latin letters A–Z.</summary>
    Uppercase = 2,

    /// <summary>Digits 0–9.</summary>
    Digits = 4,

    /// <summary>Symbols from <see cref="PasswordPolicy.Symbols"/>.</summary>
    Symbols = 8,

    /// <summary>Letters and digits.</summary>
    Alphanumeric = Lowercase | Uppercase | Digits,

    /// <summary>All classes.</summary>
    All = Alphanumeric | Symbols,
}
