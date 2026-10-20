using System.Security.Cryptography;

namespace SafeNook.Core.Generation;

/// <summary>
/// Generates random passwords using a cryptographically secure random number generator.
/// </summary>
public static class PasswordGenerator
{
    private const string LowercaseChars = "abcdefghijklmnopqrstuvwxyz";
    private const string UppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private const string DigitChars = "0123456789";
    private const string SimilarChars = "0Oo1lI|";

    /// <summary>
    /// Generates a password that satisfies <paramref name="policy"/>.
    /// </summary>
    /// <remarks>
    /// One character is drawn from each selected class, the rest uniformly from the union of all
    /// selected classes, and the result is shuffled. This guarantees every class is present, which many
    /// sites require, at a negligible cost in entropy.
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException">The length is outside the allowed range.</exception>
    /// <exception cref="ArgumentException">No character class is selected, or a selected class has no usable characters.</exception>
    public static string Generate(PasswordPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ValidateLength(policy.Length);

        var sets = BuildCharacterSets(policy);
        var alphabet = BuildAlphabet(sets);
        var buffer = new char[policy.Length];

        try
        {
            var position = 0;
            foreach (var set in sets)
            {
                buffer[position++] = Pick(set);
            }

            while (position < buffer.Length)
            {
                buffer[position++] = Pick(alphabet);
            }

            RandomNumberGenerator.Shuffle(buffer.AsSpan());
            return new string(buffer);
        }
        finally
        {
            Array.Clear(buffer);
        }
    }

    /// <summary>
    /// Estimates the entropy, in bits, of a password generated with <paramref name="policy"/>:
    /// <c>length × log2(alphabet size)</c>. This is an upper bound and slightly overestimates
    /// because every class is guaranteed to be present.
    /// </summary>
    public static double EstimateEntropyBits(PasswordPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ValidateLength(policy.Length);

        var alphabet = BuildAlphabet(BuildCharacterSets(policy));
        return policy.Length * Math.Log2(alphabet.Length);
    }

    private static void ValidateLength(int length)
    {
        if (length is < PasswordPolicy.MinLength or > PasswordPolicy.MaxLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(length),
                length,
                $"Password length must be between {PasswordPolicy.MinLength} and {PasswordPolicy.MaxLength}.");
        }
    }

    private static List<string> BuildCharacterSets(PasswordPolicy policy)
    {
        var sets = new List<string>(capacity: 4);
        AddSet(sets, policy, CharacterClasses.Lowercase, LowercaseChars);
        AddSet(sets, policy, CharacterClasses.Uppercase, UppercaseChars);
        AddSet(sets, policy, CharacterClasses.Digits, DigitChars);
        AddSet(sets, policy, CharacterClasses.Symbols, policy.Symbols ?? string.Empty);

        if (sets.Count == 0)
        {
            throw new ArgumentException("At least one character class must be selected.", nameof(policy));
        }

        return sets;
    }

    private static void AddSet(List<string> sets, PasswordPolicy policy, CharacterClasses characterClass, string characters)
    {
        if ((policy.Classes & characterClass) == 0)
        {
            return;
        }

        var usable = characters
            .Where(c => !char.IsWhiteSpace(c) && !char.IsControl(c))
            .Where(c => !policy.ExcludeSimilar || !SimilarChars.Contains(c))
            .Distinct()
            .ToArray();

        if (usable.Length == 0)
        {
            throw new ArgumentException($"Character class '{characterClass}' has no usable characters.", nameof(policy));
        }

        sets.Add(new string(usable));
    }

    // Symbols supplied by the caller may overlap with letters or digits; duplicates would bias the choice.
    private static string BuildAlphabet(List<string> sets) =>
        new(string.Concat(sets).Distinct().ToArray());

    private static char Pick(string characters) =>
        characters[RandomNumberGenerator.GetInt32(characters.Length)];
}
