using SafeNook.Core.Generation;

namespace SafeNook.Core.Tests.Generation;

public sealed class PasswordGeneratorTests
{
    // Enough runs that a missing guarantee would almost certainly show up.
    private const int Runs = 500;

    [Theory]
    [InlineData(PasswordPolicy.MinLength)]
    [InlineData(PasswordPolicy.DefaultLength)]
    [InlineData(64)]
    [InlineData(PasswordPolicy.MaxLength)]
    public void Generate_ReturnsRequestedLength(int length)
    {
        var password = PasswordGenerator.Generate(new PasswordPolicy { Length = length });

        Assert.Equal(length, password.Length);
    }

    [Fact]
    public void Generate_DefaultPolicy_ContainsEveryCharacterClass()
    {
        var policy = new PasswordPolicy { Length = PasswordPolicy.MinLength };

        for (var i = 0; i < Runs; i++)
        {
            var password = PasswordGenerator.Generate(policy);

            Assert.Contains(password, char.IsAsciiLetterLower);
            Assert.Contains(password, char.IsAsciiLetterUpper);
            Assert.Contains(password, char.IsAsciiDigit);
            Assert.Contains(password, c => PasswordPolicy.DefaultSymbols.Contains(c));
        }
    }

    [Fact]
    public void Generate_Alphanumeric_ContainsOnlyLettersAndDigits()
    {
        var policy = new PasswordPolicy { Classes = CharacterClasses.Alphanumeric };

        for (var i = 0; i < Runs; i++)
        {
            var password = PasswordGenerator.Generate(policy);

            Assert.All(password, c => Assert.True(char.IsAsciiLetterOrDigit(c), $"Unexpected character '{c}'"));
        }
    }

    [Fact]
    public void Generate_ExcludeSimilar_NeverUsesLookAlikes()
    {
        var policy = new PasswordPolicy { Length = PasswordPolicy.MaxLength, ExcludeSimilar = true };

        for (var i = 0; i < Runs; i++)
        {
            var password = PasswordGenerator.Generate(policy);

            Assert.DoesNotContain(password, c => "0Oo1lI|".Contains(c));
        }
    }

    [Fact]
    public void Generate_CustomSymbols_UsesOnlyThoseSymbols()
    {
        var policy = new PasswordPolicy { Classes = CharacterClasses.Symbols, Symbols = "#@" };

        var password = PasswordGenerator.Generate(policy);

        Assert.All(password, c => Assert.True(c is '#' or '@', $"Unexpected character '{c}'"));
    }

    [Fact]
    public void Generate_ProducesDifferentPasswords()
    {
        var policy = new PasswordPolicy();

        var passwords = Enumerable.Range(0, 100).Select(_ => PasswordGenerator.Generate(policy)).ToHashSet();

        Assert.Equal(100, passwords.Count);
    }

    [Fact]
    public void Generate_DrawsFromWholeAlphabet()
    {
        // With 10 000 characters drawn from 62 letters and digits, every character should appear.
        var policy = new PasswordPolicy { Length = PasswordPolicy.MaxLength, Classes = CharacterClasses.Alphanumeric };
        var seen = new HashSet<char>();

        for (var i = 0; i < 80; i++)
        {
            seen.UnionWith(PasswordGenerator.Generate(policy));
        }

        Assert.Equal(62, seen.Count);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(PasswordPolicy.MinLength - 1)]
    [InlineData(PasswordPolicy.MaxLength + 1)]
    public void Generate_LengthOutOfRange_Throws(int length)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => PasswordGenerator.Generate(new PasswordPolicy { Length = length }));
    }

    [Fact]
    public void Generate_NoClasses_Throws()
    {
        Assert.Throws<ArgumentException>(() => PasswordGenerator.Generate(new PasswordPolicy { Classes = CharacterClasses.None }));
    }

    [Fact]
    public void Generate_SymbolsSelectedButEmpty_Throws()
    {
        var policy = new PasswordPolicy { Classes = CharacterClasses.Symbols, Symbols = "   " };

        Assert.Throws<ArgumentException>(() => PasswordGenerator.Generate(policy));
    }

    [Fact]
    public void EstimateEntropyBits_MatchesAlphabetSize()
    {
        var policy = new PasswordPolicy { Length = 20, Classes = CharacterClasses.Alphanumeric };

        var bits = PasswordGenerator.EstimateEntropyBits(policy);

        Assert.Equal(20 * Math.Log2(62), bits, precision: 6);
    }
}
