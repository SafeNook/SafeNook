using System.CommandLine;
using System.Globalization;

using SafeNook.Core.Generation;

namespace SafeNook.Cli.Commands;

/// <summary>
/// <c>nook gen</c>: generate random passwords without touching a vault.
/// </summary>
internal static class GenCommand
{
    public static Command Create(TextWriter output, TextWriter error)
    {
        var lengthOption = new Option<int>("--length", "-l")
        {
            Description = string.Create(
                CultureInfo.InvariantCulture,
                $"Password length, {PasswordPolicy.MinLength} to {PasswordPolicy.MaxLength}."),
            DefaultValueFactory = _ => PasswordPolicy.DefaultLength,
        };

        var noSymbolsOption = new Option<bool>("--no-symbols")
        {
            Description = "Use only letters and digits.",
        };

        var excludeSimilarOption = new Option<bool>("--exclude-similar")
        {
            Description = "Exclude look-alike characters: 0 O o 1 l I |.",
        };

        var countOption = new Option<int>("--count", "-n")
        {
            Description = "How many passwords to generate.",
            DefaultValueFactory = _ => 1,
        };

        var showEntropyOption = new Option<bool>("--entropy")
        {
            Description = "Print the estimated entropy in bits to stderr.",
        };

        var command = new Command("gen", "Generate a random password.");
        command.Options.Add(lengthOption);
        command.Options.Add(noSymbolsOption);
        command.Options.Add(excludeSimilarOption);
        command.Options.Add(countOption);
        command.Options.Add(showEntropyOption);

        command.SetAction(parseResult =>
        {
            var policy = new PasswordPolicy
            {
                Length = parseResult.GetValue(lengthOption),
                Classes = parseResult.GetValue(noSymbolsOption) ? CharacterClasses.Alphanumeric : CharacterClasses.All,
                ExcludeSimilar = parseResult.GetValue(excludeSimilarOption),
            };

            var count = parseResult.GetValue(countOption);
            if (count is < 1 or > 100)
            {
                error.WriteLine("error: --count must be between 1 and 100.");
                return ExitCodes.InvalidArguments;
            }

            try
            {
                for (var i = 0; i < count; i++)
                {
                    output.WriteLine(PasswordGenerator.Generate(policy));
                }

                if (parseResult.GetValue(showEntropyOption))
                {
                    var bits = PasswordGenerator.EstimateEntropyBits(policy);
                    error.WriteLine(string.Create(CultureInfo.InvariantCulture, $"entropy: ~{bits:F0} bits"));
                }

                return ExitCodes.Success;
            }
            catch (ArgumentException ex)
            {
                error.WriteLine($"error: {FirstLine(ex.Message)}");
                return ExitCodes.InvalidArguments;
            }
        });

        return command;
    }

    // ArgumentException appends " (Parameter '...')" to the message; users don't need it.
    private static string FirstLine(string message)
    {
        var index = message.IndexOf(" (Parameter", StringComparison.Ordinal);
        return index >= 0 ? message[..index] : message;
    }
}
