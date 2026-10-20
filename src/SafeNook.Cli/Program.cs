using System.CommandLine;

using SafeNook.Cli.Commands;

namespace SafeNook.Cli;

internal static class Program
{
    private static int Main(string[] args)
    {
        var rootCommand = new RootCommand("SafeNook: a safe little nook for your secrets.");
        rootCommand.Subcommands.Add(GenCommand.Create(Console.Out, Console.Error));

        return rootCommand.Parse(args).Invoke();
    }
}
