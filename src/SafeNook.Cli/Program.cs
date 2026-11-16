using System.CommandLine;
using SafeNook.Application;
using SafeNook.Cli.Commands;

namespace SafeNook.Cli;

internal static class Program
{
    private static int Main(string[] args)
    {
        var application=new VaultApplication(new ConsoleVaultInteraction(new ConsoleSecretTerminal()));
        if(args.FirstOrDefault() is not ("init" or "ls" or "show" or "add" or "rm" or "passwd" or "recover" or "recovery" or "backup" or "restore"))
            return Run(args,application,Console.Out,Console.Error);
        using var cancellation=new CancellationTokenSource();
        ConsoleCancelEventHandler cancel=(_,e)=>{e.Cancel=true;cancellation.Cancel();};
        Console.CancelKeyPress+=cancel;
        try { return Run(args,application,Console.Out,Console.Error,cancellation.Token); }
        finally { Console.CancelKeyPress-=cancel; }
    }
    internal static int Run(string[] args,VaultApplication application,TextWriter output,TextWriter error,CancellationToken token=default)
    {
        var root=new RootCommand("SafeNook: a safe little nook for your secrets.");
        root.Subcommands.Add(GenCommand.Create(output,error));
        VaultCommands.AddTo(root,application,output,error,token);
        var parsed=root.Parse(args);
        if(parsed.Errors.Count>0 && args.Length>0 && args[0]!="gen")
        { error.WriteLine("Invalid command arguments. Use --help. Never supply secrets as arguments."); return 1; }
        return parsed.Invoke(new InvocationConfiguration {Output=output,Error=error});
    }
}
