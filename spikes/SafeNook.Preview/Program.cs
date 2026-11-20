using System.Runtime.InteropServices;
using SafeNook.Application;
using SafeNook.Cli;

namespace SafeNook.Preview;

internal static class EntryPoint
{
    private static int Main(string[] args)
    {
        Console.Error.WriteLine("SAFENOOK EXPERIMENTAL PREVIEW — SYNTHETIC DATA ONLY. Never store real secrets. Writes are not production qualified; GC is disabled.");
        if(!OperatingSystem.IsWindows() || RuntimeInformation.ProcessArchitecture!=Architecture.X64)
        {Console.Error.WriteLine("Preview requires Windows x64 and local fixed NTFS.");return 6;}
        using var cancellation=new CancellationTokenSource();
        ConsoleCancelEventHandler cancel=(_,e)=>{e.Cancel=true;cancellation.Cancel();};
        Console.CancelKeyPress+=cancel;
        try
        {
            var interaction=new ConsoleVaultInteraction(new ConsoleSecretTerminal());
            var application=VaultApplication.ForQualification(interaction,WindowsMemory.Policy());
            return SafeNook.Cli.Program.Run(args,application,Console.Out,Console.Error,cancellation.Token);
        }
        catch(VaultOperationException)
        {Console.Error.WriteLine("Preview could not admit this operation.");return 8;}
        catch
        {Console.Error.WriteLine("Preview operation failed.");return 1;}
        finally {Console.CancelKeyPress-=cancel;}
    }
}
