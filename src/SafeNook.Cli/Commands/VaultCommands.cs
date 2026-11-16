using System.CommandLine;
using System.Globalization;
using System.Text;
using SafeNook.Application;

namespace SafeNook.Cli.Commands;

internal static class VaultCommands
{
    internal static void AddTo(RootCommand root,VaultApplication application,TextWriter output,TextWriter error,CancellationToken token)
    {
        var backup=new Command("backup","Create an encrypted backup (writes disabled).");
        var verify=new Command("verify","Fully authenticate a backup, including all blobs.");
        var restore=new Command("restore","Restore into a new vault (writes disabled).");
        backup.Subcommands.Add(verify);root.Subcommands.Add(backup);root.Subcommands.Add(restore);
        foreach(var pair in new[]{(backup,0),(verify,1),(restore,2)})
        {
            var input=new Option<string>(pair.Item2==0?"--vault":"--input") {Required=true};
            var target=new Option<string>(pair.Item2==0?"--output":"--vault") {Required=true};
            var credential=new Option<string>("--credential") {DefaultValueFactory=_=>"password",Description="password or recovery; never the credential value."};
            pair.Item1.Options.Add(input);if(pair.Item2!=1) pair.Item1.Options.Add(target);pair.Item1.Options.Add(credential);
            pair.Item1.SetAction(parsed=>
            {
                try
                {
                    var selected=parsed.GetValue(credential);if(selected is not ("password" or "recovery")) throw new VaultOperationException(VaultApplicationError.InvalidArguments);
                    var hash=pair.Item2 switch {0=>application.Backup(parsed.GetValue(input)!,parsed.GetValue(target)!,selected=="recovery",token),1=>application.VerifyBackup(parsed.GetValue(input)!,selected=="recovery",token),_=>application.Restore(parsed.GetValue(input)!,parsed.GetValue(target)!,selected=="recovery",token)};
                    output.WriteLine("Verified SHA-256: "+hash);return 0;
                }
                catch(VaultOperationException e) {var (code,message)=Failure(e.Error);error.WriteLine(message);return code;}
                catch {error.WriteLine("Backup operation failed.");return 1;}
            });
        }
        foreach(var name in new[]{"init","ls","show","add","rm","passwd","recover","rotate"})
        {
            var description=name switch { "init"=>"Create a vault (production writes currently disabled).", "ls"=>"List authenticated safe metadata.",
                "passwd"=>"Change the master password (production writes disabled).", "recover"=>"Recover access using the recovery key (production writes disabled).", "rotate"=>"Replace the recovery key (production writes disabled).",
                "show"=>"Show safe metadata; --reveal explicitly requests login/note secrets.","add"=>"Add a login or note (production writes currently disabled).",_=>"Confirm a tombstone (production writes currently disabled)." };
            var command=new Command(name,description+" Experimental; not qualified for real secrets.");
            var vault=new Option<string>("--vault") {Description="Required absolute path to exactly one vault.",Required=true}; command.Options.Add(vault);
            var id=new Argument<string>("id") {Description="Canonical lowercase 32-character record ID."};
            if(name is "show" or "rm") command.Arguments.Add(id);
            var reveal=new Option<bool>("--reveal") {Description="Explicitly reveal login/note payload on the interactive terminal."};
            if(name=="show") command.Options.Add(reveal);
            var type=new Option<string>("--type") {Description="login or note; payload is prompted without echo.",Required=true};
            if(name=="add") command.Options.Add(type);
            command.SetAction(parsed=>
            {
                try
                {
                    var path=parsed.GetValue(vault)!;
                    var reply=name switch
                    {
                        "passwd"=>application.ChangePassword(path,token), "recover"=>application.Recover(path,token), "rotate"=>application.RotateRecovery(path,token),
                        "init"=>application.Init(path,token), "ls"=>application.List(path,token),
                        "show"=>application.Show(path,parsed.GetValue(id)!,parsed.GetValue(reveal),token),
                        "add"=>application.Add(path,parsed.GetValue(type)!,token),
                        _=>application.Remove(path,parsed.GetValue(id)!,token)
                    };
                    // Build all output after successful authentication/commit, never during object validation.
                    var text=new StringBuilder();
                    foreach(var item in reply.Items)
                        text.Append(item.Id).Append('\t').Append(item.Type.ToString(CultureInfo.InvariantCulture)).Append('\t')
                            .Append(item.Revision.ToString(CultureInfo.InvariantCulture)).Append('\t').Append(Escape(item.Title)).Append('\t')
                            .Append(string.Join(",",item.Tags.Select(Escape))).Append('\n');
                    if(reply.Revealed is { } secret)
                    {
                        if(secret.Username is not null) text.Append("username: ").Append(Escape(secret.Username)).Append('\n');
                        if(secret.Password is not null) text.Append("password: ").Append(Escape(secret.Password)).Append('\n');
                        foreach(var url in secret.Urls) text.Append("url: ").Append(Escape(url)).Append('\n');
                        if(secret.Note is not null) text.Append("note: ").Append(Escape(secret.Note)).Append('\n');
                    }
                    if(name is "init" or "rm" or "passwd" or "recover" or "rotate") text.Append("ok\n");
                    if(name is "ls" or "show") token.ThrowIfCancellationRequested();
                    output.Write(text.ToString()); return 0;
                }
                catch(VaultOperationException e) { var (code,message)=Failure(e.Error); error.WriteLine(message); return code; }
                catch(OperationCanceledException) { error.WriteLine("Operation cancelled."); return 130; }
                catch { error.WriteLine("Vault operation failed."); return 1; }
            });
            if(name=="rotate") { var recovery=new Command("recovery","Manage recovery credentials."); recovery.Subcommands.Add(command); root.Subcommands.Add(recovery); } else root.Subcommands.Add(command);
        }
    }
    internal static string Escape(string value)
    {
        var output=new StringBuilder();
        foreach(var rune in value.EnumerateRunes())
        {
            var category=Rune.GetUnicodeCategory(rune);
            if(category is UnicodeCategory.Control or UnicodeCategory.Format or UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator)
                output.Append("\\u").Append(rune.Value.ToString("X4",CultureInfo.InvariantCulture));
            else output.Append(rune.ToString());
        }
        return output.ToString();
    }
    private static (int,string) Failure(VaultApplicationError error)=>error switch
    {
        VaultApplicationError.WritesDisabled=>(5,"Vault writes are disabled pending storage qualification. No credentials were requested."),
        VaultApplicationError.InteractiveRequired=>(6,"An interactive terminal is required; redirected credentials are not supported."),
        VaultApplicationError.UnsupportedPlatform=>(6,"Vault access requires Windows x64 and local fixed NTFS."),
        VaultApplicationError.AuthenticationOrCorruption=>(3,"Cannot authenticate the vault or verify its data."),
        VaultApplicationError.NotFound=>(2,"Record not found."),
        VaultApplicationError.Cancelled=>(130,"Operation cancelled."),
        VaultApplicationError.Indeterminate=>(7,"Commit outcome is uncertain. Preserve the vault and reopen explicitly; do not retry the mutation."),
        VaultApplicationError.ResourceLimit=>(8,"Trusted resource limit exceeded."),
        VaultApplicationError.UnsupportedItem=>(6,"This operation supports login and note records only."),
        VaultApplicationError.InvalidArguments=>(1,"Invalid vault arguments or input."),
        _=>(1,"Vault operation rejected.")
    };
}
