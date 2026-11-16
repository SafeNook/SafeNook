using System.IO.Pipes;
using System.Security.Cryptography;
using System.Runtime.Versioning;
using SafeNook.Application;
using SafeNook.ApplicationTestData;
using SafeNook.Core.Vault;
using SafeNook.Storage;
using SafeNook.StoreTestData;

[SupportedOSPlatform("windows")]
internal static class CrashCampaign
{
    internal static void Run(string[] args)
    {
        try
        {
            var path=Path.GetFullPath(args[0]);var operation=args[2];var boundary=args[3];
            using var pipe=new NamedPipeClientStream(".",args[4],PipeDirection.Out,PipeOptions.CurrentUserOnly);pipe.Connect(15000);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            using var fixture=new GenerationFixture();for(var i=0;i<32;i++) fixture.Recovery.Span[i]=(byte)(128+i);
            using(var store=QualificationStore.Create(path,fixture.Initial(),GenerationFixture.Password,fixture.Recovery.Span,()=>fixture.Recovery.Span.ToArray(),GenerationFixture.Policy(),new NoStoreFaults(),default))
            {if(store.Commit(fixture.Next(store.Header,includeBlob:true),CredentialKind.Password,GenerationFixture.Password,[],null,new NoStoreFaults(),default).Outcome!=CommitOutcome.Committed) throw new InvalidOperationException();}
            var ui=new SyntheticInteraction {Password=System.Text.Encoding.UTF8.GetString(GenerationFixture.Password)};ui.DisplayRecovery(RecoveryCode.Encode(fixture.Recovery.Span),"");ui.ConfirmPassword=ui.NewPassword;
            var normal=VaultApplication.ForQualification(ui,GenerationFixture.Policy());var archive=path+".snbak";
            if(operation is "verify" or "restore") normal.Backup(path,archive);
            var original=VaultFormat.DecodeWrapper(File.ReadAllBytes(Path.Combine(path,"vault.json")));pipe.Write(original);pipe.Flush();
            var app=VaultApplication.ForQualification(new CrashInteraction(ui,pipe),GenerationFixture.Policy(),new PauseAt(boundary));
            switch(operation)
            {
                case "passwd":app.ChangePassword(path);break;
                case "recover":app.Recover(path);break;
                case "rotate":app.RotateRecovery(path);break;
                case "backup":app.Backup(path,archive);break;
                case "verify":app.VerifyBackup(archive);break;
                case "restore":app.Restore(archive,path+"-restored");break;
                default:throw new InvalidOperationException();
            }
            // ACK is emitted only after the application returns successful full verification/commit.
            if(boundary=="ACK")
            {
                var acknowledged=operation is "backup" or "verify"?File.ReadAllBytes(archive):VaultFormat.DecodeWrapper(File.ReadAllBytes(Path.Combine(operation=="restore"?path+"-restored":path,"vault.json")));
                Pause("ACK "+Convert.ToHexStringLower(SHA256.HashData(acknowledged)));
            }
            throw new InvalidOperationException(); // Requested boundary must be reached exactly once.
        }
        catch { Console.Error.WriteLine("Qualification helper failed.");Environment.ExitCode=2; }
    }
    private static void Pause(string marker)
    {Console.WriteLine(marker);Console.Out.Flush();Thread.Sleep(Timeout.Infinite);}
    private sealed class PauseAt(string boundary):IStoreFaults
    {public void At(CommitStep step) {if(step.ToString()==boundary) Pause("CRASH_POINT");}}
    private sealed class CrashInteraction(SyntheticInteraction inner,Stream pipe):IVaultInteraction
    {
        public bool IsInteractive=>true;
        public byte[] ReadSecret(SecretPrompt prompt,int maximumBytes,CancellationToken token)=>inner.ReadSecret(prompt,maximumBytes,token);
        public bool ConfirmRemoval(string id,CancellationToken token)=>inner.ConfirmRemoval(id,token);
        public void DisplayRecovery(string code,string vaultId)
        {
            inner.DisplayRecovery(code,vaultId);using var key=RecoveryCode.Decode(code.AsSpan());
            // Dedicated current-user-only pipe, never stdout/log/argv/env or a plaintext file.
            pipe.Write(key.Span);pipe.Flush();
        }
    }
}
