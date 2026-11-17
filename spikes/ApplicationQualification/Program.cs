using SafeNook.Application;
using SafeNook.ApplicationTestData;
using SafeNook.Core.Vault;
using SafeNook.Storage;

if(!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
if(args.Length>1 && args[1]=="verify-crash-backup") { using var checkedStore=QualificationStore.Open(Path.GetFullPath(args[0]),CredentialKind.Recovery,Enumerable.Range(128,32).Select(value=>(byte)value).ToArray(),new(65536,536870912),default); QualificationStore.VerifyPortable(Path.GetFullPath(args[0])+".snbak",CredentialKind.Recovery,Enumerable.Range(128,32).Select(value=>(byte)value).ToArray(),new(65536,536870912),default); Console.WriteLine("PASS: native crash backup fully authenticated."); return; }
if(args.Length>1 && args[1]=="crash") { CrashCampaign.Run(args); return; }
if(args.Length>1 && args[1]=="oracle") { OracleIntegration.Run(args).GetAwaiter().GetResult(); return; }
if(args.Length>1 && args[1]=="oracle-guest") { OracleIntegration.Guest(args).GetAwaiter().GetResult(); return; }
// Only synthetic fixture credentials are accepted; no qualification entry point exists in nook.
var path=Path.GetFullPath(args[0]);Directory.CreateDirectory(Path.GetDirectoryName(path)!);
var ui=new SyntheticInteraction();var application=VaultApplication.ForQualification(ui,new(65536,536870912));
application.Init(path);
var login=application.Add(path,"login").Items.Single();
var note=application.Add(path,"note").Items.Single();
if(application.List(path).Items.Length!=2 || application.Show(path,login.Id).Revealed is not null ||
    application.Show(path,login.Id,true).Revealed?.Password!="synthetic login password" || application.Show(path,note.Id,true).Revealed?.Note!=ui.Note)
    throw new InvalidOperationException("Qualification round trip failed.");
application.Remove(path,login.Id);
if(new VaultApplication(ui).List(path).Items.Length!=1 || StorageSupport.ProductionWritesSupported) throw new InvalidOperationException("Qualification invariant failed.");
var originalRecovery=ui.Recovery;
ui.ConfirmPassword=ui.NewPassword;
application.ChangePassword(path);
ui.Password=ui.NewPassword;
application.List(path);
application.Recover(path);
application.RotateRecovery(path);
if(ui.Recovery==originalRecovery) throw new InvalidOperationException("Recovery rotation failed.");
application.Recover(path);
application.List(path);
var archive=path+".snbak";var restored=path+"-restored";
var backupHash=application.Backup(path,archive);
if(application.VerifyBackup(archive)!=backupHash || application.Restore(archive,restored)!=backupHash || application.List(restored).Items.Length!=1) throw new InvalidOperationException("Backup round trip failed.");
if(ui.Issued.Any(bytes=>bytes.Any(value=>value!=0))) throw new InvalidOperationException("Owned input was not cleared.");
Console.WriteLine("PASS: application init/login/note/reveal/tombstone/reopen; owned input cleared; production writes disabled.");
