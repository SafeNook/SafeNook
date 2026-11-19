using SafeNook.Application;
using SafeNook.ApplicationTestData;
using SafeNook.Core.Vault;
using SafeNook.Storage;

if(!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
if(args.Length>1 && args[1]=="verify-crash-backup") { using var checkedStore=QualificationStore.Open(Path.GetFullPath(args[0]),CredentialKind.Recovery,Enumerable.Range(128,32).Select(value=>(byte)value).ToArray(),new(65536,536870912),default); QualificationStore.VerifyPortable(Path.GetFullPath(args[0])+".snbak",CredentialKind.Recovery,Enumerable.Range(128,32).Select(value=>(byte)value).ToArray(),new(65536,536870912),default); Console.WriteLine("PASS: native crash backup fully authenticated."); return; }
if(args.Length>1 && args[1]=="crash") { CrashCampaign.Run(args); return; }
if(args.Length>1 && args[1]=="vm-smoke-verify") { OracleIntegration.VerifySmoke(args); return; }
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
ui.Edits[SecretPrompt.Title]="edited title";
application.Edit(path,login.Id);
ui.Edits.Clear();ui.Edits[SecretPrompt.LoginPassword]="synthetic edited password";
application.Edit(path,login.Id);
if(application.Show(path,login.Id,true).Revealed?.Password!="synthetic edited password" || application.Show(path,login.Id).Items.Single().Revision!=3) throw new InvalidOperationException("Login edit failed.");
ui.Edits.Clear();ui.Edits[SecretPrompt.Note]="synthetic edited note";
application.Edit(path,note.Id);
if(application.Show(path,note.Id,true).Revealed?.Note!="synthetic edited note") throw new InvalidOperationException("Note edit failed.");
ui.Edits.Clear();
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
// Explicit synthetic source/output fixtures in a separate owner-private directory.
var io=path+"-external";Directory.CreateDirectory(io);
using(var identity=System.Security.Principal.WindowsIdentity.GetCurrent())
{
    var acl=new System.Security.AccessControl.DirectorySecurity();acl.SetOwner(identity.User!);acl.SetAccessRuleProtection(true,false);
    acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(identity.User!,System.Security.AccessControl.FileSystemRights.FullControl,System.Security.AccessControl.AccessControlType.Allow));
    System.IO.FileSystemAclExtensions.SetAccessControl(new DirectoryInfo(io),acl);
}
var source=Path.Combine(io,"synthetic-input");File.WriteAllBytes(source,[0,255,13,10,239,187,191]);
foreach(var kind in new[]{5,3,4})
{
    var imported=(kind==5?application.ImportFile(path,source):kind==3?application.ImportSshKey(path,source,source):application.ImportAgeIdentity(path,source,source)).Items.Single();
    var output=Path.Combine(io,"synthetic-output-"+kind);
    if(kind==5) application.ExportFile(path,imported.Id,output);
    else if(kind==3) application.ExportSshKey(path,imported.Id,output);
    else application.ExportAgeIdentity(path,imported.Id,output);
    if(!File.ReadAllBytes(source).AsSpan().SequenceEqual(File.ReadAllBytes(output))) throw new InvalidOperationException("Opaque round trip failed.");
}
Console.WriteLine("PASS: application init/login/note/edit/file/ssh/age/reveal/tombstone/reopen; owned input cleared; production writes disabled.");
