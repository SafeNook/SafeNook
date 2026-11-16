using SafeNook.Application;
using SafeNook.ApplicationTestData;
using SafeNook.Core.Vault;
using SafeNook.Storage;

if(!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
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
if(ui.Issued.Any(bytes=>bytes.Any(value=>value!=0))) throw new InvalidOperationException("Owned input was not cleared.");
Console.WriteLine("PASS: application init/login/note/reveal/tombstone/reopen; owned input cleared; production writes disabled.");
