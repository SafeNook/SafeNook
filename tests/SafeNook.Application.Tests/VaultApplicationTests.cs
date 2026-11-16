using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using SafeNook.Application;
using SafeNook.ApplicationTestData;
using SafeNook.Core.Vault;
using SafeNook.Storage;
using SafeNook.Cli;

namespace SafeNook.Application.Tests;

[SupportedOSPlatform("windows")]
public sealed class VaultApplicationTests
{
    public VaultApplicationTests()=>Assert.SkipWhen(!OperatingSystem.IsWindows() || RuntimeInformation.ProcessArchitecture!=Architecture.X64,"Windows x64 NTFS qualification only.");
    private static CancellationToken Token=>TestContext.Current.CancellationToken;
    private static VaultApplication App(SyntheticInteraction ui,IStoreFaults? faults=null)=>VaultApplication.ForQualification(ui,new(65536,536870912),faults);
    private static string PathForTest()
    {
        var dir=new DirectoryInfo(AppContext.BaseDirectory);while(dir is not null && !File.Exists(Path.Combine(dir.FullName,"SafeNook.slnx"))) dir=dir.Parent;
        var parent=Path.Combine(dir!.FullName,"artifacts");Directory.CreateDirectory(parent);return Path.Combine(parent,"sn-003c1-"+Guid.NewGuid().ToString("N"));
    }
    [Fact]
    public void LoginNoteTombstoneReopenRevealAndSlotPreservation()
    {
        var path=PathForTest();var ui=new SyntheticInteraction();var app=App(ui);app.Init(path,Token);
        var old=VaultFormat.DecodeWrapper(File.ReadAllBytes(Path.Combine(path,"vault.json")));
        var login=Assert.Single(app.Add(path,"login",Token).Items);ui.Title="note";var note=Assert.Single(app.Add(path,"note",Token).Items);
        Assert.Equal(2,new VaultApplication(ui).List(path,Token).Items.Length);Assert.Null(app.Show(path,login.Id,false,Token).Revealed);
        Assert.Equal("synthetic login password",app.Show(path,login.Id,true,Token).Revealed!.Password);
        Assert.Equal(ui.Note,app.Show(path,note.Id,true,Token).Revealed!.Note);
        using var stdout=new StringWriter();using var stderr=new StringWriter();
        Assert.Equal(0,Program.Run(["show",login.Id,"--vault",path],app,stdout,stderr,Token));
        Assert.DoesNotContain("synthetic login password",stdout.ToString());Assert.DoesNotContain("synthetic private username",stdout.ToString());
        Assert.Equal("",stderr.ToString());stdout.GetStringBuilder().Clear();
        Assert.Equal(0,Program.Run(["show",login.Id,"--vault",path,"--reveal"],app,stdout,stderr,Token));Assert.Contains("synthetic login password",stdout.ToString());
        app.Remove(path,login.Id,Token);Assert.Single(App(ui).List(path,Token).Items);
        Assert.Equal(VaultApplicationError.NotFound,Assert.Throws<VaultOperationException>(()=>app.Show(path,login.Id,false,Token)).Error);
        var latest=VaultFormat.DecodeWrapper(File.ReadAllBytes(Path.Combine(path,"vault.json")));
        Assert.Equal(old.AsSpan(166,216).ToArray(),latest.AsSpan(166,216).ToArray());
        using(var store=QualificationStore.Open(path,CredentialKind.Password,"synthetic master password"u8,new(65536,536870912),Token)) Assert.True(store.ReadItem(login.Id).Fields.Deleted);
        Assert.All(ui.Issued,b=>Assert.All(b,value=>Assert.Equal((byte)0,value)));
        foreach(var file in Directory.GetFiles(path,"*",SearchOption.AllDirectories))
        {
            var bytes=File.ReadAllBytes(file);Assert.True(bytes.AsSpan().IndexOf("synthetic login password"u8)<0);Assert.True(bytes.AsSpan().IndexOf("synthetic secret note"u8)<0);
        }
    }
    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void InitRequiresBothPasswordAndRecoveryConfirmation(bool recovery)
    {
        var path=PathForTest();var ui=new SyntheticInteraction();
        if(recovery) ui.ConfirmKey=false;else ui.ConfirmPassword="mismatch";
        Assert.Throws<VaultOperationException>(()=>App(ui).Init(path,Token));Assert.False(File.Exists(Path.Combine(path,"vault.json")));
        Assert.All(ui.Issued,b=>Assert.All(b,value=>Assert.Equal((byte)0,value)));
    }
    [Fact]
    public void WrongPasswordCorruptionMissingAndCancellationPublishNoOutput()
    {
        var path=PathForTest();var ui=new SyntheticInteraction();var app=App(ui);app.Init(path,Token);
        ui.Password="wrong secret";using var stdout=new StringWriter();using var stderr=new StringWriter();
        Assert.Equal(3,Program.Run(["ls","--vault",path],app,stdout,stderr,Token));Assert.Equal("",stdout.ToString());Assert.DoesNotContain(ui.Password,stderr.ToString());
        ui.Password="synthetic master password";
        Assert.Equal(VaultApplicationError.NotFound,Assert.Throws<VaultOperationException>(()=>app.Show(path,new string('a',32),false,Token)).Error);
        using var cancellation=new CancellationTokenSource();cancellation.Cancel();var count=ui.Reads;
        Assert.Equal(VaultApplicationError.Cancelled,Assert.Throws<VaultOperationException>(()=>app.List(path,cancellation.Token)).Error);Assert.Equal(count,ui.Reads);
        var root=Path.Combine(path,"vault.json");var bytes=File.ReadAllBytes(root);bytes[^1]^=1;File.WriteAllBytes(root,bytes);stdout.GetStringBuilder().Clear();
        Assert.Equal(3,Program.Run(["ls","--vault",path],app,stdout,stderr,Token));Assert.Equal("",stdout.ToString());
    }
    [Fact]
    public void RemovalRequiresConfirmation()
    {
        var path=PathForTest();var ui=new SyntheticInteraction();var app=App(ui);app.Init(path,Token);var item=Assert.Single(app.Add(path,"note",Token).Items);
        var before=File.ReadAllBytes(Path.Combine(path,"vault.json"));ui.Remove=false;
        Assert.Equal(VaultApplicationError.Cancelled,Assert.Throws<VaultOperationException>(()=>app.Remove(path,item.Id,Token)).Error);
        Assert.Equal(before,File.ReadAllBytes(Path.Combine(path,"vault.json")));Assert.Single(app.List(path,Token).Items);
    }
    [Theory]
    [InlineData((int)CommitStep.BeforePublish)] [InlineData((int)CommitStep.AfterPublish)]
    public void FaultsNeverPublishPartialStateOrReportSuccess(int step)
    {
        var path=PathForTest();var ui=new SyntheticInteraction();App(ui).Init(path,Token);
        var app=App(ui,new Fault((CommitStep)step));using var stdout=new StringWriter();using var stderr=new StringWriter();
        var code=Program.Run(["add","--type","note","--vault",path],app,stdout,stderr,Token);
        Assert.Equal((CommitStep)step==CommitStep.AfterPublish?7:1,code);Assert.Equal("",stdout.ToString());
        Assert.Equal((CommitStep)step==CommitStep.AfterPublish?1:0,App(ui).List(path,Token).Items.Length);
        Assert.DoesNotContain("private-exception",stderr.ToString());
    }
    [Fact]
    public void CancellationDuringRecoveryDeliveryLeavesNoRootAndClearsPassword()
    {
        var path=PathForTest();var ui=new SyntheticInteraction();using var cancellation=new CancellationTokenSource();
        var wrapped=new CancellingInteraction(ui,cancellation);
        var app=VaultApplication.ForQualification(wrapped,new(65536,536870912));
        Assert.Equal(VaultApplicationError.Cancelled,Assert.Throws<VaultOperationException>(()=>app.Init(path,cancellation.Token)).Error);
        Assert.False(File.Exists(Path.Combine(path,"vault.json")));
        Assert.All(ui.Issued,b=>Assert.All(b,value=>Assert.Equal((byte)0,value)));
    }
    private sealed class CancellingInteraction(SyntheticInteraction inner,CancellationTokenSource cancellation):IVaultInteraction
    {
        public bool IsInteractive=>true;
        public byte[] ReadSecret(SecretPrompt prompt,int maximumBytes,CancellationToken token)=>inner.ReadSecret(prompt,maximumBytes,token);
        public void DisplayRecovery(string code,string vaultId) { inner.DisplayRecovery(code,vaultId);cancellation.Cancel(); }
        public bool ConfirmRemoval(string id,CancellationToken token)=>false;
    }

    private sealed class Fault(CommitStep target):IStoreFaults
    { public void At(CommitStep step) { if(step==target) throw new IOException("private-exception"); } }
}
