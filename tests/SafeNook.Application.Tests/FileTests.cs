using System.Security.AccessControl;
using System.Security.Principal;
using SafeNook.Application;
using SafeNook.ApplicationTestData;
using SafeNook.Storage;

namespace SafeNook.Application.Tests;
public sealed partial class VaultApplicationTests
{
    private static string PrivateDirectory()
    {
        var path=PathForTest();Directory.CreateDirectory(path);
        using var identity=WindowsIdentity.GetCurrent();var acl=new DirectorySecurity();acl.SetOwner(identity.User!);acl.SetAccessRuleProtection(true,false);
        acl.AddAccessRule(new FileSystemAccessRule(identity.User!,FileSystemRights.FullControl,AccessControlType.Allow));new DirectoryInfo(path).SetAccessControl(acl);return path;
    }
    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(26214400)]
    public void FileExactRoundTrip(int size)
    {
        var path=PathForTest();var dir=PrivateDirectory();var source=Path.Combine(dir,"input");var output=Path.Combine(dir,"output");
        var bytes=new byte[size];new Random(42).NextBytes(bytes);File.WriteAllBytes(source,bytes);
        var ui=new SyntheticInteraction();var app=App(ui);app.Init(path,Token);var id=app.ImportFile(path,source,Token).Items.Single().Id;
        app.ExportFile(path,id,output,Token);Assert.Equal(bytes,File.ReadAllBytes(output));
        Assert.Throws<VaultOperationException>(()=>app.ExportFile(path,id,output,Token));Assert.Equal(bytes,File.ReadAllBytes(output));
        Assert.All(ui.Issued,b=>Assert.All(b,v=>Assert.Equal((byte)0,v)));
    }
    [Theory] [InlineData(false)] [InlineData(true)]
    public void OpaqueKeyCompanionsRoundTrip(bool age)
    {
        var path=PathForTest();var dir=PrivateDirectory();var source=Path.Combine(dir,"key");var pub=Path.Combine(dir,"public");
        byte[] data=[239,187,191,0,255,13,10,10,13];File.WriteAllBytes(source,data);File.WriteAllBytes(pub,[0,1,13,10]);
        var ui=new SyntheticInteraction();var app=App(ui);app.Init(path,Token);
        var id=(age?app.ImportAgeIdentity(path,source,pub,Token):app.ImportSshKey(path,source,pub,Token)).Items.Single().Id;
        if(age) {app.ExportAgeIdentity(path,id,source+"out",false,Token);app.ExportAgeIdentity(path,id,pub+"out",true,Token);}
        else {app.ExportSshKey(path,id,source+"out",false,Token);app.ExportSshKey(path,id,pub+"out",true,Token);}
        Assert.Equal(data,File.ReadAllBytes(source+"out"));Assert.Equal(File.ReadAllBytes(pub),File.ReadAllBytes(pub+"out"));
    }
    [Theory] [InlineData("readback")] [InlineData("short")] [InlineData("file-flush")] [InlineData("before")] [InlineData("rename")] [InlineData("after")]
    public void ExportFailureNeverPublishesPartialPlaintext(string failure)
    {
        var path=PathForTest();var dir=PrivateDirectory();var source=Path.Combine(dir,"input");File.WriteAllBytes(source,[1,2,3]);
        var ui=new SyntheticInteraction();var app=App(ui);app.Init(path,Token);var id=app.ImportFile(path,source,Token).Items.Single().Id;
        var root=File.ReadAllBytes(Path.Combine(path,"vault.json"));using var cancel=CancellationTokenSource.CreateLinkedTokenSource(Token);
        var target=Path.Combine(dir,"output");Assert.Throws<VaultOperationException>(()=>App(ui,new MatrixFault(failure,cancel)).ExportFile(path,id,target,cancel.Token));
        Assert.Equal(failure=="after",File.Exists(target));if(File.Exists(target)) Assert.Equal(new byte[]{1,2,3},File.ReadAllBytes(target));
        Assert.Empty(Directory.GetFiles(dir,"*.sn-export"));Assert.Equal(root,File.ReadAllBytes(Path.Combine(path,"vault.json")));
    }
    [Theory]
    [InlineData("wrong")] [InlineData("missing")] [InlineData("corrupt")] [InlineData("cancel")]
    [InlineData("unsafe-directory")] [InlineData("oversized")]
    public void FileRefusalsPreserveVaultAndDoNotExport(string failure)
    {
        var path=PathForTest();var dir=PrivateDirectory();var source=Path.Combine(dir,"input");File.WriteAllBytes(source,[0,1,2]);
        var ui=new SyntheticInteraction();var app=App(ui);app.Init(path,Token);var id=app.ImportFile(path,source,Token).Items.Single().Id;
        var root=File.ReadAllBytes(Path.Combine(path,"vault.json"));using var cancel=CancellationTokenSource.CreateLinkedTokenSource(Token);
        if(failure=="wrong") ui.Password="incorrect";
        if(failure=="missing") id=new string('a',32);
        if(failure=="corrupt") {var blob=Directory.GetFiles(Path.Combine(path,"blobs")).Single();var data=File.ReadAllBytes(blob);data[^1]^=1;File.WriteAllBytes(blob,data);}
        if(failure=="cancel") cancel.Cancel();
        var target=Path.Combine(dir,"output");
        if(failure=="unsafe-directory") target=Path.Combine(Path.GetDirectoryName(path)!,"unsafe-"+Guid.NewGuid().ToString("N"));
        if(failure=="oversized")
        {
            using(var file=new FileStream(source,FileMode.Open,FileAccess.Write)) file.SetLength(26214401);
            Assert.Throws<VaultOperationException>(()=>app.ImportFile(path,source,Token));
        }
        else Assert.Throws<VaultOperationException>(()=>app.ExportFile(path,id,target,cancel.Token));
        Assert.False(File.Exists(target));Assert.Equal(root,File.ReadAllBytes(Path.Combine(path,"vault.json")));
        Assert.Empty(Directory.GetFiles(dir,"*.sn-export"));
    }
    [Theory] [InlineData("short")] [InlineData("before")] [InlineData("after")]
    public void ImportFaultKeepsAuthenticatedOldOrNewRoot(string failure)
    {
        var path=PathForTest();var dir=PrivateDirectory();var source=Path.Combine(dir,"input");File.WriteAllBytes(source,[0,1]);
        var ui=new SyntheticInteraction();var app=App(ui);app.Init(path,Token);var root=File.ReadAllBytes(Path.Combine(path,"vault.json"));
        using var cancel=CancellationTokenSource.CreateLinkedTokenSource(Token);var faults=new MatrixFault(failure,cancel);
        var error=Assert.Throws<VaultOperationException>(()=>App(ui,faults).ImportFile(path,source,Token));
        Assert.InRange(faults.Publications,0,1);
        if(failure=="after") {Assert.Equal(VaultApplicationError.Indeterminate,error.Error);Assert.Single(app.List(path,Token).Items);}
        else {Assert.Equal(root,File.ReadAllBytes(Path.Combine(path,"vault.json")));Assert.Empty(app.List(path,Token).Items);}
    }

    [Fact]
    public void FileMissingSourceAndTombstoneRefuseWithoutOutput()
    {
        var path=PathForTest();var dir=PrivateDirectory();var ui=new SyntheticInteraction();var app=App(ui);app.Init(path,Token);
        var id=app.Add(path,"note",Token).Items.Single().Id;app.Remove(path,id,Token);
        var root=File.ReadAllBytes(Path.Combine(path,"vault.json"));var target=Path.Combine(dir,"output");
        Assert.Equal(VaultApplicationError.NotFound,Assert.Throws<VaultOperationException>(()=>app.ExportFile(path,id,target,Token)).Error);
        Assert.Throws<VaultOperationException>(()=>app.ImportFile(path,Path.Combine(dir,"missing"),Token));
        Assert.False(File.Exists(target));Assert.Equal(root,File.ReadAllBytes(Path.Combine(path,"vault.json")));
    }

}
