using System.Text;
using System.Security.Cryptography;
using SafeNook.Application;
using SafeNook.ApplicationTestData;
using SafeNook.Core.Vault;
using SafeNook.Core.Vault.Models;
using SafeNook.Storage;
using SafeNook.Cli;

namespace SafeNook.Application.Tests;

public sealed partial class VaultApplicationTests
{
    [Theory]
    [InlineData("login")] [InlineData("note")]
    public void EditPreservesIdentityHistoryAndUnspecifiedFields(string type)
    {
        var path=PathForTest();var ui=new SyntheticInteraction();var app=App(ui);app.Init(path,Token);
        var id=app.Add(path,type,Token).Items.Single().Id;
        byte[] header;ObjectReference reference;ItemDocument old;
        using(var store=QualificationStore.Open(path,CredentialKind.Password,Encoding.UTF8.GetBytes(ui.Password),new(65536,536870912),Token))
        {header=store.Header;reference=store.ReadManifest(Encoding.UTF8.GetBytes(ui.Password),Token).Items.Single();old=store.ReadItem(id);}
        var oldFile=Path.Combine(path,"items",reference.WriteId+".item");var oldCipher=File.ReadAllBytes(oldFile);
        ui.Edits[SecretPrompt.Title]="changed title";
        var reply=app.Edit(path,id,Token);Assert.Null(reply.Revealed);Assert.Equal(id,reply.Items.Single().Id);Assert.Equal(2ul,reply.Items.Single().Revision);
        using(var store=QualificationStore.Open(path,CredentialKind.Password,Encoding.UTF8.GetBytes(ui.Password),new(65536,536870912),Token))
        {
            var item=store.ReadItem(id);var next=store.ReadManifest(Encoding.UTF8.GetBytes(ui.Password),Token).Items.Single();
            Assert.Equal(old.Fields.Type,item.Fields.Type);Assert.Equal(old.Fields.CreatedAt,item.Fields.CreatedAt);Assert.Equal(reference.Sha256,item.Fields.Previous);
            Assert.Equal(old.Fields.Tags,item.Fields.Tags);Assert.NotEqual(reference.WriteId,next.WriteId);Assert.Equal(oldCipher,File.ReadAllBytes(oldFile));
            Assert.Equal(header.AsSpan(166,216).ToArray(),store.Header.AsSpan(166,216).ToArray());
            Assert.Equal(header,VaultFormat.DecodeWrapper(File.ReadAllBytes(Path.Combine(path,".backup",Convert.ToHexStringLower(header.AsSpan(44,16))+".json"))));
            foreach(var root in Directory.GetFiles(Path.Combine(path,".backup"),"*.json")) store.VerifyBackup(Path.GetFileNameWithoutExtension(root),CredentialKind.Password,Encoding.UTF8.GetBytes(ui.Password),Token);
            using var key=KeySlots.OpenPassword(header,Encoding.UTF8.GetBytes(ui.Password),65536,Token);
            using var oldPlain=ObjectCodec.Decrypt(key.Span,new(Guid.ParseExact(Convert.ToHexStringLower(header.AsSpan(12,16)),"N"),Guid.ParseExact(Convert.ToHexStringLower(header.AsSpan(28,16)),"N"),Guid.ParseExact(id,"N"),1,old.Fields.Type),Convert.FromHexString(reference.WriteId),Convert.FromHexString(reference.Sha256),oldCipher,131072,Token);
            Assert.Equal(old.Fields.Revision,VaultPayloadJson.ReadItem(oldPlain.Span,id,old.Fields.Type).Fields.Revision);
            var newCipher=File.ReadAllBytes(Path.Combine(path,"items",next.WriteId+".item"));
            Assert.False(oldCipher.AsSpan(106,12).SequenceEqual(newCipher.AsSpan(106,12)));
        }
        Assert.Equal(type=="login"?"synthetic login password":null,app.Show(path,id,true,Token).Revealed!.Password);
        Assert.Equal(type=="login"?"synthetic login notes":ui.Note,app.Show(path,id,true,Token).Revealed!.Note);
        ui.Edits.Clear();ui.Edits[type=="login"?SecretPrompt.LoginPassword:SecretPrompt.Note]="updated synthetic secret";
        app.Edit(path,id,Token);var revealed=App(ui).Show(path,id,true,Token).Revealed!;
        Assert.Equal("updated synthetic secret",type=="login"?revealed.Password:revealed.Note);
        Assert.Equal(3ul,app.Show(path,id,false,Token).Items.Single().Revision);
        Assert.All(ui.Issued,b=>Assert.All(b,value=>Assert.Equal((byte)0,value)));
        foreach(var file in Directory.GetFiles(path,"*",SearchOption.AllDirectories)) Assert.True(File.ReadAllBytes(file).AsSpan().IndexOf("updated synthetic secret"u8)<0);
    }
    [Fact]
    public void EditArraysAllFieldsAndExplicitEmptyArePreserved()
    {
        var path=PathForTest();var ui=new SyntheticInteraction();var app=App(ui);app.Init(path,Token);var id=app.Add(path,"login",Token).Items.Single().Id;
        ui.Edits[SecretPrompt.Username]="changed user";ui.Edits[SecretPrompt.Urls]="https://one.invalid\nhttps://two.invalid";
        ui.Edits[SecretPrompt.Tags]="one\ntwo";ui.Edits[SecretPrompt.Notes]="changed notes";
        app.Edit(path,id,Token);ui.Edits.Clear();ui.Edits[SecretPrompt.Title]="";app.Edit(path,id,Token);
        var reply=app.Show(path,id,true,Token);Assert.Equal("",reply.Items.Single().Title);Assert.Equal(new[]{"one","two"},reply.Items.Single().Tags);
        Assert.Equal("changed user",reply.Revealed!.Username);Assert.Equal(new[]{"https://one.invalid","https://two.invalid"},reply.Revealed.Urls);Assert.Equal("changed notes",reply.Revealed.Note);
        ui.Edits.Clear();ui.Edits[SecretPrompt.Urls]="";ui.Edits[SecretPrompt.Tags]="";app.Edit(path,id,Token);
        Assert.Empty(app.Show(path,id,true,Token).Revealed!.Urls);Assert.Empty(app.Show(path,id,false,Token).Items.Single().Tags);
    }
    [Fact]
    public void EditNoopCancelConfirmationMissingAndTombstoneDoNotPublish()
    {
        var path=PathForTest();var ui=new SyntheticInteraction();var app=App(ui);app.Init(path,Token);var id=app.Add(path,"note",Token).Items.Single().Id;
        var original=File.ReadAllBytes(Path.Combine(path,"vault.json"));app.Edit(path,id,Token);Assert.Equal(original,File.ReadAllBytes(Path.Combine(path,"vault.json")));
        ui.Edits[SecretPrompt.Note]="new secret";ui.ConfirmSecrets=false;
        Assert.Equal(VaultApplicationError.Rejected,Assert.Throws<VaultOperationException>(()=>app.Edit(path,id,Token)).Error);
        ui.ConfirmSecrets=true;ui.ConfirmChanges=false;
        Assert.Equal(VaultApplicationError.Cancelled,Assert.Throws<VaultOperationException>(()=>app.Edit(path,id,Token)).Error);
        Assert.Equal(original,File.ReadAllBytes(Path.Combine(path,"vault.json")));
        Assert.Equal(VaultApplicationError.InvalidArguments,Assert.Throws<VaultOperationException>(()=>app.Edit(path,"bad",Token)).Error);
        Assert.Equal(VaultApplicationError.NotFound,Assert.Throws<VaultOperationException>(()=>app.Edit(path,new string('a',32),Token)).Error);
        app.Remove(path,id,Token);var deleted=File.ReadAllBytes(Path.Combine(path,"vault.json"));
        Assert.Equal(VaultApplicationError.NotFound,Assert.Throws<VaultOperationException>(()=>app.Edit(path,id,Token)).Error);
        Assert.Equal(deleted,File.ReadAllBytes(Path.Combine(path,"vault.json")));
        Assert.All(ui.Issued,b=>Assert.All(b,v=>Assert.Equal((byte)0,v)));
    }
    [Theory]
    [InlineData("before")] [InlineData("after")] [InlineData("short")] [InlineData("file-flush")] [InlineData("directory-flush")]
    [InlineData("rename")] [InlineData("readback")] [InlineData("cancel")] [InlineData("pre-cancel")] [InlineData("cancel:AfterPublish")]
    public void EditFaultsPreserveRecoveryAndNeverRetry(string failure)
    {
        var path=PathForTest();var ui=new SyntheticInteraction();var normal=App(ui);normal.Init(path,Token);var id=normal.Add(path,"note",Token).Items.Single().Id;
        var original=File.ReadAllBytes(Path.Combine(path,"vault.json"));ui.Edits[SecretPrompt.Note]="replacement synthetic note";
        using var cancel=CancellationTokenSource.CreateLinkedTokenSource(Token);if(failure=="pre-cancel") cancel.Cancel();
        var faults=new MatrixFault(failure,cancel);
        var error=Assert.Throws<VaultOperationException>(()=>App(ui,faults).Edit(path,id,cancel.Token));
        var published=failure is "after" or "readback" or "cancel:AfterPublish";
        Assert.Equal(published || failure=="rename"?VaultApplicationError.Indeterminate:failure is "cancel" or "pre-cancel"?VaultApplicationError.Cancelled:VaultApplicationError.Rejected,error.Error);
        Assert.InRange(faults.Publications,0,1);Assert.DoesNotContain("synthetic",error.ToString());Assert.Null(error.InnerException);
        if(!published) Assert.Equal(original,File.ReadAllBytes(Path.Combine(path,"vault.json")));
        var reopened=normal.Show(path,id,true,Token);Assert.Equal(published?"replacement synthetic note":ui.Note,reopened.Revealed!.Note);
        using var recovery=RecoveryCode.Decode(ui.Recovery!.AsSpan());using var store=QualificationStore.Open(path,CredentialKind.Recovery,recovery.Span,new(65536,536870912),Token);
        foreach(var root in Directory.GetFiles(Path.Combine(path,".backup"),"*.json")) store.VerifyBackup(Path.GetFileNameWithoutExtension(root),CredentialKind.Recovery,recovery.Span,Token);
        Assert.All(ui.Issued,b=>Assert.All(b,v=>Assert.Equal((byte)0,v)));
    }
    [Theory]
    [InlineData("wrong-password")] [InlineData("duplicate-tags")] [InlineData("too-many-urls")] [InlineData("password-confirmation")]
    public void EditInvalidInputNeverReplacesRoot(string failure)
    {
        var path=PathForTest();var ui=new SyntheticInteraction();var app=App(ui);app.Init(path,Token);var id=app.Add(path,"login",Token).Items.Single().Id;
        var root=File.ReadAllBytes(Path.Combine(path,"vault.json"));
        var expected=VaultApplicationError.InvalidArguments;
        switch(failure)
        {
            case "wrong-password":ui.Password="incorrect synthetic";expected=VaultApplicationError.AuthenticationOrCorruption;break;
            case "duplicate-tags":ui.Edits[SecretPrompt.Tags]="same\nsame";break;
            case "too-many-urls":ui.Edits[SecretPrompt.Urls]=string.Join('\n',Enumerable.Repeat("https://example.invalid",17));break;
            default:ui.Edits[SecretPrompt.LoginPassword]="new synthetic password";ui.ConfirmSecrets=false;expected=VaultApplicationError.Rejected;break;
        }
        var error=Assert.Throws<VaultOperationException>(()=>app.Edit(path,id,Token));Assert.Equal(expected,error.Error);
        Assert.Equal(root,File.ReadAllBytes(Path.Combine(path,"vault.json")));Assert.Null(error.InnerException);
        Assert.All(ui.Issued,b=>Assert.All(b,v=>Assert.Equal((byte)0,v)));
    }
    [Fact]
    public void EditCliPublishesOnlySafeReplyAndCorruptionRefuses()
    {
        var path=PathForTest();var ui=new SyntheticInteraction();var app=App(ui);app.Init(path,Token);var id=app.Add(path,"login",Token).Items.Single().Id;
        ui.Edits[SecretPrompt.LoginPassword]="NEVER_ECHO_EDIT_SECRET";
        using var output=new StringWriter();using var error=new StringWriter();
        Assert.Equal(0,Program.Run(["edit","--vault",path,"--id",id],app,output,error,Token));
        Assert.DoesNotContain("NEVER_ECHO",output.ToString()+error);Assert.DoesNotContain("synthetic private",output.ToString()+error);
        var root=File.ReadAllBytes(Path.Combine(path,"vault.json"));
        var file=Directory.GetFiles(Path.Combine(path,"items"),"*.item").Last();
        // Corrupt the active immutable item, never a user artifact.
        using(var store=QualificationStore.Open(path,CredentialKind.Password,Encoding.UTF8.GetBytes(ui.Password),new(65536,536870912),Token)) file=Path.Combine(path,"items",store.ReadManifest(Encoding.UTF8.GetBytes(ui.Password),Token).Items.Single().WriteId+".item");
        var bytes=File.ReadAllBytes(file);bytes[^1]^=1;File.WriteAllBytes(file,bytes);
        Assert.Equal(VaultApplicationError.AuthenticationOrCorruption,Assert.Throws<VaultOperationException>(()=>app.Edit(path,id,Token)).Error);
        Assert.Equal(root,File.ReadAllBytes(Path.Combine(path,"vault.json")));
    }
}
