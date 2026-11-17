using System.Security.Cryptography;
using SafeNook.Core.Vault;
using SafeNook.Core.Vault.Models;
using SafeNook.Storage;

namespace SafeNook.Application;

public sealed partial class VaultApplication
{
    /// <summary>Edit a login/note through explicit interactive field selection and the existing authenticated COW commit.</summary>
    public VaultReply Edit(string path,string id,CancellationToken token=default)=>Run(()=>
    {
        Guard(path,true,token);
        if(!OperatingSystem.IsWindows()) throw new VaultOperationException(VaultApplicationError.UnsupportedPlatform);
        Id(id);
        var editor=_interaction as IVaultEditInteraction??throw new VaultOperationException(VaultApplicationError.InteractiveRequired);
        using var password=Input(SecretPrompt.Password,1024,token);
        using var store=QualificationStore.Open(path,CredentialKind.Password,password.Bytes,Policy,token);
        var old=Find(store,id);
        if(old.Payload is not LoginPayload and not NotePayload) Fail(VaultApplicationError.UnsupportedItem);
        var changed=false;
        string Field(SecretPrompt prompt,string previous,int limit,SecretPrompt? confirmation=null)
        {
            token.ThrowIfCancellationRequested();
            if(!editor.ReplaceField(prompt,token)) return previous;
            changed=true;
            using var replacement=Input(prompt,limit,token,true);
            if(confirmation is { } confirm)
            {
                using var repeated=Input(confirm,limit,token,true);
                if(!CryptographicOperations.FixedTimeEquals(replacement.Bytes,repeated.Bytes)) Fail(VaultApplicationError.Rejected);
            }
            return Utf8.GetString(replacement.Bytes);
        }
        string[] Lines(SecretPrompt prompt,string[] previous,int limit)
        {
            token.ThrowIfCancellationRequested();
            if(!editor.ReplaceField(prompt,token)) return previous.ToArray();
            changed=true;
            var text=Text(prompt,limit,token);
            return text.Length==0?[]:text.Split('\n');
        }
        var title=Field(SecretPrompt.Title,old.Fields.Title,1024);
        var tags=Lines(SecretPrompt.Tags,old.Fields.Tags,32*65);
        ItemPayload payload=old.Payload switch
        {
            LoginPayload login=>new LoginPayload {
                Username=Field(SecretPrompt.Username,login.Username,4096),
                Password=Field(SecretPrompt.LoginPassword,login.Password,4096,SecretPrompt.ConfirmLoginPassword),
                Urls=Lines(SecretPrompt.Urls,login.Urls,16*2049),
                Notes=Field(SecretPrompt.Notes,login.Notes,32768,SecretPrompt.ConfirmNotes)},
            NotePayload note=>new NotePayload {Text=Field(SecretPrompt.Note,note.Text,32768,SecretPrompt.ConfirmNote)},
            _=>throw new VaultOperationException(VaultApplicationError.UnsupportedItem)
        };
        token.ThrowIfCancellationRequested();
        if(!changed) return new VaultReply([Summary(old)]);
        if(!editor.ConfirmEdit(token)) Fail(VaultApplicationError.Cancelled);
        var manifest=store.ReadManifest(password.Bytes,token);
        var reference=manifest.Items.Single(r=>r.Id==id);
        var item=new ItemDocument(new ItemFields {Schema=old.Fields.Schema,Id=id,Type=old.Fields.Type,
            Revision=checked(old.Fields.Revision+1),CreatedAt=old.Fields.CreatedAt,
            UpdatedAt=Math.Max(old.Fields.UpdatedAt,checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds())),
            Title=title,Tags=tags,Deleted=false,Previous=reference.Sha256},payload);
        try {VaultPayloadJson.ValidateItem(item);}
        catch(VaultDataException) {throw new VaultOperationException(VaultApplicationError.InvalidArguments);}
        Change(store,password.Bytes,item,token);
        return new VaultReply([Summary(item)]);
    },token);
}
