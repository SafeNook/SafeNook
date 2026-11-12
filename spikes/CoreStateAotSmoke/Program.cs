using System.Text;
using SafeNook.Core.Vault;
using SafeNook.Core.Vault.Models;
using SafeNook.StateTestData;

static void Check(bool condition) { if (!condition) throw new InvalidOperationException("State smoke check failed."); }
var fixture=StateFixture.Build(secondItem:true); var policy=StateFixture.Policy();
using(var state=AuthenticatedVaultState.OpenRecovery(fixture.Header,StateFixture.Recovery,fixture.Source,policy))
{
    Check(state.ItemIds.Length==2);
    Check(state.ReadItem(StateFixture.ItemId).Payload is FilePayload);
    Check(state.ReadItem(StateFixture.OtherId).Payload is NotePayload);
    Check(fixture.Source.Reads.Where(r=>r.Kind==2).All(r=>r.Size==118));
    using(var blob=state.ReadBlob(StateFixture.BlobId)) Check(blob.Span.SequenceEqual(new byte[]{0,255,13,10,0}));
    fixture.Source.Files[(2,fixture.BlobWrite)][^1]^=1;
    var rejected=false;
    try { using var blob=state.ReadBlob(StateFixture.BlobId); } catch(VaultDataException) { rejected=true; }
    Check(rejected);
}
Check(policy.ReservedBytes==0);
fixture=StateFixture.Build();
using(var state=AuthenticatedVaultState.OpenPassword(fixture.Header,StateFixture.Password,fixture.Source,policy)) Check(state.Sequence==1);
foreach(var (type,payload) in new (ushort,string)[]
{
    (1,"{\"username\":\"u\",\"password\":\"synthetic\",\"urls\":[],\"notes\":\"n\"}"),
    (2,"{\"text\":\"note\"}"),
    (3,"{\"privateBlobId\":\""+StateFixture.BlobId+"\",\"publicBlobId\":null,\"format\":\"opaque-ssh\",\"originalName\":\"key\"}"),
    (4,"{\"identityBlobId\":\""+StateFixture.BlobId+"\",\"recipientBlobId\":null,\"format\":\"opaque-age\",\"originalName\":\"key\"}"),
})
{
    var f=StateFixture.Build(StateFixture.Item(type,payload),includeBlob:type>=3,type:type);
    using var state=AuthenticatedVaultState.OpenRecovery(f.Header,StateFixture.Recovery,f.Source,policy);
    var serialized=VaultPayloadJson.WriteItem(state.ReadItem(StateFixture.ItemId));
    try { Check(VaultPayloadJson.ReadItem(serialized,StateFixture.ItemId,type).Fields.Type==type); }
    finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(serialized); }
    var manifest=VaultPayloadJson.ReadManifest(Encoding.UTF8.GetBytes(f.ManifestJson));
    Check(VaultPayloadJson.ReadManifest(VaultPayloadJson.WriteManifest(manifest)).Sequence==1);
}
var failurePolicy=StateFixture.Policy(new RejectAllocation());
var failed=false;
try { using var bad=AuthenticatedVaultState.OpenRecovery(fixture.Header,StateFixture.Recovery,fixture.Source,failurePolicy); }
catch(VaultDataException e) { failed=e.Error==VaultDataError.ResourceLimit; }
Check(failed && failurePolicy.ReservedBytes==0);
Console.WriteLine("PASS: authenticated state, five source-generated payloads, both slots, lazy blob authentication, allocation failure.");
internal sealed class RejectAllocation:IVaultBufferAllocator
{
    public byte[] Allocate(int length)=>throw new OutOfMemoryException("synthetic diagnostic must not escape");
}
