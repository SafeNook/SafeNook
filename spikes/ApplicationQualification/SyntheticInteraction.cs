using System.Text;
using SafeNook.Application;

namespace SafeNook.ApplicationTestData;

// Synthetic test data only; never accepts real credentials or logs returned values.
internal sealed class SyntheticInteraction:IVaultInteraction
{
    internal string Password { get; set; }="synthetic master password";
    internal string NewPassword { get; set; }="synthetic new password";
    internal string ConfirmPassword { get; set; }="synthetic master password";
    internal bool ConfirmKey { get; set; }=true;
    internal bool Remove { get; set; }=true;
    internal string Title { get; set; }="test title";
    internal string Note { get; set; }="synthetic secret note";
    internal string? Recovery { get; private set; }
    internal int Reads { get; private set; }
    internal List<byte[]> Issued { get; }=[];
    public bool IsInteractive { get; set; }=true;
    public byte[] ReadSecret(SecretPrompt prompt,int maximumBytes,CancellationToken token)
    {
        token.ThrowIfCancellationRequested(); Reads++;
        var text=prompt switch
        {
            SecretPrompt.NewPassword=>NewPassword, SecretPrompt.Recovery=>Recovery!, SecretPrompt.Password=>Password, SecretPrompt.ConfirmPassword=>ConfirmPassword,
            SecretPrompt.ConfirmRecovery=>ConfirmKey?Recovery!:"invalid recovery",
            SecretPrompt.Title=>Title,SecretPrompt.Username=>"synthetic private username",SecretPrompt.LoginPassword=>"synthetic login password",
            SecretPrompt.Url=>"https://synthetic-private.invalid",SecretPrompt.Notes=>"synthetic login notes",SecretPrompt.Note=>Note,_=>throw new InvalidOperationException()
        };
        var bytes=Encoding.UTF8.GetBytes(text); Issued.Add(bytes); return bytes;
    }
    public void DisplayRecovery(string code,string vaultId) { Recovery=code; }
    public bool ConfirmRemoval(string id,CancellationToken token) { token.ThrowIfCancellationRequested(); return Remove; }
}
