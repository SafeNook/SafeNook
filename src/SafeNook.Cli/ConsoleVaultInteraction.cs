using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using SafeNook.Application;

namespace SafeNook.Cli;

internal interface ISecretTerminal
{
    bool IsInteractive { get; }
    ConsoleKeyInfo ReadKey(bool intercept,CancellationToken token);
    void Write(string text);
}
internal sealed class ConsoleSecretTerminal:ISecretTerminal
{
    public bool IsInteractive=>!Console.IsInputRedirected && !Console.IsOutputRedirected && !Console.IsErrorRedirected;
    public ConsoleKeyInfo ReadKey(bool intercept,CancellationToken token)
    {
        while(!Console.KeyAvailable) { if(token.WaitHandle.WaitOne(25)) token.ThrowIfCancellationRequested(); }
        token.ThrowIfCancellationRequested(); return Console.ReadKey(intercept);
    }
    public void Write(string text)=>Console.Error.Write(text);
}
internal sealed class ConsoleVaultInteraction(ISecretTerminal terminal):IVaultEditInteraction
{
    public bool IsInteractive=>terminal.IsInteractive;
    public byte[] ReadSecret(SecretPrompt prompt,int maximumBytes,CancellationToken token)
        =>Read(prompt.ToString()+((prompt is SecretPrompt.Note or SecretPrompt.Notes or SecretPrompt.Urls or SecretPrompt.Tags or SecretPrompt.ConfirmNote or SecretPrompt.ConfirmNotes)?" (Ctrl+D ends; Esc cancels): ":": "),maximumBytes,token,prompt is SecretPrompt.Note or SecretPrompt.Notes or SecretPrompt.Urls or SecretPrompt.Tags or SecretPrompt.ConfirmNote or SecretPrompt.ConfirmNotes);
    internal byte[] Read(string prompt,int maximumBytes,CancellationToken token,bool multiline=false)
    {
        if(!IsInteractive) throw new VaultOperationException(VaultApplicationError.InteractiveRequired);
        var chars=new char[maximumBytes]; var count=0;
        try
        {
            terminal.Write(prompt);
            while(true)
            {
                var key=terminal.ReadKey(true,token);
                if(key.Key==ConsoleKey.Escape || (key.Key==ConsoleKey.C && key.Modifiers.HasFlag(ConsoleModifiers.Control))) throw new OperationCanceledException();
                if((!multiline && key.Key==ConsoleKey.Enter) || (multiline && key.Key==ConsoleKey.D && key.Modifiers.HasFlag(ConsoleModifiers.Control))) break;
                if(key.Key==ConsoleKey.Backspace) { if(count>0) chars[--count]='\0'; continue; }
                var c=multiline && key.Key==ConsoleKey.Enter?'\n':key.KeyChar;
                if(c=='\0') continue;
                if(count==chars.Length) throw new VaultOperationException(VaultApplicationError.InvalidArguments);
                chars[count++]=c;
            }
            var utf8=new UTF8Encoding(false,true);
            var size=utf8.GetByteCount(chars.AsSpan(0,count));
            if(size>maximumBytes) throw new VaultOperationException(VaultApplicationError.InvalidArguments);
            var bytes=new byte[size];
            try { utf8.GetBytes(chars.AsSpan(0,count),bytes); token.ThrowIfCancellationRequested(); return bytes; }
            catch { CryptographicOperations.ZeroMemory(bytes); throw; }
        }
        finally { CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(chars.AsSpan())); terminal.Write("\n"); }
    }
    public void DisplayRecovery(string code,string vaultId)
    {
        if(!IsInteractive) throw new VaultOperationException(VaultApplicationError.InteractiveRequired);
        terminal.Write("Recovery key for vault "+vaultId+". Store separately; terminal recording may capture it.\n"+code+"\nRe-enter the complete key to confirm delivery.\n");
    }
    public bool ReplaceField(SecretPrompt field,CancellationToken token)
        =>Yes("Replace "+field+"? Type yes; Enter keeps existing. Arrays use one value per line; empty replacement clears: ",token);
    public bool ConfirmEdit(CancellationToken token)=>Yes("Publish edit? Type yes; Enter cancels: ",token);
    private bool Yes(string prompt,CancellationToken token)
    {
        var bytes=Read(prompt,3,token);
        try
        {
            if(bytes.Length==0) return false;
            if(bytes.AsSpan().SequenceEqual("yes"u8)) return true;
            throw new VaultOperationException(VaultApplicationError.InvalidArguments);
        }
        finally {CryptographicOperations.ZeroMemory(bytes);}
    }
    public bool ConfirmRemoval(string id,CancellationToken token)
    {
        var bytes=Read("Type the complete record ID to confirm removal (Enter cancels): ",32,token);
        try { return bytes.AsSpan().SequenceEqual(Encoding.ASCII.GetBytes(id)); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
}
