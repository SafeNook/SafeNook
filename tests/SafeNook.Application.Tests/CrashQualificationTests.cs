using System.Diagnostics;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text;
using SafeNook.Core.Vault;
using SafeNook.Storage;
using SafeNook.StoreTestData;
namespace SafeNook.Application.Tests;
public sealed partial class VaultApplicationTests
{
    public static IEnumerable<object[]> CrashCases()
    {
        foreach(var op in new[]{"passwd","recover","rotate","restore"})
        foreach(var boundary in new[]{"Authenticated","Validated","ObjectWritten","ObjectFlushed","ObjectInstalled","ManifestVerified","RootWritten","RootFlushed","BeforePublish","BeforeRename","AfterPublish","BeforeReadback","RootReadback","ACK"}) yield return [op,boundary];
        foreach(var op in new[]{"passwd","recover","rotate"}) yield return [op,"BackupWritten"];
        foreach(var boundary in new[]{"Authenticated","ObjectWritten","BeforePublish","BeforeRename","AfterPublish","BeforeReadback","ACK"}) yield return ["backup",boundary];
        foreach(var boundary in new[]{"ArchiveRead","Authenticated","ACK"}) yield return ["verify",boundary];
    }
    [Theory] [MemberData(nameof(CrashCases))]
    public async Task RealProcessKillPreservesAuthenticatedGeneration(string operation,string boundary)
    {
        var caseDirectory=PathForTest();Directory.CreateDirectory(caseDirectory);var path=Path.Combine(caseDirectory,"vault");var pipeName="safenook-crash-"+Guid.NewGuid().ToString("N");
        using var pipe=new NamedPipeServerStream(pipeName,PipeDirection.In,1,PipeTransmissionMode.Byte,PipeOptions.Asynchronous|PipeOptions.CurrentUserOnly);
        var root=new DirectoryInfo(AppContext.BaseDirectory);while(root is not null && !File.Exists(Path.Combine(root.FullName,"SafeNook.slnx"))) root=root.Parent;
        var executable=Path.Combine(root!.FullName,"spikes","ApplicationQualification","bin","Release","net10.0","ApplicationQualification.exe");
        var start=new ProcessStartInfo(executable) {UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
        foreach(var arg in new[]{path,"crash",operation,boundary,pipeName}) start.ArgumentList.Add(arg);
        using var child=Process.Start(start)!;var original=new byte[414];var nextRecovery=new byte[32];
        var published=boundary is "AfterPublish" or "BeforeReadback" or "RootReadback" or "ACK";
        try
        {
            await pipe.WaitForConnectionAsync(Token).WaitAsync(TimeSpan.FromSeconds(30),Token);
            await pipe.ReadExactlyAsync(original,Token).AsTask().WaitAsync(TimeSpan.FromSeconds(60),Token);
            var recoveryRead=operation=="rotate"?pipe.ReadExactlyAsync(nextRecovery,Token).AsTask():null;
            var marker=await child.StandardOutput.ReadLineAsync(Token).AsTask().WaitAsync(TimeSpan.FromSeconds(60),Token);
            if(boundary=="ACK")
            {
                Assert.NotNull(marker);Assert.StartsWith("ACK ",marker);Assert.Equal(68,marker.Length);
                using var ack=new FileStream(Path.Combine(caseDirectory,"observer.ack"),FileMode.CreateNew,FileAccess.Write,FileShare.None);ack.Write(Encoding.ASCII.GetBytes(marker));ack.Flush(true);
            }
            else Assert.Equal("CRASH_POINT",marker);
            if(operation=="rotate" && published) await recoveryRead!.WaitAsync(TimeSpan.FromSeconds(10),Token);
            // Independent controller kills the real helper. No exception/unwind/dispose in the child.
            child.Kill(true);await child.WaitForExitAsync(Token).WaitAsync(TimeSpan.FromSeconds(30),Token);Assert.NotEqual(0,child.ExitCode);
            if(recoveryRead is not null && !published) {try {await recoveryRead.WaitAsync(TimeSpan.FromSeconds(10),Token);} catch(EndOfStreamException) { }}
            Assert.Equal("",await child.StandardError.ReadToEndAsync(Token));Assert.Equal("",await child.StandardOutput.ReadToEndAsync(Token));
            if(boundary=="ACK")
            {
                var acknowledged=operation is "backup" or "verify"?File.ReadAllBytes(path+".snbak"):VaultFormat.DecodeWrapper(File.ReadAllBytes(Path.Combine(operation=="restore"?path+"-restored":path,"vault.json")));
                Assert.Equal(marker,"ACK "+Convert.ToHexStringLower(SHA256.HashData(acknowledged)));
            }
            var oldRecovery=Enumerable.Range(128,32).Select(value=>(byte)value).ToArray();var password=published && operation is "passwd" or "recover"?Encoding.UTF8.GetBytes("synthetic new password"):GenerationFixture.Password;
            var recovery=published && operation=="rotate"?nextRecovery:oldRecovery;
            using(var store=QualificationStore.Open(path,CredentialKind.Password,password,GenerationFixture.Policy(),Token))
            {
                var changed=published && operation is "passwd" or "recover" or "rotate";
                Assert.Equal(changed?3ul:2ul,System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(store.Header.AsSpan(60)));
                if(!changed) Assert.Equal(original,store.Header);
                else
                {
                    var unchanged=operation=="rotate"?166:274;Assert.Equal(original.AsSpan(unchanged,108).ToArray(),store.Header.AsSpan(unchanged,108).ToArray());
                    using var before=KeySlots.OpenRecovery(original,oldRecovery,Token);using var after=KeySlots.OpenRecovery(store.Header,recovery,Token);Assert.True(CryptographicOperations.FixedTimeEquals(before.Span,after.Span));Assert.Equal(original.AsSpan(12,32).ToArray(),store.Header.AsSpan(12,32).ToArray());
                }
                foreach(var backup in Directory.GetFiles(Path.Combine(path,".backup"),"*.json")) store.VerifyBackup(Path.GetFileNameWithoutExtension(backup),CredentialKind.Recovery,oldRecovery,Token);
            }
            using(var reopened=QualificationStore.Open(path,CredentialKind.Recovery,recovery,GenerationFixture.Policy(),Token)) Assert.Single(reopened.ItemIds);
            if(operation is "backup" or "verify")
            {
                Assert.Equal(operation=="verify" || published,File.Exists(path+".snbak"));
                if(File.Exists(path+".snbak")) {QualificationStore.VerifyPortable(path+".snbak",CredentialKind.Recovery,oldRecovery,GenerationFixture.Policy(),Token);using var exclusive=new FileStream(path+".snbak",FileMode.Open,FileAccess.Read,FileShare.None);}
            }
            if(operation=="restore")
            {
                Assert.Equal(published,File.Exists(Path.Combine(path+"-restored","vault.json")));
                if(published) {using var restored=QualificationStore.Open(path+"-restored",CredentialKind.Recovery,oldRecovery,GenerationFixture.Policy(),Token);Assert.Equal(original,restored.Header);Assert.Single(restored.ItemIds);foreach(var directory in new[]{"items","blobs","manifests"}) foreach(var file in Directory.GetFiles(Path.Combine(path+"-restored",directory))) Assert.Equal(File.ReadAllBytes(Path.Combine(path,directory,Path.GetFileName(file))),File.ReadAllBytes(file));}
                // The input archive handle must be released even when verification/restore was killed.
                using var exclusive=new FileStream(path+".snbak",FileMode.Open,FileAccess.Read,FileShare.None);
            }
            foreach(var file in Directory.GetFiles(caseDirectory,"*",SearchOption.AllDirectories))
            {var bytes=File.ReadAllBytes(file);Assert.True(bytes.AsSpan().IndexOf(GenerationFixture.Password)<0);Assert.True(bytes.AsSpan().IndexOf("synthetic new password"u8)<0);Assert.True(bytes.AsSpan().IndexOf("synthetic payload"u8)<0);Assert.True(bytes.AsSpan().IndexOf(oldRecovery)<0);if(nextRecovery.Any(b=>b!=0)) Assert.True(bytes.AsSpan().IndexOf(nextRecovery)<0);}
        }
        finally {if(!child.HasExited) {child.Kill(true);await child.WaitForExitAsync(Token);}CryptographicOperations.ZeroMemory(nextRecovery);}
    }
}
