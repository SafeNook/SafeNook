using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using SafeNook.Application;
using SafeNook.Core.Vault;
using SafeNook.DurabilityOracle;
using SafeNook.Storage;
using SafeNook.StoreTestData;

[SupportedOSPlatform("windows")]
internal static class OracleIntegration
{
    private static byte[] OldRecovery()=>Enumerable.Range(128,32).Select(x=>(byte)x).ToArray();
    private static byte[] NewPassword()=>"synthetic new password"u8.ToArray();
    private static bool Changes(Operation op)=>op is Operation.Password or Operation.Recover or Operation.Rotate;
    private static string Target(string path,Operation op)=>op==Operation.Restore?path+"-restored":path;
    private static void Require(bool condition) {if(!condition) throw new InvalidDataException("Oracle integration invariant failed.");}
    private sealed record Snapshot(byte[] Header,byte[] WrapperHash,byte[] HeaderHash,byte[] ArchiveHash,byte[] RawDigests)
    {
        internal ulong Sequence=>BinaryPrimitives.ReadUInt64LittleEndian(Header.AsSpan(60));
        internal byte[] Digests=>WrapperHash.Concat(HeaderHash).Concat(ArchiveHash).ToArray();
    }
    // This independently authenticates all active objects. Open and VerifyPortable include AllBlobs.
    private static Snapshot Inspect(string path,Operation op,byte[] original,byte[] recovery,Dictionary<string,byte[]> immutable,CancellationToken token)
    {
        if(op==Operation.Verify)
        {
            using var pinned=new FileStream(path+".snbak",FileMode.Open,FileAccess.Read,FileShare.Read);
            var raw=QualificationStore.VerifyPortable(path+".snbak",CredentialKind.Recovery,OldRecovery(),GenerationFixture.Policy(),token);
            var archive=new BackupArchive(pinned,token);Require(archive.Header.AsSpan().SequenceEqual(original));
            pinned.Position=0;Require(Convert.ToHexStringLower(SHA256.HashData(pinned))==raw);
            pinned.Position=0;return new(archive.Header,new byte[32],Wire.Digest(2,archive.Header),Wire.ArchiveDigest(pinned,token).GetAwaiter().GetResult(),new byte[32].Concat(SHA256.HashData(archive.Header)).Concat(Convert.FromHexString(raw)).ToArray());
        }
        var target=Target(path,op);var password=op is Operation.Password or Operation.Recover?NewPassword():GenerationFixture.Password.ToArray();
        try
        {
            byte[] header,wrapper;
            using(var store=QualificationStore.Open(target,CredentialKind.Password,password,GenerationFixture.Policy(),token))
            {
                header=store.Header;wrapper=File.ReadAllBytes(Path.Combine(target,"vault.json"));
                Require(VaultFormat.DecodeWrapper(wrapper).AsSpan().SequenceEqual(header));
                Require(store.ItemIds.Count()==1);
                var manifest=store.ReadManifest(CredentialKind.Recovery,recovery,token);
                Require(manifest.Items.Length==1 && manifest.Blobs.Length==1);
                foreach(var reference in manifest.Items.Concat(manifest.Blobs))
                {
                    var isBlob=manifest.Blobs.Any(b=>b.WriteId==reference.WriteId);
                    var source=Path.Combine(path,isBlob?"blobs":"items",reference.WriteId+(isBlob?".blob":".item"));
                    Require(immutable.TryGetValue(source,out var expectedHash) && reference.Sha256==Convert.ToHexStringLower(expectedHash));
                }
                foreach(var retained in Directory.GetFiles(Path.Combine(target,".backup"),"*.json"))
                    store.VerifyBackup(Path.GetFileNameWithoutExtension(retained),CredentialKind.Recovery,OldRecovery(),token);
            }
            using(var reopened=QualificationStore.Open(target,CredentialKind.Recovery,recovery,GenerationFixture.Policy(),token))
                Require(reopened.Header.AsSpan().SequenceEqual(header));
            var before=BinaryPrimitives.ReadUInt64LittleEndian(original.AsSpan(60));
            Require(BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(60))==before+(Changes(op)?1ul:0ul));
            Require(header.AsSpan(12,32).SequenceEqual(original.AsSpan(12,32)));
            if(Changes(op))
            {
                Require(!header.AsSpan(44,16).SequenceEqual(original.AsSpan(44,16)));
                Require(header.AsSpan(68,32).SequenceEqual(SHA256.HashData(original)));
                var unchanged=op==Operation.Rotate?166:274;
                Require(header.AsSpan(unchanged,108).SequenceEqual(original.AsSpan(unchanged,108)));
            }
            else Require(header.AsSpan().SequenceEqual(original));
            using(var oldKey=KeySlots.OpenRecovery(original,OldRecovery(),token))
            using(var newKey=KeySlots.OpenRecovery(header,recovery,token)) Require(CryptographicOperations.FixedTimeEquals(oldKey.Span,newKey.Span));
            byte[] archiveHash=new byte[32];byte[] rawArchiveHash=new byte[32];
            if(op is Operation.Backup or Operation.Verify or Operation.Restore)
            {
                // Pin exact archive bytes against writes/replacement throughout verification and hashing.
                using var stream=new FileStream(path+".snbak",FileMode.Open,FileAccess.Read,FileShare.Read);
                var rawHash=QualificationStore.VerifyPortable(path+".snbak",CredentialKind.Recovery,OldRecovery(),GenerationFixture.Policy(),token);
                rawArchiveHash=Convert.FromHexString(rawHash);
                var archive=new BackupArchive(stream,token);Require(archive.Header.AsSpan().SequenceEqual(original));
                stream.Position=0;Require(Convert.ToHexStringLower(SHA256.HashData(stream))==rawHash);
                stream.Position=0;archiveHash=Wire.ArchiveDigest(stream,token).GetAwaiter().GetResult();
            }
            return new(header,Wire.Digest(1,wrapper),Wire.Digest(2,header),archiveHash,SHA256.HashData(wrapper).Concat(SHA256.HashData(header)).Concat(rawArchiveHash).ToArray());
        }
        finally {CryptographicOperations.ZeroMemory(password);}
    }
    private sealed class Interaction(GuestBridge? bridge,string scenario):IVaultInteraction,IDisposable
    {
        internal byte[] Recovery=OldRecovery();
        public bool IsInteractive=>true;
        public byte[] ReadSecret(SecretPrompt prompt,int maximumBytes,CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            return prompt switch
            {
                SecretPrompt.Password=>GenerationFixture.Password.ToArray(),
                SecretPrompt.NewPassword=>NewPassword(),
                SecretPrompt.ConfirmPassword=>scenario=="confirmation"?"wrong synthetic confirmation"u8.ToArray():NewPassword(),
                SecretPrompt.Recovery=>Encoding.UTF8.GetBytes(RecoveryCode.Encode(Recovery)),
                SecretPrompt.ConfirmRecovery=>scenario=="confirmation"?"wrong synthetic confirmation"u8.ToArray():Encoding.UTF8.GetBytes(RecoveryCode.Encode(Recovery)),
                _=>throw new InvalidOperationException("Unexpected qualification prompt.")
            };
        }
        public void DisplayRecovery(string code,string vaultId)
        {
            using var decoded=RecoveryCode.Decode(code.AsSpan());CryptographicOperations.ZeroMemory(Recovery);Recovery=decoded.Span.ToArray();
            bridge?.Recovery(Recovery).GetAwaiter().GetResult();
        }
        public bool ConfirmRemoval(string id,CancellationToken token)=>false;
        public void Dispose()=>CryptographicOperations.ZeroMemory(Recovery);
    }
    private sealed class Hooks(GuestBridge bridge,Stream stream,string scenario,CancellationToken token):IStoreFaults
    {
        private readonly Dictionary<Boundary,uint> occurrences=[];
        internal ulong EventCount { get; private set; }
        public void At(CommitStep step)
        {
            Boundary? mapped=step switch {CommitStep.Authenticated=>Boundary.Authenticated,CommitStep.BeforePublish=>Boundary.BeforePublish,CommitStep.AfterPublish=>Boundary.AfterPublish,_=>null};
            if(mapped is not { } boundary) return;
            occurrences.TryGetValue(boundary,out var count);occurrences[boundary]=++count;EventCount++;
            bridge.Event(boundary,count).GetAwaiter().GetResult();
            if(scenario is "lost-host" or "host-crash" && boundary==Boundary.Authenticated)
            {
                // Loss test only: the host closes this pipe instead of granting continuation.
                Wire.Read(stream,token).GetAwaiter().GetResult();throw new IOException("Lost observer.");
            }
            if((scenario=="pre" && boundary==Boundary.BeforePublish) || (scenario=="post" && boundary==Boundary.AfterPublish))
                Task.Delay(Timeout.Infinite,token).GetAwaiter().GetResult();
            if(scenario=="indeterminate" && boundary==Boundary.AfterPublish) throw new IOException("Injected publication uncertainty.");
        }
    }
    internal static async Task Guest(string[] args)
    {
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(50));
        try
        {
            var path=Path.GetFullPath(args[0]);var op=Enum.Parse<Operation>(args[2]);var run=Guid.ParseExact(args[4],"N");var scenario=args[5];
            using var pipe=new NamedPipeClientStream(".",args[3],PipeDirection.InOut,PipeOptions.Asynchronous|PipeOptions.CurrentUserOnly);
            await pipe.ConnectAsync(deadline.Token);var bridge=new GuestBridge(pipe,run,op,deadline.Token);
            byte[] original;
            if(op==Operation.Verify) {using var archive=File.OpenRead(path+".snbak");original=new BackupArchive(archive,deadline.Token).Header;}
            else original=VaultFormat.DecodeWrapper(File.ReadAllBytes(Path.Combine(path,"vault.json")));
            var immutable=op==Operation.Verify?new Dictionary<string,byte[]>():Directory.GetFiles(Path.Combine(path,"items")).Concat(Directory.GetFiles(Path.Combine(path,"blobs"))).ToDictionary(f=>f,SHA256File);
            using var ui=new Interaction(bridge,scenario);var hooks=new Hooks(bridge,pipe,scenario,deadline.Token);
            var app=VaultApplication.ForQualification(ui,GenerationFixture.Policy(),hooks);
            await bridge.Event(Boundary.Start);
            switch(op)
            {
                case Operation.Password:app.ChangePassword(path,deadline.Token);break;
                case Operation.Recover:app.Recover(path,deadline.Token);break;
                case Operation.Rotate:app.RotateRecovery(path,deadline.Token);break;
                case Operation.Backup:app.Backup(path,path+".snbak",token:deadline.Token);break;
                case Operation.Verify:app.VerifyBackup(path+".snbak",token:deadline.Token);break;
                case Operation.Restore:app.Restore(path+".snbak",path+"-restored",token:deadline.Token);break;
                default:throw new InvalidOperationException();
            }
            if(scenario=="corrupt-after") CorruptBlob(Target(path,op));
            var state=Inspect(path,op,original,op==Operation.Rotate?ui.Recovery:OldRecovery(),immutable,deadline.Token);
            foreach(var pair in immutable) Require(SHA256File(pair.Key).AsSpan().SequenceEqual(pair.Value));
            await bridge.Event(Boundary.Verified);
            if(scenario=="hash") state.WrapperHash[0]^=1;
            await bridge.Acknowledge(state.Sequence,state.WrapperHash,state.HeaderHash,state.ArchiveHash);
            if(scenario=="duplicate") await Wire.Write(pipe,new Frame {Run=run,Operation=op,Sequence=3+hooks.EventCount+(op==Operation.Rotate?1ul:0ul),Boundary=Boundary.Ack,Generation=state.Sequence,Digests=state.Digests},deadline.Token);
            else await bridge.Event(Boundary.End);
            Console.WriteLine("RECEIPT");Console.Out.Flush();await Task.Delay(Timeout.Infinite,deadline.Token);
        }
        catch(VaultOperationException e) when(e.Error==VaultApplicationError.Indeterminate) {Console.WriteLine("INDETERMINATE");Environment.ExitCode=2;}
        catch {Console.WriteLine("REFUSED");Environment.ExitCode=2;}
    }
    private static void CorruptBlob(string path)
    {
        var file=Directory.GetFiles(Path.Combine(path,"blobs"),"*.blob").Single();
        using var stream=new FileStream(file,FileMode.Open,FileAccess.ReadWrite,FileShare.None);
        stream.Position=stream.Length-1;var value=stream.ReadByte();stream.Position--;stream.WriteByte((byte)(value^1));stream.Flush(true);
    }
    private sealed class FaultEvidence(string path,bool failFlush):IEvidence
    {
        private readonly Evidence inner=new(path);
        public void Append(Frame f)=>inner.Append(f);
        public void Flush() {if(failFlush) throw new IOException("Injected evidence flush failure.");inner.Flush();}
        public void Dispose()=>inner.Dispose();
    }
    internal static async Task Run(string[] args)
    {
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(70));
        var nextRecovery=new byte[32];Process? child=null;
        try
        {
            var path=Path.GetFullPath(args[0]);var op=Enum.Parse<Operation>(args[2]);var scenario=args[3];
            Require(!Directory.Exists(path));Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            using var fixture=new GenerationFixture();OldRecovery().CopyTo(fixture.Recovery.Span);
            using(var store=QualificationStore.Create(path,fixture.Initial(),GenerationFixture.Password,fixture.Recovery.Span,()=>fixture.Recovery.Span.ToArray(),GenerationFixture.Policy(),new NoStoreFaults(),deadline.Token))
                Require(store.Commit(fixture.Next(store.Header,includeBlob:true,blobBytes:"synthetic private blob sentinel - never in evidence"u8.ToArray()),CredentialKind.Password,GenerationFixture.Password,[],null,new NoStoreFaults(),deadline.Token).Outcome==CommitOutcome.Committed);
            using(var ui=new Interaction(null,"success"))
                if(op is Operation.Verify or Operation.Restore) VaultApplication.ForQualification(ui,GenerationFixture.Policy()).Backup(path,path+".snbak",token:deadline.Token);
            var original=VaultFormat.DecodeWrapper(File.ReadAllBytes(Path.Combine(path,"vault.json")));
            var immutable=Directory.GetFiles(Path.Combine(path,"items")).Concat(Directory.GetFiles(Path.Combine(path,"blobs"))).ToDictionary(f=>f,SHA256File);
            if(scenario=="corrupt")
            {
                if(op is Operation.Verify or Operation.Restore)
                {
                    using var stream=new FileStream(path+".snbak",FileMode.Open,FileAccess.ReadWrite,FileShare.None);
                    var archive=new BackupArchive(stream,deadline.Token);var blob=archive.Entries.Single(e=>e.Key.Kind==2).Value;
                    stream.Position=blob.Offset+blob.Length-1;var b=stream.ReadByte();stream.Position--;stream.WriteByte((byte)(b^1));stream.Flush(true);
                }
                else CorruptBlob(path);
            }
            var run=Guid.NewGuid();var name="safenook-real-oracle-"+run.ToString("N");
            using var pipe=new NamedPipeServerStream(name,PipeDirection.InOut,1,PipeTransmissionMode.Byte,PipeOptions.Asynchronous|PipeOptions.CurrentUserOnly);
            var evidenceDirectory=path+".oracle";Require(!Directory.Exists(evidenceDirectory));
            var sid=WindowsIdentity.GetCurrent().User!;var acl=new DirectorySecurity();acl.SetOwner(sid);acl.SetAccessRuleProtection(true,false);
            acl.AddAccessRule(new FileSystemAccessRule(sid,FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
            new DirectoryInfo(evidenceDirectory).Create(acl);
            var evidencePath=Path.Combine(evidenceDirectory,"events.bin");
            using var evidence=new FaultEvidence(evidencePath,scenario=="flush");
            using var observer=new Observer(run,op,evidence);
            var info=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
            foreach(var arg in new[]{path,"oracle-guest",op.ToString(),name,run.ToString("N"),scenario}) info.ArgumentList.Add(arg);
            child=Process.Start(info)!;await pipe.WaitForConnectionAsync(deadline.Token);
            Frame? ack=null;bool stopped=false;bool receivedKey=false;bool rejected=false;
            try
            {
                while(!observer.Complete)
                {
                    var frame=await Wire.Read(pipe,deadline.Token);
                    if(frame.Kind==FrameKind.Event && frame.Boundary==Boundary.Ack)
                    {
                        var expected=Inspect(path,op,original,op==Operation.Rotate?nextRecovery:OldRecovery(),immutable,deadline.Token);
                        Require(frame.Generation==expected.Sequence && frame.Digests.AsSpan().SequenceEqual(expected.Digests));
                        foreach(var pair in immutable) Require(SHA256File(pair.Key).AsSpan().SequenceEqual(pair.Value));
                        if(ack is null)
                        {
                            using var hashes=new FileStream(Path.Combine(evidenceDirectory,"raw-sha256.bin"),FileMode.CreateNew,FileAccess.Write,FileShare.Read);
                            hashes.Write(expected.RawDigests);hashes.Flush(true);
                        }
                    }
                    observer.Accept(frame);
                    if(frame.Kind==FrameKind.RecoveryKey) {observer.CopyRecovery(nextRecovery);receivedKey=true;}
                    if(scenario=="host-crash" && frame.Boundary==Boundary.Authenticated)
                    {
                        Console.WriteLine("HOST-CRASH "+child.Id);Console.Out.Flush();
                        await Task.Delay(Timeout.Infinite,deadline.Token);
                    }
                    if(scenario=="lost-host" && frame.Boundary==Boundary.Authenticated) {pipe.Dispose();observer.Abort();rejected=true;break;}
                    if((scenario=="pre" && frame.Boundary==Boundary.BeforePublish) || (scenario=="post" && frame.Boundary==Boundary.AfterPublish)) {stopped=true;break;}
                    if(frame.Kind==FrameKind.Event && frame.Boundary==Boundary.Ack)
                    {
                        Require(observer.AckDurable);ack=frame;
                        await Wire.Write(pipe,new Frame {Run=run,Sequence=frame.Sequence,Operation=op,Boundary=Boundary.Ack,Kind=FrameKind.Receipt},deadline.Token);
                    }
                }
            }
            catch(Exception e) when(e is IOException or InvalidDataException) {rejected=true;pipe.Dispose();}
            if(scenario=="success")
            {
                Require(observer.Complete && ack is not null && observer.AckDurable);
                Require(await child.StandardOutput.ReadLineAsync(deadline.Token)=="RECEIPT");
            }
            else if(scenario is "pre" or "post") Require(stopped && ack is null);
            else Require(rejected);
            if(scenario is "confirmation" or "indeterminate" or "corrupt" or "corrupt-after" or "lost-host")
            {
                Require(await child.StandardOutput.ReadLineAsync(deadline.Token)==(scenario=="indeterminate"?"INDETERMINATE":"REFUSED"));
                await child.WaitForExitAsync(deadline.Token);Require(child.ExitCode==2);
            }
            if(!child.HasExited) {child.Kill(true);await child.WaitForExitAsync(deadline.Token);}
            Require(child.ExitCode!=0);Require(await child.StandardError.ReadToEndAsync(deadline.Token)=="");
            var published=scenario is "success" or "post" or "indeterminate" or "hash" or "flush" or "duplicate" or "corrupt-after";
            if(scenario is not ("corrupt" or "corrupt-after"))
            {
                if(published)
                {
                    var state=Inspect(path,op,original,op==Operation.Rotate?nextRecovery:OldRecovery(),immutable,deadline.Token);
                    if(ack is not null)
                    {
                        Require(ack.Digests.AsSpan().SequenceEqual(state.Digests));
                        Require(File.ReadAllBytes(Path.Combine(evidenceDirectory,"raw-sha256.bin")).AsSpan().SequenceEqual(state.RawDigests));
                    }
                }
                else
                {
                    using var old=QualificationStore.Open(path,CredentialKind.Password,GenerationFixture.Password,GenerationFixture.Policy(),deadline.Token);
                    Require(old.Header.AsSpan().SequenceEqual(original));
                    using var key=KeySlots.OpenRecovery(old.Header,OldRecovery(),deadline.Token);
                }
                foreach(var pair in immutable)
                {
                    Require(SHA256File(pair.Key).AsSpan().SequenceEqual(pair.Value));
                    if(op==Operation.Restore && published) Require(SHA256File(Path.Combine(Target(path,op),Path.GetRelativePath(path,pair.Key))).AsSpan().SequenceEqual(pair.Value));
                }
                if(op==Operation.Restore && !published) Require(!File.Exists(Path.Combine(Target(path,op),"vault.json")));
                if(op==Operation.Backup && !published) Require(!File.Exists(path+".snbak"));
            }
            else Require(ack is null);
            // Persisted evidence contains event records only. Never scan or erase unknown files.
            evidence.Dispose();var logged=File.ReadAllBytes(evidencePath);
            Require(logged.AsSpan().IndexOf(GenerationFixture.Password)<0);
            Require(logged.AsSpan().IndexOf("synthetic private blob sentinel - never in evidence"u8)<0);
            Require(logged.AsSpan().IndexOf(OldRecovery())<0);
            if(receivedKey) Require(logged.AsSpan().IndexOf(nextRecovery)<0);
            var persistedAcks=new List<Frame>();
            for(var offset=0;offset<logged.Length;offset+=Frame.Size)
            {
                var recorded=Frame.Decode(logged.AsSpan(offset,Frame.Size).ToArray());Require(recorded.Kind==FrameKind.Event && recorded.Run==run && recorded.Operation==op);
                if(recorded.Boundary==Boundary.Ack) persistedAcks.Add(recorded);
            }
            if(scenario is "success" or "duplicate")
            {
                Require(persistedAcks.Count==1 && ack is not null);
                Require(persistedAcks[0].Generation==ack!.Generation && persistedAcks[0].Digests.AsSpan().SequenceEqual(ack.Digests));
            }
            if(scenario is "pre" or "post" or "confirmation" or "indeterminate" or "corrupt" or "corrupt-after" or "hash" or "lost-host") Require(persistedAcks.Count==0);
            Require(!StorageSupport.ProductionWritesSupported);
            Console.WriteLine("PASS: real vault oracle "+op+" "+scenario);
        }
        catch {Console.Error.WriteLine("Real vault oracle qualification failed.");Environment.ExitCode=2;}
        finally
        {
            if(child is not null) {if(!child.HasExited) {child.Kill(true);child.WaitForExit();}child.Dispose();}
            CryptographicOperations.ZeroMemory(nextRecovery);
        }
    }
    private static byte[] SHA256File(string path) {using var stream=File.OpenRead(path);return SHA256.HashData(stream);}
}
