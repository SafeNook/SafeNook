using System.Diagnostics;
using SafeNook.DurabilityOracle;
using SafeNook.Core.Vault;
using SafeNook.Storage;
using SafeNook.StoreTestData;

namespace SafeNook.Application.Tests;

[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public sealed class OracleIntegrationTests
{
    public OracleIntegrationTests()=>Assert.SkipWhen(!OperatingSystem.IsWindows(),"Windows storage qualification only.");
    public static IEnumerable<object[]> Cases()
    {
        foreach(var op in Enum.GetValues<Operation>())
        {
            foreach(var scenario in new[]{"success","hash","flush","duplicate","corrupt"}) yield return [op,scenario];
            if(op!=Operation.Verify) foreach(var scenario in new[]{"pre","post","indeterminate","lost-host"}) yield return [op,scenario];
            if(op is Operation.Password or Operation.Recover or Operation.Rotate)
                foreach(var scenario in new[]{"confirmation","corrupt-after"}) yield return [op,scenario];
        }
    }
    [Theory]
    [InlineData("pre",false)] [InlineData("post",false)] [InlineData("ack",false)] [InlineData("ack",true)]
    public async Task VmSmokePauseAndRebootVerifier(string phase,bool corruptEvidence)
    {
        var root=new DirectoryInfo(AppContext.BaseDirectory);while(root is not null && !File.Exists(Path.Combine(root.FullName,"SafeNook.slnx"))) root=root.Parent;
        var executable=Path.Combine(root!.FullName,"spikes","ApplicationQualification","bin","Release","net10.0","ApplicationQualification.exe");
        var path=Path.Combine(root.FullName,"artifacts","sn-003q4-"+Guid.NewGuid().ToString("N"),"vault");
        Process Launch(params string[] arguments)
        {
            var info=new ProcessStartInfo(executable){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
            foreach(var argument in arguments) info.ArgumentList.Add(argument);return Process.Start(info)!;
        }
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(60));
        using var controller=Launch(path,"oracle","Password","vm-"+phase);
        string? baseline;
        try
        {
            baseline=await controller.StandardOutput.ReadLineAsync(deadline.Token);Assert.StartsWith("BASELINE-SHA256 ",baseline);
            Assert.StartsWith("VM-READY "+phase+" ",await controller.StandardOutput.ReadLineAsync(deadline.Token));
            Assert.False(controller.HasExited);controller.Kill(true);await controller.WaitForExitAsync(deadline.Token);
            Assert.Equal("",await controller.StandardError.ReadToEndAsync(deadline.Token));
        }
        finally {if(!controller.HasExited) {controller.Kill(true);controller.WaitForExit();}}
        if(corruptEvidence)
        {
            var evidence=Path.Combine(path+".oracle","raw-sha256.bin");var bytes=File.ReadAllBytes(evidence);bytes[0]^=1;File.WriteAllBytes(evidence,bytes);
        }
        using var verify=Launch(path,"vm-smoke-verify",phase);
        try
        {
            var output=verify.StandardOutput.ReadToEndAsync(deadline.Token);var error=verify.StandardError.ReadToEndAsync(deadline.Token);
            await verify.WaitForExitAsync(deadline.Token);
            Assert.Equal(corruptEvidence?2:0,verify.ExitCode);
            if(corruptEvidence) {Assert.DoesNotContain("PASS",await output);Assert.Contains("preserve evidence",await error);}
            else {Assert.Contains(baseline!,await output);Assert.Contains("PASS: guest-local VM smoke "+phase,await output);Assert.Equal("",await error);}
        }
        finally {if(!verify.HasExited) {verify.Kill(true);verify.WaitForExit();}}
    }
    [Fact]
    public async Task ActualHostKillLeavesOldGenerationAndGuestRefusesPublication()
    {
        var root=new DirectoryInfo(AppContext.BaseDirectory);while(root is not null && !File.Exists(Path.Combine(root.FullName,"SafeNook.slnx"))) root=root.Parent;
        var executable=Path.Combine(root!.FullName,"spikes","ApplicationQualification","bin","Release","net10.0","ApplicationQualification.exe");
        var path=Path.Combine(root.FullName,"artifacts","sn-003q3-host-loss-"+Guid.NewGuid().ToString("N"),"vault");
        var start=new ProcessStartInfo(executable){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
        foreach(var arg in new[]{path,"oracle","Password","host-crash"}) start.ArgumentList.Add(arg);
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(60));using var host=Process.Start(start)!;Process? guest=null;
        try
        {
            var marker=await host.StandardOutput.ReadLineAsync(deadline.Token);Assert.NotNull(marker);Assert.StartsWith("HOST-CRASH ",marker);
            guest=Process.GetProcessById(int.Parse(marker[11..]));
            host.Kill(false);await host.WaitForExitAsync(deadline.Token);await guest.WaitForExitAsync(deadline.Token);Assert.NotEqual(0,guest.ExitCode);
            using(var store=QualificationStore.Open(path,CredentialKind.Password,GenerationFixture.Password,GenerationFixture.Policy(),deadline.Token))
                Assert.Equal(2ul,System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(store.Header.AsSpan(60)));
            using var recovered=QualificationStore.Open(path,CredentialKind.Recovery,Enumerable.Range(128,32).Select(x=>(byte)x).ToArray(),GenerationFixture.Policy(),deadline.Token);
            Assert.Single(recovered.ItemIds);
        }
        finally
        {
            if(!host.HasExited) {host.Kill(true);host.WaitForExit();}
            if(guest is not null) {if(!guest.HasExited) {guest.Kill(true);guest.WaitForExit();}guest.Dispose();}
        }
    }
    [Theory] [MemberData(nameof(Cases))]
    public async Task RealVaultAcknowledgementSurvivesIndependentProcessKill(Operation operation,string scenario)
    {
        var root=new DirectoryInfo(AppContext.BaseDirectory);while(root is not null && !File.Exists(Path.Combine(root.FullName,"SafeNook.slnx"))) root=root.Parent;
        var executable=Path.Combine(root!.FullName,"spikes","ApplicationQualification","bin","Release","net10.0","ApplicationQualification.exe");
        var path=Path.Combine(root.FullName,"artifacts","sn-003q3-"+Guid.NewGuid().ToString("N"),"vault");
        var start=new ProcessStartInfo(executable){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
        foreach(var arg in new[]{path,"oracle",operation.ToString(),scenario}) start.ArgumentList.Add(arg);
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(80));using var host=Process.Start(start)!;
        try
        {
            var output=host.StandardOutput.ReadToEndAsync(deadline.Token);var error=host.StandardError.ReadToEndAsync(deadline.Token);
            await host.WaitForExitAsync(deadline.Token);
            Assert.Equal("",await error);Assert.Equal(0,host.ExitCode);
            Assert.Equal("PASS: real vault oracle "+operation+" "+scenario,(await output).Trim());
        }
        finally {if(!host.HasExited) {host.Kill(true);host.WaitForExit();}}
    }
}
