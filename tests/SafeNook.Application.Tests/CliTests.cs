using System.Text;
using SafeNook.Application;
using SafeNook.Cli;
using SafeNook.ApplicationTestData;
using SafeNook.Cli.Commands;

namespace SafeNook.Application.Tests;

public sealed class CliTests
{
    [Theory]
    [InlineData("init")] [InlineData("add")] [InlineData("rm")] [InlineData("passwd")] [InlineData("recover")] [InlineData("recovery")]
    public void ProductionWritesRefuseBeforeAnyInteraction(string command)
    {
        var args=new List<string>{command,"--vault",Path.GetFullPath("nonexistent-test-vault")};
        if(command=="recovery") args.Insert(1,"rotate");
        if(command=="add") args.AddRange(["--type","login"]);
        if(command=="rm") args.Add(new string('a',32));
        using var output=new StringWriter();using var error=new StringWriter();
        var result=Program.Run(args.ToArray(),new VaultApplication(new NoInteraction()),output,error,TestContext.Current.CancellationToken);
        Assert.Equal(5,result);Assert.Equal("",output.ToString());Assert.Contains("disabled",error.ToString());
    }
    [Theory]
    [InlineData("")] [InlineData("init")] [InlineData("ls")] [InlineData("show")] [InlineData("add")] [InlineData("rm")]
    public void HelpNeverRequestsCredentials(string name)
    {
        using var output=new StringWriter(); using var error=new StringWriter();
        var result=Program.Run(name.Length==0?["--help"]:[name,"--help"],new VaultApplication(new NoInteraction()),output,error,TestContext.Current.CancellationToken);
        Assert.Equal(0,result);Assert.NotEmpty(output.ToString());Assert.Equal("",error.ToString());
    }
    [Theory]
    [InlineData("--password")] [InlineData("--recovery-key")] [InlineData("--unsafe")] [InlineData("--force-write")] [InlineData("--qualification")]
    public void ForbiddenArgumentsAreNotEchoed(string option)
    {
        using var output=new StringWriter(); using var error=new StringWriter();
        var result=Program.Run(["init","--vault","private-path",option,"NEVER_ECHO_SECRET"],new VaultApplication(new NoInteraction()),output,error,TestContext.Current.CancellationToken);
        Assert.Equal(1,result);Assert.DoesNotContain("NEVER_ECHO_SECRET",output+error.ToString());Assert.DoesNotContain("private-path",error.ToString());
    }
    [Fact]
    public void MissingAndExtraArgumentsAreSafe()
    {
        using var output=new StringWriter();using var error=new StringWriter();
        Assert.Equal(1,Program.Run(["show","secret-extra"],new VaultApplication(new NoInteraction()),output,error,TestContext.Current.CancellationToken));
        Assert.DoesNotContain("secret-extra",error.ToString());
    }
    [Fact]
    public void NoninteractiveReadsRefuseWithoutReadingCredentials()
    {
        var input=new SyntheticInteraction {IsInteractive=false}; using var output=new StringWriter();using var error=new StringWriter();
        Assert.Equal(6,Program.Run(["ls","--vault",Path.GetFullPath("unused")],new VaultApplication(input),output,error,TestContext.Current.CancellationToken));Assert.Equal(0,input.Reads);
    }
    [Fact]
    public void TerminalInputIsInterceptedAndNeverEchoed()
    {
        var terminal=new Terminal([Key('a'),Key('b'),new('\b',ConsoleKey.Backspace,false,false,false),Key('ç'),new('\r',ConsoleKey.Enter,false,false,false)]);
        var input=new ConsoleVaultInteraction(terminal); var bytes=input.ReadSecret(SecretPrompt.Password,1024,TestContext.Current.CancellationToken);
        Assert.Equal("aç",Encoding.UTF8.GetString(bytes));Assert.All(terminal.Intercepts,Assert.True);Assert.Equal("Password: \n",terminal.Output.ToString());
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes);
    }
    [Fact]
    public void TerminalCancelAndLimitDoNotEchoInput()
    {
        var cancelled=new Terminal([Key('s'),new('\0',ConsoleKey.Escape,false,false,false)]);
        Assert.Throws<OperationCanceledException>(()=>new ConsoleVaultInteraction(cancelled).ReadSecret(SecretPrompt.Password,10,TestContext.Current.CancellationToken));
        Assert.Equal("Password: \n",cancelled.Output.ToString());
        var bounded=new Terminal([Key('x'),Key('y')]);
        Assert.Throws<VaultOperationException>(()=>new ConsoleVaultInteraction(bounded).ReadSecret(SecretPrompt.Password,1,TestContext.Current.CancellationToken));
        Assert.DoesNotContain("xy",bounded.Output.ToString());
    }
    [Fact]
    public void MetadataEscapesTerminalControls()
    { Assert.Equal("title\\u001B[2J\\u000A\\u202E",VaultCommands.Escape("title\u001b[2J\n\u202e")); }
    private static ConsoleKeyInfo Key(char value)=>new(value,ConsoleKey.A,false,false,false);
    private sealed class NoInteraction:IVaultInteraction
    {
        public bool IsInteractive=>throw new InvalidOperationException("Interaction forbidden");
        public byte[] ReadSecret(SecretPrompt prompt,int maximumBytes,CancellationToken token)=>throw new InvalidOperationException();
        public void DisplayRecovery(string code,string vaultId)=>throw new InvalidOperationException();
        public bool ConfirmRemoval(string id,CancellationToken token)=>throw new InvalidOperationException();
    }
    private sealed class Terminal(IEnumerable<ConsoleKeyInfo> keys):ISecretTerminal
    {
        private readonly Queue<ConsoleKeyInfo> _keys=new(keys);
        internal StringBuilder Output { get; }=new(); internal List<bool> Intercepts { get; }=[];
        public bool IsInteractive=>true;
        public ConsoleKeyInfo ReadKey(bool intercept,CancellationToken token) { Intercepts.Add(intercept);token.ThrowIfCancellationRequested();return _keys.Dequeue(); }
        public void Write(string text)=>Output.Append(text);
    }
}
