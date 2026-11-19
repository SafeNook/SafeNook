using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace SafeNook.Storage;

internal sealed unsafe partial class WindowsFileSystem
{
    internal byte[] ImportBytes(string name,int limit,CancellationToken token)
    {
        using var handle=OpenRelative(_directories[""],name,false,1,share:1,securityCheck:false);
        var length=RandomAccess.GetLength(handle);
        if(length<0 || length>limit) throw new IOException("Input limit exceeded.");
        var bytes=new byte[(int)length];
        try
        {
            var offset=0;
            while(offset<bytes.Length) {token.ThrowIfCancellationRequested();var n=RandomAccess.Read(handle,bytes.AsSpan(offset),offset);if(n==0) throw new IOException();offset+=n;}
            if(RandomAccess.GetLength(handle)!=length) throw new IOException();
            Validate(handle,false,false);token.ThrowIfCancellationRequested();return bytes;
        }
        catch {CryptographicOperations.ZeroMemory(bytes);throw;}
    }
    internal void ExportBytes(string name,ReadOnlySpan<byte> bytes,IStoreFaults faults,CancellationToken token)
    {
        Component(name);
        // Destination directory itself must have the same exact private ACL as the file.
        Validate(_directories[""],true);
        var staging=Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16))+".sn-export";
        using var handle=OpenRelative(_directories[""],staging,false,2,true,true,0);
        var attempted=false;
        try
        {
            token.ThrowIfCancellationRequested();var count=faults.WriteLength(bytes.Length);
            if(count<0 || count>bytes.Length) throw new IOException();
            RandomAccess.Write(handle,bytes[..count],0);faults.At(CommitStep.ObjectWritten);
            if(count!=bytes.Length) throw new IOException();
            faults.BeforeFlush(false);if(!WindowsNative.FlushFileBuffers(handle)) NativeFail("export-flush");
            faults.At(CommitStep.BeforeReadback);
            var check=new byte[bytes.Length];
            try
            {
                var offset=0;while(offset<check.Length) {token.ThrowIfCancellationRequested();var n=RandomAccess.Read(handle,check.AsSpan(offset),offset);if(n==0) throw new IOException();offset+=n;}
                if(RandomAccess.GetLength(handle)!=bytes.Length || !check.AsSpan().SequenceEqual(bytes)) throw new IOException();
            }
            finally {CryptographicOperations.ZeroMemory(check);}
            Validate(handle,false);token.ThrowIfCancellationRequested();faults.At(CommitStep.BeforePublish);
            faults.At(CommitStep.BeforeRename);token.ThrowIfCancellationRequested();attempted=true;
            Rename(handle,_directories[""],name,false);faults.At(CommitStep.AfterPublish);
            FlushDirectory("",faults);Validate(handle,false);
        }
        catch
        {
            if(attempted) throw new StoreException(CommitOutcome.Indeterminate,"export-publication");
            // Delete by the exclusively held file handle, never by a potentially substituted path.
            byte delete=1;
            if(WindowsNative.NtSetInformationFile(handle,out _,(nint)(&delete),1,13)<0)
                throw new StoreException(CommitOutcome.RejectedBeforePublication,"export-private-staging-retained");
            throw;
        }
    }
}
