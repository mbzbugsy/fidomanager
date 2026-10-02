using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace WindowsBrokerSpike;

[SupportedOSPlatform("windows")]
internal static class PipeEndpoint
{
    internal static string Name(TokenIdentity identity) => "FidoManager-M15-" +
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"{identity.Sid}/{identity.LogonSid}/{identity.Logon}/{identity.Session}")))[..32];

    internal static NamedPipeServerStream Create(TokenIdentity owner)
    {
        // Individual rights omit FILE_CREATE_PIPE_INSTANCE (4). Medium mandatory label admits the
        // medium client. User SID is not sufficient: the retained process + token check follows.
        string sddl = $"D:P(A;;GA;;;SY)(A;;0x00120003;;;{owner.Sid})S:(ML;;NW;;;ME)";
        Native.Check(Native.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, out nint sd, out _));
        SafePipeHandle? handle = null;
        try
        {
            Native.SecurityAttributes attributes = new() { Length = (uint)Marshal.SizeOf<Native.SecurityAttributes>(), Descriptor = sd };
            handle = Native.CreateNamedPipeW(@"\\.\pipe\" + Name(owner), 3 | 0x00080000 | 0x40000000,
                0x8, 1, Wire.Limit, Wire.Limit, 1000, ref attributes); // FIRST_INSTANCE, OVERLAPPED, REJECT_REMOTE
            if (handle.IsInvalid) throw new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError());
            string actual = Descriptor(handle);
            RawSecurityDescriptor parsed = new(actual);
            if (parsed.DiscretionaryAcl is not { Count: 2 }) throw new InvalidDataException("unexpected DACL");
            foreach (GenericAce ace in parsed.DiscretionaryAcl)
            {
                if (ace is not CommonAce a || a.AceQualifier != AceQualifier.AccessAllowed || a.AceFlags != AceFlags.None
                    || !((a.SecurityIdentifier.Value == owner.Sid && a.AccessMask == 0x120003)
                         || (a.SecurityIdentifier.Value == "S-1-5-18" && a.AccessMask is 0x10000000 or 0x1f01ff)))
                    throw new InvalidDataException("unexpected pipe principal/rights");
            }
            Program.Log("IPC", new { RequestedSddl = sddl, EffectiveSddl = actual, Pipe = Name(owner) });
            return new NamedPipeServerStream(PipeDirection.InOut, true, false, handle);
        }
        catch { handle?.Dispose(); throw; }
        finally { Native.LocalFree(sd); }
    }

    private static string Descriptor(SafePipeHandle handle)
    {
        const uint information = 1 | 2 | 4 | 0x10; // owner/group/DACL/mandatory label, not arbitrary audit SACL
        Native.GetKernelObjectSecurity(handle, information, 0, 0, out uint size);
        if (size is 0 or > 65536) throw new InvalidDataException("SD size");
        nint buffer = Marshal.AllocHGlobal((int)size);
        try
        {
            Native.Check(Native.GetKernelObjectSecurity(handle, information, buffer, size, out _));
            Native.Check(Native.ConvertSecurityDescriptorToStringSecurityDescriptorW(buffer, 1, information, out nint text, out _));
            try { return Marshal.PtrToStringUni(text) ?? throw new InvalidDataException("SD text"); }
            finally { Native.LocalFree(text); }
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    internal static NamedPipeClientStream Connect(TokenIdentity identity)
    {
        string name = @"\\.\pipe\" + Name(identity);
        System.Diagnostics.Stopwatch elapsed = System.Diagnostics.Stopwatch.StartNew();
        do
        {
            // Identification SQOS, non-inheritable, exact rights (no GENERIC_WRITE).
            SafePipeHandle handle = Native.CreateFileW(name, 0x120003, 0, 0, 3, 0x40000000 | 0x00100000 | 0x00010000, 0);
            if (!handle.IsInvalid) return new NamedPipeClientStream(PipeDirection.InOut, true, true, handle);
            int error = Marshal.GetLastPInvokeError(); handle.Dispose();
            if (error is not (2 or 231)) throw new System.ComponentModel.Win32Exception(error);
            Native.WaitNamedPipeW(name, 100);
            Thread.Sleep(50);
        } while (elapsed.Elapsed < TimeSpan.FromSeconds(10));
        throw new TimeoutException("broker connection");
    }
}
