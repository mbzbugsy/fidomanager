using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace WindowsBrokerSpike;

internal sealed record TokenIdentity(string Sid, string LogonSid, string Logon, uint Session, bool Elevated, uint Integrity);

[SupportedOSPlatform("windows")]
internal sealed class Peer : IDisposable
{
    internal SafeFileHandle Handle { get; }
    internal uint Pid { get; }
    internal long Created { get; }
    internal TokenIdentity Identity { get; }
    internal string Image { get; }
    internal bool Alive => Native.WaitForSingleObject(Handle, 0) == 258;

    internal Peer(uint pid) : this(Native.Handle(Native.OpenProcess(0x100000 | 0x1000, false, pid))) { }
    internal Peer(SafeFileHandle handle)
    {
        Handle = handle;
        try
        {
            Pid = Native.GetProcessId(handle);
            Native.Check(Native.GetProcessTimes(handle, out long created, out _, out _, out _)); Created = created;
            Native.Check(Native.OpenProcessToken(handle, 8, out SafeFileHandle token));
            using (token) Identity = ReadToken(token);
            StringBuilder path = new(32768); uint length = (uint)path.Capacity;
            Native.Check(Native.QueryFullProcessImageNameW(handle, 0, path, ref length)); Image = path.ToString();
            if (!Alive) throw new InvalidOperationException("process already exited");
        }
        catch { handle.Dispose(); throw; }
    }

    private static T Info<T>(SafeFileHandle token, int kind, Func<nint, T> read)
    {
        Native.GetTokenInformation(token, kind, 0, 0, out uint needed);
        if (needed is 0 or > 65536) throw new InvalidDataException("token buffer bound");
        nint buffer = Marshal.AllocHGlobal((int)needed);
        try { Native.Check(Native.GetTokenInformation(token, kind, buffer, needed, out _)); return read(buffer); }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    internal static TokenIdentity ReadToken(SafeFileHandle token)
    {
        string sid = Info(token, 1, p => new SecurityIdentifier(Marshal.ReadIntPtr(p)).Value);
        string logonSid = Info(token, 2, p =>
        {
            int count = Marshal.ReadInt32(p), start = IntPtr.Size == 8 ? 8 : 4, stride = IntPtr.Size == 8 ? 16 : 8;
            for (int i = 0; i < count; i++)
            {
                nint group = p + start + i * stride;
                if (((uint)Marshal.ReadInt32(group, IntPtr.Size) & 0xc0000000) == 0xc0000000)
                    return new SecurityIdentifier(Marshal.ReadIntPtr(group)).Value;
            }
            throw new InvalidDataException("no logon SID");
        });
        string logon = Info(token, 10, p => Marshal.PtrToStructure<Native.TokenStatistics>(p).AuthenticationId.ToString());
        uint session = Info(token, 12, p => (uint)Marshal.ReadInt32(p));
        bool elevated = Info(token, 20, p => Marshal.ReadInt32(p) != 0);
        uint integrity = Info(token, 25, p =>
        {
            nint label = Marshal.ReadIntPtr(p);
            byte count = Marshal.ReadByte(Native.GetSidSubAuthorityCount(label));
            if (count == 0) throw new InvalidDataException("integrity SID");
            return (uint)Marshal.ReadInt32(Native.GetSidSubAuthority(label, (uint)count - 1));
        });
        return new(sid, logonSid, logon, session, elevated, integrity);
    }

    internal static void SameSession(TokenIdentity one, TokenIdentity two)
        => IdentityRules.SameSession(one, two);
    internal object Evidence() => new { Pid, Created, Identity, Image };
    public void Dispose() => Handle.Dispose();
}
