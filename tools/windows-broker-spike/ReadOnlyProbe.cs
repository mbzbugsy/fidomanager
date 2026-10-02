using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace WindowsBrokerSpike;

[SupportedOSPlatform("windows")]
internal static class ReadOnlyProbe
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate void Init(int flags);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate nint New();
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate nint InfoNew(nuint count);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate void Free(ref nint pointer);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate void InfoFree(ref nint pointer, nuint count);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int Manifest(nint list, nuint max, out nuint count);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate nint At(nint list, nuint index);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate nint Path(nint entry);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate short Id(nint entry);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int Open(nint device, nint path);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int Timeout(nint device, int milliseconds);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int Close(nint device);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int GetInfo(nint device, nint info);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)][return: MarshalAs(UnmanagedType.I1)] private delegate bool Flag(nint device);

    internal static WorkerReport Run()
    {
        // Fixed sibling path, never client input/PATH/current directory. Dependencies restricted to
        // the DLL directory + System32. Development directory trust is still an unresolved gate.
        string dll = System.IO.Path.Combine(AppContext.BaseDirectory, "libfido2", "fido2.dll");
        string hash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(dll)));
        nint library = Native.LoadLibraryExW(dll, 0, 0x100 | 0x800);
        if (library == 0) throw new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError());
        T Fn<T>(string name) where T : Delegate => Marshal.GetDelegateForFunctionPointer<T>(NativeLibrary.GetExport(library, name));
        nint list = 0;
        try
        {
            Fn<Init>("fido_init")(0);
            list = Fn<InfoNew>("fido_dev_info_new")(16);
            if (list == 0) throw new OutOfMemoryException();
            int manifest = Fn<Manifest>("fido_dev_info_manifest")(list, 16, out nuint count);
            if (count > 16) throw new InvalidDataException("native count bound");
            List<DeviceObservation> observations = new();
            // Eight opens maximum; outer process budget remains authoritative even if a native
            // enumeration/open ignores its timeout. Nothing imports a secret/mutation function.
            for (nuint i = 0; i < count && i < 8; i++)
            {
                nint entry = Fn<At>("fido_dev_info_ptr")(list, i);
                if (entry == 0) throw new InvalidDataException("native entry");
                nint path = Fn<Path>("fido_dev_info_path")(entry);
                string nativePath = Marshal.PtrToStringUTF8(path) ?? throw new InvalidDataException("native path");
                bool hid = nativePath.StartsWith(@"\\?\hid#", StringComparison.OrdinalIgnoreCase);
                string backend = nativePath == "windows://hello" ? "windows-hello" : hid ? "direct-hid-candidate" : "other-transport-candidate";
                int vendor = (ushort)Fn<Id>("fido_dev_info_vendor")(entry), product = (ushort)Fn<Id>("fido_dev_info_product")(entry);
                nint device = Fn<New>("fido_dev_new")();
                if (device == 0) throw new OutOfMemoryException();
                bool opened = false;
                try
                {
                    if (Fn<Timeout>("fido_dev_set_timeout")(device, 1500) != 0) throw new InvalidDataException("native timeout");
                    int open = Fn<Open>("fido_dev_open")(device, path); opened = open == 0;
                    int? infoResult = null; bool? credman = null;
                    if (opened)
                    {
                        backend = Fn<Flag>("fido_dev_is_winhello")(device) ? "windows-hello" : hid ? "direct-hid" : "other-direct-transport";
                        nint info = Fn<New>("fido_cbor_info_new")();
                        if (info == 0) throw new OutOfMemoryException();
                        try
                        {
                            infoResult = Fn<GetInfo>("fido_dev_get_cbor_info")(device, info);
                            if (infoResult == 0) credman = Fn<Flag>("fido_dev_supports_credman")(device);
                        }
                        finally { Fn<Free>("fido_cbor_info_free")(ref info); }
                    }
                    string pathHash = Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(nativePath)));
                    observations.Add(new(backend, pathHash, vendor, product, open, infoResult, credman));
                }
                finally
                {
                    if (opened) Fn<Close>("fido_dev_close")(device);
                    Fn<Free>("fido_dev_free")(ref device);
                }
            }
            using Peer self = new((uint)Environment.ProcessId);
            return new(self.Pid, self.Created, self.Identity, hash, manifest, (int)count, observations.ToArray());
        }
        finally
        {
            if (list != 0) Fn<InfoFree>("fido_dev_info_free")(ref list, 16);
            Native.FreeLibrary(library);
        }
    }
}
