using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace WindowsBrokerSpike;

[SupportedOSPlatform("windows")]
internal static class Native
{
    internal static void Check(bool ok) { if (!ok) throw new Win32Exception(Marshal.GetLastPInvokeError()); }
    internal static SafeFileHandle Handle(SafeFileHandle h) { if (h.IsInvalid) throw new Win32Exception(Marshal.GetLastPInvokeError()); return h; }
    [StructLayout(LayoutKind.Sequential)] internal struct SecurityAttributes { internal uint Length; internal nint Descriptor; internal int Inherit; }
    [StructLayout(LayoutKind.Sequential)] internal struct Luid { internal uint Low; internal int High; public override string ToString() => $"{High:x8}{Low:x8}"; }
    [StructLayout(LayoutKind.Sequential)]
    internal struct TokenStatistics
    { internal Luid TokenId, AuthenticationId; internal long Expiration; internal uint Type, Impersonation, Charged, Available, Groups, Privileges; internal Luid Modified; }
    [StructLayout(LayoutKind.Sequential)]
    internal struct Startup
    { internal uint Size; internal nint Reserved, Desktop, Title; internal uint X, Y, XSize, YSize, XChars, YChars, Fill, Flags; internal ushort Show, ReservedSize; internal nint ReservedBytes, Input, Output, Error; }
    [StructLayout(LayoutKind.Sequential)] internal struct StartupEx { internal Startup Startup; internal nint Attributes; }
    [StructLayout(LayoutKind.Sequential)] internal struct ProcessInfo { internal nint Process, Thread; internal uint Pid, Tid; }
    [StructLayout(LayoutKind.Sequential)]
    internal struct JobBasic
    { internal long ProcessTime, JobTime; internal uint Flags; internal nuint MinWorking, MaxWorking; internal uint ActiveLimit; internal nuint Affinity; internal uint Priority, Scheduling; }
    [StructLayout(LayoutKind.Sequential)] internal struct IoCounters { internal ulong ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes; }
    [StructLayout(LayoutKind.Sequential)]
    internal struct JobLimits
    { internal JobBasic Basic; internal IoCounters Io; internal nuint ProcessMemory, JobMemory, PeakProcess, PeakJob; }
    [StructLayout(LayoutKind.Sequential)]
    internal struct JobAccounting
    { internal long User, Kernel, PeriodUser, PeriodKernel; internal uint Faults, TotalProcesses, ActiveProcesses, TerminatedProcesses; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct ShellInfo
    { internal uint Size, Mask; internal nint Window; internal string Verb, File, Parameters, Directory; internal int Show; internal nint Instance, IdList; internal string? Class; internal nint ClassKey; internal uint Hotkey; internal nint Icon, Process; }

    [DllImport("kernel32.dll", SetLastError = true)] internal static extern SafeFileHandle OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool GetProcessTimes(SafeFileHandle process, out long creation, out long exit, out long kernel, out long user);
    [DllImport("kernel32.dll")] internal static extern uint GetProcessId(SafeFileHandle process);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern uint WaitForSingleObject(SafeFileHandle handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool GetExitCodeProcess(SafeFileHandle process, out uint code);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool TerminateProcess(SafeFileHandle process, uint code);
    [DllImport("kernel32.dll")] internal static extern nint GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool DuplicateHandle(SafeFileHandle sourceProcess, nint sourceHandle, nint targetProcess, out SafeFileHandle duplicate, uint access, bool inherit, uint options);
    [DllImport("kernelbase.dll")] internal static extern bool CompareObjectHandles(SafeHandle first, SafeHandle second);
    [DllImport("kernel32.dll")] internal static extern nint GetCurrentThread();
    [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool OpenThreadToken(nint thread, uint access, bool openAsSelf, out SafeFileHandle token);
    [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool OpenProcessToken(SafeFileHandle process, uint access, out SafeFileHandle token);
    [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool GetTokenInformation(SafeFileHandle token, int kind, nint buffer, uint length, out uint needed);
    [DllImport("advapi32.dll")] internal static extern nint GetSidSubAuthorityCount(nint sid);
    [DllImport("advapi32.dll")] internal static extern nint GetSidSubAuthority(nint sid, uint index);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern bool QueryFullProcessImageNameW(SafeFileHandle process, uint flags, StringBuilder name, ref uint size);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string sddl, uint revision, out nint sd, out uint size);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(nint sd, uint revision, uint info, out nint sddl, out uint size);
    [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool GetKernelObjectSecurity(SafePipeHandle handle, uint info, nint sd, uint size, out uint needed);
    [DllImport("kernel32.dll")] internal static extern nint LocalFree(nint memory);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern SafePipeHandle CreateNamedPipeW(string name, uint open, uint mode, uint instances, uint output, uint input, uint timeout, ref SecurityAttributes security);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern SafePipeHandle CreateFileW(string name, uint access, uint sharing, nint security, uint disposition, uint flags, nint template);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern bool WaitNamedPipeW(string name, uint timeout);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint pid);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint pid);
    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern bool ShellExecuteExW(ref ShellInfo info);
    [DllImport("ole32.dll")] internal static extern int CoInitializeEx(nint reserved, uint flags);
    [DllImport("ole32.dll")] internal static extern void CoUninitialize();
    [DllImport("user32.dll", SetLastError = true)] internal static extern bool AllowSetForegroundWindow(uint pid);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern SafeFileHandle CreateJobObjectW(nint security, string? name);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool SetInformationJobObject(SafeFileHandle job, int kind, ref JobLimits limits, uint length);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool QueryInformationJobObject(SafeFileHandle job, int kind, out JobAccounting accounting, uint length, out uint returned);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool TerminateJobObject(SafeFileHandle job, uint code);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool IsProcessInJob(SafeFileHandle process, SafeFileHandle job, out bool member);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool CreatePipe(out SafeFileHandle read, out SafeFileHandle write, ref SecurityAttributes attributes, uint size);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool SetHandleInformation(SafeHandle handle, uint mask, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool InitializeProcThreadAttributeList(nint list, int count, uint flags, ref nuint size);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool UpdateProcThreadAttribute(nint list, uint flags, nuint kind, nint value, nuint size, nint previous, nint returned);
    [DllImport("kernel32.dll")] internal static extern void DeleteProcThreadAttributeList(nint list);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern bool CreateProcessW(string executable, StringBuilder command, nint processSecurity, nint threadSecurity, bool inherit, uint flags, nint environment, string directory, ref StartupEx startup, out ProcessInfo info);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern uint ResumeThread(SafeFileHandle thread);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern nint LoadLibraryExW(string file, nint reserved, uint flags);
    [DllImport("kernel32.dll")] internal static extern bool FreeLibrary(nint module);
}
