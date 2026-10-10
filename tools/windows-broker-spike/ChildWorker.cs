using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace WindowsBrokerSpike;

[SupportedOSPlatform("windows")]
internal static class ChildWorker
{
    // No breakaway, no shared job handle, no inherited pipe server/client/token handles.
    internal static string Run(bool hang, CancellationToken cancel, bool orphanFixture = false)
    {
        // Deliberately inheritable unrelated object: prove the explicit list excludes it before
        // child code runs. Compare object identity, so a coincident numeric handle is not a leak.
        using EventWaitHandle sentinel = new(false, EventResetMode.ManualReset);
        Native.Check(Native.SetHandleInformation(sentinel.SafeWaitHandle, 1, 1));
        using SafeFileHandle job = Native.Handle(Native.CreateJobObjectW(0, null));
        Native.JobLimits limits = new() { Basic = new() { Flags = 0x2000 } }; // KILL_ON_JOB_CLOSE
        Native.Check(Native.SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf<Native.JobLimits>()));
        Native.SecurityAttributes security = new() { Length = (uint)Marshal.SizeOf<Native.SecurityAttributes>(), Inherit = 1 };
        Native.Check(Native.CreatePipe(out SafeFileHandle read, out SafeFileHandle write, ref security, Wire.Limit));
        using (read) using (write)
        {
            Native.Check(Native.SetHandleInformation(read, 1, 0));
            nuint size = 0;
            Native.InitializeProcThreadAttributeList(0, 2, 0, ref size);
            nint attributes = Marshal.AllocHGlobal(checked((int)size));
            nint handles = Marshal.AllocHGlobal(2 * IntPtr.Size);
            nint environment = Marshal.StringToHGlobalUni("SystemRoot=" + Environment.GetFolderPath(Environment.SpecialFolder.Windows) + "\0\0");
            bool initialized = false;
            try
            {
                Native.Check(Native.InitializeProcThreadAttributeList(attributes, 2, 0, ref size)); initialized = true;
                Marshal.WriteIntPtr(handles, write.DangerousGetHandle());
                Native.Check(Native.UpdateProcThreadAttribute(attributes, 0, 0x00020002, handles, (nuint)IntPtr.Size, 0, 0));
                // Windows 10+ JOB_LIST closes the create-then-assign orphan race, including a
                // parent killed while its freshly created child is still suspended. No fallback.
                Marshal.WriteIntPtr(handles, IntPtr.Size, job.DangerousGetHandle());
                Native.Check(Native.UpdateProcThreadAttribute(attributes, 0, 0x0002000d, handles + IntPtr.Size, (nuint)IntPtr.Size, 0, 0));
                string exe = Environment.ProcessPath ?? throw new InvalidOperationException("apphost required");
                if (!exe.EndsWith("WindowsBrokerSpike.exe", StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("run the built apphost, not dotnet DLL");
                Native.StartupEx startup = new()
                {
                    Startup = new()
                    {
                        Size = (uint)Marshal.SizeOf<Native.StartupEx>(),
                        Flags = 0x100,
                        Output = write.DangerousGetHandle(),
                        Error = write.DangerousGetHandle()
                    },
                    Attributes = attributes
                };
                string mode = hang ? "worker-hang" : "worker-probe";
                Native.Check(Native.CreateProcessW(exe, new StringBuilder($"\"{exe}\" --ack-nonshipping {mode}"),
                    0, 0, true, 0x4 | 0x80000 | 0x400 | 0x08000000, environment, AppContext.BaseDirectory,
                    ref startup, out Native.ProcessInfo info)); // SUSPENDED + EXTENDED_STARTUP + UNICODE_ENV + NO_WINDOW
                using SafeFileHandle process = new(info.Process, true);
                using SafeFileHandle thread = new(info.Thread, true);
                bool reaped = false;
                try
                {
                    Native.Check(Native.IsProcessInJob(process, job, out bool member));
                    if (!member) throw new InvalidOperationException("worker job membership");
                    using Peer parent = new((uint)Environment.ProcessId);
                    using Peer child = new(info.Pid);
                    Peer.SameSession(parent.Identity, child.Identity);
                    if (parent.Identity.Integrity != child.Identity.Integrity || parent.Identity.Elevated != child.Identity.Elevated)
                        throw new InvalidOperationException("worker token changed");
                    bool copied = Native.DuplicateHandle(process, sentinel.SafeWaitHandle.DangerousGetHandle(),
                        Native.GetCurrentProcess(), out SafeFileHandle candidate, 0, false, 2);
                    int copyError = copied ? 0 : Marshal.GetLastPInvokeError();
                    using (candidate)
                    {
                        if (!copied && copyError != 6) throw new System.ComponentModel.Win32Exception(copyError, "sentinel inheritance query");
                        if (copied && Native.CompareObjectHandles(candidate, sentinel.SafeWaitHandle))
                            throw new InvalidOperationException("unrelated inheritable handle leaked into worker");
                    }
                    Program.Log("WINDOWS", new
                    {
                        Worker = child.Evidence(),
                        JobMember = member,
                        InheritedHandles = "stdout/stderr only",
                        InheritableSentinelExcluded = true,
                        SentinelCheckedWhileSuspended = true,
                        AtomicJobAssignment = true,
                        SuspendedUntilValidated = true
                    });
                    if (Native.ResumeThread(thread) == uint.MaxValue) throw new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError());
                    write.Dispose(); // only child holds the write end now
                    using FileStream output = new(read, FileAccess.Read);
                    using CancellationTokenSource deadline = CancellationTokenSource.CreateLinkedTokenSource(cancel);
                    deadline.CancelAfter(hang ? TimeSpan.FromSeconds(orphanFixture ? 30 : 2) : TimeSpan.FromSeconds(12));
                    // Anonymous pipe is synchronous; WaitAsync bounds waiting even if its read blocks.
                    Task<WorkerReport> pending = Task.Run(() => Wire.Read<WorkerReport>(output, default).GetAwaiter().GetResult());
                    try
                    {
                        WorkerReport result = pending.WaitAsync(deadline.Token).GetAwaiter().GetResult();
                        if (result.Pid != info.Pid || result.Created != child.Created || result.Identity != child.Identity)
                            throw new InvalidDataException("worker identity mismatch");
                        if (Native.WaitForSingleObject(process, 2000) != 0) throw new TimeoutException("worker exit");
                        Native.Check(Native.GetExitCodeProcess(process, out uint code));
                        if (code != 0) throw new InvalidDataException("worker failed");
                        Native.Check(Native.TerminateJobObject(job, 125)); // also contain any descendants
                        reaped = Quiescent(job, process);
                        if (!reaped) throw new InvalidOperationException("job still active after worker exit");
                        Program.Log("DIRECT-ACCESS", result.Evidence());
                        return System.Text.Json.JsonSerializer.Serialize(result.Evidence());
                    }
                    catch (OperationCanceledException) when (hang && !cancel.IsCancellationRequested)
                    {
                        Native.Check(Native.TerminateJobObject(job, 125));
                        reaped = Quiescent(job, process);
                        if (!reaped) throw new InvalidOperationException("quarantined: hung child not proven dead");
                        Program.Log("WINDOWS", new { HangTimeout = true, WorkerReaped = true, Pid = info.Pid });
                        return "fixture-contained";
                    }
                    finally
                    {
                        if (!reaped)
                        {
                            Native.TerminateJobObject(job, 125);
                            Native.TerminateProcess(process, 125);
                            reaped = Quiescent(job, process);
                            if (!reaped) throw new InvalidOperationException("quarantined: no child teardown proof; no replacement");
                        }
                        // EOF follows child death. Observe reader failure without an unbounded join.
                        _ = pending.ContinueWith(t => { _ = t.Exception; }, TaskContinuationOptions.OnlyOnFaulted);
                    }
                }
                finally
                {
                    if (!reaped)
                    {
                        Native.TerminateProcess(process, 125);
                        if (Native.WaitForSingleObject(process, 2000) != 0)
                            Program.Log("UNRESOLVED", new { UnreapedSuspendedChild = info.Pid });
                    }
                }
            }
            finally
            {
                if (initialized) Native.DeleteProcThreadAttributeList(attributes);
                Marshal.FreeHGlobal(attributes); Marshal.FreeHGlobal(handles); Marshal.FreeHGlobal(environment);
            }
        }
    }
    private static bool Quiescent(SafeFileHandle job, SafeFileHandle process)
    {
        System.Diagnostics.Stopwatch elapsed = System.Diagnostics.Stopwatch.StartNew();
        do
        {
            Native.Check(Native.QueryInformationJobObject(job, 1, out Native.JobAccounting accounting,
                (uint)Marshal.SizeOf<Native.JobAccounting>(), out _));
            if (accounting.ActiveProcesses == 0 && Native.WaitForSingleObject(process, 0) == 0) return true;
            Thread.Sleep(25);
        } while (elapsed.Elapsed < TimeSpan.FromSeconds(2));
        return false;
    }
}

internal sealed record DeviceObservation(string Backend, string PathHash, int Vendor, int Product, int Open, int? GetInfo, bool? Credman, string? Manufacturer, string? ProductName);
internal sealed record WorkerReport(uint Pid, long Created, TokenIdentity Identity, string DllSha256, int Manifest, int Count, DeviceObservation[] Devices)
{
    internal object Evidence() => new { Pid, Created, Identity = Identity.Evidence(), DllSha256, Manifest, Count, Devices };
}
