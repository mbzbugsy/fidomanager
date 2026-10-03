using System.Text.Json;

namespace WindowsBrokerSpike;

internal static class Program
{
    private static StreamWriter? evidence;
    [STAThread]
    private static int Main(string[] args)
    {
        try
        {
            if (args is ["self-test"]) { SelfTest.Run(); return 0; }
            if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Windows runtime required");
            if (args.Length < 2 || args[0] != "--ack-nonshipping")
                throw new ArgumentException("Use self-test or --ack-nonshipping identity|probe|client placeholder|client probe|containment-test");
            return Runtime.Run(args[1..]);
        }
        catch (Exception e)
        {
            Log("UNRESOLVED", new
            {
                FailClosed = true,
                Type = e.GetType().Name,
                e.HResult,
                Frames = new System.Diagnostics.StackTrace(e, true).GetFrames()
                    .Where(f => f.GetMethod()?.DeclaringType?.Namespace is string ns
                        && (ns == "WindowsBrokerSpike" || ns == "System.IO.Pipes"))
                    .Select(f => new { Method = f.GetMethod()?.DeclaringType?.Name + "." + f.GetMethod()?.Name, Line = f.GetFileLineNumber() }),
                NativeError = e is System.ComponentModel.Win32Exception native ? (int?)native.NativeErrorCode : null,
                e.Message
            });
            return 1;
        }
        finally { evidence?.Dispose(); }
    }
    internal static void StartEvidence()
    {
        // Diagnostic output only. Never read as authorization or recovery state.
        string directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "FidoManager-M15-Evidence");
        Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, $"{Environment.ProcessId}-{Guid.NewGuid():N}.log");
        evidence = new StreamWriter(new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read)) { AutoFlush = true };
        Console.Error.WriteLine("[WINDOWS-MANAGED][WINDOWS] Evidence file: " + path);
    }
    internal static string RedactDescriptor(string descriptor)
        => System.Text.RegularExpressions.Regex.Replace(descriptor, @"S-1-(?:\d+-)*\d+", "<principal-sid>");

    internal static void Log(string label, object value)
    {
        string context = OperatingSystem.IsWindows() ? "[WINDOWS-MANAGED]" : "";
        string line = $"{context}[{label}] {JsonSerializer.Serialize(new { Utc = DateTimeOffset.UtcNow, Value = value })}";
        Console.Error.WriteLine(line);
        evidence?.WriteLine(line);
    }
}
