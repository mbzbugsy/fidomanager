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
            Log("UNRESOLVED", new { FailClosed = true, Type = e.GetType().Name, e.Message });
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
        Console.Error.WriteLine("[WINDOWS] Evidence file: " + path);
    }
    internal static void Log(string label, object value)
    {
        string line = $"[{label}] {JsonSerializer.Serialize(new { Utc = DateTimeOffset.UtcNow, Value = value })}";
        Console.Error.WriteLine(line);
        evidence?.WriteLine(line);
    }
}
