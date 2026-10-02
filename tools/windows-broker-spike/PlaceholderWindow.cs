using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace WindowsBrokerSpike;

[SupportedOSPlatform("windows")]
internal static class PlaceholderWindow
{
    private delegate nint WindowProc(nint window, uint message, nuint wparam, nint lparam);
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WindowClass
    { internal uint Size, Style; internal nint Procedure; internal int ClassExtra, WindowExtra; internal nint Instance, Icon, Cursor, Background; internal string? Menu; internal string ClassName; internal nint SmallIcon; }
    [StructLayout(LayoutKind.Sequential)]
    private struct Message
    { internal nint Window; internal uint Kind; internal nuint Wparam; internal nint Lparam; internal uint Time; internal int X, Y; internal uint Private; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern nint GetModuleHandleW(string? name);
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern ushort RegisterClassExW(ref WindowClass windowClass);
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool UnregisterClassW(string name, nint instance);
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern nint CreateWindowExW(uint extended, string className, string title, uint style, int x, int y, int width, int height, nint parent, nint menu, nint instance, nint parameter);
    [DllImport("user32.dll")] private static extern nint DefWindowProcW(nint window, uint message, nuint wparam, nint lparam);
    [DllImport("user32.dll", SetLastError = true)] private static extern int GetMessageW(out Message message, nint window, uint min, uint max);
    [DllImport("user32.dll")] private static extern bool TranslateMessage(ref Message message);
    [DllImport("user32.dll")] private static extern nint DispatchMessageW(ref Message message);
    [DllImport("user32.dll")] private static extern bool ShowWindow(nint window, int command);
    [DllImport("user32.dll")] private static extern bool DestroyWindow(nint window);
    [DllImport("user32.dll")] private static extern bool IsWindow(nint window);
    [DllImport("user32.dll")] private static extern void PostQuitMessage(int code);
    [DllImport("user32.dll", SetLastError = true)] private static extern nuint SetTimer(nint window, nuint id, uint milliseconds, nint callback);
    [DllImport("user32.dll")] private static extern bool SetForegroundWindow(nint window);
    [DllImport("user32.dll")] private static extern nint GetForegroundWindow();
    [DllImport("user32.dll")] private static extern nint SetFocus(nint window);
    [DllImport("user32.dll")] private static extern bool IsDialogMessageW(nint window, ref Message message);
    [DllImport("wtsapi32.dll", SetLastError = true)] private static extern bool WTSRegisterSessionNotification(nint window, uint scope);
    [DllImport("wtsapi32.dll")] private static extern bool WTSUnRegisterSessionNotification(nint window);

    internal static string Run(Peer client, Request binding, CancellationToken cancel)
    {
        string result = "presentation-failed";
        Stopwatch elapsed = Stopwatch.StartNew();
        bool foregroundLogged = false;
        bool logForeground = false;
        Guid prompt = Guid.NewGuid(); // broker-minted, one native window, bound to this immutable request
        Guid workflow = Guid.NewGuid(); // client nonce/id are correlation, not backend workflow identity
        WindowProc procedure = (window, message, wparam, lparam) =>
        {
            // Callback never throws through unmanaged code. Buttons have no secret entry field.
            if (message == 0x111 && ((wparam & 0xffff) is 1 or 2))
            {
                result = (wparam & 0xffff) == 1 ? "placeholder-accepted" : "cancelled";
                DestroyWindow(window); return 0;
            }
            if (message == 0x10) { result = "cancelled"; DestroyWindow(window); return 0; }
            if (message == 0x11) { result = "shutdown"; DestroyWindow(window); return 1; }
            if (message == 0x2b1 || (message == 0x218 && wparam == 4))
            { result = "session-loss"; DestroyWindow(window); return 0; }
            if (message == 0x113)
            {
                if (!foregroundLogged)
                {
                    // Store evidence outside the callback; no serialization/PInvoke exception here.
                    foregroundLogged = true;
                    logForeground = true;
                }
                if (cancel.IsCancellationRequested || !client.Alive || elapsed.Elapsed >= TimeSpan.FromSeconds(30))
                {
                    result = elapsed.Elapsed >= TimeSpan.FromSeconds(30) ? "timeout" : "client-loss-or-protocol";
                    DestroyWindow(window);
                }
                return 0;
            }
            if (message == 2) { PostQuitMessage(0); return 0; }
            return DefWindowProcW(window, message, wparam, lparam);
        };
        nint instance = GetModuleHandleW(null);
        string name = "FidoManagerM15Placeholder";
        WindowClass wc = new()
        {
            Size = (uint)Marshal.SizeOf<WindowClass>(),
            Instance = instance,
            ClassName = name,
            Procedure = Marshal.GetFunctionPointerForDelegate(procedure),
            Background = 6
        };
        if (RegisterClassExW(ref wc) == 0) throw new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError());
        nint hwnd = 0;
        try
        {
            hwnd = CreateWindowExW(0, name, "FidoManager M1.5 — NON-SHIPPING / NO PIN", 0xc80000,
                unchecked((int)0x80000000), unchecked((int)0x80000000), 520, 210, 0, 0, instance, 0);
            if (hwnd == 0) throw new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError());
            if (CreateWindowExW(0, "STATIC", $"Non-secret placeholder only.\nClient PID {client.Pid}; request {binding.Id}.\nNo FIDO operation is authorized by this window.",
                0x50000000, 20, 15, 465, 80, hwnd, 0, instance, 0) == 0
                || CreateWindowExW(0, "BUTTON", "Accept placeholder", 0x50010000, 20, 110, 180, 35, hwnd, 1, instance, 0) == 0)
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError());
            nint cancelButton = CreateWindowExW(0, "BUTTON", "Cancel", 0x50010000, 220, 110, 130, 35, hwnd, 2, instance, 0);
            if (cancelButton == 0) throw new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError());
            Native.Check(WTSRegisterSessionNotification(hwnd, 0));
            if (SetTimer(hwnd, 1, 100, 0) == 0) throw new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError());
            ShowWindow(hwnd, 5);
            SetFocus(cancelButton);
            bool foreground = SetForegroundWindow(hwnd);
            Program.Log("UI", new
            {
                Binding = binding,
                Workflow = workflow,
                PromptInstance = prompt,
                BrokerPid = Environment.ProcessId,
                Client = client.Evidence(),
                Hwnd = hwnd.ToInt64(),
                OwnerHwnd = 0,
                SetForegroundWindow = foreground,
                ForegroundHwnd = GetForegroundWindow().ToInt64(),
                Thread = Environment.CurrentManagedThreadId
            });
            while (true)
            {
                int code = GetMessageW(out Message msg, 0, 0, 0);
                if (code == 0) break;
                if (code == -1) throw new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError());
                if (!IsDialogMessageW(hwnd, ref msg)) { TranslateMessage(ref msg); DispatchMessageW(ref msg); }
                if (logForeground)
                {
                    Program.Log("UI", new { ForegroundAfterEvent = GetForegroundWindow().ToInt64() });
                    logForeground = false;
                }
            }
            if (IsWindow(hwnd)) throw new InvalidOperationException("no native teardown proof");
            // Cancellation is a veto even when an accept event won the window-close race.
            if (cancel.IsCancellationRequested || !client.Alive) result = "client-loss-or-protocol";
            if (elapsed.Elapsed >= TimeSpan.FromSeconds(30)) result = "timeout";
            Program.Log("UI", new { Result = result, WindowDestroyed = true });
            return result;
        }
        finally
        {
            if (hwnd != 0) { WTSUnRegisterSessionNotification(hwnd); if (IsWindow(hwnd)) DestroyWindow(hwnd); }
            UnregisterClassW(name, instance);
            GC.KeepAlive(procedure);
        }
    }
}
