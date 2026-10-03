using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace WindowsBrokerSpike;

[SupportedOSPlatform("windows")]
internal static class Runtime
{
    internal static int Run(string[] args)
    {
        using Peer self = new((uint)Environment.ProcessId);
        if (args is ["worker-hang"]) { Thread.Sleep(Timeout.Infinite); return 1; }
        if (args is ["worker-probe"])
        { Wire.Write(Console.OpenStandardOutput(), ReadOnlyProbe.Run(), default).GetAwaiter().GetResult(); return 0; }
        Program.StartEvidence();
        Program.Log("WINDOWS", new { Os = Environment.OSVersion.ToString(), Framework = Environment.Version.ToString(), Architecture = RuntimeInformation.ProcessArchitecture.ToString(), Self = self.Evidence() });
        if (args is ["identity"]) return 0;
        if (args is ["ipc-unrelated"])
        {
            using NamedPipeClientStream pipe = PipeEndpoint.Connect(self.Identity);
            using CancellationTokenSource deadline = new(TimeSpan.FromSeconds(2));
            Wire.Read<Challenge>(pipe, deadline.Token).GetAwaiter().GetResult();
            throw new InvalidOperationException("unexpected challenge to unrelated process");
        }
        if (args is ["probe"]) { ChildWorker.Run(false, default); return 0; }
        if (args is ["containment-test"]) { ChildWorker.Run(true, default); return 0; }
        if (args is ["orphan-fixture"]) { ChildWorker.Run(true, default, true); return 0; }
        if (args is ["client", "placeholder" or "probe"])
        { Client(self, args[1]); return 0; }
        if (args is ["ipc-negative", "version" or "kind" or "stale" or "oversize" or "malformed" or "unknown-field" or "duplicate" or "client-loss" or "stall"])
        { Client(self, args[1]); return 0; }
        if (args is ["broker", string pid, string created])
        { Broker(self, uint.Parse(pid), long.Parse(created)); return 0; }
        throw new ArgumentException("unknown spike mode");
    }

    private static void Client(Peer self, string kind)
    {
        if (self.Identity.Elevated || self.Identity.Integrity != 0x2000)
            throw new InvalidOperationException("client must be unelevated medium integrity");
        Native.ShellInfo launch = new()
        {
            Size = (uint)Marshal.SizeOf<Native.ShellInfo>(),
            Mask = 0x40 | 0x100,
            Verb = "runas",
            File = self.Image,
            Parameters = $"--ack-nonshipping broker {self.Pid} {self.Created}",
            Directory = AppContext.BaseDirectory,
            Show = 1
        };
        Marshal.ThrowExceptionForHR(Native.CoInitializeEx(0, 2)); // STA for ShellExecuteEx
        try { Native.Check(Native.ShellExecuteExW(ref launch)); } // UAC is launch consent only.
        finally { Native.CoUninitialize(); }
        if (launch.Process == 0) throw new InvalidOperationException("no retained elevated launch handle");
        using Peer broker = new(new SafeFileHandle(launch.Process, true));
        Program.Log("WINDOWS", new { LaunchedBroker = broker.Evidence() });
        Peer.SameElevationSession(self, broker);
        if (!broker.Identity.Elevated || broker.Identity.Integrity < 0x3000)
            throw new InvalidOperationException("broker not elevated");
        Program.Log("UI", new { AllowSetForegroundWindow = Native.AllowSetForegroundWindow(broker.Pid) });
        using NamedPipeClientStream pipe = PipeEndpoint.Connect(self.Identity);
        Native.Check(Native.GetNamedPipeServerProcessId(pipe.SafePipeHandle, out uint serverPid));
        if (serverPid != broker.Pid || !broker.Alive) throw new InvalidDataException("unexpected server process");
        using Peer connected = new(serverPid);
        IdentityRules.SameProcess(broker.Pid, broker.Created, serverPid, connected.Created);
        if (connected.Image != broker.Image)
            throw new InvalidDataException("server replacement");
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(40));
        Challenge hello = Wire.Read<Challenge>(pipe, timeout.Token).GetAwaiter().GetResult();
        if (hello.Version != Wire.Version || hello.Broker == Guid.Empty) throw new InvalidDataException("broker hello");
        Request request = new(Wire.Version, hello.Broker, Guid.NewGuid(), 1, kind == "probe" ? "probe" : "placeholder");
        switch (kind)
        {
            case "version": request = request with { Version = 2 }; break;
            case "kind": request = request with { Kind = "approve" }; break;
            case "stale": request = request with { Broker = Guid.NewGuid() }; break;
        }
        if (kind == "oversize")
            pipe.Write(new byte[] { 0, 0, 0x10, 1 }); // 4097, no payload: reject before allocation
        else if (kind is "malformed" or "unknown-field")
        {
            string json = kind == "malformed" ? "{" : System.Text.Json.JsonSerializer.Serialize(request)[..^1] + ",\"Approved\":true}";
            byte[] bytes = System.Text.Encoding.UTF8.GetBytes(json), header = new byte[4];
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(header, (uint)bytes.Length);
            pipe.Write(header); pipe.Write(bytes); pipe.Flush();
        }
        else if (kind == "stall") Thread.Sleep(15000);
        else Wire.Write(pipe, request, timeout.Token).GetAwaiter().GetResult();
        if (kind == "duplicate") Wire.Write(pipe, request, timeout.Token).GetAwaiter().GetResult();
        if (kind == "client-loss") { Program.Log("IPC", new { Test = "client-loss", ClientExiting = self.Pid }); return; }
        ResponseSlot slot = new(request);
        Task<Response> pending = Wire.Read<Response>(pipe, timeout.Token);
        while (!pending.IsCompleted)
        {
            if (!broker.Alive) { slot.LoseBroker(); throw new IOException("broker lost; reconnect forbidden"); }
            Thread.Sleep(50);
        }
        Response response = pending.GetAwaiter().GetResult();
        if (!broker.Alive)
        {
            slot.LoseBroker();
            throw new IOException("broker lost before terminal delivery");
        }
        slot.Accept(response);
        Program.Log("IPC", response);
    }

    private static void Broker(Peer self, uint pid, long created)
    {
        if (!self.Identity.Elevated || self.Identity.Integrity < 0x3000)
            throw new InvalidOperationException("broker must be high integrity/elevated");
        using Peer client = new(pid); // CLI PID/time are hints. Hold the OS handle, never signal by PID.
        if (client.Created != created || client.Identity.Elevated || client.Identity.Integrity != 0x2000)
            throw new InvalidDataException("stale launch/client token");
        Peer.SameElevationSession(client, self); // alternate credentials intentionally unsupported
        using NamedPipeServerStream pipe = PipeEndpoint.Create(client.Identity); // initiating medium logon owns the namespace
        using CancellationTokenSource deadline = new(TimeSpan.FromSeconds(10));
        Task connect = pipe.WaitForConnectionAsync(deadline.Token);
        while (!connect.IsCompleted)
        {
            if (!client.Alive) throw new IOException("launching client died");
            Thread.Sleep(50);
        }
        connect.GetAwaiter().GetResult();
        Native.Check(Native.GetNamedPipeClientProcessId(pipe.SafePipeHandle, out uint actualPid));
        using Peer peer = new(actualPid);
        IdentityRules.SameProcess(client.Pid, client.Created, actualPid, peer.Created);
        if (!client.Alive)
            throw new InvalidDataException("pipe peer is not retained launching process");
        Peer.SameSession(client.Identity, peer.Identity);
        Guid generation = Guid.NewGuid();
        Wire.Write(pipe, new Challenge(Wire.Version, generation), deadline.Token).GetAwaiter().GetResult();
        Request request = Wire.Read<Request>(pipe, deadline.Token).GetAwaiter().GetResult();
        // Read first: named pipe impersonation represents the last received message's context.
        string? impersonated = null;
        pipe.RunAsClient(() =>
        {
            // Query the identification token directly; no lazy managed identity assembly loads
            // while impersonating an identification-only caller. OpenAsSelf changes query access,
            // not the token being observed. RunAsClient still reverts before any work.
            Native.Check(Native.OpenThreadToken(Native.GetCurrentThread(), 8, true, out SafeFileHandle token));
            using (token) impersonated = Peer.ReadSid(token);
        });
        if (impersonated != client.Identity.Sid) throw new InvalidDataException("pipe impersonation SID mismatch");
        Program.Log("IPC", new { ConnectedPeer = peer.Evidence(), ImpersonatedSidMatchesClient = impersonated == client.Identity.Sid });
        Lifecycle state = new(generation, request.Client); state.Begin(request);
        using CancellationTokenSource lost = new();
        using CancellationTokenSource watchStop = new();
        // Any second byte/frame or EOF revokes. No queue and no client approval/cancellation payload.
        Task watcher = Task.Run(async () =>
        {
            try { byte[] extra = new byte[1]; await pipe.ReadExactlyAsync(extra, watchStop.Token); }
            catch (Exception e) when (e is IOException or OperationCanceledException or ObjectDisposedException) { }
            if (!watchStop.IsCancellationRequested) lost.Cancel();
        });
        Task lifetime = Task.Run(async () =>
        {
            try
            {
                while (!watchStop.IsCancellationRequested)
                { if (!client.Alive) { lost.Cancel(); break; } await Task.Delay(50, watchStop.Token); }
            }
            catch (OperationCanceledException) { }
        });
        try
        {
            string result;
            try
            {
                result = request.Kind == "placeholder"
                    ? PlaceholderWindow.Run(client, request, lost.Token)
                    : ChildWorker.Run(false, lost.Token);
                state.Decide(request, result);
            }
            catch { state.Revoke("runtime-failure"); throw; }
            if (lost.IsCancellationRequested || !client.Alive) state.Revoke("client-loss-or-protocol");
            Response response = state.Finish(true); // Run returns only after window destruction / child exit proof.
            if (!lost.IsCancellationRequested && client.Alive)
            {
                using CancellationTokenSource writeDeadline = new(TimeSpan.FromSeconds(2));
                Wire.Write(pipe, response, writeDeadline.Token).GetAwaiter().GetResult();
                // Stay alive until client close (bounded), so the client can check retained server
                // liveness before consuming the terminal frame. EOF here ends a completed session.
                if (!watcher.Wait(2000)) Program.Log("IPC", new { CompletedConnectionIdleExpired = true });
            }
            Program.Log("IPC", response);
        }
        finally
        {
            watchStop.Cancel(); pipe.Dispose();
            if (!Task.WaitAll([watcher, lifetime], 2000))
                throw new InvalidOperationException("connection watcher teardown not proven");
        }
        // One-shot authority; no journal, tokens, device handles or permits survive this launch.
    }
}
