using System.Buffers.Binary;
using System.Text;

namespace WindowsBrokerSpike;

internal static class SelfTest
{
    internal static void Run()
    {
        int checks = 0;
        void Check(bool condition) { checks++; if (!condition) throw new Exception("assertion " + checks); }
        void Reject(Action action)
        {
            checks++;
            try { action(); }
            catch (Exception e) when (e is InvalidDataException
                or InvalidOperationException or System.Text.Json.JsonException or EndOfStreamException)
            { return; }
            throw new Exception("expected rejection " + checks);
        }
        Guid b = Guid.NewGuid(), c = Guid.NewGuid();
        Request r = new(1, b, c, 1, "placeholder");
        void Read(byte[] bytes) => Wire.Read<Request>(new MemoryStream(bytes), default).GetAwaiter().GetResult();
        byte[] Frame(string json)
        {
            byte[] payload = Encoding.UTF8.GetBytes(json), result = new byte[payload.Length + 4];
            BinaryPrimitives.WriteUInt32BigEndian(result, (uint)payload.Length);
            payload.CopyTo(result, 4); return result;
        }
        using MemoryStream wire = new();
        Wire.Write(wire, r, default).GetAwaiter().GetResult(); wire.Position = 0;
        Check(Wire.Read<Request>(wire, default).GetAwaiter().GetResult() == r);
        string requestJson = System.Text.Json.JsonSerializer.Serialize(r);
        byte[] atBound = Frame(requestJson.PadRight(Wire.Limit));
        Check(Wire.Read<Request>(new MemoryStream(atBound), default).GetAwaiter().GetResult() == r);
        foreach (uint size in new uint[] { 0, Wire.Limit + 1, uint.MaxValue })
        {
            byte[] header = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(header, size);
            Reject(() => Read(header)); // No payload exists; oversized header must reject immediately.
        }
        foreach (string json in new[] { "null", "[]", "{", "{}", "{\"Version\":1,\"Version\":1}",
            "{\"Version\":1,\"Broker\":\"" + b + "\",\"Client\":\"" + c + "\",\"Id\":1,\"Kind\":\"probe\",\"Pin\":\"x\"}" })
            Reject(() => Read(Frame(json)));
        Reject(() => Read(new byte[] { 0, 0 }));
        Reject(() => Read(new byte[] { 0, 0, 0, 4, 1 }));
        Reject(() => Read(Frame("{\"Outer\":{\"Duplicate\":1,\"Duplicate\":2}}")));
        Reject(() => Wire.Write(new MemoryStream(), new { Text = new string('x', 4096) }, default).GetAwaiter().GetResult());
        foreach (Request bad in new[] { r with { Version = 2 }, r with { Broker = Guid.NewGuid() },
            r with { Client = Guid.Empty }, r with { Id = 0 }, r with { Kind = "approve" }, r with { Kind = "raw-ctap" } })
            Reject(() => Wire.Check(bad, b));
        Lifecycle state = new(b, c); state.Begin(r);
        Reject(() => state.Begin(r)); // second client / duplicate / concurrent request never queued
        Reject(() => state.Decide(r with { Client = Guid.NewGuid() }, "placeholder-accepted"));
        Reject(() => state.Decide(r with { Broker = Guid.NewGuid() }, "placeholder-accepted"));
        state.Decide(r, "placeholder-accepted");
        Reject(() => state.Decide(r, "placeholder-accepted"));
        Reject(() => state.Finish(false)); // keep reservation until native/worker teardown proof
        Response terminal = state.Finish(true); Check(terminal.Result == "placeholder-accepted");
        Reject(() => state.Finish(true)); Reject(() => state.Begin(r with { Id = 2 }));
        foreach (string failure in new[] { "client-loss", "broker-loss", "worker-loss", "timeout", "shutdown", "session-loss", "protocol" })
        {
            Lifecycle lost = new(b, c); lost.Begin(r); lost.Decide(r, "placeholder-accepted");
            lost.Revoke(failure); Check(lost.Finish(true).Result == "revoked:" + failure);
            Reject(() => lost.Decide(r, "placeholder-accepted"));
        }
        Reject(() => new Lifecycle(b, Guid.NewGuid()).Begin(r)); // stale old client / reconnect
        Reject(() => new Lifecycle(Guid.NewGuid(), c).Begin(r)); // restarted broker
        foreach (Response bad in new[] { terminal with { Version = 2 }, terminal with { Broker = Guid.NewGuid() },
            terminal with { Client = Guid.NewGuid() }, terminal with { Id = 2 } })
            Reject(() => new ResponseSlot(r).Accept(bad));
        ResponseSlot slot = new(r); slot.Accept(terminal); Reject(() => slot.Accept(terminal));
        ResponseSlot dead = new(r); dead.LoseBroker(); Reject(() => dead.Accept(terminal));
        TokenIdentity identity = new("S-1-5-21-1", "S-1-5-5-1-2", "logon-1", 1, false, 0x2000);
        IdentityRules.SameSession(identity, identity with { Elevated = true, Integrity = 0x3000 });
        foreach (TokenIdentity different in new[] { identity with { Sid = "other-admin" },
            identity with { LogonSid = "other-logon-sid" }, identity with { Logon = "other-logon" }, identity with { Session = 2 } })
            Reject(() => IdentityRules.SameSession(identity, different));
        IdentityRules.SameProcess(10, 100, 10, 100);
        Reject(() => IdentityRules.SameProcess(10, 100, 11, 100));
        Reject(() => IdentityRules.SameProcess(10, 100, 10, 200)); // PID recycled, same SID still insufficient
        Console.WriteLine($"[TEST] {checks} assertions passed (portable model/codec only; no Windows evidence)");
    }
}
