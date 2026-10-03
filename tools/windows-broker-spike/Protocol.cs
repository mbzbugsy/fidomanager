using System.Buffers.Binary;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WindowsBrokerSpike;

// Separate experimental wire format; no application IPC, PIN, path, CTAP or approval input.
internal sealed record Challenge(int Version, Guid Broker);
internal sealed record Request(int Version, Guid Broker, Guid Client, ulong Id, string Kind);
internal sealed record Response(int Version, Guid Broker, Guid Client, ulong Id, string Result);
internal static class Wire
{
    internal const int Version = 1;
    internal const int Limit = 4096;
    private static readonly JsonSerializerOptions Options = new()
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        RespectRequiredConstructorParameters = true,
        MaxDepth = 8
    };

    internal static async Task<T> Read<T>(Stream stream, CancellationToken cancel)
    {
        byte[] header = new byte[4];
        await stream.ReadExactlyAsync(header, cancel);
        uint size = BinaryPrimitives.ReadUInt32BigEndian(header);
        if (size is 0 or > Limit) throw new InvalidDataException("frame bound");
        byte[] payload = new byte[size]; // Header checked before allocation or payload read.
        await stream.ReadExactlyAsync(payload, cancel);
        using JsonDocument doc = JsonDocument.Parse(payload, new() { MaxDepth = 8 });
        if (doc.RootElement.ValueKind != JsonValueKind.Object)
            throw new InvalidDataException("object required");
        // System.Text.Json normally accepts duplicate properties. Reject them explicitly.
        RejectDuplicates(doc.RootElement);
        return JsonSerializer.Deserialize<T>(payload, Options)
            ?? throw new InvalidDataException("null message");
    }

    private static void RejectDuplicates(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            HashSet<string> keys = new(StringComparer.Ordinal);
            foreach (JsonProperty p in element.EnumerateObject())
            {
                if (!keys.Add(p.Name)) throw new InvalidDataException("duplicate property");
                RejectDuplicates(p.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
            foreach (JsonElement item in element.EnumerateArray()) RejectDuplicates(item);
    }

    internal static async Task Write<T>(Stream stream, T message, CancellationToken cancel)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(message, Options);
        if (bytes.Length is 0 or > Limit) throw new InvalidDataException("outgoing bound");
        byte[] header = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(header, (uint)bytes.Length);
        await stream.WriteAsync(header, cancel);
        await stream.WriteAsync(bytes, cancel);
        await stream.FlushAsync(cancel);
    }

    internal static void Check(Request request, Guid broker)
    {
        if (request.Version != Version || request.Broker != broker || request.Client == Guid.Empty
            || request.Id == 0 || request.Kind is not ("placeholder" or "probe"))
            throw new InvalidDataException("version/generation/request/kind");
    }
}
