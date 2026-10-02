namespace WindowsBrokerSpike;

// Deterministic model used by the harness, not a replacement for fido-service or its permits.
// One launch, one retained client, one request. Reconnect never adopts the old authority.
internal sealed class Lifecycle(Guid broker, Guid client)
{
    private Request? active;
    private string? decision;
    private bool revoked;
    private bool closed;
    private bool delivered;

    internal void Begin(Request request)
    {
        Wire.Check(request, broker);
        if (closed || active != null || request.Client != client)
            throw new InvalidOperationException("closed/stale client/zero queue");
        active = request;
    }

    internal void Decide(Request request, string result)
    {
        if (active != request || closed || decision != null)
            throw new InvalidOperationException("stale/duplicate/late completion");
        decision = result;
    }

    internal void Revoke(string failure)
    {
        if (delivered) return;
        revoked = true;
        decision = failure; // Failure vetoes a success waiting for teardown.
    }

    internal Response Finish(bool quiescent)
    {
        if (!quiescent || active == null || delivered || decision == null)
            throw new InvalidOperationException("no teardown proof/terminal result");
        delivered = true;
        closed = true;
        return new(Wire.Version, broker, client, active.Id,
            revoked ? "revoked:" + decision : decision);
    }
}

internal sealed class ResponseSlot(Request request)
{
    private bool consumed;
    internal void Accept(Response response)
    {
        if (consumed || response.Version != Wire.Version || response.Broker != request.Broker
            || response.Client != request.Client || response.Id != request.Id || string.IsNullOrEmpty(response.Result))
            throw new InvalidDataException("stale/duplicate/late response");
        consumed = true;
    }
    internal void LoseBroker() => consumed = true;
}
