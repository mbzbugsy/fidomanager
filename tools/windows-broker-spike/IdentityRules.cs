namespace WindowsBrokerSpike;

internal static class IdentityRules
{
    internal static void SameSession(TokenIdentity one, TokenIdentity two)
    {
        if (one.Sid != two.Sid || one.LogonSid != two.LogonSid || one.Logon != two.Logon || one.Session != two.Session)
            throw new InvalidOperationException($"alternate identity/session/logon unsupported; no authority migration (same-user={one.Sid == two.Sid}, same-logon-sid={one.LogonSid == two.LogonSid}, same-logon={one.Logon == two.Logon}, same-session={one.Session == two.Session})");
    }

    internal static void ElevationPair(TokenIdentity medium, TokenIdentity high, TokenIdentity linkedMedium)
    {
        // A different AuthenticationId is admitted only with an OS-derived linked-token proof.
        // Never admit another user/logon SID/session, or accept request-supplied identity data.
        if (medium.Elevated || medium.Integrity != 0x2000 || !high.Elevated || high.Integrity < 0x3000
            || medium.Sid != high.Sid || medium.LogonSid != high.LogonSid || medium.Session != high.Session
            || linkedMedium != medium)
            throw new InvalidOperationException("not an OS-linked same-user medium/high token pair");
    }
    internal static void SameProcess(uint retainedPid, long retainedCreation, uint pipePid, long pipeCreation)
    {
        if (retainedPid != pipePid || retainedCreation != pipeCreation)
            throw new InvalidDataException("pipe process is not retained launch; PID reuse/replacement");
    }
}
