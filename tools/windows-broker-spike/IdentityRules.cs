namespace WindowsBrokerSpike;

internal static class IdentityRules
{
    internal static void SameSession(TokenIdentity one, TokenIdentity two)
    {
        if (one.Sid != two.Sid || one.LogonSid != two.LogonSid || one.Logon != two.Logon || one.Session != two.Session)
            throw new InvalidOperationException("alternate identity/session/logon unsupported; no authority migration");
    }

    internal static void SameProcess(uint retainedPid, long retainedCreation, uint pipePid, long pipeCreation)
    {
        if (retainedPid != pipePid || retainedCreation != pipeCreation)
            throw new InvalidDataException("pipe process is not retained launch; PID reuse/replacement");
    }
}
