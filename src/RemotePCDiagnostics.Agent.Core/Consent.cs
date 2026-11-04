namespace RemotePCDiagnostics.Agent.Core;

public enum ConsentOutcome { Allowed, Declined, TimedOut, Failed }

/// <summary>Whether to ask the person at the PC, and how the <c>consent</c> prompt reports its answer.</summary>
public static class ConsentPolicy
{
    /// <summary>Exit codes of <c>RemotePCDiagnostics.Agent.exe consent</c>.</summary>
    public const int ExitAllowed = 0, ExitDeclined = 1, ExitTimedOut = 2, ExitFailed = 3;

    public const string Caption = "Remote PC Diagnostics";

    /// <summary>
    /// Ask unless both sides allow skipping it: the local ceiling is <see cref="ConsentCeiling.Unattended"/> AND the relay didn't ask for
    /// consent. The relay and technicians can only make it stricter.
    /// </summary>
    public static bool MustAsk(ConsentCeiling ceiling, bool requireConsent) => requireConsent || ceiling != ConsentCeiling.Unattended;

    public static string PromptText(string? technician)
    {
        var who = AgentCommandLine.CleanTechnician(technician);
        if (who.Length == 0) who = "A technician";
        return $"{who} wants to start a Remote PC Diagnostics session on this computer. Allow?";
    }

    public static ConsentOutcome FromExitCode(int exitCode) => exitCode switch
    {
        ExitAllowed => ConsentOutcome.Allowed,
        ExitDeclined => ConsentOutcome.Declined,
        ExitTimedOut => ConsentOutcome.TimedOut,
        _ => ConsentOutcome.Failed,
    };

    /// <summary>Win32 MessageBox results: IDYES = 6, IDNO = 7, MB_TIMEDOUT = 32000. Anything else (0 = the box couldn't be shown) is a failure.</summary>
    public static int ExitCodeForMessageBoxResult(int result) => result switch
    {
        6 => ExitAllowed,
        7 => ExitDeclined,
        32000 => ExitTimedOut,
        _ => ExitFailed,
    };
}
