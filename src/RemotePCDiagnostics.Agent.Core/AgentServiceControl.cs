namespace RemotePCDiagnostics.Agent.Core;

/// <summary>
/// sc.exe arguments for <see cref="AgentLayout.ServiceName"/>.
/// Startup is Automatic, not delayed-auto: after an upgrade or a reboot the service has to reach the relay
/// without waiting out the delayed-start timer (about two minutes).
/// Failure restart is cleared while the old process is stopped, then put back before the new one is started.
/// A clean exit does not trip those actions, so a new process must not exit 0 while the previous one is still dying.
/// </summary>
public static class AgentServiceControl
{
    public const string AutomaticStartType = "auto";

    public const string FailureRestartActions = "reset= 86400 actions= restart/5000/restart/15000/restart/60000";

    public const string ClearedFailureActions = "reset= 0 actions= \"\"";

    public static string QuoteName(string name)
    {
        if (string.IsNullOrEmpty(name) || name.IndexOfAny([' ', '\t', '"']) < 0)
            return name;
        return "\"" + name.Replace("\"", "", StringComparison.Ordinal) + "\"";
    }

    public static string SetAutomatic(string serviceName) =>
        $"config {QuoteName(serviceName)} start= {AutomaticStartType}";

    public static string ClearFailureFlag(string serviceName) =>
        $"failureflag {QuoteName(serviceName)} 0";

    public static string ApplyFailureRestart(string serviceName) =>
        $"failure {QuoteName(serviceName)} {FailureRestartActions}";

    public static string ClearFailureRestart(string serviceName) =>
        $"failure {QuoteName(serviceName)} {ClearedFailureActions}";

    public static string Start(string serviceName) => $"start {QuoteName(serviceName)}";

    /// <summary>sc.exe arguments for one planned upgrade action. Empty when that action is not an sc.exe command.</summary>
    public static IReadOnlyList<string> ArgumentsFor(AgentUpgradeAction action) => action switch
    {
        DisableFailureRestartAction disable =>
        [
            ClearFailureFlag(disable.ServiceName),
            ClearFailureRestart(disable.ServiceName),
        ],
        EnsureServiceRecoveryAction ensure =>
        [
            SetAutomatic(ensure.ServiceName),
            ClearFailureFlag(ensure.ServiceName),
            ApplyFailureRestart(ensure.ServiceName),
        ],
        _ => [],
    };
}
