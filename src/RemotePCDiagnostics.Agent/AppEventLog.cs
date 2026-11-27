using System.Diagnostics;

namespace RemotePCDiagnostics.Agent;

/// <summary>
/// The app's Windows Event Log: source "RemotePCDiagnostics" in its own log "RemotePCDiagnostics" (Applications and Services Logs).
/// Registering the source needs administrator, so the Agent does it (<see cref="AgentMachineSetup"/>); the app only writes through it.
/// </summary>
public static class AppEventLog
{
    public const string OwnLogName = "RemotePCDiagnostics";
    public const string SourceName = "RemotePCDiagnostics";
    /// <summary>Size of the app's own log; the oldest entries are overwritten when it is full.</summary>
    public const int OwnLogKilobytes = 20480;

    /// <summary>Registers the source under the app's own log and sets the log's size (administrator).</summary>
    public static void CreateOwnLog()
    {
        if (!OperatingSystem.IsWindows()) return;
        if (!EventLog.SourceExists(SourceName)) EventLog.CreateEventSource(new EventSourceCreationData(SourceName, OwnLogName));
        using var log = new EventLog(OwnLogName);
        if (log.MaximumKilobytes != OwnLogKilobytes) log.MaximumKilobytes = OwnLogKilobytes;
        log.ModifyOverflowPolicy(OverflowAction.OverwriteAsNeeded, 0);
    }

    /// <summary>
    /// Whether the source is registered. Without administrator, Windows can only answer "yes": looking for a missing source also
    /// searches the Security log, which throws, so that counts as not registered.
    /// </summary>
    public static bool SourceRegistered()
    {
        if (!OperatingSystem.IsWindows()) return false;
        try { return EventLog.SourceExists(SourceName); }
        catch (System.Security.SecurityException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
    }
}
