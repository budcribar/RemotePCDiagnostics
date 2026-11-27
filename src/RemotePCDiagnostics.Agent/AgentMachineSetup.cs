using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Session;
using ILogger = Microsoft.Extensions.Logging.ILogger;
using RemotePCDiagnostics.Logging;

namespace RemotePCDiagnostics.Agent;

/// <summary>
/// The administrator-only setup the app needs, done by the Agent for it (the app never runs as administrator;
/// <see cref="AdminPipeFraming.OpPrepareMachine"/>):
/// <list type="bullet">
/// <item>secures %ProgramData%\RemotePCDiagnostics and its admin-only state folder;</item>
/// <item>registers the app's Windows Event Log source in its own log.</item>
/// </list>
/// Each part is a no-op once done, so the app asks every time the Agent connects.
/// </summary>
public sealed class AgentMachineSetup(ILogger? log) : IMachineSetup
{
    private readonly object _gate = new();

    public MachineSetupResult Prepare()
    {
        lock (_gate)
        {
            if (!OperatingSystem.IsWindows()) return new(false, false);
            return new(SecureStateFolder(), EnsureEventSource());
        }
    }

    private bool SecureStateFolder()
    {
        if (!ProtectedStateFolder.Ensure(log)) return false;
        try { AgentPaths.EnsureSessionsDirectory(); } catch { }
        return true;
    }

    /// <summary>Registers the source in the app's own log when it isn't registered yet.</summary>
    private bool EnsureEventSource()
    {
        try
        {
            if (AppEventLog.SourceRegistered()) return true;
            AppEventLog.CreateOwnLog();
            log.Info($"Event log: source '{AppEventLog.SourceName}' registered in the {AppEventLog.OwnLogName} log");
            return true;
        }
        catch (Exception ex)
        {
            log.Warn($"Event log: source '{AppEventLog.SourceName}' could not be registered: {ex.GetType().Name}: {ex.Message}");
            return false;
        }
    }
}
