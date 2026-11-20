using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Migrations;
using RemotePCDiagnostics.Core.Session;
using ILogger = Microsoft.Extensions.Logging.ILogger;
using RemotePCDiagnostics.Logging;

namespace RemotePCDiagnostics.Agent;

/// <summary>
/// The administrator-only setup the app used to do when it was started as administrator, done by the Agent for it (the app never runs
/// as administrator; <see cref="AdminPipeFraming.OpPrepareMachine"/>):
/// <list type="bullet">
/// <item>secures %ProgramData%\RemotePCDiagnostics and its admin-only state folder, and moves the state files there from the user's
/// %LOCALAPPDATA% (only when <paramref name="legacyStateFolder"/> is given: the agent service runs as SYSTEM, whose profile isn't the
/// user's);</item>
/// <item>registers the app's Windows Event Log source in its own log;</item>
/// <item>runs the one-time history updates (event log format 3, then the move to the app's own log).</item>
/// </list>
/// Each part is a no-op once done (markers in migrations.json), so the app asks every time the Agent connects.
/// </summary>
public sealed class AgentMachineSetup(ILogger? log, string? legacyStateFolder) : IMachineSetup
{
    private readonly object _gate = new();

    /// <summary>For the elevated helper and launcher, which run with the signed-in user's own (elevated) token.</summary>
    public static AgentMachineSetup ForSignedInUser(ILogger? log) => new(log, ProtectedState.LegacyFolder());

    /// <summary>For the agent service (SYSTEM): everything except moving the user's old state files.</summary>
    public static AgentMachineSetup ForService(ILogger? log) => new(log, null);

    public MachineSetupResult Prepare()
    {
        lock (_gate)
        {
            if (!OperatingSystem.IsWindows())
                return new(false, false, nameof(MigrationOutcome.Waiting), nameof(MigrationOutcome.Waiting));
            var secured = SecureStateFolder();
            var source = EnsureEventSource();
            var markers = new MigrationMarkers(MigrationMarkers.DefaultPath());
            var workDir = EventLogV3Migration.DefaultWorkDir();
            var v3 = Run("History update (event log format 3)", () =>
                new EventLogV3Migration(new WindowsEventLogMigrationIo(log), markers, workDir, log).Run());
            var move = Run($"Event log move to the {AppEventLog.OwnLogName} log", () =>
                new EventLogMoveMigration(new WindowsEventLogMoveIo(), markers, workDir, log).Run());
            return new(secured, source, v3.ToString(), move.ToString());
        }
    }

    private bool SecureStateFolder()
    {
        if (!ProtectedStateFolder.Ensure(log)) return false;
        if (legacyStateFolder is not null)
        {
            try
            {
                var outcome = new ProtectedStateMigration(legacyStateFolder, ProtectedState.Folder(),
                    new MigrationMarkers(MigrationMarkers.DefaultPath()), log).Run();
                if (outcome != MigrationOutcome.AlreadyDone) log.Info($"State move to {ProtectedState.Folder()}: {outcome}");
            }
            catch (Exception ex) { log.Warn($"State move to {ProtectedState.Folder()} failed: {ex.Message}"); }
        }
        try { AgentPaths.EnsureSessionsDirectory(); } catch { }
        return true;
    }

    /// <summary>
    /// Registers the source in the app's own log when it isn't registered anywhere. A PC that had events before has it under Application
    /// until <see cref="EventLogMoveMigration"/> moves it.
    /// </summary>
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

    private MigrationOutcome Run(string name, Func<MigrationOutcome> migration)
    {
        try
        {
            var outcome = migration();
            if (outcome != MigrationOutcome.AlreadyDone) log.Info($"{name}: {outcome}");
            return outcome;
        }
        catch (Exception ex)
        {
            log.Warn($"{name} failed: {ex.Message}");
            return MigrationOutcome.Failed;
        }
    }
}
