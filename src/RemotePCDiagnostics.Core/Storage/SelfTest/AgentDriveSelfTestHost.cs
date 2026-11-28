using System.Runtime.Versioning;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Core.Storage;

/// <summary>
/// The Agent's one <see cref="AgentDriveSelfTest"/>: the PC's drives and power plan, the power journal in the protected state folder, and a
/// timer that lets go of the power settings once no drive is testing (the app may have closed while a test ran).
/// </summary>
[SupportedOSPlatform("windows")]
public static class AgentDriveSelfTestHost
{
    public static readonly TimeSpan IdleCheckEvery = TimeSpan.FromMinutes(1);
    private static readonly object Gate = new();
    private static AgentDriveSelfTest? _instance;
    private static SelfTestPowerGuard? _guard;
    private static Timer? _timer;

    public static ProcessResult Run(DriveSelfTestAction action)
    {
        var instance = Instance();
        var result = instance.Run(action);
        lock (Gate)
        {
            // The timer runs only while the power settings are held.
            if (_guard!.Holding) _timer ??= new Timer(_ => Tick(), null, IdleCheckEvery, IdleCheckEvery);
            else { _timer?.Dispose(); _timer = null; }
        }
        return result;
    }

    /// <summary>
    /// When the Agent starts: puts back power settings a self-test changed before a crash or restart (a restart also stops the test).
    /// Never throws.
    /// </summary>
    public static void RecoverAtStart(ILogger? log = null)
    {
        try
        {
            var path = ProtectedState.PathFor(SelfTestPowerGuard.JournalFile);
            if (!File.Exists(path)) return;
            log.Info("[selftest] A drive self-test's power settings were still changed at start; restoring them when no drive is testing.");
            Instance(log).CheckIdle();
        }
        catch (Exception ex) { log.Warn($"[selftest] Couldn't restore the power settings at start: {ex.Message}"); }
    }

    private static void Tick()
    {
        AgentDriveSelfTest instance;
        lock (Gate) instance = _instance!;
        instance.CheckIdle();
        lock (Gate)
        {
            if (_guard!.Holding) return;
            _timer?.Dispose();
            _timer = null;
        }
    }

    private static AgentDriveSelfTest Instance(ILogger? log = null)
    {
        lock (Gate)
        {
            if (_instance is not null) return _instance;
            _guard = new SelfTestPowerGuard(new WindowsSelfTestPowerSystem(), ProtectedState.PathFor(SelfTestPowerGuard.JournalFile), log);
            return _instance = new AgentDriveSelfTest(new WindowsSelfTestDevices(), _guard, log);
        }
    }
}
