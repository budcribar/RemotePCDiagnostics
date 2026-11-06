namespace RemotePCDiagnostics.Core;

/// <summary>Launch-time background run of selected modules (host side). Disable with REMOTEPC_AUTORUN=0.</summary>
public static class AutoRun
{
    public const string EnvironmentVariable = "REMOTEPC_AUTORUN";

    public static bool IsEnabled(Func<string, string?> getEnv)
    {
        var v = getEnv(EnvironmentVariable)?.Trim();
        return !(v is "0" || string.Equals(v, "false", StringComparison.OrdinalIgnoreCase) || string.Equals(v, "off", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Starts the named modules in the background if enabled; returns the started tasks (empty when disabled). Never throws.</summary>
    public static IReadOnlyList<Task<DiagnosticResult>> Start(DiagnosticsService service, Func<string, string?> getEnv, ILogger? log, params string[] moduleNames)
    {
        if (!IsEnabled(getEnv)) { log.Info("Auto-run disabled via " + EnvironmentVariable); return []; }
        var tasks = new List<Task<DiagnosticResult>>();
        foreach (var name in moduleNames)
        {
            // Not service.Modules: that hides detectable modules (Drive health) until detection finishes, which is usually after launch.
            if (!service.CanRun(name)) continue;
            log.Info($"Auto-run: starting {name}");
            var t = service.RunAsync(name);
            _ = t.ContinueWith(r => log.Info($"Auto-run: {name} finished: {(r.IsCompletedSuccessfully ? r.Result.Status.ToString() : r.Exception?.GetBaseException().Message)}"), TaskScheduler.Default);
            tasks.Add(t);
        }
        return tasks;
    }
}
