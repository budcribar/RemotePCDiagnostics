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
            var t = service.RunAsync(name, isBackgroundAutoRun: true);
            _ = t.ContinueWith(r => log.Info($"Auto-run: {name} finished: {(r.IsCompletedSuccessfully ? r.Result.Status.ToString() : r.Exception?.GetBaseException().Message)}"), TaskScheduler.Default);
            tasks.Add(t);
        }
        return tasks;
    }

    /// <summary>
    /// Starts all enabled read-only checks (<see cref="IDiagnosticModule.IncludeInRunAll"/>) in the background, prioritizing
    /// <see cref="ModuleSlugs.Osquery"/> and <see cref="Sensors.LibreHardwareMonitorModule.ModuleName"/> first and throttling
    /// concurrency so older PCs stay responsive. When <paramref name="slowChecksDelay"/> is set, the remaining (longer) system
    /// checks wait for that grace window after launch so immediate RPCD updates are not competing with WUA/WMI/BIOS scans.
    /// Respects <see cref="EnvironmentVariable"/> and <see cref="Checks.CheckSettings"/>.
    /// </summary>
    public static Task StartEnabledChecksAsync(
        DiagnosticsService service,
        Checks.CheckSettingsService? settings,
        Func<string, string?> getEnv,
        ILogger? log,
        int maxConcurrency = 3,
        TimeSpan? slowChecksDelay = null,
        CancellationToken ct = default)
    {
        if (!IsEnabled(getEnv))
        {
            log.Info("Auto-run disabled via " + EnvironmentVariable);
            return Task.CompletedTask;
        }

        var checkSettings = settings?.Settings ?? new Checks.CheckSettings();
        var priorityNames = new[] { ModuleSlugs.Osquery, Sensors.LibreHardwareMonitorModule.ModuleName };
        var enabledOrdered = Checks.CheckEnableRules.ApplyOrder(
            service.Modules.Where(m => m.IncludeInRunAll && checkSettings.IsEnabled(m.Name)).Select(m => m.Name),
            id => id,
            checkSettings.Order);

        var fastQueue = new List<string>();
        var restQueue = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in priorityNames)
            if (checkSettings.IsEnabled(p) && service.CanRun(p) && seen.Add(p))
                fastQueue.Add(p);
        foreach (var name in enabledOrdered)
            if (service.CanRun(name) && seen.Add(name))
                restQueue.Add(name);

        if (fastQueue.Count == 0 && restQueue.Count == 0) return Task.CompletedTask;

        var limit = Math.Max(1, maxConcurrency);
        return Task.Run(async () =>
        {
            using var gate = new SemaphoreSlim(limit, limit);

            async Task RunBatchAsync(IReadOnlyList<string> batch)
            {
                if (batch.Count == 0) return;
                var tasks = batch.Select(async name =>
                {
                    await gate.WaitAsync(ct).ConfigureAwait(false);
                    try
                    {
                        if (ct.IsCancellationRequested) return;
                        if (settings is not null && !settings.IsEnabled(name)) return;
                        log.Info($"Auto-run: starting {name}");
                        var result = await service.RunAsync(name, ct: ct, isBackgroundAutoRun: true).ConfigureAwait(false);
                        log.Info($"Auto-run: {name} finished: {result.Status}");
                    }
                    catch (OperationCanceledException) { }
                    catch (Exception ex) { log.Info($"Auto-run: {name} failed: {ex.Message}"); }
                    finally { gate.Release(); }
                }).ToList();
                await Task.WhenAll(tasks).ConfigureAwait(false);
            }

            if (slowChecksDelay is { } delay && delay > TimeSpan.Zero && restQueue.Count > 0)
            {
                await RunBatchAsync(fastQueue).ConfigureAwait(false);
                try { await Task.Delay(delay, ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { return; }
                await RunBatchAsync(restQueue).ConfigureAwait(false);
            }
            else
            {
                var all = new List<string>(fastQueue.Count + restQueue.Count);
                all.AddRange(fastQueue);
                all.AddRange(restQueue);
                await RunBatchAsync(all).ConfigureAwait(false);
            }
        }, ct);
    }
}
