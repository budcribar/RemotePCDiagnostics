using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Logging;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Benchmarks;

/// <summary>
/// Before/after benchmarks for one service call. State (settings, the "before" run, a pending "after") is saved, so the
/// "before" survives the restart and the "after" can run by itself once the PC is back.
/// </summary>
public sealed class BenchmarkService(BenchmarkRunner runner, IBenchmarkStore store, RemediationService? remediation = null,
    ISessionContext? session = null, Action<LogLevel, string>? events = null, ILogger? log = null, Func<TimeSpan, CancellationToken, Task>? delay = null)
{
    private readonly object _gate = new();
    private BenchmarkState _state = LoadState(store);

    private static BenchmarkState LoadState(IBenchmarkStore store)
    {
        var state = store.Load();
        if (state is null) return new BenchmarkState(new BenchmarkSettings());
        if (state.Settings.SchemaVersion < BenchmarkSettings.CurrentSchemaVersion)
        {
            var added = Benchmarks.IdleResourceKinds.Concat(Benchmarks.ResourceSnapshotKinds);
            var enabled = Enum.GetValues<BenchmarkKind>().Where(state.Settings.Enabled.Union(added).Contains).ToList();
            state = state with { Settings = state.Settings with { SchemaVersion = BenchmarkSettings.CurrentSchemaVersion, Enabled = enabled } };
            store.Save(state);
        }
        return state;
    }
    private CancellationTokenSource? _cts;

    public event Action? Changed;
    public BenchmarkSettings Settings => _state.Settings;
    public BenchmarkRun? Before => _state.Before;
    public BenchmarkRun? After => _state.After;
    public bool AfterPendingRestart => _state.RunAfterOnStartup;
    public bool BeforePendingRestart => _state.RunBeforeOnStartup;
    public BenchmarkPhase? Running { get; private set; }
    public string? Progress { get; private set; }
    public string? Message { get; private set; }
    public BenchmarkComparison Comparison => BenchmarkComparison.Build(Before, After);

    private void Log(string m) => log.Info("[benchmark] " + m);
    private void LogWarn(string m) => log.Warn("[benchmark] " + m);
    private void Raise() { try { Changed?.Invoke(); } catch (Exception ex) { LogWarn("Changed handler failed: " + ex.Message); } }
    private void Save(BenchmarkState s) { lock (_gate) _state = s; store.Save(s); Raise(); }

    public void UpdateSettings(BenchmarkSettings s)
    {
        if (Running is not null) return;
        Save(_state with { Settings = s with { Runs = Math.Clamp(s.Runs, 1, 5), Enabled = s.Enabled.Distinct().ToList() } });
    }

    /// <summary>Starts a new service call: forgets earlier results (settings are kept).</summary>
    public void Clear()
    {
        if (Running is not null) return;
        Message = null;
        Save(new BenchmarkState(Settings));
    }

    public void Stop() { try { _cts?.Cancel(); } catch (ObjectDisposedException) { } }

    /// <param name="bootsSince">Before only: count just the start-ups after this time (the service workflow's restart before the baseline).</param>
    public async Task<BenchmarkRun?> RunAsync(BenchmarkPhase phase, CancellationToken ct = default, DateTimeOffset? bootsSince = null)
    {
        lock (_gate)
        {
            if (Running is not null) return null;
            Running = phase;
            _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        }
        Message = null;
        Raise();
        var cts = _cts;
        try
        {
            var settings = Settings;
            var prog = new Progress<string>(p => { Progress = p; Raise(); });
            var run = await runner.RunAsync(phase, settings, phase == BenchmarkPhase.After ? Before?.TimeUtc : null, prog, cts.Token,
                phase == BenchmarkPhase.Before ? bootsSince : null).ConfigureAwait(false);
            Save(phase == BenchmarkPhase.Before ? _state with { Before = run, After = null, RunBeforeOnStartup = false } : _state with { After = run });
            Message = run.Completed ? null : "Stopped before every benchmark finished; the finished ones are kept.";
            WriteEvent(run);
            return run;
        }
        finally
        {
            lock (_gate) { Running = null; Progress = null; _cts = null; }
            cts.Dispose();
            Raise();
        }
    }

    /// <summary>
    /// Remembers to run the "before" benchmark when the app starts again, then restarts the PC (60 s warning, auto-resume). Then the before and after
    /// start-up times are each one full restart the app asked for, instead of whatever the last few start-ups in Windows' log were.
    /// </summary>
    public async Task<RemediationResult> RestartThenRunBeforeAsync(CancellationToken ct = default)
    {
        if (remediation is null) return new(false, "Restarting isn't available from here.");
        if (Running is not null) return new(false, "A benchmark is running.");
        Save(new BenchmarkState(Settings, RunBeforeOnStartup: true, RestartRequestedUtc: DateTimeOffset.UtcNow));
        var r = await remediation.ExecuteAsync(new AreaAction(RemediationKind.ScheduleCleanRestart, "Restart, then benchmark"), ct).ConfigureAwait(false);
        if (!r.Success) Save(_state with { RunBeforeOnStartup = false, RestartRequestedUtc = null });
        Message = r.Success ? "Restarting in 60 seconds. The before benchmark runs by itself a few minutes after the PC is back." : r.Message;
        Raise();
        return r;
    }

    /// <summary>Remembers to run the "after" benchmark when the app starts again, then restarts the PC (60 s warning, auto-resume).</summary>
    public async Task<RemediationResult> RestartThenRunAfterAsync(CancellationToken ct = default)
    {
        if (remediation is null) return new(false, "Restarting isn't available from here.");
        if (Before is null) return new(false, "Run the before benchmark first.");
        Save(_state with { RunAfterOnStartup = true });
        var r = await remediation.ExecuteAsync(new AreaAction(RemediationKind.ScheduleCleanRestart, "Restart, then benchmark"), ct).ConfigureAwait(false);
        if (!r.Success) Save(_state with { RunAfterOnStartup = false });
        Message = r.Success ? "Restarting in 60 seconds. The after benchmark runs by itself a few minutes after the PC is back." : r.Message;
        Raise();
        return r;
    }

    /// <summary>Called once at app start: if an "after" was requested before a restart, wait for start-up to settle and run it.</summary>
    public async Task ResumeAfterRestartAsync(CancellationToken ct = default)
    {
        if (BeforePendingRestart)
        {
            var since = _state.RestartRequestedUtc;
            Save(_state with { RunBeforeOnStartup = false }); // once only, even if this run fails
            Message = $"Waiting {Settings.SettleAfterRestart.TotalMinutes:0} minutes for start-up to settle before the before benchmark…";
            Raise();
            Log("resume: before benchmark scheduled after settle");
            await (delay ?? Task.Delay)(Settings.SettleAfterRestart, ct).ConfigureAwait(false);
            await RunAsync(BenchmarkPhase.Before, ct, since).ConfigureAwait(false);
            return;
        }
        if (!AfterPendingRestart) return;
        Save(_state with { RunAfterOnStartup = false }); // once only, even if this run fails
        Message = $"Waiting {Settings.SettleAfterRestart.TotalMinutes:0} minutes for start-up to settle before the after benchmark…";
        Raise();
        Log("resume: after benchmark scheduled after settle");
        await (delay ?? Task.Delay)(Settings.SettleAfterRestart, ct).ConfigureAwait(false);
        await RunAsync(BenchmarkPhase.After, ct).ConfigureAwait(false);
    }

    private void WriteEvent(BenchmarkRun run)
    {
        try
        {
            var actor = ServiceActor.From(session);
            var lines = run.Measurements.Select(m => $"  {m.Kind}={m.Median?.ToString("0.###", System.Globalization.CultureInfo.InvariantCulture) ?? "n/a"}");
            var text = $"Performance benchmark ({run.Phase})\r\nActor: {actor}\r\nCompleted: {(run.Completed ? "yes" : "no")}\r\nOn battery: {run.Conditions.OnBattery?.ToString() ?? "unknown"}\r\nResults:\r\n{string.Join("\r\n", lines)}";
            if (run.Phase == BenchmarkPhase.After && Before is not null) text += "\r\n" + Comparison.OverallText;
            events?.Invoke(LogLevel.Information, text);
        }
        catch (Exception ex) { LogWarn("event write failed: " + ex.Message); }
    }
}
