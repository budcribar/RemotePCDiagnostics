using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Logging;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Benchmarks;

/// <summary>Why a pass cannot start. <see cref="Setting"/> is the control that blocks it (<c>restartBeforeAfter</c>, <c>enabled</c>, <c>baseline</c> or <c>benchmark</c>).</summary>
public sealed record BenchmarkBlock(string Setting, string Reason);

/// <summary>One pass an agent can start, and why it cannot when <see cref="Available"/> is false.</summary>
public sealed record BenchmarkStartChoice(string Pass, bool Restart, string Control, bool Available, string? Setting = null, string? Reason = null);

/// <summary>
/// One benchmark kind an agent can turn on or off. <see cref="Control"/> is the checkbox test id when <see cref="Available"/> is true.
/// A kind the PC cannot run has no control: it is reported, and it cannot be enabled.
/// </summary>
public sealed record BenchmarkTestChoice(string Id, bool Available, bool Enabled, string? Control = null, string? Reason = null);

/// <summary>Which benchmark kinds are saved as enabled, and which this PC can turn on.</summary>
public static class BenchmarkTestRules
{
    /// <summary>Shown when a kind is hidden because this PC lacks the hardware or software it measures.</summary>
    public const string UnavailableReason = "This PC doesn't have the hardware or software this test needs.";

    /// <summary>The checkbox test id for one kind. The id is the kind's name, the same string as <c>settings.enabled</c>.</summary>
    public static string Control(BenchmarkKind kind) => "bench-enable-" + kind;

    /// <summary>Every kind, in catalog order. Hidden kinds are included as unavailable and have no <see cref="BenchmarkTestChoice.Control"/>.</summary>
    public static IReadOnlyList<BenchmarkTestChoice> Choices(BenchmarkSettings settings, Func<BenchmarkKind, bool> isAvailable) =>
        Benchmarks.All.Select(info =>
        {
            var available = isAvailable(info.Kind);
            return new BenchmarkTestChoice(
                info.Kind.ToString(), available, settings.IsEnabled(info.Kind),
                available ? Control(info.Kind) : null, available ? null : UnavailableReason);
        }).ToList();

    /// <summary>
    /// The enabled list after turning <paramref name="kind"/> on or off, in enum order, the same list the Benchmark page saves.
    /// Turning a hidden kind on leaves the list as it was.
    /// </summary>
    public static IReadOnlyList<BenchmarkKind> WithEnabled(BenchmarkSettings settings, BenchmarkKind kind, bool on, bool available)
    {
        if (on && !available)
            return settings.Enabled;
        var set = settings.Enabled.ToList();
        if (on && !set.Contains(kind)) set.Add(kind);
        if (!on) set.Remove(kind);
        return Enum.GetValues<BenchmarkKind>().Where(set.Contains).ToList();
    }
}

/// <summary>Result of asking for a pass. <see cref="Started"/> is false when nothing ran and the restart choice was left as it was.</summary>
public sealed record BenchmarkPassStart(bool Started, BenchmarkBlock? Blocked, RemediationResult? Restart);

/// <summary>Rules for starting a benchmark pass. A refusal names the blocking setting and does not change the restart choice.</summary>
public static class BenchmarkStartRules
{
    public const string RestartSetting = "restartBeforeAfter";
    public const string EnabledSetting = "enabled";
    public const string BaselineSetting = "baseline";
    public const string RunningSetting = "benchmark";

    public static string Control(BenchmarkPhase phase, bool restart) =>
        (restart ? "bench-restart-" : "bench-run-") + (phase == BenchmarkPhase.Before ? "before" : "after");

    /// <param name="restartPending">A pass is saved to run after a restart.</param>
    /// <param name="restartImminent">This app asked Windows to restart moments ago, so the restart is still counting down.</param>
    public static BenchmarkBlock? Block(BenchmarkPhase phase, bool restart, bool busy, bool hasBaseline, bool hasMeasurements, bool restartPending, bool canRestart,
        bool restartImminent = false)
    {
        if (busy)
            return new(RunningSetting, "A benchmark is already running.");
        if (!hasMeasurements)
            return new(EnabledSetting, "No measurements are selected.");
        if (phase == BenchmarkPhase.After && !hasBaseline)
            return new(BaselineSetting, "Run the before benchmark first.");
        if (restartImminent)
            return new(RestartSetting, "Windows is about to restart to run a benchmark.");
        // A pass without a restart may still start: the restart may have been cancelled in Windows, and starting it drops the waiting one.
        if (restart && restartPending)
            return new(RestartSetting, "A restart is already waiting to run a benchmark.");
        if (restart && !canRestart)
            return new(RestartSetting, "Restarting isn't available from here.");
        return null;
    }
}

/// <summary>
/// Before/after benchmarks for one service call. State (settings, the "before" run, a pending "after") is saved, so the
/// "before" survives the restart and the "after" can run by itself once the PC is back.
/// </summary>
public sealed class BenchmarkService(BenchmarkRunner runner, IBenchmarkStore store, RemediationService? remediation = null,
    ISessionContext? session = null, Action<LogLevel, string>? events = null, ILogger? log = null, Func<TimeSpan, CancellationToken, Task>? delay = null,
    DeveloperBuildRunner? devRunner = null, IDeveloperEnvironmentProbe? devEnv = null)
{
    private readonly object _gate = new();
    private BenchmarkState _state = LoadState(store);

    private static BenchmarkState LoadState(IBenchmarkStore store) => LoadSaved(store) ?? new BenchmarkState(new BenchmarkSettings());

    private static BenchmarkState? LoadSaved(IBenchmarkStore store)
    {
        var state = store.Load();
        if (state is null) return null;
        if (state.Settings.SchemaVersion < BenchmarkSettings.CurrentSchemaVersion)
        {
            var added = new List<BenchmarkKind>();
            if (state.Settings.SchemaVersion < 2)
                added.AddRange(Benchmarks.IdleResourceKinds.Concat(Benchmarks.ResourceSnapshotKinds));
            if (state.Settings.SchemaVersion < 3)
                added.Add(BenchmarkKind.Speedometer);
            var enabled = Enum.GetValues<BenchmarkKind>().Where(state.Settings.Enabled.Union(added).Contains).ToList();
            state = state with { Settings = state.Settings with { SchemaVersion = BenchmarkSettings.CurrentSchemaVersion, Enabled = enabled } };
            store.Save(state);
        }
        return state;
    }
    private CancellationTokenSource? _cts;

    public event Action? Changed;
    /// <summary>A pass finished (completed or stopped with results kept) and was saved. Raised after the save, off the UI thread.</summary>
    public event Action<BenchmarkRun>? PassFinished;
    public BenchmarkSettings Settings => _state.Settings;
    public BenchmarkRun? Before => _state.Before;
    public BenchmarkRun? After => _state.After;
    public bool AfterPendingRestart => _state.RunAfterOnStartup;
    public bool BeforePendingRestart => _state.RunBeforeOnStartup;
    public BenchmarkPhase? Running { get; private set; }
    public BenchmarkPhase? Settling { get; private set; }
    public TimeSpan? SettleRemaining { get; private set; }
    public TimeSpan? SettleTotal { get; private set; }
    public double? SettleFraction { get; private set; }
    public string? Progress { get; private set; }
    public string? Message { get; private set; }
    /// <summary>The last start that was refused. Cleared when a pass actually starts. A refusal does not change <see cref="BenchmarkSettings.RestartBeforeAfter"/>.</summary>
    public BenchmarkBlock? Blocked { get; private set; }

    /// <summary>Clock for the restart countdown (tests replace it).</summary>
    public TimeProvider Clock { get; init; } = TimeProvider.System;

    /// <summary>How long after this app asks Windows to restart (60 s warning) a pass without a restart stays blocked.</summary>
    public static readonly TimeSpan RestartCountdown = TimeSpan.FromMinutes(2);
    private DateTimeOffset? _restartScheduledAt;
    private bool RestartImminent => _restartScheduledAt is { } at && Clock.GetUtcNow() - at < RestartCountdown
        && (BeforePendingRestart || AfterPendingRestart);
    public BenchmarkComparison Comparison => BenchmarkComparison.Build(Before, After);

    // ---- Developer benchmarks (Phase 1 & 2) ----
    public IReadOnlyList<DetectedToolchain> DetectedToolchains { get; private set; } = [];
    public DevDrivePrecheckResult? DevDrivePrecheck { get; private set; }
    public DeveloperBuildResult? LastAntivirusComparison { get; private set; }
    public DevDriveComparisonResult? LastDevDriveComparison { get; private set; }
    public bool RunningDeveloperAction { get; private set; }

    /// <summary>
    /// True when a benchmark kind should be shown on this PC. Developer kinds are hidden when their toolchain is absent,
    /// and the C# clean build is also hidden when the installed SDK is older than the pin can target (NPU rule: do not offer a test this PC cannot run).
    /// </summary>
    public bool IsKindAvailable(BenchmarkKind kind)
    {
        if (!Benchmarks.IsDeveloperKind(kind)) return true;
        var lang = Benchmarks.LanguageFor(kind);
        if (lang is null) return false;
        var tc = DetectedToolchains.FirstOrDefault(t => t.Language == lang.Value);
        if (tc is null) return false;
        if (lang == DeveloperLanguage.CSharp)
            return DeveloperCSharpPin.TargetFrameworkForSdk(tc.MajorVersion) is not null;
        return true;
    }

    public IReadOnlyList<BenchmarkInfo> AvailableBenchmarks =>
        Benchmarks.All.Where(i => IsKindAvailable(i.Kind)).ToList();

    public static string FormatCountdown(TimeSpan remaining)
    {
        var secs = Math.Max(0, (int)Math.Ceiling(remaining.TotalSeconds));
        return $"{secs / 60}:{secs % 60:00}";
    }

    public static async Task WaitWithCountdownAsync(TimeSpan duration, Func<TimeSpan, CancellationToken, Task> delay,
        Action<TimeSpan, double> onTick, CancellationToken ct, TimeSpan? tickInterval = null)
    {
        onTick(duration, 0.0);
        var waitTask = delay(duration, ct);
        if (!waitTask.IsCompleted && duration > TimeSpan.Zero)
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            var step = tickInterval ?? TimeSpan.FromSeconds(1);
            while (!waitTask.IsCompleted)
            {
                await Task.WhenAny(waitTask, Task.Delay(step, ct)).ConfigureAwait(false);
                if (waitTask.IsCompleted) break;
                var elapsed = sw.Elapsed;
                var rem = duration - elapsed;
                if (rem < TimeSpan.Zero) rem = TimeSpan.Zero;
                var frac = Math.Clamp(elapsed.TotalSeconds / duration.TotalSeconds, 0.0, 1.0);
                onTick(rem, frac);
            }
        }
        await waitTask.ConfigureAwait(false);
    }

    private void Log(string m) => log.Info("[benchmark] " + m);
    private void LogWarn(string m) => log.Warn("[benchmark] " + m);
    private void Raise() { try { Changed?.Invoke(); } catch (Exception ex) { LogWarn("Changed handler failed: " + ex.Message); } }
    private void Save(BenchmarkState s) { lock (_gate) _state = s; store.Save(s); Raise(); }

    /// <summary>
    /// Reads the saved state again: the app reads it through the Agent, which may connect after the service was made. Does nothing while a
    /// benchmark runs or waits, or when nothing could be read. True when it read the state.
    /// </summary>
    public bool Reload()
    {
        if (Running is not null || Settling is not null) return false;
        var saved = LoadSaved(store);
        if (saved is null) return false;
        lock (_gate)
        {
            if (Running is not null || Settling is not null) return false;
            _state = saved;
        }
        Raise();
        return true;
    }

    public void UpdateSettings(BenchmarkSettings s)
    {
        if (Running is not null || Settling is not null) return;
        Save(_state with { Settings = s with { Runs = Math.Clamp(s.Runs, 1, 5), Enabled = s.Enabled.Distinct().ToList() } });
    }

    public BenchmarkBlock? BlockFor(BenchmarkPhase phase, bool restart) => BenchmarkStartRules.Block(
        phase, restart, Running is not null || Settling is not null || RunningDeveloperAction, Before is not null,
        Settings.Enabled.Count > 0, BeforePendingRestart || AfterPendingRestart, remediation is not null, RestartImminent);

    /// <summary>Every benchmark kind, including kinds hidden on this PC, and the checkbox that toggles each available one.</summary>
    public IReadOnlyList<BenchmarkTestChoice> TestChoices() => BenchmarkTestRules.Choices(Settings, IsKindAvailable);

    public IReadOnlyList<BenchmarkStartChoice> StartChoices() =>
        new[] { BenchmarkPhase.Before, BenchmarkPhase.After }
            .SelectMany(phase => new[] { false, true }.Select(restart =>
            {
                var block = BlockFor(phase, restart);
                return new BenchmarkStartChoice(
                    phase == BenchmarkPhase.Before ? "before" : "after", restart, BenchmarkStartRules.Control(phase, restart),
                    block is null, block?.Setting, block?.Reason);
            }))
            .ToList();

    /// <summary>
    /// Starts <paramref name="phase"/> with the requested restart choice. The choice is saved only once the pass has started
    /// (the run is underway, or Windows has been asked to restart). A refusal leaves <see cref="BenchmarkSettings.RestartBeforeAfter"/> as it was.
    /// </summary>
    public async Task<BenchmarkPassStart> BeginPassAsync(BenchmarkPhase phase, bool restart, CancellationToken ct = default)
    {
        var block = BlockFor(phase, restart);
        if (block is not null)
        {
            Blocked = block;
            Raise();
            return new(false, block, null);
        }

        Blocked = null;
        if (restart)
        {
            var result = phase == BenchmarkPhase.Before
                ? await RestartThenRunBeforeAsync(ct).ConfigureAwait(false)
                : await RestartThenRunAfterAsync(ct).ConfigureAwait(false);
            if (!result.Success)
            {
                Blocked = new BenchmarkBlock(BenchmarkStartRules.RestartSetting, result.Message);
                Raise();
                return new(false, Blocked, result);
            }
            return new(true, null, result);
        }

        var run = await RunAsync(phase, ct, restartChoice: false).ConfigureAwait(false);
        if (run is null)
        {
            Blocked = new BenchmarkBlock(BenchmarkStartRules.RunningSetting, "A benchmark is already running.");
            Raise();
            return new(false, Blocked, null);
        }
        return new(true, null, null);
    }

    /// <summary>Starts a new service call: forgets earlier results (settings are kept).</summary>
    public void Clear()
    {
        if (Running is not null || Settling is not null) return;
        Message = null;
        Save(new BenchmarkState(Settings));
    }

    public void Stop() { try { _cts?.Cancel(); } catch (ObjectDisposedException) { } }

    /// <param name="bootsSince">Before only: count just the start-ups after this time (the service workflow's restart before the baseline).</param>
    /// <param name="restartChoice">When set, saved as soon as this run starts and not before. Null leaves the saved choice alone (resume after a restart already recorded it).
    /// False also drops a pass waiting for a restart: the person chose to run now instead.</param>
    public async Task<BenchmarkRun?> RunAsync(BenchmarkPhase phase, CancellationToken ct = default, DateTimeOffset? bootsSince = null, bool? restartChoice = null)
    {
        BenchmarkState? commit = null;
        lock (_gate)
        {
            if (Running is not null || Settling is not null) return null;
            if (restartChoice is { } choice)
            {
                var next = _state with { Settings = _state.Settings with { RestartBeforeAfter = choice } };
                if (!choice) next = next with { RunBeforeOnStartup = false, RunAfterOnStartup = false, RestartRequestedUtc = null };
                if (next != _state)
                {
                    _state = next;
                    commit = next;
                }
            }
            Running = phase;
            _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        }
        var cts = _cts;
        try
        {
            if (commit is not null) store.Save(commit);
            Message = null;
            Raise();
            var settings = Settings;
            var prog = new SyncProgress(p => { Progress = p; Raise(); });
            var preferredSpeedometerEngine = phase == BenchmarkPhase.After
                ? Before?.Get(BenchmarkKind.Speedometer)?.RunIdentity?.Engine
                : null;
            var run = await runner.RunAsync(phase, settings, phase == BenchmarkPhase.After ? Before?.TimeUtc : null, prog, cts.Token,
                phase == BenchmarkPhase.Before ? bootsSince : null, preferredSpeedometerEngine).ConfigureAwait(false);
            Save(phase == BenchmarkPhase.Before ? _state with { Before = run, After = null, RunBeforeOnStartup = false } : _state with { After = run });
            Message = run.Completed ? null : "Stopped before every benchmark finished; the finished ones are kept.";
            WriteEvent(run);
            try { PassFinished?.Invoke(run); } catch (Exception ex) { LogWarn("PassFinished handler failed: " + ex.Message); }
            return run;
        }
        finally
        {
            lock (_gate) { Running = null; Progress = null; _cts = null; }
            cts.Dispose();
            Raise();
        }
    }

    private sealed class SyncProgress(Action<string> onReport) : IProgress<string>
    {
        public void Report(string value) => onReport(value);
    }

    /// <summary>
    /// Remembers to run the "before" benchmark when the app starts again, then restarts the PC (60 s warning, auto-resume). Then the before and after
    /// start-up times are each one full restart the app asked for, instead of whatever the last few start-ups in Windows' log were.
    /// </summary>
    public async Task<RemediationResult> RestartThenRunBeforeAsync(CancellationToken ct = default)
    {
        if (remediation is null) return new(false, "Restarting isn't available from here.");
        if (Running is not null || Settling is not null) return new(false, "A benchmark is running.");
        var previous = _state;
        // The restart choice is saved with the pending pass, in one write, before Windows is asked to restart.
        Save(new BenchmarkState(Settings with { RestartBeforeAfter = true }, RunBeforeOnStartup: true, RestartRequestedUtc: Clock.GetUtcNow()));
        if (store.Load() is not { RunBeforeOnStartup: true }) return RestartNotSaved(previous);
        var r = await ScheduleRestartAsync(previous, ct).ConfigureAwait(false);
        Message = r.Success ? "Restarting in 60 seconds. The before benchmark runs by itself a few minutes after the PC is back." : r.Message;
        Raise();
        return r;
    }

    /// <summary>Remembers to run the "after" benchmark when the app starts again, then restarts the PC (60 s warning, auto-resume).</summary>
    public async Task<RemediationResult> RestartThenRunAfterAsync(CancellationToken ct = default)
    {
        if (remediation is null) return new(false, "Restarting isn't available from here.");
        if (Running is not null || Settling is not null) return new(false, "A benchmark is running.");
        if (Before is null) return new(false, "Run the before benchmark first.");
        var previous = _state;
        Save(_state with { Settings = _state.Settings with { RestartBeforeAfter = true }, RunAfterOnStartup = true });
        if (store.Load() is not { RunAfterOnStartup: true }) return RestartNotSaved(previous);
        var r = await ScheduleRestartAsync(previous, ct).ConfigureAwait(false);
        Message = r.Success ? "Restarting in 60 seconds. The after benchmark runs by itself a few minutes after the PC is back." : r.Message;
        Raise();
        return r;
    }

    /// <summary>
    /// Asks Windows to restart. When it doesn't, everything saved for the restart is put back as it was: the earlier results and the restart choice.
    /// </summary>
    private async Task<RemediationResult> ScheduleRestartAsync(BenchmarkState previous, CancellationToken ct)
    {
        RemediationResult r;
        try
        {
            r = await remediation!.ExecuteAsync(new AreaAction(RemediationKind.ScheduleCleanRestart, "Restart, then benchmark"), ct).ConfigureAwait(false);
        }
        catch
        {
            Save(previous);
            throw;
        }
        if (r.Success) _restartScheduledAt = Clock.GetUtcNow();
        else Save(previous);
        return r;
    }

    /// <summary>
    /// The restart must not go ahead when the request to run afterwards didn't reach the disk (the state folder is for administrators
    /// only, so the app saves it through the Agent, which may not be connected): the PC would restart and nothing would follow.
    /// </summary>
    private RemediationResult RestartNotSaved(BenchmarkState previous)
    {
        lock (_gate) _state = previous;
        Message = "The PC was not restarted: the benchmark could not be saved to run afterwards. " + ElevationService.AdminRepairHint;
        LogWarn("restart refused: the pending benchmark could not be saved");
        Raise();
        return new(false, Message);
    }

    /// <summary>
    /// Called once at app start: if a "before" or "after" was requested before a restart, wait for start-up to settle and run it.
    /// The request stays saved through the settle wait and is dropped when the pass starts (or the wait is stopped by hand), so
    /// an app that is itself restarted while waiting (a browser refresh starts a new copy) waits again and still runs the pass.
    /// Once the pass has started it is not tried again, even if it fails.
    /// </summary>
    public async Task ResumeAfterRestartAsync(CancellationToken ct = default)
    {
        if (!BeforePendingRestart && !AfterPendingRestart) return;
        var phase = BeforePendingRestart ? BenchmarkPhase.Before : BenchmarkPhase.After;
        var since = BeforePendingRestart ? _state.RestartRequestedUtc : null;
        var label = phase == BenchmarkPhase.Before ? "before" : "after";
        void Forget() => Save(phase == BenchmarkPhase.Before ? _state with { RunBeforeOnStartup = false } : _state with { RunAfterOnStartup = false });

        var wait = Settings.SettleAfterRestart;
        CancellationTokenSource settleCts;
        lock (_gate)
        {
            if (Running is not null || Settling is not null) return;
            Settling = phase;
            _cts = settleCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        }
        Log($"resume: {label} benchmark scheduled after settle");
        try
        {
            await WaitWithCountdownAsync(wait, delay ?? Task.Delay, (rem, frac) =>
            {
                SettleRemaining = rem;
                SettleTotal = wait;
                SettleFraction = frac;
                Message = $"Waiting {wait.TotalMinutes:0} minutes for start-up to settle before the {label} benchmark ({FormatCountdown(rem)} left)…";
                Raise();
            }, settleCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            Forget(); // stopped by hand: it must not start by itself at the next app start
            Message = $"Stopped waiting before the {label} benchmark started.";
            return;
        }
        finally
        {
            lock (_gate)
            {
                Settling = null;
                SettleRemaining = null;
                SettleTotal = null;
                SettleFraction = null;
                if (ReferenceEquals(_cts, settleCts)) _cts = null;
            }
            settleCts.Dispose();
            Raise();
        }
        Forget(); // once only from here on, even if this run fails
        await RunAsync(phase, ct, since).ConfigureAwait(false);
    }

    /// <summary>Read-only probe of installed toolchains and Dev Drive comparison eligibility. Never builds anything.</summary>
    public async Task RefreshDeveloperEnvironmentAsync(CancellationToken ct = default)
    {
        if (devEnv is null) return;
        try
        {
            DetectedToolchains = await devEnv.DetectToolchainsAsync(ct).ConfigureAwait(false);
            if (devRunner is not null)
                DevDrivePrecheck = await devRunner.EvaluateDevDrivePrecheckAsync(ct).ConfigureAwait(false);
            Raise();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            LogWarn("developer environment refresh failed: " + ex.Message);
        }
    }

    /// <summary>
    /// Approval-gated antivirus comparison: runs the C# clean build under current policy, then with a temporary Agent Defender
    /// exclusion on the RPCD temp folder, then removes the exclusion. Requires explicit <paramref name="userConfirmed"/> for this run.
    /// </summary>
    public async Task<DeveloperBuildResult?> RunAntivirusComparisonAsync(bool userConfirmed, CancellationToken ct = default)
    {
        if (!userConfirmed)
        {
            Message = "Antivirus comparison requires explicit approval for this run.";
            Raise();
            return null;
        }
        if (devRunner is null)
        {
            Message = "Developer benchmark runner is not available.";
            Raise();
            return null;
        }
        CancellationTokenSource cts;
        lock (_gate)
        {
            if (Running is not null || Settling is not null || RunningDeveloperAction) return null;
            RunningDeveloperAction = true;
            _cts = cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        }
        Message = DeveloperScoring.BusyPcWarning;
        Raise();
        try
        {
            var prog = new SyncProgress(p => { Progress = p; Raise(); });
            var res = await devRunner.RunCSharpCleanBuildAsync(new DeveloperBuildOptions(IncludeAntivirusComparison: true), prog, cts.Token).ConfigureAwait(false);
            LastAntivirusComparison = res;
            Message = res.Succeeded ? res.FormatDetail() : res.Note ?? "Antivirus comparison did not complete.";
            return res;
        }
        catch (OperationCanceledException)
        {
            Message = "Antivirus comparison cancelled; temporary exclusion and build folder were cleaned up.";
            return null;
        }
        finally
        {
            lock (_gate) { RunningDeveloperAction = false; Progress = null; if (ReferenceEquals(_cts, cts)) _cts = null; }
            cts.Dispose();
            Raise();
        }
    }

    /// <summary>
    /// Phase 2 opt-in Dev Drive comparison: builds the cached C# pin on NTFS, then on a temporary ~50 GB Dev Drive VHDX created
    /// and cleaned up by the elevated Agent. Requires explicit <paramref name="userConfirmed"/> for this run; never started by <see cref="RunAsync"/>.
    /// </summary>
    public async Task<DevDriveComparisonResult?> RunDevDriveComparisonAsync(bool userConfirmed, CancellationToken ct = default)
    {
        if (!userConfirmed)
        {
            Message = "Dev Drive comparison requires explicit approval for this run.";
            Raise();
            return null;
        }
        if (devRunner is null)
        {
            Message = "Developer benchmark runner is not available.";
            Raise();
            return null;
        }
        CancellationTokenSource cts;
        lock (_gate)
        {
            if (Running is not null || Settling is not null || RunningDeveloperAction) return null;
            RunningDeveloperAction = true;
            _cts = cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        }
        Message = DeveloperScoring.BusyPcWarning;
        Raise();
        try
        {
            var prog = new SyncProgress(p => { Progress = p; Raise(); });
            var res = await devRunner.RunDevDriveComparisonAsync(progress: prog, ct: cts.Token).ConfigureAwait(false);
            LastDevDriveComparison = res;
            Message = res.FormatSummary();
            return res;
        }
        catch (OperationCanceledException)
        {
            Message = "Dev Drive comparison cancelled; temporary VHDX and build folders were cleaned up.";
            return null;
        }
        finally
        {
            lock (_gate) { RunningDeveloperAction = false; Progress = null; if (ReferenceEquals(_cts, cts)) _cts = null; }
            cts.Dispose();
            Raise();
        }
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
