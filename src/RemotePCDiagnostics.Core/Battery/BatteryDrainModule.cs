using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Stress;

namespace RemotePCDiagnostics.Core.Battery;

/// <summary>What the page shows while a drain runs: the state line and every reading so far.</summary>
public sealed record BatteryDrainLive(BatteryDrainMode Mode, string State, string Message, bool Paused, IReadOnlyList<BatteryDrainSample> Samples)
{
    public BatteryDrainMeasure Measure => BatteryDrainMeasure.From(Samples);
}

/// <summary>
/// Guided battery drain and runtime measurement (RPCD #295). Runs only on battery: the app works the PC (maximum load or balanced), the
/// Agent keeps it from sleeping, dimming or hibernating and puts those settings back afterwards, and at 5 % it shuts the PC down (once
/// the person confirmed they saved their work; unconfirmed, the run stops at 15 %). A reading every 30 s goes to a log on disk, so a PC
/// that turns off mid-run is still judged at the next start: Failed above 10 %. Never part of Run all; Cancel stops it and restores.
/// </summary>
public sealed class BatteryDrainModule(
    IBatteryDrainReadings readings, IBatteryDrainAgent agent, IBatteryDrainLoad load, IBatteryDrainLogStore logs,
    ILogger? log = null, IStressClock? clock = null, Func<DateTimeOffset>? now = null, Func<DateTimeOffset>? bootTime = null,
    Func<int>? processId = null) : AreaModuleBase(log), IDiagnosticModule, ICancellableScan // relisted so IncludeInRunAll below reimplements it
{
    public const string ModuleName = ModuleSlugs.BatteryDrain;
    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.BatteryDrain;
    public override string DisplayName => "Battery drain & runtime test";
    protected override string FailedMessage => "Couldn't run the battery drain test on this PC.";
    public bool IncludeInRunAll => false;

    /// <summary>The next run's mode (the page and Admin set it; Maximum load otherwise).</summary>
    public BatteryDrainMode Mode { get; set; } = BatteryDrainMode.MaxLoad;

    private volatile bool _confirmed;
    /// <summary>The person saved their work and agreed to the shutdown at 5 %. May be set before the run or while it runs.</summary>
    public bool ShutdownConfirmed
    {
        get => _confirmed;
        set { _confirmed = value; LiveChanged?.Invoke(this, EventArgs.Empty); }
    }

    /// <summary>The running drain's state, or null when none runs.</summary>
    public BatteryDrainLive? Live { get; private set; }
    /// <summary>The readings of the last run that finished in this app session (for batterydrain-data).</summary>
    public IReadOnlyList<BatteryDrainSample>? LastSamples { get; private set; }

    /// <summary>Raised on every reading and change of state (the page redraws).</summary>
    public event EventHandler? LiveChanged;

    private readonly object _cancelGate = new();
    private CancellationTokenSource? _run;
    private readonly IStressClock _clock = clock ?? new StopwatchStressClock();

    public void Cancel()
    {
        lock (_cancelGate) _run?.Cancel();
    }

    private DateTimeOffset Now() => (now ?? (() => DateTimeOffset.UtcNow))();
    private DateTimeOffset Boot() => (bootTime ?? (() => DateTimeOffset.UtcNow - TimeSpan.FromMilliseconds(Environment.TickCount64)))();
    private int Pid() => (processId ?? (() => Environment.ProcessId))();

    /// <summary>
    /// A run that never ended the way the app meant it to and isn't this app's live one: the PC turned off (a different boot) or the app
    /// closed. Null otherwise.
    /// </summary>
    public (BatteryDrainRunLog Log, BatteryDrainEnd End)? Leftover()
    {
        if (Live is not null || logs.Read() is not { End: null } run) return null;
        // The same boot (within a couple of minutes: the clock may have been adjusted) means only the app went away.
        var sameBoot = (run.BootUtc - Boot()).Duration() < TimeSpan.FromMinutes(2);
        return (run, sameBoot ? BatteryDrainEnd.AppClosed : BatteryDrainEnd.PcShutOff);
    }

    /// <summary>The batteries now (the page shows the charge and whether the charger is connected before a run).</summary>
    public Task<BatteryDrainReading?> ReadNowAsync(CancellationToken ct) => readings.ReadAsync(ct);

    public override Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken cancellationToken = default) => Task.FromResult(ModuleAvailability.Available);

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        // A run the PC (or the app) didn't finish is judged first: its readings are where it stopped.
        if (Leftover() is { } left)
        {
            logs.Write(null);
            var leftMode = BatteryDrainReport.ParseMode(left.Log.Mode) ?? BatteryDrainMode.MaxLoad;
            Log($"{Name}: the last run ended without the app ({left.End}) at {left.Log.Samples.LastOrDefault()?.Percent} %.");
            // An Agent that missed the end (it restarted with the PC) puts the settings back at its start; ask anyway.
            var restored = await agent.SendAsync(BatteryDrainPowerAction.Restore, CancellationToken.None).ConfigureAwait(false);
            return BatteryDrainReport.Build(left.Log.Samples, leftMode, left.End, left.Log.ShutdownConfirmed, PowerText(restored, applied: true),
                "found when the test was next run; run it again to start a new drain");
        }

        var first = await readings.ReadAsync(ct).ConfigureAwait(false);
        if (first is null || first.PercentOrComputed is null)
            return BatteryDrainReport.NotStarted("No battery", "This PC reports no battery, so there is nothing to drain.", notOnThisPc: true);
        if (first.OnAc)
            return BatteryDrainReport.NotStarted("Unplug the charger to start",
                "The test measures the battery, so it only starts on battery. Unplug the charger, then run it again.");
        if (first.PercentOrComputed <= BatteryDrainLimits.ConfirmByPercent)
            return BatteryDrainReport.NotStarted($"The battery is at {first.PercentOrComputed} %",
                $"Charge it to at least {Math.Max(BatteryDrainLimits.MinPercentToJudge + BatteryDrainLimits.ConfirmByPercent, 50)} % (100 % gives the best measurement), unplug the charger, then run the test.");

        var applied = await agent.SendAsync(BatteryDrainPowerAction.Apply, ct).ConfigureAwait(false);
        if (applied.NeedsAgent)
            return BatteryDrainReport.NotStarted(BatteryDrainReport.NeedsAgentSummary, applied.Error is { } e && e.Contains("too old", StringComparison.Ordinal) ? e
                : "Keeping the PC awake through the run, putting the power settings back and the shutdown at 5 % need administrator rights. " + ElevationService.AdminRepairHint,
                needsAgent: true);
        if (!applied.Ok) return BatteryDrainReport.NotStarted("Couldn't change the power settings", applied.Error ?? "The Agent didn't change them.");

        var mode = Mode;
        using var run = CancellationTokenSource.CreateLinkedTokenSource(ct);
        lock (_cancelGate) _run = run;
        var samples = new List<BatteryDrainSample>();
        var started = Now();
        var t0 = _clock.Elapsed;
        var runLog = new BatteryDrainRunLog
        {
            Mode = BatteryDrainReport.ModeArg(mode), StartedUtc = started, BootUtc = Boot(), ProcessId = Pid(), ShutdownConfirmed = ShutdownConfirmed,
        };
        BatteryDrainEnd end = BatteryDrainEnd.Cancelled;
        string? endDetail = null;
        BatteryDrainAgentAnswer? finish = null;
        try
        {
            Add(samples, first, t0);
            Save(runLog, samples);
            load.Start(mode);
            Publish(mode, "running", samples, false, progress);
            (end, endDetail) = await DrainAsync(mode, samples, runLog, t0, progress, run.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (run.IsCancellationRequested)
        {
            end = BatteryDrainEnd.Cancelled;
        }
        finally
        {
            load.Stop();
            lock (_cancelGate) if (ReferenceEquals(_run, run)) _run = null;
            // The log is finished before the shutdown is asked for, so a clean end never looks like a PC that turned off.
            logs.Write(runLog with { Samples = [.. samples], End = end.ToString(), ShutdownConfirmed = ShutdownConfirmed });
            var shutDown = end == BatteryDrainEnd.ReachedStop && ShutdownConfirmed;
            finish = await agent.SendAsync(shutDown ? BatteryDrainPowerAction.Shutdown : BatteryDrainPowerAction.Restore, CancellationToken.None).ConfigureAwait(false);
            if (shutDown && !finish.Ok) endDetail = "the Agent couldn't shut the PC down: " + finish.Error;
            LastSamples = [.. samples];
            Live = null;
            LiveChanged?.Invoke(this, EventArgs.Empty);
            logs.Write(null);
        }
        Log($"{Name}: {end} after {samples.Count} readings ({samples.FirstOrDefault()?.Percent} % → {samples.LastOrDefault()?.Percent} %).");
        return BatteryDrainReport.Build(samples, mode, end, ShutdownConfirmed, PowerText(finish, applied: true), endDetail);
    }

    private async Task<(BatteryDrainEnd, string?)> DrainAsync(BatteryDrainMode mode, List<BatteryDrainSample> samples, BatteryDrainRunLog runLog,
        TimeSpan t0, IProgress<string>? progress, CancellationToken ct)
    {
        var missed = 0;
        var agentMissed = 0;
        TimeSpan? pausedAt = null;
        var limit = BatteryDrainLimits.MaxDuration(mode);
        while (true)
        {
            await _clock.DelayAsync(BatteryDrainLimits.SampleEvery, ct).ConfigureAwait(false);
            var renewed = await agent.SendAsync(BatteryDrainPowerAction.Renew, ct).ConfigureAwait(false);
            agentMissed = renewed.Ok ? 0 : agentMissed + 1;
            // The Agent puts the settings back three minutes after the last renew, so the run can't go on without it.
            if (agentMissed >= BatteryDrainLimits.MaxMissedReadings) return (BatteryDrainEnd.ReadingsLost, "the Agent stopped answering: " + renewed.Error);

            var r = await readings.ReadAsync(ct).ConfigureAwait(false);
            if (r?.PercentOrComputed is null)
            {
                if (++missed >= BatteryDrainLimits.MaxMissedReadings) return (BatteryDrainEnd.ReadingsLost, "the battery stopped reporting its charge");
                continue;
            }
            missed = 0;
            var s = Add(samples, r, t0);
            Save(runLog, samples);

            if (s.OnAc)
            {
                if (pausedAt is null)
                {
                    pausedAt = _clock.Elapsed;
                    load.Stop();
                    Log($"{Name}: charger connected at {s.Percent} %: paused.");
                }
                if (_clock.Elapsed - pausedAt >= BatteryDrainLimits.ResumeWindow) return (BatteryDrainEnd.ChargerConnected, null);
                var left = BatteryDrainLimits.ResumeWindow - (_clock.Elapsed - pausedAt.Value);
                Publish(mode, "paused", samples, true, progress, $"Charger connected: paused. Unplug it within {Math.Max(1, (int)Math.Ceiling(left.TotalMinutes))} min to resume.");
                continue;
            }
            if (pausedAt is not null)
            {
                pausedAt = null;
                load.Start(mode);
                Log($"{Name}: on battery again at {s.Percent} %: resumed.");
            }

            if (s.Percent <= BatteryDrainLimits.StopAtPercent) return (ShutdownConfirmed ? BatteryDrainEnd.ReachedStop : BatteryDrainEnd.NotConfirmed, null);
            if (s.Percent <= BatteryDrainLimits.ConfirmByPercent && !ShutdownConfirmed) return (BatteryDrainEnd.NotConfirmed, null);
            if (_clock.Elapsed - t0 >= limit) return (BatteryDrainEnd.TimeLimit, null);
            Publish(mode, "running", samples, false, progress);
        }
    }

    private BatteryDrainSample Add(List<BatteryDrainSample> samples, BatteryDrainReading r, TimeSpan t0)
    {
        var s = BatteryDrainSample.Of(r, Now(), Math.Round((_clock.Elapsed - t0).TotalSeconds, 1));
        samples.Add(s);
        return s;
    }

    private void Save(BatteryDrainRunLog runLog, List<BatteryDrainSample> samples) =>
        logs.Write(runLog with { Samples = [.. samples], ShutdownConfirmed = ShutdownConfirmed });

    private void Publish(BatteryDrainMode mode, string state, List<BatteryDrainSample> samples, bool paused, IProgress<string>? progress, string? message = null)
    {
        var m = BatteryDrainMeasure.From(samples);
        var last = samples[^1];
        message ??= $"Draining ({(mode == BatteryDrainMode.Balanced ? "balanced" : "maximum load")}): {last.Percent} % · {BatteryDrainReport.Duration(m.BatterySeconds)} · "
                    + $"{BatteryDrainReport.Wh(m.DeliveredMWh)} delivered" + (m.AverageWatts is { } w ? $" · {w:0.0} W" : "")
                    + (ShutdownConfirmed ? $" · shuts down at {BatteryDrainLimits.StopAtPercent} %" : $" · stops at {BatteryDrainLimits.ConfirmByPercent} % unless the shutdown is confirmed");
        Live = new BatteryDrainLive(mode, state, message, paused, [.. samples]);
        // Progress from the charge used so far towards the stop level.
        var startPct = samples[0].Percent ?? 100;
        var stopAt = ShutdownConfirmed ? BatteryDrainLimits.StopAtPercent : BatteryDrainLimits.ConfirmByPercent;
        var span = Math.Max(1, startPct - stopAt);
        progress.ReportStep(Math.Clamp((startPct - (last.Percent ?? startPct)) * 1000 / span, 0, 1000), 1000, message);
        LiveChanged?.Invoke(this, EventArgs.Empty);
    }

    private static string PowerText(BatteryDrainAgentAnswer? a, bool applied)
    {
        if (!applied) return "";
        if (a is null) return "Couldn't put back: the Agent didn't answer. It puts them back by itself within 3 minutes.";
        if (!a.Ok) return "Couldn't put back now: " + a.Error + ". The Agent tries again within 3 minutes and at its next start.";
        return a.Answer!.ShutdownInSeconds is { } s
            ? $"Sleep, display and battery settings put back; the PC shuts down {s} s after the end"
            : "Sleep, display and battery settings were changed for the run and put back";
    }
}
