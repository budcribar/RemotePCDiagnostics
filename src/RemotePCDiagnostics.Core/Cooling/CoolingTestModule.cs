using System.Text.Json.Serialization;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Stress;

namespace RemotePCDiagnostics.Core.Cooling;

[JsonConverter(typeof(JsonStringEnumConverter<CoolingTestMode>))]
public enum CoolingTestMode { Quick, Full }

/// <summary>Full CPU load while the fan response is watched; disposing it stops the load.</summary>
public interface ICoolingLoad
{
    IAsyncDisposable Start();
}

/// <summary>One worker per logical processor running the CPU stress test's checked workload (on the stress scheduler, full speed in the background).</summary>
public sealed class CpuCoolingLoad(ICpuWorkload? workload = null, int? threads = null) : ICoolingLoad
{
    public IAsyncDisposable Start() => new Running(workload ?? DeterministicCpuWorkload.Instance, Math.Max(1, threads ?? Environment.ProcessorCount));

    private sealed class Running : IAsyncDisposable
    {
        private int _stop;
        private readonly Task _workers;

        public Running(ICpuWorkload workload, int threads)
        {
            _workers = StressTaskScheduler.RunParallel(threads, t =>
            {
                var seed = 0x9E3779B97F4A7C15UL * (ulong)(t + 1);
                while (Volatile.Read(ref _stop) == 0) seed = workload.Compute(seed, 200_000) | 1UL;
            });
        }

        public async ValueTask DisposeAsync()
        {
            Volatile.Write(ref _stop, 1);
            await _workers.ConfigureAwait(false);
        }
    }
}

/// <summary>
/// Cooling test (DiagnosticTest #284): watches the CPU's heat at low load (fails when it stays near Tj max for a minute without work),
/// then runs 90 seconds of full CPU load and checks that the fans speed up and the temperature levels off, then (through the Agent) switches
/// every Windows power mode and the maker's thermal profile, reads each back, and puts the originals back. Reads the same sensors as
/// Temperatures &amp; fans. On demand only, never in Run all, cancellable; cancelling stops the load and restores the modes.
/// </summary>
public sealed class CoolingTestModule(
    ICoolingSource source,
    ICoolingLoad cpuLoad,
    Func<string?>? maker = null,
    ILogger? log = null,
    CoolingRules? rules = null,
    IStressClock? clock = null) : AreaModuleBase(log), IDiagnosticModule, ICancellableScan // relisted so IncludeInRunAll below reimplements it
{
    public const string ModuleName = ModuleSlugs.Cooling;
    public const string NeedsAgentText = "Needs the Agent: switching thermal modes needs administrator rights, which only the Agent has.";
    /// <summary>Samples at the start with neither a CPU temperature nor a fan before the test gives up (nothing to judge).</summary>
    public const int ProbeSamples = 3;

    private readonly CoolingRules _r = rules ?? CoolingRules.Default;
    private readonly object _scanGate = new();
    private CancellationTokenSource? _scan;

    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.Cooling;
    public override string DisplayName => "Cooling test";
    public bool IncludeInRunAll => false;
    protected override string FailedMessage => "The cooling test couldn't run.";

    /// <summary>Quick watches low load for 2 minutes, Full for 5. Set before the run starts.</summary>
    public CoolingTestMode Mode { get; set; } = CoolingTestMode.Quick;

    /// <summary>Switch and read back the thermal modes at the end (through the Agent). Set before the run starts.</summary>
    public bool SwitchModes { get; set; } = true;

    /// <summary>The live samples of the run in progress (the page draws them while it runs).</summary>
    public IReadOnlyList<CoolingSample> LiveSamples { get { lock (_samples) return [.. _samples]; } }
    private readonly List<CoolingSample> _samples = [];

    public TimeSpan IdleFor => Mode == CoolingTestMode.Full ? _r.IdleFull : _r.IdleQuick;
    /// <summary>About how long the run takes, without the mode switching.</summary>
    public TimeSpan Estimated => IdleFor + _r.LoadFor + _r.CoolFor;

    public void Cancel()
    {
        lock (_scanGate) _scan?.Cancel();
    }

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        using var scan = CancellationTokenSource.CreateLinkedTokenSource(ct);
        lock (_scanGate) _scan = scan;
        lock (_samples) _samples.Clear();
        var clk = clock ?? new StopwatchStressClock();
        var started = DateTimeOffset.Now;
        var modesTouched = false;
        var modesRestored = false;
        try
        {
            return await RunAsync(clk, started, progress, () => modesTouched = true, () => modesRestored = true, scan.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (scan.IsCancellationRequested)
        {
            if (ct.IsCancellationRequested) throw;
            return AreaReport.ScanCancelled() with { Summary = "Cooling test cancelled" + (modesTouched ? "; thermal modes put back" : "") };
        }
        finally
        {
            if (modesTouched && !modesRestored) await RestoreAsync().ConfigureAwait(false);
            lock (_scanGate) { if (ReferenceEquals(_scan, scan)) _scan = null; }
        }
    }

    private async Task<AreaReport> RunAsync(IStressClock clk, DateTimeOffset started, IProgress<string>? progress, Action touched, Action onRestored, CancellationToken ct)
    {
        var t0 = clk.Elapsed;
        double? tjMax = null;
        var approximate = false;
        var total = Estimated.TotalSeconds;

        async Task<CoolingSample> Take(string phase)
        {
            var reading = await source.SampleAsync(ct).ConfigureAwait(false);
            tjMax ??= reading.TjMaxC;
            approximate |= reading.Approximate;
            var s = new CoolingSample(Math.Round((clk.Elapsed - t0).TotalSeconds, 1), phase, reading.CpuC, reading.LoadPercent, reading.FanRpm);
            lock (_samples) _samples.Add(s);
            return s;
        }

        void Report(string text, CoolingSample s)
        {
            var now = $"{text} · CPU {(s.CpuC is { } c ? $"{c:0}°C" : "—")}, {(s.LoadPercent is { } l ? $"{l:0}%" : "—")} load{(s.FanRpm is { } f ? $", fan {f:N0} RPM" : "")}";
            progress.ReportStep((int)Math.Min(total, s.At), (int)total, now);
            RaiseUpdated(new DiagnosticResult<double>(Name, DiagnosticStatus.Running, now, started, Math.Min(100, s.At / total * 100)));
        }

        // Phase 1: low load. Load is the PC's own (the test adds none), so a hot CPU here is a cooling problem, not a workload.
        progress.ReportStep(0, (int)total, "Watching the CPU's heat at low load…");
        var idle = new List<CoolingSample>();
        var idleEnd = IdleFor.TotalSeconds;
        while (true)
        {
            var s = await Take(CoolingRules.Idle).ConfigureAwait(false);
            idle.Add(s);
            if (idle.Count == ProbeSamples && idle.All(x => x.CpuC is null && x.FanRpm is null))
                return new AreaReport([], "Not available on this PC: it reports no CPU temperature or fan speed", DiagnosticStatus.Warning) { NotOnThisPc = true };
            Report($"Heat at low load: {Clock(s.At)} of {Clock(idleEnd)}", s);
            if (s.At >= idleEnd - 1e-6) break;
            await clk.DelayAsync(_r.SampleEvery, ct).ConfigureAwait(false);
        }

        // Phase 2: full CPU load, stopped early when the CPU nears Tj max.
        var load = new List<CoolingSample>();
        double? stoppedAt = null;
        var idleLastAt = idle[^1].At;
        var loadEnd = idleLastAt + _r.LoadFor.TotalSeconds;
        var stopAbove = (tjMax ?? _r.DefaultTjMaxC) - _r.StopMarginC;
        if (idle[^1].CpuC is { } preTemp && preTemp >= stopAbove)
        {
            stoppedAt = preTemp;
            LogWarn($"[cooling] load skipped at {preTemp:0.0}°C (limit {stopAbove:0})");
        }
        else
        {
            Log($"[cooling] idle done ({idle.Count} samples, tjMax={tjMax?.ToString() ?? "unknown"}); starting {_r.LoadFor.TotalSeconds:0} s of full load");
            var running = cpuLoad.Start();
            try
            {
                while (true)
                {
                    await clk.DelayAsync(_r.SampleEvery, ct).ConfigureAwait(false);
                    var s = await Take(CoolingRules.Load).ConfigureAwait(false);
                    load.Add(s);
                    Report($"Fan response under full load: {Clock(s.At - idleLastAt)} of {Clock(_r.LoadFor.TotalSeconds)}", s);
                    if (s.CpuC is { } c && c >= stopAbove) { stoppedAt = c; LogWarn($"[cooling] load stopped at {c:0.0}°C (limit {stopAbove:0})"); break; }
                    if (s.At >= loadEnd - 1e-6) break;
                }
            }
            finally { await running.DisposeAsync().ConfigureAwait(false); }
        }

        // Phase 3: cooling down (shown on the chart; the temperature should fall once the load stops).
        var coolStart = load.Count > 0 ? load[^1].At : idleLastAt;
        var coolEnd = coolStart + _r.CoolFor.TotalSeconds;
        while (true)
        {
            await clk.DelayAsync(_r.SampleEvery, ct).ConfigureAwait(false);
            var s = await Take(CoolingRules.Cool).ConfigureAwait(false);
            Report($"Cooling down: {Clock(s.At - coolStart)} of {Clock(_r.CoolFor.TotalSeconds)}", s);
            if (s.At >= coolEnd - 1e-6) break;
        }

        var cards = new List<AreaCard>
        {
            CoolingJudge.IdleVerdict(idle, tjMax, approximate, _r),
            CoolingJudge.FanVerdict(idle, load, stoppedAt, _r),
        };

        // Phase 4: the maker's "fans at max" switch where there is one (HP Omen and Victus), then the thermal modes, both through the
        // Agent: each switched and read back, then the originals put back.
        AreaCard? fanMax = null;
        CoolingModesReply? listed = null;
        if (SwitchModes)
        {
            listed = await source.ModesAsync([CoolingModesAction.List], ct).ConfigureAwait(false);
            List<CoolingSample> cool;
            lock (_samples) cool = _samples.Where(x => x.Phase == CoolingRules.Cool).ToList();
            var loadPeakFan = load.Where(x => x.FanRpm is not null).Select(x => x.FanRpm!.Value).DefaultIfEmpty(double.NaN).Max();
            fanMax = await FanMaxAsync(listed, Take, Report, cool, double.IsNaN(loadPeakFan) ? null : loadPeakFan, clk, touched, ct).ConfigureAwait(false);
        }
        cards.Add(fanMax ?? CoolingJudge.FanControl(maker?.Invoke()));
        if (SwitchModes)
        {
            progress.ReportStep((int)total, (int)total, "Switching thermal modes…");
            RaiseUpdated(new DiagnosticResult<double>(Name, DiagnosticStatus.Running, "Switching thermal modes…", started, 100));
            cards.Add(await ModesAsync(listed!, clk, touched, onRestored, ct).ConfigureAwait(false));
        }
        List<CoolingSample> all;
        lock (_samples) all = [.. _samples];
        cards.Add(CoolingJudge.Samples(all, _r));
        return Build(cards, idle, load);
    }

    private async Task<AreaCard> ModesAsync(CoolingModesReply listed, IStressClock clk, Action touched, Action onRestored, CancellationToken ct)
    {
        const string title = "Thermal modes";
        var columns = new[] { "Setting", "Mode", "Result" };
        if (listed.NoAgent)
            return new(CoolingJudge.ModesCard, title, AreaLevel.Neutral, "Skipped: " + NeedsAgentText, "Windows power mode and the maker's thermal profile", columns, [],
                EmptyText: "Install the Agent (or turn on Admin Repair Mode) and run the test again to switch them.");
        if (!listed.Ok)
            return new(CoolingJudge.ModesCard, title, AreaLevel.Warning, "Couldn't read the thermal modes: " + listed.Error, "", columns, []);

        var rows = new List<AreaRow>();
        var failed = new List<string>();      // a mode that was refused, or read back as another, on a setting that does switch
        var stuck = new List<string>();       // a setting that took none of its modes: it reads the same whatever is set
        var switched = 0;
        var tookTotal = 0;                    // modes that changed a setting (not the one it already had)
        var notes = new List<string>();
        var groups = listed.Answer!.Groups.Where(g => g.Kind != CoolingModes.FanMaxKind).ToList();
        var windows = groups.FirstOrDefault(g => g.Kind == CoolingModes.WindowsKind && g.Options.Count > 0);
        // The other settings as each Windows power mode left them: one that changes with it follows the Windows power mode.
        var seenWithWindows = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
        foreach (var group in groups)
        {
            if (group.Options.Count == 0)
            {
                rows.Add(new(AreaLevel.Neutral, [group.Title, group.Current is { } c ? group.NameOf(c) : "—", "Not switched: " + (group.Note ?? "nothing to switch")]));
                continue;
            }
            var original = group.Current;
            rows.Add(new(AreaLevel.Neutral, [group.Title, group.NameOf(original), "Was set before the test"]));
            if (group.Kind != CoolingModes.WindowsKind && windows is not null
                && windows.Options.FirstOrDefault(o => o.Id == WindowsPowerMode.Balanced.ToString()) is { } balanced)
            {
                // Some makers tie their profile to the Windows power mode; with Windows on Balanced the profile is free to change.
                touched();
                var w = await source.ModesAsync([CoolingModesAction.Set, CoolingModes.WindowsKind, balanced.Id], ct).ConfigureAwait(false);
                if (w.Ok && w.Answer!.SetError is null)
                    rows.Add(new(AreaLevel.Neutral, [windows.Title, balanced.Name, $"Set first, so the {group.Title} isn't held by Best performance"]));
            }
            var took = 0;
            var groupFailed = new List<(string Option, string Why, AreaRow Row)>();
            foreach (var option in group.Options)
            {
                touched();
                var r = await source.ModesAsync([CoolingModesAction.Set, group.Kind, option.Id], ct).ConfigureAwait(false);
                var back = r.Answer?.Group(group.Kind)?.Current;
                if (group.Kind == CoolingModes.WindowsKind && r.Answer is { } after)
                    foreach (var other in after.Groups.Where(g => g.Kind != group.Kind && g.Current is not null))
                        (seenWithWindows.TryGetValue(other.Kind, out var seen) ? seen : seenWithWindows[other.Kind] = new(StringComparer.OrdinalIgnoreCase)).Add(other.Current!);
                if (!r.Ok || r.Answer!.SetError is not null)
                {
                    var why = r.Error ?? r.Answer!.SetError!;
                    groupFailed.Add((option.Name, why, new(AreaLevel.Warning, [group.Title, option.Name, "Couldn't set: " + why])));
                }
                else if (!string.Equals(back, option.Id, StringComparison.OrdinalIgnoreCase))
                    groupFailed.Add((option.Name, $"reads {group.NameOf(back)}", new(AreaLevel.Warning, [group.Title, option.Name, $"Didn't read back as set: reads {group.NameOf(back)}"])));
                else
                {
                    rows.Add(new(AreaLevel.Ok, [group.Title, option.Name, string.Equals(option.Id, original, StringComparison.OrdinalIgnoreCase) ? "Already set" : "Set and read back"]));
                    switched++;
                    if (!string.Equals(option.Id, original, StringComparison.OrdinalIgnoreCase)) took++;
                }
                await clk.DelayAsync(TimeSpan.FromMilliseconds(500), ct).ConfigureAwait(false);
            }
            tookTotal += took;
            if (groupFailed.Count > 0 && took == 0)
            {
                // Nothing but the mode it already had: the setting doesn't switch from Windows here. Not a cooling fault.
                stuck.Add($"{group.Title} stays at {group.NameOf(original)}");
                rows.AddRange(groupFailed.Select(f => f.Row with { Level = AreaLevel.Neutral }));
            }
            else
            {
                rows.AddRange(groupFailed.Select(f => f.Row));
                failed.AddRange(groupFailed.Select(f => $"{f.Option} ({f.Why})"));
            }
        }
        foreach (var (kind, seen) in seenWithWindows)
            if (seen.Count > 1 && groups.FirstOrDefault(g => g.Kind == kind) is { } follower)
                notes.Add($"The {follower.Title} changed with the Windows power mode ({string.Join(", ", seen.Select(follower.NameOf))}), so it follows that setting.");

        var restored = true;
        if (switched + failed.Count + stuck.Count > 0)
        {
            restored = await RestoreAsync().ConfigureAwait(false);
            onRestored();
            rows.Add(new(restored ? AreaLevel.Ok : AreaLevel.Warning, ["All", "Before the test", restored ? "Put back" : "Couldn't be put back; the Agent tries again when it next starts"]));
        }
        if (!restored) notes.Add("The modes in use before the test couldn't all be put back. Check Settings, System, Power (Power mode) and the maker's app.");
        if (stuck.Count > 0)
            notes.Add("A setting that reads the same whatever is set is either held by the maker's service (or the Windows power mode) or its firmware accepts the request without acting on it. That says nothing about the cooling itself.");

        var meta = string.Join(" · ", groups.Select(g => $"{g.Title}: {g.NameOf(g.Current)}").Concat(stuck.Select(x => "Not switchable here: " + x)));
        var note = notes.Count > 0 ? string.Join(" ", notes) : null;
        // A mode that won't switch is worth a look (firmware, the maker's app), but it isn't a cooling fault: a warning at most.
        if (failed.Count > 0)
            return new(CoolingJudge.ModesCard, title, AreaLevel.Warning, "Profile won't set: " + string.Join(", ", failed), meta, columns, rows,
                Note: string.Join(" ", ["A thermal mode that won't set (or reads back as another) points to the maker's firmware or its service. Update the BIOS and the maker's app.", .. notes]), PreserveRowOrder: true);
        if (tookTotal == 0)
            return new(CoolingJudge.ModesCard, title, AreaLevel.Neutral,
                stuck.Count > 0 ? "Not switchable here: " + string.Join("; ", stuck) + " whatever is set" : "Not supported: no thermal mode on this PC can be switched from Windows",
                meta, columns, rows, Note: note, PreserveRowOrder: true);
        return new(CoolingJudge.ModesCard, title, restored ? AreaLevel.Ok : AreaLevel.Warning,
            $"Passed: {AreaModuleBase.Plural(tookTotal, "mode")} switched and read back{(restored ? ", then put back" : "; the old modes couldn't all be put back")}", meta, columns, rows,
            Note: note, PreserveRowOrder: true);
    }

    /// <summary>
    /// Sets the maker's fans to max for <see cref="CoolingRules.FanMaxFor"/> with the CPU idle, watching their speed, then puts them back.
    /// Null when this PC has no such switch (the fan control card then says so) or the Agent isn't there.
    /// </summary>
    private async Task<AreaCard?> FanMaxAsync(CoolingModesReply listed, Func<string, Task<CoolingSample>> take, Action<string, CoolingSample> report, IReadOnlyList<CoolingSample> before,
        double? loadPeakFan, IStressClock clk, Action touched, CancellationToken ct)
    {
        if (!listed.Ok || listed.Answer!.Group(CoolingModes.FanMaxKind) is not { Options.Count: > 0 } group) return null;
        var original = group.Current ?? HpFanMaxSetting.Auto;
        var maxName = group.NameOf(HpFanMaxSetting.Max);
        touched();
        var set = await source.ModesAsync([CoolingModesAction.Set, CoolingModes.FanMaxKind, HpFanMaxSetting.Max], ct).ConfigureAwait(false);
        var setError = !set.Ok ? set.Error : set.Answer!.SetError;
        var readBack = setError is null && string.Equals(set.Answer!.Group(CoolingModes.FanMaxKind)?.Current, HpFanMaxSetting.Max, StringComparison.Ordinal);
        var atMax = new List<CoolingSample>();
        try
        {
            if (setError is null)
            {
                var start = clk.Elapsed;
                while (clk.Elapsed - start < _r.FanMaxFor)
                {
                    await clk.DelayAsync(_r.SampleEvery, ct).ConfigureAwait(false);
                    var s = await take(CoolingRules.FanMax).ConfigureAwait(false);
                    atMax.Add(s);
                    report($"Fans at max: {Clock((clk.Elapsed - start).TotalSeconds)} of {Clock(_r.FanMaxFor.TotalSeconds)}", s);
                }
            }
        }
        finally
        {
            // Back to how it was (automatic) straight away, from the journal, so the thermal modes after this start from a fresh one.
            if (!await RestoreAsync().ConfigureAwait(false)) LogWarn($"[cooling] fans at max not put back to {group.NameOf(original)}");
        }
        return CoolingJudge.FanMaxVerdict(maxName, setError, readBack, before, atMax, loadPeakFan, _r);
    }

    private async Task<bool> RestoreAsync()
    {
        try
        {
            var r = await source.ModesAsync([CoolingModesAction.Restore], CancellationToken.None).ConfigureAwait(false);
            if (!r.Ok) LogWarn($"[cooling] restore failed: {r.Error}");
            return r.Ok && r.Answer!.Restored != false;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException) { LogWarn($"[cooling] restore failed: {ex.Message}"); return false; }
    }

    private AreaReport Build(List<AreaCard> cards, IReadOnlyList<CoolingSample> idle, IReadOnlyList<CoolingSample> load)
    {
        var status = AreaReport.Worst(cards.Select(c => c.Level));
        var judged = cards.Where(c => c.Id is CoolingJudge.IdleCard or CoolingJudge.FansCard or CoolingJudge.ModesCard).ToList();
        var worst = judged.Where(c => c.Level is AreaLevel.Error).Concat(judged.Where(c => c.Level is AreaLevel.Warning)).FirstOrDefault();
        var passed = judged.Where(c => c.Level == AreaLevel.Ok).Select(c => c.Headline.StartsWith("Passed: ", StringComparison.Ordinal) ? c.Headline["Passed: ".Length..] : c.Headline).ToList();
        var summary = worst is not null ? worst.Headline : passed.Count > 0 ? "Passed: " + string.Join(" · ", passed) : "Cooling test finished";
        var metrics = new List<KeyMetric>();
        if (CoolingJudge.Median(idle.Where(s => s.CpuC is not null && (s.LoadPercent is not { } l || l < _r.LowLoadPercent)).Select(s => s.CpuC!.Value)) is { } it)
            metrics.Add(new("cooling.idle-cpu", "CPU temperature at low load", Math.Round(it), "°C", MetricTrend.LowerIsBetter));
        if (load.Where(s => s.CpuC is not null).Select(s => s.CpuC!.Value).DefaultIfEmpty(double.NaN).Max() is var lt && !double.IsNaN(lt))
            metrics.Add(new("cooling.load-cpu", "Hottest CPU temperature under load", Math.Round(lt), "°C", MetricTrend.LowerIsBetter));
        // The summary keeps the whole verdict; the cards show it as a short label with the sentence in their list.
        return new AreaReport(cards.Select(CoolingJudge.Compact).ToList(), summary, status) { KeyMetrics = metrics.Count > 0 ? metrics : null };
    }

    private static string Clock(double seconds)
    {
        var s = (int)Math.Max(0, Math.Round(seconds));
        return $"{s / 60}:{s % 60:00}";
    }
}
