using System.Globalization;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Sensors;
using RemotePCDiagnostics.Core.Stress;

namespace RemotePCDiagnostics.Core.GpuMemory;

/// <summary>
/// Graphics memory (VRAM) test: writes and checks patterns in each graphics chip's memory with a compute shader, Quick (walking ones and
/// zeros, address in address, random, about 1.5 minutes per chip) or Extended (those plus moving inversions, repeated for about 10 minutes
/// per chip). One card per graphics chip, tested one after the other. Never part of Run all; cancelled with Cancel. It is a stress test
/// too: the stress suite runs it after the GPU stress test, Quick in the short run and Extended in the long run, with the suite's time per
/// test shared by the chips. It runs in the app (no administrator rights) and offscreen, so it works from a remote session.
/// </summary>
public sealed class GpuMemoryModule(
    IGpuMemorySource source,
    ISensorProvider? sensors = null,
    ILogger? log = null,
    Func<IStressClock>? clockFactory = null,
    GpuMemoryOptions? options = null) : AreaModuleBase(log), ICancellableScan, IStressSuiteModule
{
    public const string ModuleName = ModuleSlugs.GpuMemory;
    private readonly object _scanGate = new();
    private CancellationTokenSource? _scan;

    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.GpuMemory;
    public override string DisplayName => "Graphics memory (VRAM) test";
    public bool IncludeInRunAll => false;
    protected override string FailedMessage => "The graphics memory test couldn't run.";

    /// <summary>Quick or Extended. Set before the run starts.</summary>
    public GpuMemoryMode Mode { get; set; } = GpuMemoryMode.Quick;

    private TimeSpan? _suiteTime;

    /// <summary>How long the whole run takes. Started on its own, each chip gets the mode's full time (Quick 1.5 min, Extended 10 min);
    /// the stress suite sets it to its time per test, and the chips share it (never under <see cref="MinPerChip"/> each).</summary>
    public TimeSpan Duration
    {
        get => _suiteTime ?? PerChip(null) * Math.Max(1, LastAdapters?.Count ?? 1);
        set => _suiteTime = value;
    }

    /// <summary>The shortest time a chip gets when the suite's time is shared: enough for at least one pass of every quick pattern.</summary>
    public static readonly TimeSpan MinPerChip = TimeSpan.FromSeconds(30);

    private TimeSpan PerChip(int? chips) =>
        _suiteTime is { } total && chips is > 0 ? TimeSpan.FromTicks(Math.Max(MinPerChip.Ticks, total.Ticks / chips.Value))
        : options?.Duration ?? GpuMemoryOptions.DefaultDuration(Mode);

    // ---- The stress suite ----------------------------------------------------------------------------------------------

    public string SuiteName => "Graphics memory";
    public void Stop() => Cancel();
    public object SaveSuiteSettings() => (Mode, _suiteTime);
    public void RestoreSuiteSettings(object saved) { if (saved is ValueTuple<GpuMemoryMode, TimeSpan?> s) { Mode = s.Item1; _suiteTime = s.Item2; } }

    /// <summary>Quick in the short run, Extended in the long run, for the suite's time per test.</summary>
    public void ApplySuiteMode(StressSuiteMode mode)
    {
        Mode = mode == StressSuiteMode.Extended ? GpuMemoryMode.Extended : GpuMemoryMode.Quick;
        _suiteTime = StressSuiteDurations.PerTest(mode);
    }

    public bool IsUnavailableResult(DiagnosticResult result) => result.Report() is AreaReport { NotOnThisPc: true };
    public bool IsOverheatedResult(DiagnosticResult result) =>
        result.Report() is AreaReport && LastResults is { } rs && rs.Any(r => r.Outcome == GpuMemoryOutcome.Overheated);
    public bool IsCouldNotRunResult(DiagnosticResult result) => result.Report() is AreaReport { CouldNotRunReason: not null } or Exception;
    public bool IsStoppedByUserResult(DiagnosticResult result) => result.Cancelled || result.Report() is AreaReport { Cancelled: true };

    /// <summary>The graphics chips as last listed (the page's preview, and each run). Null before the first read.</summary>
    public IReadOnlyList<GpuMemoryAdapter>? LastAdapters { get; private set; }

    /// <summary>The last run's results per chip (the page's details and the gpumemory-data export).</summary>
    public IReadOnlyList<GpuMemoryAdapterResult>? LastResults { get; private set; }

    /// <summary>Live progress while a run is going.</summary>
    public GpuMemoryProgress? LastProgress { get; private set; }

    public void Cancel()
    {
        lock (_scanGate) _scan?.Cancel();
    }

    /// <summary>Lists the graphics chips without testing them.</summary>
    public IReadOnlyList<GpuMemoryAdapter> Preview()
    {
        try { return LastAdapters = source.ListAdapters(); }
        catch (Exception ex) { LogWarn($"GPU memory: adapter list failed: {ex.Message}"); return LastAdapters ?? []; }
    }

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        var mode = Mode;
        var opts = (options ?? new GpuMemoryOptions()) with { Mode = mode };
        progress.ReportStep(0, 100, "Finding the graphics chips…");
        IReadOnlyList<GpuMemoryAdapter> adapters;
        try { adapters = LastAdapters = source.ListAdapters(); }
        catch (Exception ex)
        {
            var why = "The graphics chips couldn't be listed: " + ex.Message;
            LogWarn("GPU memory: " + why);
            return new AreaReport([], why, DiagnosticStatus.Error) { CouldNotRunReason = why };
        }
        LastResults = null;
        if (adapters.Count == 0)
            return new AreaReport([], "Not supported: Windows made no graphics chip available to this app (Basic Render Driver or Remote Desktop only)", DiagnosticStatus.Warning) { NotOnThisPc = true };
        if (_suiteTime is not null) opts = opts with { Duration = PerChip(adapters.Count) };

        using var scan = CancellationTokenSource.CreateLinkedTokenSource(ct);
        lock (_scanGate) _scan = scan;
        var started = DateTimeOffset.Now;
        var results = new List<GpuMemoryAdapterResult>();
        try
        {
            for (var i = 0; i < adapters.Count; i++)
            {
                var a = adapters[i];
                var test = new GpuMemoryTest(source, sensors, clockFactory?.Invoke(), Logger);
                var index = i;
                var p = new InlineProgress(x =>
                {
                    LastProgress = x;
                    var overall = (index + x.Fraction) / adapters.Count * 100;
                    var text = $"{Kind(mode, true)} graphics memory test{(adapters.Count > 1 ? $" {index + 1} of {adapters.Count}" : "")}: {x.Adapter}, pass {x.Pass}, "
                        + $"{x.TestedBytes / GpuMemoryPlan.MB:N0} MB, {(x.Errors == 0 ? "no errors" : Plural((int)Math.Min(x.Errors, int.MaxValue), "error"))}";
                    progress.ReportStep((int)Math.Round(overall), 100, text);
                    RaiseUpdated(new DiagnosticResult<double>(Name, DiagnosticStatus.Running, text, started, overall));
                });
                var r = await test.RunAsync(a, opts, i, adapters.Count, p, scan.Token).ConfigureAwait(false);
                results.Add(r);
                if (r.Outcome == GpuMemoryOutcome.Cancelled) break;
            }
        }
        finally
        {
            lock (_scanGate) { if (ReferenceEquals(_scan, scan)) _scan = null; }
            LastProgress = null;
        }
        LastResults = results;
        if (ct.IsCancellationRequested) throw new OperationCanceledException(ct);
        if (results.Any(r => r.Outcome == GpuMemoryOutcome.Cancelled))
            return AreaReport.ScanCancelled() with { Summary = $"{Kind(mode, true)} graphics memory test cancelled: the graphics memory was freed" };
        return Report(results, mode);
    }

    public static AreaReport Report(IReadOnlyList<GpuMemoryAdapterResult> results, GpuMemoryMode mode)
    {
        var cards = results.Select((r, i) => Card(r, i)).ToList();
        var summary = string.Join(" · ", cards.Select(c => results.Count > 1 ? $"{c.Title}: {c.Headline}" : c.Headline));
        var status = AreaReport.Worst(cards.Select(c => c.Level));
        var report = new AreaReport(cards, summary, status)
        {
            KeyMetrics =
            [
                new KeyMetric("TestedMb", "Graphics memory tested", results.Sum(r => r.TestedMb), "MB", MetricTrend.HigherIsBetter),
                new KeyMetric("Errors", "Graphics memory errors", results.Sum(r => r.Errors), "", MetricTrend.LowerIsBetter),
            ],
        };
        if (results.All(r => r.Outcome == GpuMemoryOutcome.CouldNotRun))
            return report with { Status = DiagnosticStatus.Error, CouldNotRunReason = "No graphics chip could be tested: " + string.Join(" · ", results.Select(r => $"{r.Adapter.Name}: {r.Reason}")) };
        return report;
    }

    public static AreaLevel Level(GpuMemoryAdapterResult r) => r.Outcome switch
    {
        GpuMemoryOutcome.ErrorsFound or GpuMemoryOutcome.DriverReset or GpuMemoryOutcome.Hung => AreaLevel.Error,
        GpuMemoryOutcome.Passed => r.TestedFraction < GpuMemoryPlan.WarnBelowFraction ? AreaLevel.Warning : AreaLevel.Ok,
        GpuMemoryOutcome.NotSupported => AreaLevel.Neutral,
        _ => AreaLevel.Warning,
    };

    public static string Headline(GpuMemoryAdapterResult r)
    {
        var tested = Mb(r.TestedBytes);
        var share = $"{r.TestedFraction * 100:0}%";
        return r.Outcome switch
        {
            GpuMemoryOutcome.Passed when r.TestedFraction < GpuMemoryPlan.WarnBelowFraction =>
                $"No errors, but only {tested} ({share} of {Mb(r.MemoryBytes)}) could be tested; close other apps and games and run it again",
            GpuMemoryOutcome.Passed => $"Passed: {tested} ({share}) tested, {Plural(r.Passes, "pass", "passes")}, no errors",
            GpuMemoryOutcome.ErrorsFound => $"Failed: {Plural((int)Math.Min(r.Errors, int.MaxValue), "wrong value")} in {tested} of graphics memory",
            GpuMemoryOutcome.DriverReset => "Failed: the graphics driver stopped responding during the test (device removed)",
            GpuMemoryOutcome.Hung => "Failed: the graphics chip stopped responding during the test",
            GpuMemoryOutcome.Overheated => $"Stopped early: the PC got too hot ({Plural(r.Passes, "pass", "passes")} finished, no errors so far)",
            GpuMemoryOutcome.Cancelled => "Cancelled",
            GpuMemoryOutcome.NotSupported => "Not supported: " + r.Reason,
            _ => "Couldn't test: " + r.Reason,
        };
    }

    private static AreaCard Card(GpuMemoryAdapterResult r, int index)
    {
        var id = "gpu-" + index.ToString(CultureInfo.InvariantCulture);
        var level = Level(r);
        var meta = Meta(r);
        string[] columns = ["Offset", "Expected", "Read back", "Wrong bits", "Pattern", "Pass"];
        var rows = r.FirstErrors.Select(e => new AreaRow(AreaLevel.Error,
        [
            "0x" + e.ByteOffset.ToString("X", CultureInfo.InvariantCulture), "0x" + e.Expected.ToString("X8", CultureInfo.InvariantCulture),
            "0x" + e.Actual.ToString("X8", CultureInfo.InvariantCulture), Bits(e.FlippedBits), GpuMemoryStep.PatternName(e.Pattern),
            e.Pass.ToString(CultureInfo.InvariantCulture),
        ], SortKeys: [e.ByteOffset.ToString("D16", CultureInfo.InvariantCulture), null, null, null, null, null])).ToList();
        var note = r.Outcome switch
        {
            GpuMemoryOutcome.ErrorsFound => "The graphics memory didn't hold what was written. That causes artifacts, crashes and freezes in games and video. "
                + "Run the test again to confirm; if it fails again the graphics card (or, for built-in graphics, the PC's memory) needs repair or replacement."
                + (r.Errors > r.FirstErrors.Count ? $" The first {r.FirstErrors.Count} wrong values are listed." : ""),
            GpuMemoryOutcome.DriverReset => $"Windows reset the graphics driver while its memory was being tested ({r.Reason}). Update the graphics driver and run it again; "
                + "if it keeps happening, the graphics hardware may be faulty. Crashes & unexpected restarts shows the driver resets Windows logged.",
            GpuMemoryOutcome.Hung => "A test step never finished. Restart the PC, update the graphics driver and run it again.",
            GpuMemoryOutcome.Overheated => "The test stopped to protect the PC. Check that the fans spin and the vents aren't blocked, then run it again.",
            _ => null,
        };
        var card = new AreaCard(id, r.Adapter.Name, level, Headline(r), meta, columns, rows,
            EmptyText: r.Outcome == GpuMemoryOutcome.Passed ? "Every value read back matched what was written." : "No wrong values were found.", Note: note, PreserveRowOrder: true);
        return r.Outcome is GpuMemoryOutcome.DriverReset or GpuMemoryOutcome.Hung
            ? card with { RunCheck = new AreaCheckLink(ModuleSlugs.Crashes, "Check graphics driver crashes") }
            : card;
    }

    private static string Meta(GpuMemoryAdapterResult r)
    {
        var parts = new List<string>
        {
            r.Adapter.Integrated ? $"Built-in graphics (shares the PC's memory, up to {Mb(r.MemoryBytes)} tested)" : $"{Mb(r.MemoryBytes)} dedicated memory",
            $"{Kind(r.Mode)} test",
        };
        if (r.TestedBytes > 0) parts.Add($"{Mb(r.TestedBytes)} tested in {Plural(r.Blocks, "block")}");
        if (r.Passes > 0) parts.Add(Plural(r.Passes, "pass", "passes"));
        if (r.MaxTemperatureC is { } t) parts.Add($"GPU up to {t:0}°C" + (r.StartTemperatureC is { } s ? $" (started at {s:0}°C)" : ""));
        else parts.Add("GPU temperature not reported");
        parts.Add($"ran {Clock(r.Ran)}");
        return string.Join(" · ", parts);
    }

    /// <summary>The bit numbers set in <paramref name="mask"/> ("3, 17").</summary>
    public static string Bits(uint mask)
    {
        var bits = Enumerable.Range(0, 32).Where(b => (mask & (1u << b)) != 0).ToList();
        return bits.Count == 0 ? "" : bits.Count > 8 ? $"{bits.Count} bits" : "bit " + string.Join(", ", bits);
    }

    public static string Mb(long bytes) => bytes >= 1024 * GpuMemoryPlan.MB
        ? (bytes / (1024.0 * GpuMemoryPlan.MB)).ToString("0.#", CultureInfo.InvariantCulture) + " GB"
        : (bytes / GpuMemoryPlan.MB).ToString("N0", CultureInfo.InvariantCulture) + " MB";

    private static string Clock(TimeSpan t) => t.TotalMinutes >= 1 ? $"{(int)t.TotalMinutes} min {t.Seconds} s" : $"{t.Seconds} s";

    public static string Kind(GpuMemoryMode mode, bool capital = false) => (mode, capital) switch
    {
        (GpuMemoryMode.Extended, false) => "extended",
        (GpuMemoryMode.Extended, true) => "Extended",
        (_, false) => "quick",
        _ => "Quick",
    };

    public static string ModeArg(GpuMemoryMode mode) => mode == GpuMemoryMode.Extended ? "extended" : "quick";

    private sealed class InlineProgress(Action<GpuMemoryProgress> a) : IProgress<GpuMemoryProgress> { public void Report(GpuMemoryProgress value) => a(value); }
}
