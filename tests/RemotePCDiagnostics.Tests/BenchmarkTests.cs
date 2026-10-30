using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Benchmarks;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Tests;

public class BenchmarkTests
{
    private static BenchmarkMeasurement M(BenchmarkKind k, params double[] v) => new(k, v);
    private static readonly BenchmarkConditions Plugged = new(false, 50, "Balanced");

    private static BenchmarkRun Run(BenchmarkPhase p, params BenchmarkMeasurement[] m) => new(p, DateTimeOffset.UtcNow, Plugged, m);

    // ---- comparison ----
    [Fact]
    public void Comparison_ImprovementsNoiseAndOverall()
    {
        var before = Run(BenchmarkPhase.Before, M(BenchmarkKind.BootTime, 41, 43, 40), M(BenchmarkKind.CpuMulti, 6000, 6100, 6050), M(BenchmarkKind.DnsLookup, 40, 42, 41));
        var after = Run(BenchmarkPhase.After, M(BenchmarkKind.BootTime, 30), M(BenchmarkKind.CpuMulti, 6100, 6000, 6080), M(BenchmarkKind.DnsLookup, 41, 40, 42));
        var c = BenchmarkComparison.Build(before, after);
        var boot = c.Deltas.Single(d => d.Info.Kind == BenchmarkKind.BootTime);
        Assert.Equal(BenchmarkVerdict.Better, boot.Verdict);
        Assert.Equal(27, Math.Round(boot.ImprovementPercent!.Value));
        Assert.Equal("Start-up time: 41.0 s → 30.0 s (27% faster)", boot.Sentence);
        Assert.Equal(BenchmarkVerdict.NoChange, c.Deltas.Single(d => d.Info.Kind == BenchmarkKind.CpuMulti).Verdict); // within noise
        Assert.True(c.OverallPercent > 2);
        Assert.StartsWith("Overall about", c.OverallText);
    }

    [Fact]
    public void Comparison_SmallAbsoluteChangesDontCount_AndRatiosAreCapped()
    {
        // 0.6% → 0.2% idle CPU is "3× better" relatively but meaningless; a 10× processor jump is capped at 2×.
        var c = BenchmarkComparison.Build(
            Run(BenchmarkPhase.Before, M(BenchmarkKind.IdleCpu, 0.6), M(BenchmarkKind.CpuSingle, 100)),
            Run(BenchmarkPhase.After, M(BenchmarkKind.IdleCpu, 0.2), M(BenchmarkKind.CpuSingle, 1000)));
        Assert.Equal(BenchmarkVerdict.NoChange, c.Deltas.Single(d => d.Info.Kind == BenchmarkKind.IdleCpu).Verdict);
        Assert.Equal(BenchmarkVerdict.Better, c.Deltas.Single(d => d.Info.Kind == BenchmarkKind.CpuSingle).Verdict);
        // weights: idle 1 (ratio 1), single 1 (ratio capped 2) → geometric mean √2 → +41%
        Assert.Equal(41, Math.Round(c.OverallPercent!.Value));
    }

    [Fact]
    public void Comparison_WorseAndNotMeasured_AndConditionWarnings()
    {
        var before = new BenchmarkRun(BenchmarkPhase.Before, DateTimeOffset.UtcNow, new(false, 45, "Balanced"), [M(BenchmarkKind.ProgramStart, 200, 205, 202), M(BenchmarkKind.BootTime, 30)]);
        var after = new BenchmarkRun(BenchmarkPhase.After, DateTimeOffset.UtcNow, new(true, 70, "Balanced"), [M(BenchmarkKind.ProgramStart, 300, 310, 305), new(BenchmarkKind.BootTime, [], "not yet recorded")]);
        var c = BenchmarkComparison.Build(before, after);
        Assert.Equal(BenchmarkVerdict.Worse, c.Deltas.Single(d => d.Info.Kind == BenchmarkKind.ProgramStart).Verdict);
        var boot = c.Deltas.Single(d => d.Info.Kind == BenchmarkKind.BootTime);
        Assert.Equal(BenchmarkVerdict.NotMeasured, boot.Verdict);
        Assert.Contains("not yet recorded", boot.Sentence);
        Assert.Contains(c.Warnings, w => w.Contains("on battery"));
        Assert.Contains(c.Warnings, w => w.Contains("70°C"));
        Assert.True(c.OverallPercent < -2);
        Assert.StartsWith("Overall about", c.OverallText);
        Assert.EndsWith("slower", c.OverallText);
    }

    [Fact]
    public void Comparison_NothingToCompare() => Assert.Null(BenchmarkComparison.Build(null, null).OverallPercent);

    [Fact]
    public void Measurement_MedianAndSpread()
    {
        var m = M(BenchmarkKind.ProgramStart, 300, 100, 200);
        Assert.Equal(200, m.Median);
        Assert.Equal(1.0, m.Spread, 3);
        Assert.Equal(150, M(BenchmarkKind.ProgramStart, 100, 200).Median);
        Assert.Null(new BenchmarkMeasurement(BenchmarkKind.ProgramStart, []).Median);
    }

    // ---- boot records ----
    private static WinEvent Boot(DateTimeOffset t, string ms) =>
        new(t, BootRecord.Channel, "Microsoft-Windows-Diagnostics-Performance", 100, 2, "Windows has started up", [], new Dictionary<string, string> { ["BootTime"] = ms, ["MainPathBootTime"] = "12000" });

    [Fact]
    public void Boot_BeforeUsesRecentStarts_AfterOnlyNewOnes()
    {
        var now = DateTimeOffset.UtcNow;
        var boots = new[] { Boot(now.AddMinutes(-5), "30000"), Boot(now.AddDays(-1), "41000"), Boot(now.AddDays(-2), "43000"), Boot(now.AddDays(-3), "40000"), Boot(now.AddDays(-4), "99000") }
            .Select(BootRecord.From).OfType<BootRecord>().ToList();
        Assert.Equal(12, boots[0].MainPathSeconds);
        var before = BenchmarkRunner.SelectBoots(BenchmarkPhase.Before, boots.Skip(1).ToList(), null);
        Assert.Equal([41.0, 43.0, 40.0], before.Samples);
        var after = BenchmarkRunner.SelectBoots(BenchmarkPhase.After, boots, now.AddHours(-1));
        Assert.Equal([30.0], after.Samples);
        var none = BenchmarkRunner.SelectBoots(BenchmarkPhase.After, boots.Skip(1).ToList(), now.AddHours(-1));
        Assert.Empty(none.Samples);
        Assert.Contains("hasn't recorded", none.Note);
        Assert.Null(BootRecord.From(Boot(now, "0")));
    }

    // ---- runner with fake probes ----
    private sealed class FakeProbes : IBenchmarkProbes
    {
        public List<string> Started = [];
        public bool FailDisk;
        public BenchmarkConditions ReadConditions() => Plugged;
        public Task<IdleSample?> SampleIdleAsync(TimeSpan d, CancellationToken ct) => Task.FromResult<IdleSample?>(new(3.5, 42));
        public Task<double?> StartProgramAsync(BuiltInProgram p, CancellationToken ct) { Started.Add(p.Name); return Task.FromResult<double?>(100); }
        public Task<double?> DiskRandomReadIopsAsync(TimeSpan d, CancellationToken ct) => FailDisk ? throw new IOException("no space") : Task.FromResult<double?>(8000);
        public Task<IReadOnlyList<WinEvent>> ReadBootEventsAsync(CancellationToken ct) =>
            Task.FromResult<IReadOnlyList<WinEvent>>([Boot(DateTimeOffset.UtcNow.AddDays(-1), "35000")]);
    }

    private static readonly BenchmarkSettings Fast = new()
    {
        Runs = 2, IdleSample = TimeSpan.Zero, CpuSingleRun = TimeSpan.FromMilliseconds(100), CpuMultiRun = TimeSpan.FromMilliseconds(100), DiskRun = TimeSpan.Zero,
    };

    private static Task Resolve(string name, CancellationToken ct) => name.StartsWith("rpd-") ? Task.CompletedTask : throw new InvalidOperationException();

    [Fact]
    public async Task Runner_MeasuresEverythingEnabled_OnlyBuiltInPrograms()
    {
        var probes = new FakeProbes();
        var progress = new List<string>();
        var run = await new BenchmarkRunner(probes, resolve: Resolve).RunAsync(BenchmarkPhase.Before, Fast, null, new SyncProgress(progress.Add), default);
        Assert.True(run.Completed, "run stopped early");
        Assert.Contains(progress, p => p.StartsWith("Measuring disk"));
        Assert.Equal(Enum.GetValues<BenchmarkKind>().Length, run.Measurements.Count);
        Assert.Equal(3.5, run.Get(BenchmarkKind.IdleCpu)!.Median);
        Assert.Equal(42, run.Get(BenchmarkKind.Paging)!.Median);
        Assert.Equal(35, run.Get(BenchmarkKind.BootTime)!.Median);
        Assert.Equal(100, run.Get(BenchmarkKind.ProgramStart)!.Median);
        Assert.Equal(0.125, run.Get(BenchmarkKind.DiskLatency)!.Median);    // 1000 / 8000 IOPS
        Assert.True(run.Get(BenchmarkKind.CpuMulti)!.Median > 0, "multi-core score");
        Assert.Equal(2, run.Get(BenchmarkKind.DnsLookup)!.Samples.Count);
        Assert.Equal(BuiltInPrograms.All.Count * 2, probes.Started.Count);
        Assert.All(BuiltInPrograms.All, p => Assert.DoesNotContain(':', p.FileName)); // System32-relative: Windows' own programs only
    }

    [Fact]
    public async Task Runner_OnlyEnabled_AndFailuresBecomeNotes()
    {
        var probes = new FakeProbes { FailDisk = true };
        var run = await new BenchmarkRunner(probes, resolve: Resolve).RunAsync(BenchmarkPhase.Before,
            Fast with { Enabled = [BenchmarkKind.DiskLatency, BenchmarkKind.IdleCpu] }, null, null, default);
        Assert.Equal([BenchmarkKind.IdleCpu, BenchmarkKind.DiskLatency], run.Measurements.Select(m => m.Kind));
        Assert.Empty(run.Get(BenchmarkKind.DiskLatency)!.Samples);
        Assert.Equal("the disk test couldn't run", run.Get(BenchmarkKind.DiskLatency)!.Note);
    }

    [Fact]
    public async Task Runner_Stop_KeepsFinishedResults()
    {
        using var cts = new CancellationTokenSource();
        var progress = new SyncProgress(p => { if (p.StartsWith("Timing website")) cts.Cancel(); });
        var run = await new BenchmarkRunner(new FakeProbes(), resolve: Resolve).RunAsync(BenchmarkPhase.Before, Fast, null, progress, cts.Token);
        Assert.False(run.Completed);
        Assert.NotNull(run.Get(BenchmarkKind.IdleCpu));
        Assert.Null(run.Get(BenchmarkKind.DiskLatency));
    }

    private sealed class SyncProgress(Action<string> a) : IProgress<string> { public void Report(string v) => a(v); }

    [Fact]
    public void CpuScore_MoreThreadsMoreWork() => Assert.True(BenchmarkRunner.CpuScore(1, TimeSpan.FromMilliseconds(100)) > 0);

    // ---- service: persistence, restart flow ----
    private sealed class MemStore : IBenchmarkStore
    {
        public BenchmarkState? State;
        public BenchmarkState? Load() => State is null ? null : BenchmarkState.FromJson(State.ToJson()); // through JSON, like the file
        public void Save(BenchmarkState s) => State = s;
    }

    [Fact]
    public async Task Service_BeforeSurvivesRestart_AfterRunsOnceOnStartup()
    {
        var store = new MemStore();
        var launcher = new ScriptedLauncher((_, _) => ScriptedLauncher.Ok(""));
        var runner = new SystemCommandRunner(launcher);
        var statePath = Path.Combine(Path.GetTempPath(), "rpd-bench-reboot-" + Guid.NewGuid().ToString("N") + ".json");
        var rem = new RemediationService(runner, new SessionContext(SessionMode.Remote), rebootResume: new RebootResumeCoordinator(runner, stateFilePath: statePath, executablePath: @"C:\App\RemotePCDiagnostics.Host.exe"));
        var events = new List<string>();
        var svc = new BenchmarkService(new BenchmarkRunner(new FakeProbes(), resolve: Resolve), store, rem, new SessionContext(SessionMode.Remote), (_, t) => events.Add(t));
        svc.UpdateSettings(Fast);
        await svc.RunAsync(BenchmarkPhase.Before);
        Assert.NotNull(store.State!.Before);

        var r = await svc.RestartThenRunAfterAsync();
        Assert.True(r.Success);
        Assert.True(store.State.RunAfterOnStartup);
        Assert.Contains(launcher.Calls, c => c.Args.Contains("/r"));

        // "App restarts": a new service instance loads the saved state.
        var delays = new List<TimeSpan>();
        var svc2 = new BenchmarkService(new BenchmarkRunner(new FakeProbes(), resolve: Resolve), store, rem, delay: (d, _) => { delays.Add(d); return Task.CompletedTask; });
        Assert.NotNull(svc2.Before);
        await svc2.ResumeAfterRestartAsync();
        Assert.Equal([Fast.SettleAfterRestart], delays);
        Assert.NotNull(svc2.After);
        Assert.False(store.State.RunAfterOnStartup);
        await svc2.ResumeAfterRestartAsync(); // only once
        Assert.Single(delays);
        Assert.Contains(events, e => e.Contains("Performance benchmark (Before)"));
    }

    [Fact]
    public async Task Service_NewBeforeClearsOldAfter_AndClearKeepsSettings()
    {
        var store = new MemStore();
        var svc = new BenchmarkService(new BenchmarkRunner(new FakeProbes(), resolve: Resolve), store);
        svc.UpdateSettings(Fast with { Runs = 9 });
        Assert.Equal(5, svc.Settings.Runs); // clamped
        await svc.RunAsync(BenchmarkPhase.Before);
        await svc.RunAsync(BenchmarkPhase.After);
        Assert.NotNull(svc.After);
        await svc.RunAsync(BenchmarkPhase.Before);
        Assert.Null(svc.After);
        svc.Clear();
        Assert.Null(svc.Before);
        Assert.Equal(5, svc.Settings.Runs);
        Assert.False((await new BenchmarkService(new BenchmarkRunner(new FakeProbes()), new MemStore()).RestartThenRunAfterAsync()).Success); // no remediation / no before
    }

    [Fact]
    public void FileStore_RoundTrips()
    {
        var path = Path.Combine(Path.GetTempPath(), "rpd-bench-" + Guid.NewGuid().ToString("N"), "benchmarks.json");
        var store = new FileBenchmarkStore(path);
        Assert.Null(store.Load());
        store.Save(new BenchmarkState(new BenchmarkSettings { Runs = 1 }, Run(BenchmarkPhase.Before, M(BenchmarkKind.BootTime, 30)), null, true));
        var back = store.Load()!;
        Assert.Equal(1, back.Settings.Runs);
        Assert.Equal(30, back.Before!.Get(BenchmarkKind.BootTime)!.Median);
        Assert.True(back.RunAfterOnStartup);
        Directory.Delete(Path.GetDirectoryName(path)!, true);
    }
}
