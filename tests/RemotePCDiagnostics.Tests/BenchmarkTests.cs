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
    [Theory]
    [InlineData(47.5, "47% shorter; needs confirmation")]
    [InlineData(132.9, "47% longer; needs confirmation")]
    public void Comparison_LargeBootChangeWithinWideRangeIsUncertain(double afterSeconds, string summary)
    {
        var comparison = BenchmarkComparison.Build(
            Run(BenchmarkPhase.Before, M(BenchmarkKind.BootTime, 129.4, 90.2, 81.8)),
            Run(BenchmarkPhase.After, M(BenchmarkKind.BootTime, afterSeconds)));
        var boot = Assert.Single(comparison.Deltas);
        Assert.Equal(BenchmarkVerdict.Uncertain, boot.Verdict);
        Assert.Equal(summary, boot.ChangeSummary);
        Assert.Contains("one after measurement", boot.Note);
        Assert.Contains("before runs varied by 53%", boot.Note);
        Assert.DoesNotContain("after 0%", boot.Note);
        Assert.DoesNotContain("no measurable change", boot.Sentence);
        Assert.Equal(0d, comparison.OverallPercent);
    }

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

    private static WinEvent BootFull(DateTimeOffset t, int bootMs, int mainMs, int postMs, bool afterInstall = false) =>
        new(t, BootRecord.Channel, "Microsoft-Windows-Diagnostics-Performance", 100, 2, "Windows has started up", [], new Dictionary<string, string>
        {
            ["BootTime"] = bootMs.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["MainPathBootTime"] = mainMs.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["BootPostBootTime"] = postMs.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["BootIsRebootAfterInstall"] = afterInstall ? "true" : "false",
        });

    [Fact]
    public void Boot_BeforeWithWorkflowRestart_UsesOnlyThatStart()
    {
        var now = DateTimeOffset.UtcNow;
        var boots = new[] { BootFull(now.AddMinutes(-4), 60000, 30000, 30000), BootFull(now.AddDays(-1), 129400, 40000, 89400), BootFull(now.AddDays(-2), 81800, 30000, 51800) }
            .Select(BootRecord.From).OfType<BootRecord>().ToList();
        var before = BenchmarkRunner.SelectBoots(BenchmarkPhase.Before, boots, null, bootsSince: now.AddMinutes(-10));
        Assert.Equal([60.0], before.Samples);
        Assert.Equal("until the desktop 30.0 s + settling after sign-in 30.0 s", before.Detail);
        var notYet = BenchmarkRunner.SelectBoots(BenchmarkPhase.Before, boots, null, bootsSince: now.AddMinutes(-1));
        Assert.Empty(notYet.Samples);
        Assert.Contains("hasn't recorded the start-up after the restart yet", notYet.Note);
    }

    [Fact]
    public void Boot_StartsRightAfterUpdatesAreNeverUsed()
    {
        var now = DateTimeOffset.UtcNow;
        var boots = new[] { BootFull(now.AddMinutes(-5), 200000, 120000, 80000, afterInstall: true), BootFull(now.AddDays(-1), 41000, 20000, 21000),
                            BootFull(now.AddDays(-2), 43000, 20000, 23000), BootFull(now.AddDays(-3), 40000, 20000, 20000) }
            .Select(BootRecord.From).OfType<BootRecord>().ToList();
        Assert.True(boots[0].AfterInstall);
        Assert.Equal([41.0, 43.0, 40.0], BenchmarkRunner.SelectBoots(BenchmarkPhase.Before, boots, null).Samples);
        var after = BenchmarkRunner.SelectBoots(BenchmarkPhase.After, boots, now.AddHours(-1));
        Assert.Empty(after.Samples);
        Assert.Contains("right after Windows installed updates", after.Note);
    }

    [Fact]
    public void Comparison_ShowsTheStartUpBreakdown_AndOneSampleEachSideIsAFairComparison()
    {
        var comparison = BenchmarkComparison.Build(
            Run(BenchmarkPhase.Before, new BenchmarkMeasurement(BenchmarkKind.BootTime, [90.2], null, "until the desktop 30.0 s + settling after sign-in 60.2 s")),
            Run(BenchmarkPhase.After, new BenchmarkMeasurement(BenchmarkKind.BootTime, [47.5], null, "until the desktop 29.0 s + settling after sign-in 18.5 s")));
        var boot = Assert.Single(comparison.Deltas);
        Assert.Equal(BenchmarkVerdict.Better, boot.Verdict);
        Assert.Equal("Before: until the desktop 30.0 s + settling after sign-in 60.2 s. After: until the desktop 29.0 s + settling after sign-in 18.5 s.", boot.Note);
    }

    // ---- runner with fake probes ----
    private sealed class FakeProbes : IBenchmarkProbes
    {
        public List<string> Started = [];
        public bool FailDisk;
        public Queue<IdleResourceSample?> IdleResources = new();
        public Task<IdleResourceSample?> ReadIdleResourcesAsync(CancellationToken ct) => Task.FromResult(IdleResources.Count > 0 ? IdleResources.Dequeue() : null);
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
        ResourceSampleInterval = TimeSpan.Zero,
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
    public async Task Service_RestartThenBefore_CountsOnlyStartUpsAfterTheRestart()
    {
        var store = new MemStore();
        var launcher = new ScriptedLauncher((_, _) => ScriptedLauncher.Ok(""));
        var runner = new SystemCommandRunner(launcher);
        var statePath = Path.Combine(Path.GetTempPath(), "rpd-bench-reboot-" + Guid.NewGuid().ToString("N") + ".json");
        var rem = new RemediationService(runner, new SessionContext(SessionMode.Remote), rebootResume: new RebootResumeCoordinator(runner, stateFilePath: statePath, executablePath: @"C:\App\RemotePCDiagnostics.Host.exe"));
        var svc = new BenchmarkService(new BenchmarkRunner(new FakeProbes(), resolve: Resolve), store, rem, new SessionContext(SessionMode.Remote));
        svc.UpdateSettings(Fast);

        var r = await svc.RestartThenRunBeforeAsync();
        Assert.True(r.Success);
        Assert.True(store.State!.RunBeforeOnStartup);
        Assert.NotNull(store.State.RestartRequestedUtc);
        Assert.Contains(launcher.Calls, c => c.Args.Contains("/r"));

        var delays = new List<TimeSpan>();
        var svc2 = new BenchmarkService(new BenchmarkRunner(new FakeProbes(), resolve: Resolve), store, rem, delay: (d, _) => { delays.Add(d); return Task.CompletedTask; });
        Assert.True(svc2.BeforePendingRestart);
        await svc2.ResumeAfterRestartAsync();
        Assert.Equal([Fast.SettleAfterRestart], delays);
        Assert.NotNull(svc2.Before);
        Assert.False(store.State.RunBeforeOnStartup);
        // The fake log only has a start-up from yesterday, before the restart: it must not count.
        var boot = svc2.Before!.Get(BenchmarkKind.BootTime);
        Assert.NotNull(boot);
        Assert.Empty(boot!.Samples);
        Assert.Contains("after the restart", boot.Note);
        await svc2.ResumeAfterRestartAsync(); // only once
        Assert.Single(delays);
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

    [Fact]
    public void Service_LegacySchemaVersion_UpgradesAndEnablesNewResourceAndSnapshotKinds()
    {
        var path = Path.Combine(Path.GetTempPath(), "rpd-bench-legacy-" + Guid.NewGuid().ToString("N"), "benchmarks.json");
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            // Simulate a pre-SchemaVersion benchmarks.json on disk with only 2 original benchmarks enabled and Runs = 1.
            File.WriteAllText(path, """{"Settings":{"Enabled":["BootTime","ProgramStart"],"Runs":1,"RestartBeforeAfter":false}}""");
            var store = new FileBenchmarkStore(path);
            var svc = new BenchmarkService(new BenchmarkRunner(new FakeProbes(), resolve: Resolve), store);
            Assert.Equal(BenchmarkSettings.CurrentSchemaVersion, svc.Settings.SchemaVersion);
            Assert.Equal(1, svc.Settings.Runs);
            Assert.False(svc.Settings.RestartBeforeAfter);
            Assert.Contains(BenchmarkKind.BootTime, svc.Settings.Enabled);
            Assert.Contains(BenchmarkKind.ProgramStart, svc.Settings.Enabled);
            Assert.DoesNotContain(BenchmarkKind.CpuSingle, svc.Settings.Enabled);
            Assert.All(Benchmarks.IdleResourceKinds, k => Assert.Contains(k, svc.Settings.Enabled));
            Assert.All(Benchmarks.ResourceSnapshotKinds, k => Assert.Contains(k, svc.Settings.Enabled));
            Assert.Equal(BenchmarkSettings.CurrentSchemaVersion, store.Load()!.Settings.SchemaVersion);
        }
        finally { Directory.Delete(Path.GetDirectoryName(path)!, true); }
    }

    [Fact]
    public void Comparison_ResourceAndInventoryMetrics_ShowAbsoluteSavingsWithoutSkewingWeightZero()
    {
        var before = Run(BenchmarkPhase.Before,
            M(BenchmarkKind.MemoryUsedMb, 9400),
            M(BenchmarkKind.DiskFreeGb, 120.0),
            M(BenchmarkKind.EnabledStartupApps, 14),
            M(BenchmarkKind.ActiveScheduledTasks, 28),
            M(BenchmarkKind.InstalledBloatwareApps, 12));
        var after = Run(BenchmarkPhase.After,
            M(BenchmarkKind.MemoryUsedMb, 7400),
            M(BenchmarkKind.DiskFreeGb, 161.2),
            M(BenchmarkKind.EnabledStartupApps, 5),
            M(BenchmarkKind.ActiveScheduledTasks, 16),
            M(BenchmarkKind.InstalledBloatwareApps, 2));
        var c = BenchmarkComparison.Build(before, after);
        var mem = c.Deltas.Single(d => d.Info.Kind == BenchmarkKind.MemoryUsedMb);
        var disk = c.Deltas.Single(d => d.Info.Kind == BenchmarkKind.DiskFreeGb);
        var startup = c.Deltas.Single(d => d.Info.Kind == BenchmarkKind.EnabledStartupApps);
        var tasks = c.Deltas.Single(d => d.Info.Kind == BenchmarkKind.ActiveScheduledTasks);
        var bloat = c.Deltas.Single(d => d.Info.Kind == BenchmarkKind.InstalledBloatwareApps);

        Assert.Equal("2000 MB freed (21% less)", mem.ChangeSummary);
        Assert.Equal("+41.2 GB freed", disk.ChangeSummary);
        Assert.Equal("9 fewer", startup.ChangeSummary);
        Assert.Equal("12 fewer", tasks.ChangeSummary);
        Assert.Equal("10 fewer", bloat.ChangeSummary);
    }

    // ---- idle resources: background-process filtering, sampling, weights ----
    [Fact]
    public void BackgroundProcesses_ExcludeThisAppItsChildrenBenchmarkToolsAndPseudoProcesses()
    {
        const int Own = 5000;
        ProcessRow[] rows =
        [
            new(0, 0, "[System Process]"), new(4, 0, "System"), new(120, 4, "Registry"), new(2400, 4, "Memory Compression"),
            new(700, 600, "services.exe"), new(900, 700, "svchost.exe"), new(901, 700, "svchost.exe"), new(3000, 2900, "explorer.exe"),
            new(3100, 3000, "OneDrive.exe"),                                                  // a real background program: counted
            new(Own, 3000, "RemotePCDiagnostics.Host.exe"),
            new(5100, Own, "msedgewebview2.exe"), new(5101, 5100, "msedgewebview2.exe"),     // WebView2 tree under the app
            new(5200, Own, "powershell.exe"), new(5201, 5200, "conhost.exe"),                 // inventory query and its console
            new(5300, Own, "osqueryi.exe"),
            new(6000, 4242, "charmap.exe"), new(6100, 1, "powercfg.exe"), new(6101, 6100, "conhost.exe"), // benchmark programs, orphaned
            new(7000, 7000, "weird-self-parent.exe"),                                         // self-parent doesn't loop
        ];
        Assert.Equal(6, BackgroundProcessCount.Count(rows, Own)); // services, 2× svchost, explorer, OneDrive, weird
        Assert.Equal(6, BackgroundProcessCount.Count(rows.Where(r => r.Pid != Own), Own)); // children still found if the app's own row is missing
        // Seen from another process: the app, its two WebView2 processes and osqueryi now count; benchmark tools and their consoles still don't.
        Assert.Equal(10, BackgroundProcessCount.Count(rows, ownPid: 99999));
        Assert.Equal("cmd", BackgroundProcessCount.Stem(@"C:\Windows\System32\cmd.EXE"));
        Assert.Contains("powershell", BackgroundProcessCount.BenchmarkTools);
    }

    [Fact]
    public async Task Runner_SamplesIdleResourcesSeveralTimes_KeepsEverySample_MedianWins()
    {
        var probes = new FakeProbes();
        foreach (var (mb, n) in new[] { (8000.0, 150), (9500.0, 171), (8100.0, 152), (8050.0, 151), (7980.0, 149) }) // one start-up spike
            probes.IdleResources.Enqueue(new(mb, n));
        var waits = new List<TimeSpan>();
        var settings = Fast with { ResourceSamples = 5, ResourceSampleInterval = TimeSpan.FromSeconds(5), Enabled = [BenchmarkKind.MemoryUsedMb, BenchmarkKind.BackgroundProcesses, BenchmarkKind.DiskFreeGb] };
        var run = await new BenchmarkRunner(probes, delay: (d, _) => { waits.Add(d); return Task.CompletedTask; }).RunAsync(BenchmarkPhase.Before, settings, null, null, default);

        Assert.Equal(Enumerable.Repeat(TimeSpan.FromSeconds(5), 4), waits); // 5 samples, 4 gaps = 20 s
        var mem = run.Get(BenchmarkKind.MemoryUsedMb)!;
        Assert.Equal([8000.0, 9500, 8100, 8050, 7980], mem.Samples);
        Assert.Equal(8050, mem.Median);
        Assert.Equal(151, run.Get(BenchmarkKind.BackgroundProcesses)!.Median);
        Assert.Equal(5, run.Get(BenchmarkKind.BackgroundProcesses)!.Samples.Count);
        Assert.Equal("not available", run.Get(BenchmarkKind.DiskFreeGb)!.Note); // inventory still read once (fake has none)
        Assert.Equal(20, settings.ResourceSampleSeconds);
    }

    [Fact]
    public async Task Runner_IdleResourcesUnavailable_DoesntWait()
    {
        var waits = new List<TimeSpan>();
        var run = await new BenchmarkRunner(new FakeProbes(), delay: (d, _) => { waits.Add(d); return Task.CompletedTask; })
            .RunAsync(BenchmarkPhase.Before, Fast with { Enabled = [BenchmarkKind.MemoryUsedMb] }, null, null, default);
        Assert.Empty(waits);
        Assert.Empty(run.Get(BenchmarkKind.MemoryUsedMb)!.Samples);
        Assert.Equal("not available", run.Get(BenchmarkKind.MemoryUsedMb)!.Note);
    }

    [Fact]
    public void Settings_Default_PassStaysWithinThreeMinutes() =>
        Assert.InRange(new BenchmarkSettings().EstimatedSeconds(), 140, 180);

    [Fact]
    public void Comparison_MemoryAndProcessNoise_DontSwingOverall()
    {
        Assert.Equal(0.5, Benchmarks.Info(BenchmarkKind.MemoryUsedMb).Weight);
        Assert.Equal(0.0, Benchmarks.Info(BenchmarkKind.BackgroundProcesses).Weight);

        // Idle memory wandering ~150 MB between restarts, and a few on-demand processes: not a change, overall unaffected.
        var c = BenchmarkComparison.Build(
            Run(BenchmarkPhase.Before, M(BenchmarkKind.BootTime, 30, 30, 30), M(BenchmarkKind.MemoryUsedMb, 8000, 8020, 7990, 8010, 8005), M(BenchmarkKind.BackgroundProcesses, 150, 151, 150, 152, 150)),
            Run(BenchmarkPhase.After, M(BenchmarkKind.BootTime, 30, 30, 30), M(BenchmarkKind.MemoryUsedMb, 7850, 7860, 7840, 7855, 7850), M(BenchmarkKind.BackgroundProcesses, 147, 147, 148, 146, 147)));
        Assert.Equal(BenchmarkVerdict.NoChange, c.Deltas.Single(d => d.Info.Kind == BenchmarkKind.MemoryUsedMb).Verdict);
        Assert.Equal(BenchmarkVerdict.NoChange, c.Deltas.Single(d => d.Info.Kind == BenchmarkKind.BackgroundProcesses).Verdict);
        Assert.Equal(0, c.OverallPercent!.Value, 6);

        // A real 10% memory saving is reported, but with start-up time unchanged it moves the headline only ~2%, not ~5% as at weight 1.5;
        // 40 fewer processes is reported as a count and doesn't move it at all.
        var real = BenchmarkComparison.Build(
            Run(BenchmarkPhase.Before, M(BenchmarkKind.BootTime, 30), M(BenchmarkKind.MemoryUsedMb, 8000), M(BenchmarkKind.BackgroundProcesses, 190)),
            Run(BenchmarkPhase.After, M(BenchmarkKind.BootTime, 30), M(BenchmarkKind.MemoryUsedMb, 7200), M(BenchmarkKind.BackgroundProcesses, 150)));
        Assert.Equal(BenchmarkVerdict.Better, real.Deltas.Single(d => d.Info.Kind == BenchmarkKind.MemoryUsedMb).Verdict);
        var procs = real.Deltas.Single(d => d.Info.Kind == BenchmarkKind.BackgroundProcesses);
        Assert.Equal(BenchmarkVerdict.Better, procs.Verdict);
        Assert.Equal("40 fewer", procs.ChangeSummary);
        Assert.Equal(2.1, Math.Round(real.OverallPercent!.Value, 1)); // (8000/7200)^(0.5/2.5) − 1
    }
}
