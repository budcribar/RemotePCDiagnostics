using RemotePCDiagnostics.Core;

namespace RemotePCDiagnostics.Tests;

public class ChecksScreenTests
{
    private static (DiagnosticsService Svc, ResultStore Store, ChecksScreenState State, FakeStressModule[] Stress) Build(
        Func<FakeStressModule, CancellationToken, Task<DiagnosticResult>>? stressRun = null)
    {
        var store = new ResultStore();
        var stress = new[] { new FakeStressModule("CpuStress", "CPU", stressRun), new FakeStressModule("MemoryTest", "Memory", stressRun) };
        var svc = new DiagnosticsService(store, [
            new FakeModule("A", async ct => { await Task.Delay(5, ct); return FakeModule.Ok("A"); }),
            new FakeModule("B", _ => Task.FromResult(new DiagnosticResult("B", DiagnosticStatus.Warning, "meh", DateTimeOffset.Now))),
            stress[0], stress[1]]);
        return (svc, store, new ChecksScreenState(svc, store), stress);
    }

    [Theory]
    [InlineData(DiagnosticStatus.Ok, "fine", RowKind.Passed)]
    [InlineData(DiagnosticStatus.Warning, "slow", RowKind.Warning)]
    [InlineData(DiagnosticStatus.Error, "bad", RowKind.Critical)]
    [InlineData(DiagnosticStatus.Warning, "Cancelled", RowKind.Cancelled)]
    [InlineData(DiagnosticStatus.Warning, "Stopped", RowKind.Cancelled)]
    [InlineData(DiagnosticStatus.NotRun, "Not run", RowKind.NotRun)]
    [InlineData(DiagnosticStatus.Running, "Running…", RowKind.Running)]
    public void KindOf_MatchesRealResult(DiagnosticStatus st, string msg, RowKind expected) =>
        Assert.Equal(expected, CheckRows.KindOf(new DiagnosticResult("M", st, msg, DateTimeOffset.Now) { Cancelled = expected == RowKind.Cancelled }));

    [Fact]
    public void CouldNotRun_FromAreaReportWithNoVerdict()
    {
        var report = new RemotePCDiagnostics.Core.Areas.AreaReport([], "The graphics chips couldn't be listed: overflow", DiagnosticStatus.Error) { CouldNotRunReason = "overflow" };
        var r = new DiagnosticResult("GpuMemory", DiagnosticStatus.Error, report.Summary, DateTimeOffset.Now, report);
        Assert.True(CheckRows.IsCouldNotRun(r));
        Assert.False(CheckRows.IsCouldNotRun(new DiagnosticResult("GpuMemory", DiagnosticStatus.Error, "1 error", DateTimeOffset.Now)));
    }

    [Fact]
    public void CouldNotRun_FromAvailabilityPayload() =>
        Assert.Equal(RowKind.CouldNotRun, CheckRows.KindOf(new DiagnosticResult("M", DiagnosticStatus.Error, "no", DateTimeOffset.Now, ModuleAvailability.Unavailable("no"))));

    [Fact]
    public void Labels_UseModeTheResultRanIn_WarningNeverPassed()
    {
        Assert.Equal("Passed", CheckRows.Label(RowKind.Passed, "short run"));
        Assert.Equal("Warning", CheckRows.Label(RowKind.Warning, "short run"));
        Assert.Equal("Warning (extended run)", CheckRows.Label(RowKind.Warning, "extended run"));
        Assert.Equal("Passed", CheckRows.Label(RowKind.Passed, null));
        Assert.Equal("Cancelled", CheckRows.Label(RowKind.Cancelled, "short run"));
        Assert.Equal("Not run", CheckRows.Label(RowKind.NotRun, "short run"));
    }

    [Fact]
    public void Pills_CountRealStates()
    {
        var p = CheckRows.Pills([RowKind.Passed, RowKind.Passed, RowKind.Warning, RowKind.NotRun, RowKind.Cancelled]);
        Assert.Equal(new[] { ("ok", "2 passed"), ("warn", "1 warning"), ("na", "1 cancelled"), ("na", "1 not run") }, p);
        Assert.Empty(CheckRows.Pills([]));
    }

    [Fact]
    public void FilterPills_GroupRunningPassedWarningAndFailed_AndKeepActiveZeroPill()
    {
        var kinds = new[] { RowKind.Running, RowKind.Passed, RowKind.Passed, RowKind.Warning, RowKind.Critical, RowKind.CouldNotRun, RowKind.Blocked, RowKind.NotRun };
        var pills = CheckRows.FilterPills(kinds);
        Assert.Equal(
        [
            new CheckFilterPill(CheckStatusFilter.Running, "run", "1 running", 1),
            new CheckFilterPill(CheckStatusFilter.Passed, "ok", "2 passed", 2),
            new CheckFilterPill(CheckStatusFilter.Warning, "warn", "1 warning", 1),
            new CheckFilterPill(CheckStatusFilter.Failed, "err", "3 failed", 3),
        ], pills);

        // An active filter with 0 remaining matches still renders so the user can see and clear it.
        var afterFinish = CheckRows.FilterPills([RowKind.Passed], activeFilter: CheckStatusFilter.Running);
        Assert.Equal(
        [
            new CheckFilterPill(CheckStatusFilter.Running, "run", "0 running", 0),
            new CheckFilterPill(CheckStatusFilter.Passed, "ok", "1 passed", 1),
        ], afterFinish);
    }

    [Fact]
    public void A_test_the_catalog_puts_on_the_Interactive_tests_page_is_not_on_the_Checks_list()
    {
        var store = new ResultStore();
        // The battery drain test once answered IncludeInRunAll true through the interface; its catalog page keeps it off the list anyway.
        var svc = new DiagnosticsService(store, [new FakeModule("A", _ => Task.FromResult(FakeModule.Ok("A"))),
            new FakeModule(ModuleSlugs.BatteryDrain, _ => Task.FromResult(FakeModule.Ok(ModuleSlugs.BatteryDrain)))]);
        var s = new ChecksScreenState(svc, store);
        Assert.Equal(["A"], s.ChecksModules.Select(m => m.Name));
        Assert.Equal("interactive", s.PageFor(ModuleSlugs.BatteryDrain));
        Assert.Null(s.GroupOf(ModuleSlugs.BatteryDrain));
    }

    [Fact]
    public void The_battery_drain_test_is_never_in_Run_all_through_the_interface()
    {
        var m = new Core.Battery.BatteryDrainModule(null!, null!, null!, null!);
        Assert.False(((IDiagnosticModule)m).IncludeInRunAll);
    }

    [Fact]
    public void Pages_ChecksAndStressAreSeparate_AuditHasItsOwnPage()
    {
        var (_, _, s, _) = Build();
        Assert.Equal(["A", "B"], s.ChecksModules.Select(m => m.Name));
        Assert.Equal(["CpuStress", "MemoryTest"], s.StressModules.Select(m => m.Name));
        Assert.Equal("checks", s.PageFor("B"));
        Assert.Equal("stress", s.PageFor("MemoryTest"));
        Assert.Equal("security-audit", s.PageFor("SecurityAudit"));
        Assert.Equal("interactive", s.PageFor("Webcam"));
        Assert.Equal("interactive", s.PageFor("SpeakerToMic"));
        Assert.Equal("interactive", s.PageFor("MicToSpeaker"));
        Assert.Equal("checks", s.PageFor("Unknown"));
        Assert.Equal(CheckGroup.Checks, s.GroupOf("a"));
        Assert.Equal(CheckGroup.Stress, s.GroupOf("CpuStress"));
        Assert.Null(s.GroupOf("SecurityAudit"));
        Assert.Null(s.GroupOf("Webcam"));
        Assert.Null(s.GroupOf("SpeakerToMic"));
        Assert.Null(s.GroupOf("MicToSpeaker"));
    }

    [Theory]
    [InlineData("stress", CheckGroup.Stress)]
    [InlineData("Stress/", CheckGroup.Stress)]
    [InlineData("stress?x=1#top", CheckGroup.Stress)]
    [InlineData("checks", CheckGroup.Checks)]
    [InlineData("checks/", CheckGroup.Checks)]
    [InlineData("", CheckGroup.Checks)]
    [InlineData(null, CheckGroup.Checks)]
    [InlineData("stresses", CheckGroup.Checks)]
    public void GroupForPath_PicksTheList(string? path, CheckGroup expected) => Assert.Equal(expected, ChecksScreenState.GroupForPath(path));

    [Fact]
    public void EachPageRemembersItsOwnSelection_FallsBackToFirst()
    {
        var (_, _, s, _) = Build();
        Assert.Equal("A", s.SelectedIn(CheckGroup.Checks)!.Name);
        Assert.Equal("CpuStress", s.SelectedIn(CheckGroup.Stress)!.Name);
        s.FocusModule("MemoryTest");
        s.FocusModule("B");
        Assert.Equal("B", s.SelectedIn(CheckGroup.Checks)!.Name);
        Assert.Equal("MemoryTest", s.SelectedIn(CheckGroup.Stress)!.Name);   // visiting Checks doesn't reset the Stress tests page
        s.SelectedModule = "SecurityAudit";                                  // not on either page: both keep theirs
        Assert.Equal("B", s.SelectedIn(CheckGroup.Checks)!.Name);
    }

    [Fact]
    public void Selection_TriState_AndDefaults()
    {
        var (_, _, s, _) = Build();
        Assert.True(s.AllSelected(CheckGroup.Checks));
        s.FocusModule("B");
        Assert.Equal("B", s.SelectedModule);
        Assert.False(s.CollapsedChecks);
        s.FocusModule("CpuStress");
        Assert.Equal("CpuStress", s.SelectedModule);
        Assert.False(s.CollapsedStress);
        Assert.Equal(2, s.SelectedCount(CheckGroup.Stress));
        s.SetSelected("A", false);
        Assert.Null(s.AllSelected(CheckGroup.Checks));
        Assert.Equal(1, s.SelectedCount(CheckGroup.Checks));
        s.SelectAll(CheckGroup.Checks, false);
        Assert.False(s.AllSelected(CheckGroup.Checks));
        s.SelectAll(CheckGroup.Checks, true);
        Assert.True(s.AllSelected(CheckGroup.Checks));
        s.FocusModule("B");
        Assert.Equal("B", s.SelectedModule);
        Assert.False(s.CollapsedChecks);
        s.FocusModule("CpuStress");
        Assert.Equal("CpuStress", s.SelectedModule);
        Assert.False(s.CollapsedStress);
    }

    [Fact]
    public async Task ChecksGroup_RunsSelectedSequentially_WithProgress()
    {
        var (_, store, s, _) = Build();
        s.SetSelected("B", false);
        var seen = new List<GroupRunProgress>();
        s.Changed += () => { if (s.Progress is { } p) lock (seen) seen.Add(p); };
        await s.RunGroupAsync(CheckGroup.Checks);
        Assert.Equal(DiagnosticStatus.Ok, store.Get("A").Status);
        Assert.Equal(DiagnosticStatus.NotRun, store.Get("B").Status);
        Assert.Contains(seen, p => p.Index == 1 && p.Total == 1 && p.Current == "A");
        Assert.Null(s.RunningGroup);
        Assert.False(s.CollapsedChecks);
    }

    [Fact]
    public async Task StressGroup_RunsOnlySelected_InMode_AndLabels()
    {
        var (_, store, s, stress) = Build();
        s.SetSelected("MemoryTest", false);
        s.Mode = StressSuiteMode.Extended;
        await s.RunGroupAsync(CheckGroup.Stress);
        Assert.Equal(DiagnosticStatus.Ok, store.Get("CpuStress").Status);
        Assert.Equal(DiagnosticStatus.NotRun, store.Get("MemoryTest").Status);
        Assert.Equal(DiagnosticStatus.NotRun, store.Get("A").Status); // no quick checks
        Assert.Equal(TimeSpan.FromMinutes(5), stress[0].DurationsSeen.Single());
        Assert.Equal("extended run", s.RunLabel("CpuStress"));
        s.Mode = StressSuiteMode.Short; // changing mode later doesn't relabel
        Assert.Equal("Passed (extended run)", CheckRows.Label(CheckRows.KindOf(store.Get("CpuStress")), s.RunLabel("CpuStress")));
    }

    /// <summary>An on-demand test listed on the Stress tests page (like SFC/DISM): a separate step after the stress tests.</summary>
    private sealed class SeparateStep(string name, Func<CancellationToken, Task<DiagnosticResult>> run) : IDiagnosticModule
    {
        public int Runs;
        public string Name => name;
        public Guid Id => TestIds.For(name);
        public bool IncludeInRunAll => false;
#pragma warning disable CS0067
        public event EventHandler<DiagnosticResult>? Updated;
#pragma warning restore CS0067
        public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken ct = default) => Task.FromResult(ModuleAvailability.Available);
        public Task<DiagnosticResult> RefreshAsync(IProgress<string>? p, CancellationToken ct = default) { Interlocked.Increment(ref Runs); return run(ct); }
    }

    private static (DiagnosticsService Svc, ChecksScreenState State, SeparateStep[] Separate) BuildWithSeparateSteps(
        Func<FakeStressModule, CancellationToken, Task<DiagnosticResult>> stressRun, Func<string, DiagnosticResult>? step = null)
    {
        var store = new ResultStore();
        step ??= FakeModule.Ok;
        var separate = new[]
        {
            new SeparateStep("SfcScan", _ => Task.FromResult(step("SfcScan"))),
            new SeparateStep("DismScanHealth", _ => Task.FromResult(step("DismScanHealth"))),
        };
        var svc = new DiagnosticsService(store, [new FakeStressModule("CpuStress", "CPU", stressRun), separate[0], separate[1]]);
        var s = new ChecksScreenState(svc, store);
        s.SelectAll(CheckGroup.Stress, true);
        return (svc, s, separate);
    }

    [Fact]
    public async Task StressRun_CancelledFromOutsideThisPage_DoesNotStartTheSeparateSteps()
    {
        var gate = new TaskCompletionSource();
        var (svc, s, separate) = BuildWithSeparateSteps(async (m, ct) =>
        {
            gate.TrySetResult();
            await Task.Delay(Timeout.Infinite, ct);
            return FakeModule.Ok(m.Name);
        });
        Assert.Equal("CpuStress", s.StressModules[0].Name);
        Assert.Equal(3, s.StressModules.Count);
        var run = s.RunGroupAsync(CheckGroup.Stress);
        await gate.Task;
        svc.CancelStressSuite(); // the Dashboard's Cancel and a stress test's own Stop button: not ChecksScreenState.Stop
        await run;
        Assert.Null(s.RunningGroup);
        Assert.All(separate, step => Assert.Equal(0, step.Runs));
    }

    [Fact]
    public async Task StressRun_SeparateStepStoppedByTheUser_DoesNotStartTheNextOne()
    {
        var (_, s, separate) = BuildWithSeparateSteps((m, _) => Task.FromResult(FakeModule.Ok(m.Name)),
            name => new DiagnosticResult(name, DiagnosticStatus.Warning, "Cancelled", DateTimeOffset.Now) { Cancelled = true });
        await s.RunGroupAsync(CheckGroup.Stress);
        Assert.Equal(1, separate.Sum(step => step.Runs)); // whichever is first ran and was stopped; the other never started
    }

    [Fact]
    public async Task StressRun_Finished_RunsTheSeparateSteps()
    {
        var (_, s, separate) = BuildWithSeparateSteps((m, _) => Task.FromResult(FakeModule.Ok(m.Name)));
        await s.RunGroupAsync(CheckGroup.Stress);
        Assert.All(separate, step => Assert.Equal(1, step.Runs));
    }

    [Fact]
    public async Task Stop_CancelsAndKeepsLastCompletedResult()
    {
        var gate = new TaskCompletionSource();
        var block = false;
        var (_, store, s, _) = Build(async (m, ct) =>
        {
            if (!block) return FakeModule.Ok(m.Name);
            gate.TrySetResult();
            await Task.Delay(Timeout.Infinite, ct);
            return FakeModule.Ok(m.Name);
        });
        await s.RunGroupAsync(CheckGroup.Stress);
        Assert.Equal(RowKind.Passed, CheckRows.KindOf(store.Get("CpuStress")));
        block = true;
        var run = s.RunGroupAsync(CheckGroup.Stress);
        await gate.Task;
        Assert.Equal(CheckGroup.Stress, s.RunningGroup);
        s.Stop();
        await run;
        Assert.Equal(RowKind.Cancelled, CheckRows.KindOf(store.Get("CpuStress")));
        var last = s.LastCompleted("CpuStress");
        Assert.NotNull(last);
        Assert.Equal(DiagnosticStatus.Ok, last!.Value.Result.Status);
        Assert.Equal("short run", last.Value.RunLabel);
        Assert.Equal(DiagnosticStatus.Ok, store.Get("MemoryTest").Status); // not started after Stop: first run's result kept
    }

    [Fact]
    public async Task RunButtons_DisabledRules()
    {
        var gate = new TaskCompletionSource();
        var release = new TaskCompletionSource();
        var (svc, _, s, stress) = Build(async (m, ct) => { gate.TrySetResult(); await release.Task.WaitAsync(ct); return FakeModule.Ok(m.Name); });
        var mods = svc.Modules;
        Assert.True(s.CanRunSingle(mods.First(m => m.Name == "A")));
        var run = s.RunGroupAsync(CheckGroup.Stress);
        await gate.Task;
        Assert.True(s.IsBusy);
        Assert.False(s.CanRunSingle(mods.First(m => m.Name == "A")));
        Assert.False(s.CanRunSingle(stress[1]));
        await s.RunGroupAsync(CheckGroup.Checks); // ignored while busy (returns at once)
        Assert.Equal(CheckGroup.Stress, s.RunningGroup);
        Assert.False(s.IsRunAll);
        Assert.Equal(["MemoryTest"], s.RemainingSteps());
        release.SetResult();
        await run;
        Assert.False(s.IsBusy);
        Assert.True(s.CanRunSingle(stress[1]));
    }

    [Fact]
    public void Banner_RunProgress_Problems_Healthy()
    {
        var mods = new[] { new BannerModule("A", "Drive health", false, false, DiagnosticStatus.Ok), new BannerModule("B", "App crashes", false, false, DiagnosticStatus.Warning, "1 crash") };
        var sum = DashboardSummary.Build(mods, null);
        Assert.Equal(("run", "Running 2 of 5: CPU stress test"), ChecksBanner.Build(sum, new GroupRunProgress(CheckGroup.Stress, 2, 5, "CPU stress test"), true));
        Assert.Equal(("warn", "1 thing to look at: App crashes"), ChecksBanner.Build(sum, null, true));
        var ok = DashboardSummary.Build([mods[0]], null);
        Assert.Equal(("ok", "Your PC looks healthy"), ChecksBanner.Build(ok, null, true));
        Assert.Equal(("ok", "Not checked yet"), ChecksBanner.Build(ok, null, false));
    }

    [Fact]
    public async Task StressGroup_SurfacesSuiteSummary_AndErrors_InsteadOfSwallowing()
    {
        var (svc, _, s, stress) = Build();
        stress[1].CouldNotRun = true;
        await s.RunGroupAsync(CheckGroup.Stress);
        Assert.NotNull(s.LastSuiteResult);
        Assert.Equal(StressSuiteOutcome.Completed, s.LastSuiteResult!.Outcome);
        Assert.Contains("Skipped: Memory", s.LastRunNote);

    }

    [Fact]
    public async Task RunAllChecks_RunsEveryCheckModule_EvenWhenUnticked_AndTracksCheckItems()
    {
        var gate = new TaskCompletionSource();
        var release = new TaskCompletionSource();
        var store = new ResultStore();
        var svc = new DiagnosticsService(store, [
            new FakeModule("A", async (p, ct) =>
            {
                p?.ReportStep(1, 2, "Step one");
                gate.TrySetResult();
                await release.Task.WaitAsync(ct);
                return FakeModule.Ok("A");
            }),
            new FakeModule("B", _ => Task.FromResult(new DiagnosticResult("B", DiagnosticStatus.Warning, "warn", DateTimeOffset.Now)))]);
        var s = new ChecksScreenState(svc, store);
        s.SetSelected("B", false);

        var run = s.RunAllChecksAsync();
        await gate.Task;

        Assert.Equal(CheckGroup.Checks, s.RunningGroup);
        Assert.Equal(2, s.TotalChecksCount);
        var live = s.LiveCheckItems(store);
        Assert.Equal(2, live.Count);
        Assert.Equal(DiagnosticStatus.Running, live[0].Status);
        Assert.Equal("Step one", live[0].Message);
        Assert.Equal(1, live[0].Step);
        Assert.Equal(2, live[0].Total);
        Assert.True(s.IsRunAll);
        // B runs beside A (checks run up to MaxConcurrentChecks at once), so it finishes while A is still going.
        await WaitUntilAsync(() => s.CheckItems.Any(c => c.Id == "B" && c.Status == DiagnosticStatus.Warning));
        Assert.True(s.CheckProgressFraction > 0.5 && s.CheckProgressFraction < 1);
        Assert.Empty(s.RemainingSteps());
        Assert.Contains(svc.RunningModules, run => run.ModuleName == "A" && run.RunId is not null);

        release.SetResult();
        await run;

        Assert.Equal(DiagnosticStatus.Ok, store.Get("A").Status);
        Assert.Equal(DiagnosticStatus.Warning, store.Get("B").Status);
        Assert.Null(s.RunningGroup);
        Assert.Empty(s.CheckItems);
        Assert.False(s.IsRunAll);
        Assert.Empty(s.RemainingSteps());
        Assert.Empty(svc.RunningModules);
    }

    [Fact]
    public async Task RunAllChecks_RunsAtMostMaxConcurrentChecksAtOnce()
    {
        var store = new ResultStore();
        var release = new TaskCompletionSource();
        var running = 0;
        var peak = 0;
        var names = Enumerable.Range(1, ChecksScreenState.MaxConcurrentChecks + 2).Select(i => $"C{i}").ToArray();
        var svc = new DiagnosticsService(store, [.. names.Select(n => (IDiagnosticModule)new FakeModule(n, async ct =>
        {
            var now = Interlocked.Increment(ref running);
            int seen;
            while ((seen = Volatile.Read(ref peak)) < now && Interlocked.CompareExchange(ref peak, now, seen) != seen) { }
            try { await release.Task.WaitAsync(ct); return FakeModule.Ok(n); }
            finally { Interlocked.Decrement(ref running); }
        }))]);
        var s = new ChecksScreenState(svc, store);

        var run = s.RunAllChecksAsync();
        await WaitUntilAsync(() => Volatile.Read(ref running) == ChecksScreenState.MaxConcurrentChecks);
        await Task.Delay(50);
        Assert.Equal(ChecksScreenState.MaxConcurrentChecks, Volatile.Read(ref running));
        Assert.Equal(2, s.CheckItems.Count(c => c.Id.StartsWith('C') && c.Status == DiagnosticStatus.NotRun));
        Assert.Equal(ChecksScreenState.MaxConcurrentChecks, s.Progress?.Index);
        Assert.Equal(names.Length, s.Progress?.Total);
        Assert.Equal(ChecksScreenState.MaxConcurrentChecks, s.Progress!.Current.Split(", ").Length);

        release.SetResult();
        await run;

        Assert.Equal(ChecksScreenState.MaxConcurrentChecks, peak);
        Assert.All(names, n => Assert.Equal(DiagnosticStatus.Ok, store.Get(n).Status));
        Assert.Null(s.RunningGroup);
    }

    [Fact]
    public async Task RunAllChecks_RunsHardwareInventoryFirst_ThenTheRestTogether()
    {
        var store = new ResultStore();
        var inventoryRelease = new TaskCompletionSource();
        var inventoryStarted = new TaskCompletionSource();
        var othersStarted = 0;
        var othersRelease = new TaskCompletionSource();
        var svc = new DiagnosticsService(store, [
            new FakeModule("A", async ct => { Interlocked.Increment(ref othersStarted); await othersRelease.Task.WaitAsync(ct); return FakeModule.Ok("A"); }),
            new FakeModule("B", async ct => { Interlocked.Increment(ref othersStarted); await othersRelease.Task.WaitAsync(ct); return FakeModule.Ok("B"); }),
            new FakeModule(ModuleSlugs.Osquery, async ct => { inventoryStarted.TrySetResult(); await inventoryRelease.Task.WaitAsync(ct); return FakeModule.Ok(ModuleSlugs.Osquery); })]);
        var s = new ChecksScreenState(svc, store);

        var run = s.RunAllChecksAsync();
        await inventoryStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await Task.Delay(50);
        Assert.Equal(0, Volatile.Read(ref othersStarted));
        Assert.Equal(1, s.Progress?.Index);

        inventoryRelease.SetResult();
        await WaitUntilAsync(() => Volatile.Read(ref othersStarted) == 2);
        othersRelease.SetResult();
        await run;

        Assert.Equal(DiagnosticStatus.Ok, store.Get(ModuleSlugs.Osquery).Status);
        Assert.Equal(DiagnosticStatus.Ok, store.Get("A").Status);
        Assert.Equal(DiagnosticStatus.Ok, store.Get("B").Status);
    }

    [Fact]
    public async Task RunAllChecks_Stop_LeavesQueuedChecksUnstarted()
    {
        var store = new ResultStore();
        var startedNames = new System.Collections.Concurrent.ConcurrentBag<string>();
        var names = Enumerable.Range(1, ChecksScreenState.MaxConcurrentChecks + 2).Select(i => $"C{i}").ToArray();
        var svc = new DiagnosticsService(store, [.. names.Select(n => (IDiagnosticModule)new FakeModule(n, async ct =>
        {
            startedNames.Add(n);
            await Task.Delay(Timeout.Infinite, ct);
            return FakeModule.Ok(n);
        }))]);
        var s = new ChecksScreenState(svc, store);

        var run = s.RunAllChecksAsync();
        await WaitUntilAsync(() => startedNames.Count == ChecksScreenState.MaxConcurrentChecks);
        s.Stop();
        await run;

        Assert.Equal(ChecksScreenState.MaxConcurrentChecks, startedNames.Count);
        Assert.Null(s.RunningGroup);
        Assert.Null(s.LastRunNote);
    }

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        for (var i = 0; i < 500 && !condition(); i++) await Task.Delay(10);
        Assert.True(condition());
    }

    [Fact]
    public void Stop_CancelsStandaloneCancellableScan()
    {
        var store = new ResultStore();
        var scan = new StubCancellableScan();
        var svc = new DiagnosticsService(store, [scan]);
        var s = new ChecksScreenState(svc, store);

        s.Stop();

        Assert.True(scan.Cancelled);
    }

    private sealed class StubCancellableScan : IDiagnosticModule, RemotePCDiagnostics.Core.Areas.ICancellableScan
    {
        public bool Cancelled { get; private set; }
        public Guid Id { get; } = Guid.NewGuid();
        public string Name => "StubScan";
        public string DisplayName => "Stub scan";
        public bool IncludeInRunAll => false;
        public event EventHandler<DiagnosticResult>? Updated { add { } remove { } }
        public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken ct = default) =>
            Task.FromResult(ModuleAvailability.Available);
        public Task<DiagnosticResult> RefreshAsync(IProgress<string>? progress = null, CancellationToken ct = default) =>
            Task.FromResult(new DiagnosticResult(Name, DiagnosticStatus.Ok, "ok", DateTimeOffset.Now));
        public void Cancel() => Cancelled = true;
    }
}
