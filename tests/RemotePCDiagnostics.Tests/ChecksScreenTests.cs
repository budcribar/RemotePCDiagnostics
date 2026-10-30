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
    [InlineData(DiagnosticStatus.NotRun, "Not run yet", RowKind.NotRun)]
    [InlineData(DiagnosticStatus.Running, "Running…", RowKind.Running)]
    public void KindOf_MatchesRealResult(DiagnosticStatus st, string msg, RowKind expected) =>
        Assert.Equal(expected, CheckRows.KindOf(new DiagnosticResult("M", st, msg, DateTimeOffset.Now)));

    [Fact]
    public void Unavailable_FromAvailabilityPayload() =>
        Assert.Equal(RowKind.Unavailable, CheckRows.KindOf(new DiagnosticResult("M", DiagnosticStatus.Error, "no", DateTimeOffset.Now, ModuleAvailability.Unavailable("no"))));

    [Fact]
    public void Labels_UseModeTheResultRanIn_WarningNeverPassed()
    {
        Assert.Equal("Passed (short run)", CheckRows.Label(RowKind.Passed, "short run"));
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
}
