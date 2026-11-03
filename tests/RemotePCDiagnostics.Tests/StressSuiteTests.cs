using System.Collections.Concurrent;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Stress;

namespace RemotePCDiagnostics.Tests;

internal sealed class FakeStressModule(string name, string suiteName, Func<FakeStressModule, CancellationToken, Task<DiagnosticResult>>? run = null,
    bool available = true) : IStressSuiteModule
{
    public string Name => name;
    public string SuiteName => suiteName;
    public bool IncludeInRunAll => false;
    public event EventHandler<DiagnosticResult>? Updated;
    public TimeSpan Duration { get; set; } = TimeSpan.FromMinutes(3);
    public List<TimeSpan> DurationsSeen { get; } = new();
    public int StopCalls;
    public bool Unavailable;
    public bool Hot;
    public bool CouldNotRun;
    public Action? OnStart, OnEnd;
    private CancellationTokenSource? _stop;
    public void Stop() { Interlocked.Increment(ref StopCalls); _stop?.Cancel(); }
    public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken ct = default) =>
        Task.FromResult(available ? ModuleAvailability.Available : ModuleAvailability.Unavailable("no device"));
    public async Task<DiagnosticResult> RefreshAsync(IProgress<string>? p, CancellationToken ct = default)
    {
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _stop = stop;
        DurationsSeen.Add(Duration);
        OnStart?.Invoke();
        try
        {
            if (run is not null) return await run(this, stop.Token);
            await Task.Delay(10, stop.Token);
            return FakeModule.Ok(name);
        }
        catch (OperationCanceledException)
        {
            return new DiagnosticResult(name, DiagnosticStatus.Warning, "Stopped", DateTimeOffset.Now);
        }
        finally { OnEnd?.Invoke(); _stop = null; }
    }
    bool IStressSuiteModule.IsUnavailableResult(DiagnosticResult r) => Unavailable;
    bool IStressSuiteModule.IsOverheatedResult(DiagnosticResult r) => Hot && r.Status == DiagnosticStatus.Error;
    bool IStressSuiteModule.IsStoppedByUserResult(DiagnosticResult r) => r.Status == DiagnosticStatus.Warning && r.Message == "Stopped";
    bool IStressSuiteModule.IsCouldNotRunResult(DiagnosticResult r) => CouldNotRun || r.Payload is Exception;
    public void Push(DiagnosticResult r) => Updated?.Invoke(this, r);
}

public class StressSuiteTests
{
    private static (DiagnosticsService Svc, ResultStore Store, FakeStressModule[] Mods, ConcurrentQueue<string> Events) Build(
        Func<string, Func<FakeStressModule, CancellationToken, Task<DiagnosticResult>>?>? run = null, Func<string, bool>? available = null)
    {
        var store = new ResultStore();
        var events = new ConcurrentQueue<string>();
        var names = new[] { ("CpuStress", "CPU"), ("MemoryTest", "Memory"), ("DiskSpeed", "Disk"), ("GpuStress", "GPU"), ("NetworkTest", "Network") };
        // Registered in a scrambled order: the suite must still use CPU, Memory, Disk, GPU, Network.
        var mods = names.Select(n => new FakeStressModule(n.Item1, n.Item2, run?.Invoke(n.Item1), available?.Invoke(n.Item1) ?? true)).ToArray();
        int active = 0;
        foreach (var m in mods)
        {
            var n = m.Name;
            m.OnStart = () => { if (Interlocked.Increment(ref active) != 1) events.Enqueue("OVERLAP"); events.Enqueue("start:" + n); };
            m.OnEnd = () => { events.Enqueue("end:" + n); Interlocked.Decrement(ref active); };
        }
        var svc = new DiagnosticsService(store, [mods[4], mods[2], new FakeModule("Quick", _ => Task.FromResult(FakeModule.Ok("Quick"))), mods[0], mods[3], mods[1]]);
        return (svc, store, mods, events);
    }

    private sealed class ListProgress : IProgress<StressSuiteProgress>
    {
        public ConcurrentQueue<StressSuiteProgress> Items { get; } = new();
        public void Report(StressSuiteProgress v) => Items.Enqueue(v);
    }

    [Fact]
    public async Task RunsStrictlyInOrder_NeverOverlapping_AfterQuickChecks()
    {
        var (svc, store, mods, events) = Build();
        var r = await svc.RunStressSuiteAsync(StressSuiteMode.Short, null);
        Assert.Equal(StressSuiteOutcome.Completed, r.Outcome);
        Assert.DoesNotContain("OVERLAP", events);
        Assert.Equal(new[] { "start:CpuStress", "end:CpuStress", "start:MemoryTest", "end:MemoryTest", "start:DiskSpeed", "end:DiskSpeed",
            "start:GpuStress", "end:GpuStress", "start:NetworkTest", "end:NetworkTest" }, events.ToArray());
        Assert.Equal(DiagnosticStatus.Ok, store.Get("Quick").Status);
        Assert.All(r.Steps, s => Assert.Equal(StressSuiteStepState.Passed, s.State));
        Assert.Equal("short run", svc.StressRunLabel("CpuStress"));
        Assert.Null(svc.StressRunLabel("Quick"));
    }

    [Theory]
    [InlineData(StressSuiteMode.Short, 1, "short run")]
    [InlineData(StressSuiteMode.Extended, 5, "extended run")]
    public async Task SetsDurationsForRun_AndRestoresThem(StressSuiteMode mode, int minutes, string label)
    {
        var (svc, _, mods, _) = Build();
        await svc.RunStressSuiteAsync(mode, null);
        Assert.All(mods, m => Assert.Equal(TimeSpan.FromMinutes(minutes), Assert.Single(m.DurationsSeen)));
        Assert.All(mods, m => Assert.Equal(TimeSpan.FromMinutes(3), m.Duration));
        Assert.Equal(label, svc.StressRunLabel("NetworkTest"));
    }

    [Fact]
    public async Task RestoresDurations_WhenModuleThrows()
    {
        var (svc, store, mods, _) = Build(n => n == "MemoryTest" ? (_, _) => throw new InvalidOperationException("boom") : null);
        var r = await svc.RunStressSuiteAsync(StressSuiteMode.Extended, null);
        // A test that crashed couldn't run: it is skipped with the reason, not reported as a hardware problem.
        Assert.Equal(StressSuiteOutcome.Completed, r.Outcome);
        Assert.Equal(StressSuiteStepState.Skipped, r.Steps[1].State);
        Assert.Contains("boom", r.Message);
        Assert.All(mods, m => Assert.Equal(TimeSpan.FromMinutes(3), m.Duration));
        Assert.Equal(DiagnosticStatus.Error, store.Get("MemoryTest").Status);
    }

    [Fact]
    public async Task StopsOnError_RestNotRun()
    {
        var (svc, _, mods, _) = Build(n => n == "MemoryTest" ? (_, _) => Task.FromResult(new DiagnosticResult(n, DiagnosticStatus.Error, "errors found", DateTimeOffset.Now)) : null);
        var r = await svc.RunStressSuiteAsync(StressSuiteMode.Short, null);
        Assert.Equal(StressSuiteOutcome.StoppedOnProblem, r.Outcome);
        Assert.Equal(new[] { StressSuiteStepState.Passed, StressSuiteStepState.Problem, StressSuiteStepState.NotRun, StressSuiteStepState.NotRun, StressSuiteStepState.NotRun },
            r.Steps.Select(s => s.State).ToArray());
        Assert.Empty(mods[2].DurationsSeen);
        Assert.Contains("Memory", r.Message);
        Assert.Contains("remaining tests were not run", r.Message);
    }

    [Fact]
    public async Task StopsOnOverheated_WithFriendlyMessage()
    {
        var (svc, _, mods, _) = Build(n => n == "CpuStress" ? (_, _) => Task.FromResult(new DiagnosticResult(n, DiagnosticStatus.Error, "Stopped: CPU got too hot", DateTimeOffset.Now)) : null);
        mods[0].Hot = true;
        var r = await svc.RunStressSuiteAsync(StressSuiteMode.Short, null);
        Assert.Equal(StressSuiteOutcome.StoppedOnProblem, r.Outcome);
        Assert.Contains("too hot", r.Message);
        Assert.All(mods.Skip(1), m => Assert.Empty(m.DurationsSeen));
    }

    [Fact]
    public async Task SkipsUnavailableModule_WithoutFailing()
    {
        var (svc, store, mods, _) = Build(available: n => n != "GpuStress");
        var r = await svc.RunStressSuiteAsync(StressSuiteMode.Short, null);
        Assert.Equal(StressSuiteOutcome.Completed, r.Outcome);
        Assert.Equal(StressSuiteStepState.Skipped, r.Steps.Single(s => s.ModuleName == "GpuStress").State);
        Assert.Empty(mods[3].DurationsSeen);
        Assert.Single(mods[4].DurationsSeen);
        Assert.Equal(DiagnosticStatus.NotRun, store.Get("GpuStress").Status);
    }

    [Fact]
    public async Task SkipsModule_WhoseResultSaysNoDevice()
    {
        var (svc, _, mods, _) = Build(n => n == "GpuStress" ? (_, _) => Task.FromResult(new DiagnosticResult(n, DiagnosticStatus.Warning, "No graphics card found", DateTimeOffset.Now)) : null);
        mods[3].Unavailable = true;
        var r = await svc.RunStressSuiteAsync(StressSuiteMode.Short, null);
        Assert.Equal(StressSuiteOutcome.Completed, r.Outcome);
        Assert.Equal(StressSuiteStepState.Skipped, r.Steps[3].State);
        Assert.Single(mods[4].DurationsSeen);
    }

    [Fact]
    public async Task Cancel_StopsCurrentTest_EndsSequence_RestoresDurations()
    {
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var (svc, _, mods, _) = Build(n => n == "DiskSpeed" ? async (_, ct) => { started.TrySetResult(); await Task.Delay(Timeout.Infinite, ct); return FakeModule.Ok(n); } : null);
        var run = svc.RunStressSuiteAsync(StressSuiteMode.Extended, null);
        await started.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(TimeSpan.FromMinutes(5), mods[2].Duration);
        svc.CancelStressSuite();
        var r = await run.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(StressSuiteOutcome.Cancelled, r.Outcome);
        Assert.True(mods[2].StopCalls >= 1);
        Assert.Empty(mods[3].DurationsSeen);
        Assert.Empty(mods[4].DurationsSeen);
        Assert.All(mods, m => Assert.Equal(TimeSpan.FromMinutes(3), m.Duration));
        Assert.Equal(StressSuiteStepState.NotRun, r.Steps[4].State);
        Assert.False(svc.IsStressSuiteRunning);
    }

    [Fact]
    public async Task ModuleStop_WhileSuiteRunning_CancelsRemainingSuite()
    {
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var (svc, _, mods, _) = Build(n => n == "MemoryTest" ? async (_, ct) => { started.TrySetResult(); await Task.Delay(Timeout.Infinite, ct); return FakeModule.Ok(n); } : null);
        var run = svc.RunStressSuiteAsync(StressSuiteMode.Short, null);
        await started.Task.WaitAsync(TimeSpan.FromSeconds(10));
        mods[1].Stop();
        var r = await run.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(StressSuiteOutcome.Cancelled, r.Outcome);
        Assert.Empty(mods[2].DurationsSeen);
        Assert.Empty(mods[3].DurationsSeen);
        Assert.Empty(mods[4].DurationsSeen);
    }

    [Fact]
    public async Task ExternalToken_CancelsSuite()
    {
        using var cts = new CancellationTokenSource();
        var (svc, _, mods, _) = Build(n => n == "CpuStress" ? async (_, ct) => { cts.Cancel(); await Task.Delay(Timeout.Infinite, ct); return FakeModule.Ok(n); } : null);
        var r = await svc.RunStressSuiteAsync(StressSuiteMode.Short, null, cts.Token).WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(StressSuiteOutcome.Cancelled, r.Outcome);
        Assert.Empty(mods[1].DurationsSeen);
    }

    [Fact]
    public async Task DoubleStart_IsRejected()
    {
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var (svc, _, mods, _) = Build(n => n == "CpuStress" ? async (_, _) => { await gate.Task; return FakeModule.Ok(n); } : null);
        var first = svc.RunStressSuiteAsync(StressSuiteMode.Short, null);
        Assert.True(svc.IsStressSuiteRunning);
        await Assert.ThrowsAsync<InvalidOperationException>(() => svc.RunStressSuiteAsync(StressSuiteMode.Extended, null));
        gate.SetResult();
        var r = await first.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(StressSuiteOutcome.Completed, r.Outcome);
        Assert.Single(mods[0].DurationsSeen);
        Assert.False(svc.IsStressSuiteRunning);
        Assert.Equal(StressSuiteOutcome.Completed, (await svc.RunStressSuiteAsync(StressSuiteMode.Short, null)).Outcome);
    }

    [Fact]
    public async Task ReportsProgress()
    {
        var (svc, _, _, _) = Build();
        var p = new ListProgress();
        await svc.RunStressSuiteAsync(StressSuiteMode.Short, p);
        var items = p.Items.ToArray();
        Assert.Equal("Running quick checks…", items[0].Headline);
        Assert.Contains(items, x => x.Headline == "Stress test 2 of 5: Memory");
        Assert.Contains(items, x => x.Headline == "Stress test 5 of 5: Network");
        Assert.True(items[^1].Finished);
        Assert.Equal("Stress tests finished (short run).", items[^1].Headline);
        Assert.Same(items[^1], svc.LastStressSuiteProgress);
    }

    [Fact]
    public async Task ModuleUpdates_StillReachStore()
    {
        var (svc, store, mods, _) = Build(n => n == "CpuStress" ? (m, _) => { m.Push(new DiagnosticResult(n, DiagnosticStatus.Running, "half way", DateTimeOffset.Now)); return Task.FromResult(FakeModule.Ok(n)); } : null);
        var seen = new ConcurrentQueue<string>();
        store.Changed += (_, r) => { if (r.ModuleName == "CpuStress") seen.Enqueue(r.Message); };
        await svc.RunStressSuiteAsync(StressSuiteMode.Short, null);
        Assert.Contains("half way", seen);
        Assert.Equal(DiagnosticStatus.Ok, store.Get("CpuStress").Status);
    }

    // ---- couldn't run vs real problem (IdeaPad: 400 MB free → memory test never ran, suite halted as "found a problem") ----
    [Fact]
    public async Task CouldNotRun_IsSkippedWithReason_AndRemainingTestsStillRun()
    {
        var (svc, _, mods, _) = Build(n => n == "MemoryTest"
            ? (_, _) => Task.FromResult(new DiagnosticResult(n, DiagnosticStatus.Warning, "Couldn't run: not enough free memory", DateTimeOffset.Now))
            : null);
        mods[1].CouldNotRun = true;
        var r = await svc.RunStressSuiteAsync(StressSuiteMode.Short, null);
        Assert.Equal(StressSuiteOutcome.Completed, r.Outcome);
        Assert.Equal(new[] { StressSuiteStepState.Passed, StressSuiteStepState.Skipped, StressSuiteStepState.Passed, StressSuiteStepState.Passed, StressSuiteStepState.Passed },
            r.Steps.Select(s => s.State).ToArray());
        Assert.All(mods.Skip(2), m => Assert.Single(m.DurationsSeen));
        Assert.DoesNotContain("found a problem", r.Message);
        Assert.Contains("Skipped: Memory (Couldn't run: not enough free memory)", r.Message);
        Assert.Equal("Skipped: Couldn't run: not enough free memory", r.Steps[1].Message);
    }

    [Fact]
    public async Task RealMemoryModule_LowMemory_SkipsAndContinues_MemoryErrorsStillStop()
    {
        static async Task<StressSuiteResult> Run(IMemTestHelperLauncher launcher, long available)
        {
            var store = new ResultStore();
            var mem = new MemoryTestModule(new FakeMemoryInfo(available), launcher, new SequenceSensorProvider(_ => throw new PlatformNotSupportedException(), available: false),
                clockFactory: () => new FakeStressClock());
            var others = new[] { ("CpuStress", "CPU"), ("DiskSpeed", "Disk"), ("GpuStress", "GPU"), ("NetworkTest", "Network") }.Select(n => new FakeStressModule(n.Item1, n.Item2)).ToArray();
            var svc = new DiagnosticsService(store, [others[0], mem, others[1], others[2], others[3]]);
            return await svc.RunStressSuiteAsync(StressSuiteMode.Short, null, runQuickChecks: false);
        }
        var low = await Run(new FakeHelperLauncher(), 300 * MemorySizing.MB);
        Assert.Equal(StressSuiteOutcome.Completed, low.Outcome);
        Assert.Equal(StressSuiteStepState.Skipped, low.Steps[1].State);
        Assert.Contains("not enough free memory", low.Steps[1].Message);
        Assert.Equal(StressSuiteStepState.Passed, low.Steps[4].State); // network still ran
        Assert.DoesNotContain("found a problem", low.Message);

        var bad = await Run(new FakeHelperLauncher(h => { h.Send(new MemTestMessage.Allocated(256 * MemorySizing.MB));
            h.Send(new MemTestMessage.BadWord(4096, 0, 8)); h.Send(new MemTestMessage.Done(256 * MemorySizing.MB, 1, 1)); h.Exit(); }), 16 * MemorySizing.GB);
        Assert.Equal(StressSuiteOutcome.StoppedOnProblem, bad.Outcome);
        Assert.Equal(StressSuiteStepState.Problem, bad.Steps[1].State);
        Assert.Contains("found a problem (Memory errors found)", bad.Message);
        Assert.Equal(StressSuiteStepState.NotRun, bad.Steps[2].State);
    }
}
