using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Stress;

namespace RemotePCDiagnostics.Tests;

/// <summary>The one runner the stress pages start, stop and time their test with.</summary>
public sealed class StressTestRunnerTests
{
    internal sealed record TickProgress(TimeSpan Elapsed, TimeSpan Duration) : StressProgressBase(Elapsed, Duration);

    /// <summary>A stress test that reports 15 s in, then runs until it is stopped.</summary>
    internal sealed class HeldStressModule(string name) : StressModuleBase<TickProgress, string>(null)
    {
        public override string Name => name;
        public override Guid Id => TestIds.For(name);
        public override string DisplayName => name;
        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public List<TimeSpan> DurationsSeen { get; } = [];

        protected override async Task<string> RunTestAsync(StressCleanup cleanup, IProgress<TickProgress> progress, CancellationToken cancellationToken)
        {
            DurationsSeen.Add(Duration);
            progress.Report(new TickProgress(TimeSpan.FromSeconds(15), Duration));
            Started.TrySetResult();
            try { await Task.Delay(Timeout.Infinite, cancellationToken); }
            catch (OperationCanceledException) { return "Stopped"; }
            return "Done";
        }

        protected override (DiagnosticStatus Status, string Headline) Describe(string report) => (DiagnosticStatus.Ok, report);
    }

    private static readonly TimeSpan Wait = TimeSpan.FromSeconds(10);

    private static (DiagnosticsService Svc, ResultStore Store, HeldStressModule Cpu, HeldStressModule Memory) Build()
    {
        var store = new ResultStore();
        var cpu = new HeldStressModule("CpuStress");
        var memory = new HeldStressModule("MemoryTest");
        return (new DiagnosticsService(store, [cpu, memory]), store, cpu, memory);
    }

    private static async Task Until(Func<bool> condition)
    {
        var end = DateTime.UtcNow + Wait;
        while (!condition())
        {
            if (DateTime.UtcNow > end) throw new TimeoutException();
            await Task.Delay(10);
        }
    }

    [Fact]
    public async Task Start_PutsThePagesSettingsOnTheTest_ThenReportsItsTime()
    {
        var (svc, store, cpu, _) = Build();
        using var runner = new StressTestRunner<TickProgress, string>(svc, store, cpu);
        var changes = 0;
        runner.Changed += (_, _) => Interlocked.Increment(ref changes);

        Assert.True(runner.CanStart);
        Assert.False(runner.CanStop);
        Assert.Null(runner.TimeText);

        Assert.True(runner.Start(() => cpu.Duration = TimeSpan.FromMinutes(5)));
        await cpu.Started.Task.WaitAsync(Wait);
        await Until(() => runner.IsRunning);

        Assert.Equal(new[] { TimeSpan.FromMinutes(5) }, cpu.DurationsSeen);
        Assert.True(changes > 0);
        Assert.False(runner.CanStart);
        Assert.True(runner.CanStop);
        Assert.Equal(0.05, runner.Fraction, 3);
        Assert.Equal(TimeSpan.FromSeconds(15), runner.Elapsed);
        Assert.Equal("0:15 of 5:00", runner.TimeText);
        Assert.Equal("0:15 of 5:00", runner.LiveProgress?.Headline);

        runner.Stop();
        await Until(() => !svc.IsRunning(cpu.Name) && !runner.IsRunning);

        Assert.Null(runner.Progress);
        Assert.Null(runner.LiveProgress);
        Assert.Equal(0, runner.Fraction);
        Assert.True(runner.CanStart);
    }

    [Fact]
    public async Task Start_WhileAnotherStressTestRuns_DoesNothing()
    {
        var (svc, store, cpu, memory) = Build();
        using var runner = new StressTestRunner<TickProgress, string>(svc, store, cpu);
        _ = svc.RunAsync(memory.Name);
        await memory.Started.Task.WaitAsync(Wait);

        var applied = false;
        Assert.True(runner.IsOtherBusy);
        Assert.False(runner.CanStart);
        Assert.False(runner.CanStop);
        Assert.False(runner.Start(() => applied = true));
        Assert.False(applied);
        Assert.Empty(cpu.DurationsSeen);

        memory.Stop();
        await Until(() => !svc.IsAnyStressRunning);
        Assert.True(runner.CanStart);
    }

    [Fact]
    public async Task Stop_DuringTheStressSuite_EndsTheWholeRun()
    {
        var (svc, store, cpu, memory) = Build();
        using var runner = new StressTestRunner<TickProgress, string>(svc, store, cpu);
        var finished = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        runner.SuiteFinished += (_, _) => finished.TrySetResult();

        var suite = svc.RunStressSuiteAsync(StressSuiteMode.Short, null, runQuickChecks: false);
        await cpu.Started.Task.WaitAsync(Wait);
        Assert.True(runner.IsSuiteRunning);
        Assert.True(runner.CanStop);

        runner.Stop();
        await suite.WaitAsync(Wait);
        await finished.Task.WaitAsync(Wait);

        Assert.False(memory.Started.Task.IsCompleted);
        Assert.False(svc.IsStressSuiteRunning);
    }

    [Fact]
    public async Task Dispose_StopsPassingOnTheTestsProgress()
    {
        var (svc, store, cpu, _) = Build();
        var runner = new StressTestRunner<TickProgress, string>(svc, store, cpu);
        var changes = 0;
        runner.Changed += (_, _) => Interlocked.Increment(ref changes);
        runner.Dispose();
        runner.Dispose();

        _ = svc.RunAsync(cpu.Name);
        await cpu.Started.Task.WaitAsync(Wait);
        cpu.Stop();
        await Until(() => !svc.IsRunning(cpu.Name));

        Assert.Equal(0, changes);
    }
}
