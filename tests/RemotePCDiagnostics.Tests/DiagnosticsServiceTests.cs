using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Tests;

public class DiagnosticsServiceTests
{
    [Fact]
    public void Register_SeedsNotRun_AndRejectsDuplicates()
    {
        var store = new ResultStore();
        var svc = new DiagnosticsService(store);
        svc.Register(new FakeModule("A", _ => Task.FromResult(FakeModule.Ok("A"))));
        Assert.Equal(DiagnosticStatus.NotRun, store.Get("A").Status);
        Assert.Throws<InvalidOperationException>(() => svc.Register(new FakeModule("a", _ => Task.FromResult(FakeModule.Ok("a")))));
    }

    [Fact]
    public async Task Run_ExceptionBecomesError()
    {
        var store = new ResultStore();
        var svc = new DiagnosticsService(store, [new FakeModule("Bad", _ => throw new InvalidOperationException("boom"))]);
        var r = await svc.RunAsync("Bad");
        Assert.Equal(DiagnosticStatus.Error, r.Status);
        Assert.Equal("boom", store.Get("Bad").Message);
    }

    [Fact]
    public async Task Run_UnavailableModuleIsError()
    {
        var svc = new DiagnosticsService(new ResultStore(), [new FakeModule("X", _ => Task.FromResult(FakeModule.Ok("X")), available: false)]);
        var r = await svc.RunAsync("X");
        Assert.Equal(DiagnosticStatus.Error, r.Status);
        Assert.Equal("missing tool", r.Message);
    }

    [Fact]
    public async Task RunAll_SlowAndFailingModulesDoNotBlockOthers()
    {
        var store = new ResultStore();
        var gate = new TaskCompletionSource();
        var fastDone = new TaskCompletionSource();
        // RunAll schedules each module via Task.Run, so the Slow module may not have started yet
        // when Fast completes (seen on Windows CI). Signal when Slow is actually inside RefreshAsync.
        var slowStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        store.Changed += (_, r) => { if (r.ModuleName == "Fast" && r.Status == DiagnosticStatus.Ok) fastDone.TrySetResult(); };
        var svc = new DiagnosticsService(store,
        [
            new FakeModule("Slow", async _ => { slowStarted.TrySetResult(); await gate.Task; return FakeModule.Ok("Slow"); }),
            new FakeModule("Bad", _ => throw new Exception("fail")),
            new FakeModule("Fast", _ => Task.FromResult(FakeModule.Ok("Fast"))),
        ]);

        var all = svc.RunAllAsync();
        await fastDone.Task.WaitAsync(TimeSpan.FromSeconds(10));
        await slowStarted.Task.WaitAsync(TimeSpan.FromSeconds(10));
        // Fast finished and Slow is still blocked on the gate: it must be Running, not done.
        Assert.Equal(DiagnosticStatus.Running, store.Get("Slow").Status);
        gate.SetResult();
        var results = await all;
        Assert.Equal([DiagnosticStatus.Ok, DiagnosticStatus.Error, DiagnosticStatus.Ok], results.Select(r => r.Status));
    }

    [Fact]
    public async Task ModuleUpdatedEvent_FlowsToStore()
    {
        var store = new ResultStore();
        var m = new FakeModule("Live", _ => Task.FromResult(FakeModule.Ok("Live")));
        _ = new DiagnosticsService(store, [m]);
        m.Push(new DiagnosticResult("Live", DiagnosticStatus.Warning, "hot", DateTimeOffset.Now));
        Assert.Equal("hot", store.Get("Live").Message);
        await Task.CompletedTask;
    }

    [Fact]
    public async Task OsqueryModule_MissingExe_ReportsNotFound()
    {
        var runner = new OsqueryRunner(Path.GetTempPath());
        Assert.False(runner.Exists);
        var r = await new DiagnosticsService(new ResultStore(), [new OsqueryModule(runner)]).RunAsync("Osquery");
        Assert.Equal(DiagnosticStatus.Error, r.Status);
        Assert.Contains("not found", r.Message);
    }
}
