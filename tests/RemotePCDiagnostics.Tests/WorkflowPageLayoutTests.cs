using RemotePCDiagnostics.Core.Optimizations;
using Bunit;
using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Benchmarks;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Workflow;
using RemotePCDiagnostics.UI;
using RemotePCDiagnostics.UI.Pages;

namespace RemotePCDiagnostics.Tests;

/// <summary>Service workflow page layout: one progress indicator (the Progress card), fix results start collapsed, short intro.</summary>
public class WorkflowPageLayoutTests : BunitContext
{
    private sealed class Sys : IWorkflowSystem
    {
        public Task<bool> RegisterResumeAsync(CancellationToken ct) => Task.FromResult(true);
        public Task<bool> RemoveResumeAsync(CancellationToken ct) => Task.FromResult(true);
        public Task<bool> RestartAsync(TimeSpan d, string m, CancellationToken ct) => Task.FromResult(true);
        public Task AbortRestartAsync(CancellationToken ct) => Task.CompletedTask;
        public TimeSpan Uptime => TimeSpan.FromDays(1);
        public RestartSignInStatus GetRestartSignIn() => new(false, true);
        public string ReportFile(DateTimeOffset when) => "/tmp/r.html";
        public void SaveReport(string path, string html) { }
    }
    private sealed class Store(WorkflowState s) : IWorkflowStore
    {
        public WorkflowState? Load() => WorkflowState.FromJson(s.ToJson());
        public void Save(WorkflowState x) { }
    }
    private sealed class NoProbes : IBenchmarkProbes
    {
        public BenchmarkConditions ReadConditions() => new(null, null);
        public Task<IdleSample?> SampleIdleAsync(TimeSpan duration, CancellationToken ct) => Task.FromResult<IdleSample?>(null);
        public Task<double?> StartProgramAsync(BuiltInProgram program, CancellationToken ct) => Task.FromResult<double?>(null);
        public Task<double?> DiskRandomReadIopsAsync(TimeSpan duration, CancellationToken ct) => Task.FromResult<double?>(null);
        public Task<IReadOnlyList<WinEvent>> ReadBootEventsAsync(CancellationToken ct) => Task.FromResult<IReadOnlyList<WinEvent>>([]);
    }
    private sealed class BStore : IBenchmarkStore { public BenchmarkState? Load() => null; public void Save(BenchmarkState s) { } }

    [Theory]
    [InlineData("Applying")]
    [InlineData("AfterBenchmark")]
    public void Running_workflow_has_no_overall_bar_and_starts_with_fix_results_collapsed(string stage)
    {
        JSInterop.Mode = JSRuntimeMode.Loose;
        var results = new ResultStore();
        var diag = new DiagnosticsService(results, []);
        var rem = new RemediationService(new SystemCommandRunner(), new SessionContext(SessionMode.Remote));
        var bench = new BenchmarkService(new BenchmarkRunner(new NoProbes()), new BStore());
        var titles = new[] { "Stop FastSystemTests from waking the PC", "Page file is under pressure", "Turn off PayPal Honey in Microsoft Edge", "Skip the Office start screen" };
        var st = new WorkflowState
        {
            ReviewRulesVersion = WorkflowService.CurrentReviewRulesVersion,
            Stage = Enum.Parse<WorkflowStage>(stage), StartedUtc = DateTimeOffset.UtcNow,
            Fixes = titles.Select((t, i) => new WorkflowFix("f" + i, t, "why", "Windows", SuggestionRisk.Low, FixSource.Remediation, i)).ToList(),
            Approved = titles.Select((t, i) => "f" + i).ToList(),
            Outcomes = titles.Take(3).Select((t, i) => new FixOutcome("f" + i, t, true, "Done: " + t + ". Takes effect after a restart.")).ToList(),
            Restarts = [new WorkflowRestart("x", DateTimeOffset.UtcNow.AddMinutes(-30), true)],
        };
        var flow = new WorkflowService(diag, results, rem, bench, new Sys(), new Store(st), session: new SessionContext(SessionMode.Remote));
        Services.AddSingleton(results); Services.AddSingleton(diag); Services.AddSingleton(bench); Services.AddSingleton(flow);
        Services.AddSingleton<ISessionContext>(new SessionContext(SessionMode.Remote));
        Services.AddSingleton(new AppServices());
        var cut = Render<WorkflowPage>();

        Assert.Empty(cut.FindAll(".wf-overall-progress"));
        var outcomes = cut.Find("[data-testid='wf-outcomes']");
        Assert.Equal("details", outcomes.TagName, ignoreCase: true);
        Assert.False(outcomes.HasAttribute("open"));
        Assert.Contains("Fix results (3)", outcomes.QuerySelector("summary")!.TextContent);
        Assert.Equal(8, cut.FindAll(".wf-step").Count);
        Assert.DoesNotContain("restart →", cut.Find("[data-testid='wf-intro']").TextContent);
    }
}

/// <summary>Removing the "continue" task: a task that's already gone counts as removed, however COM reports it.</summary>
public class TaskSchedulerNotFoundTests
{
    [Fact]
    public void Missing_task_is_recognised_as_FileNotFound_or_COM_HRESULT()
    {
        Assert.True(RemotePCDiagnostics.Core.Platform.WindowsTaskScheduler.IsNotFound(new FileNotFoundException("The system cannot find the file specified. (0x80070002)")));
        Assert.True(RemotePCDiagnostics.Core.Platform.WindowsTaskScheduler.IsNotFound(new System.Runtime.InteropServices.COMException("x", unchecked((int)0x80070003))));
        Assert.False(RemotePCDiagnostics.Core.Platform.WindowsTaskScheduler.IsNotFound(new UnauthorizedAccessException()));
    }
}
