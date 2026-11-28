using Bunit;
using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Workflow;
using RemotePCDiagnostics.UI;
using RemotePCDiagnostics.UI.Pages;

namespace RemotePCDiagnostics.Tests;

/// <summary>One long run at a time: while checks run, the QA check (and the workflow) can't start, and say why.</summary>
public class RunGateTests : BunitContext
{
    [Fact]
    public async Task While_checks_run_QA_Start_is_greyed_out_with_the_reason_and_comes_back_after()
    {
        JSInterop.Mode = JSRuntimeMode.Loose;
        var release = new TaskCompletionSource();
        var store = new ResultStore();
        var check = new FakeModule("SlowCheck", async (_, ct) => { await release.Task.WaitAsync(ct); return FakeModule.Ok("SlowCheck"); });
        var diag = new DiagnosticsService(store, [check]);
        var screen = new ChecksScreenState(diag, store);
        var runner = new BenchQaRunner(diag, store);
        Services.AddSingleton(store);
        Services.AddSingleton(diag);
        Services.AddSingleton(screen);
        Services.AddSingleton<ISessionContext>(new SessionContext(SessionMode.Local));
        Services.AddSingleton(new AppServices(BenchQa: runner));

        Assert.Null(RunGate.BusyReason(RunKind.Qa, screen, diag, runner, null));
        var run = screen.RunAllChecksAsync();
        Assert.Equal(CheckGroup.Checks, screen.RunningGroup);
        Assert.Equal(RunGate.ChecksBusy, RunGate.BusyReason(RunKind.Qa, screen, diag, runner, null));
        Assert.Equal(RunGate.ChecksBusy, RunGate.BusyReason(RunKind.Workflow, screen, diag, runner, null));
        Assert.Equal(RunGate.ChecksBusy, RunGate.BusyReason(RunKind.Stress, screen, diag, runner, null));
        Assert.Null(RunGate.BusyReason(RunKind.Checks, screen, diag, runner, null));

        var page = Render<BrandingCertificatePage>();
        page.WaitForAssertion(() =>
        {
            var start = page.Find("[data-testid=bench-qa-start]");
            Assert.True(start.HasAttribute("disabled"));
            Assert.Equal(RunGate.ChecksBusy, start.GetAttribute("data-busy-reason"));
            Assert.Equal(RunGate.ChecksBusy, page.Find("[data-testid=bench-qa-busy]").TextContent);
        });

        release.SetResult();
        await run.WaitAsync(TimeSpan.FromSeconds(10));
        page.WaitForAssertion(() =>
        {
            Assert.Null(page.Find("[data-testid=bench-qa-start]").GetAttribute("data-busy-reason"));
            Assert.Empty(page.FindAll("[data-testid=bench-qa-busy]"));
        });
    }
}
