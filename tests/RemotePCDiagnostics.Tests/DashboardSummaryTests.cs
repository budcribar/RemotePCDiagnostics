using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Security;

namespace RemotePCDiagnostics.Tests;

public class DashboardSummaryTests
{
    private static BannerModule Check(string name, string display, DiagnosticStatus s, string? msg = null) => new(name, display, false, false, s, msg);
    private static BannerModule Stress(string name, string display, DiagnosticStatus s = DiagnosticStatus.NotRun, string? msg = null) => new(name, display, true, true, s, msg);
    private static BannerModule Audit(DiagnosticStatus s = DiagnosticStatus.NotRun, string? msg = null) => new(SecurityAuditModule.ModuleName, "Security audit", true, false, s, msg);

    private static List<BannerModule> AllStress(DiagnosticStatus s = DiagnosticStatus.NotRun) =>
        [Stress("CpuStress", "CPU stress test", s), Stress("MemoryTest", "Memory test", s), Stress("GpuStress", "Graphics (GPU) stress test", s)];

    private static StressSuiteProgress Suite(bool finished, params (string Name, StressSuiteStepState State)[] steps) =>
        new(StressSuiteMode.Short, steps.Length, steps.Length, null, steps.Select(s => new StressSuiteStep(s.Name, s.Name, s.State)).ToList(), finished, "done");

    [Fact]
    public void Problems_ErrorsFirst_ThenModuleOrder()
    {
        var sum = DashboardSummary.Build([
            Check("EventLog", "Windows error log", DiagnosticStatus.Warning),
            Check("Services", "Services", DiagnosticStatus.Ok),
            Check("Crashes", "App crashes", DiagnosticStatus.Error),
            Check("Programs", "Programs & updates", DiagnosticStatus.Warning)], null);
        Assert.Equal(["Crashes", "EventLog", "Programs"], sum.Problems.Select(p => p.Name));
        Assert.Equal([true, false, false], sum.Problems.Select(p => p.IsError));
        Assert.True(sum.HasError);
        Assert.Equal("3 things to look at", sum.TitleLead);
    }

    [Fact]
    public void SingleProblem_IsSingular()
    {
        var sum = DashboardSummary.Build([Check("EventLog", "Windows error log", DiagnosticStatus.Warning), Check("Crashes", "App crashes", DiagnosticStatus.Ok)], null);
        Assert.Equal("1 thing to look at", sum.TitleLead);
        Assert.False(sum.HasError);
        Assert.Equal("Windows error log", Assert.Single(sum.Problems).DisplayName);
    }

    [Fact]
    public void Problems_IncludeOnDemandModules()
    {
        var sum = DashboardSummary.Build([Stress("CpuStress", "CPU stress test", DiagnosticStatus.Error)], null);
        Assert.Equal("CpuStress", Assert.Single(sum.Problems).Name);
    }

    [Fact]
    public void CancelledWarnings_AreNotProblems()
    {
        var sum = DashboardSummary.Build([
            Stress("CpuStress", "CPU stress test", DiagnosticStatus.Warning, "Cancelled"),
            Audit(DiagnosticStatus.Warning, SecurityAuditModule.CancelledMessage),
            Check("EventLog", "Windows error log", DiagnosticStatus.Warning, "3 errors")], null);
        Assert.Equal("EventLog", Assert.Single(sum.Problems).Name);
    }

    [Fact]
    public void NothingRun_NoteSaysStressTestsAndSecurityAudit()
    {
        var sum = DashboardSummary.Build([Check("EventLog", "Windows error log", DiagnosticStatus.Ok), .. AllStress(), Audit()], null);
        Assert.Equal(4, sum.NotRun.Count);
        Assert.Equal("On-demand tests not run: 4 (stress tests and security audit)", sum.NotRunNote);
        Assert.Equal("use Run all + stress tests", sum.NotRunHint);
    }

    [Fact]
    public void AfterSuite_SkippedStressModulesAreNotCounted_AuditRemains()
    {
        var mods = new List<BannerModule> { Stress("CpuStress", "CPU stress test", DiagnosticStatus.Ok), Stress("MemoryTest", "Memory test", DiagnosticStatus.Ok), Stress("GpuStress", "Graphics (GPU) stress test"), Audit() };
        var sum = DashboardSummary.Build(mods, Suite(true, ("CpuStress", StressSuiteStepState.Passed), ("MemoryTest", StressSuiteStepState.Passed), ("GpuStress", StressSuiteStepState.Skipped)));
        Assert.Equal("On-demand tests not run: 1 (security audit)", sum.NotRunNote);
        Assert.Null(sum.NotRunHint);
    }

    [Fact]
    public void SuiteStillRunning_SkippedNotYetApplied()
    {
        var mods = new List<BannerModule> { Stress("GpuStress", "Graphics (GPU) stress test") };
        var sum = DashboardSummary.Build(mods, Suite(false, ("GpuStress", StressSuiteStepState.Skipped)));
        Assert.Single(sum.NotRun);
    }

    [Fact]
    public void CancelledSuite_UnreachedStepsStillNotRun()
    {
        var mods = new List<BannerModule> { Stress("CpuStress", "CPU stress test", DiagnosticStatus.Ok), Stress("MemoryTest", "Memory test"), Stress("GpuStress", "Graphics (GPU) stress test"), Audit() };
        var sum = DashboardSummary.Build(mods, Suite(true, ("CpuStress", StressSuiteStepState.Passed), ("MemoryTest", StressSuiteStepState.NotRun), ("GpuStress", StressSuiteStepState.Pending)));
        Assert.Equal(3, sum.NotRun.Count);
        Assert.Equal("On-demand tests not run: 3 (memory test, graphics (GPU) stress test and security audit)", sum.NotRunNote);
        Assert.Equal("use Run all + stress tests", sum.NotRunHint);
    }

    [Fact]
    public void EverythingRun_NoNote()
    {
        var sum = DashboardSummary.Build([.. AllStress(DiagnosticStatus.Ok), Audit(DiagnosticStatus.Ok)], null);
        Assert.Null(sum.NotRunNote);
        Assert.Empty(sum.Problems);
    }
}
