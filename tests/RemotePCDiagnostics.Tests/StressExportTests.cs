using System.Text.Json;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Tests;

public class StressExportTests
{
    private static readonly DateTimeOffset At = new(2026, 11, 16, 20, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Lists_tests_with_selection_state_and_run_ids()
    {
        var runId = Guid.NewGuid();
        var tests = new List<StressExport.Test>
        {
            new("CpuStress", "CPU stress test", true, new DiagnosticResult("CpuStress", DiagnosticStatus.Ok, "Passed: 100% load for 1 min", At) { RunId = runId }, "short run"),
            new("MemoryTest", "Memory test", false, new DiagnosticResult("MemoryTest", DiagnosticStatus.NotRun, "", At), null),
        };

        using var doc = JsonDocument.Parse(StressExport.ToJson(StressSuiteMode.Short, false, null, null, null, tests));
        var root = doc.RootElement;

        Assert.Equal("short", root.GetProperty("mode").GetString());
        Assert.Equal(1, root.GetProperty("minutesPerTest").GetDouble());
        Assert.False(root.GetProperty("running").GetBoolean());
        Assert.Equal(["CpuStress"], root.GetProperty("selectedCheckIds").EnumerateArray().Select(e => e.GetString()));
        var cpu = root.GetProperty("tests")[0];
        Assert.Equal("passed", cpu.GetProperty("state").GetString());
        Assert.Equal(runId, cpu.GetProperty("runId").GetGuid());
        Assert.Equal("short run", cpu.GetProperty("runLabel").GetString());
        Assert.True(cpu.TryGetProperty("completedAt", out _));
        var mem = root.GetProperty("tests")[1];
        Assert.Equal("notrun", mem.GetProperty("state").GetString());
        Assert.False(mem.TryGetProperty("completedAt", out _));
    }

    [Fact]
    public void Reports_suite_progress_while_running_and_the_last_suite_after()
    {
        var steps = new List<StressSuiteStep> { new("CpuStress", "CPU", StressSuiteStepState.Passed), new("MemoryTest", "Memory", StressSuiteStepState.Running) };
        var progress = new StressSuiteProgress(StressSuiteMode.Extended, 2, 5, "Memory", steps, false, null);
        var last = new StressSuiteResult(StressSuiteMode.Short, StressSuiteOutcome.StoppedOnProblem, steps, "Stopped: memory error");

        using var running = JsonDocument.Parse(StressExport.ToJson(StressSuiteMode.Extended, true, progress, null, null, []));
        var p = running.RootElement.GetProperty("progress");
        Assert.Equal(2, p.GetProperty("index").GetInt32());
        Assert.Equal("Stress test 2 of 5: Memory", p.GetProperty("headline").GetString());
        Assert.Equal("running", p.GetProperty("steps")[1].GetProperty("state").GetString());

        using var done = JsonDocument.Parse(StressExport.ToJson(StressSuiteMode.Short, false, progress, last, "1 test stopped", []));
        Assert.False(done.RootElement.TryGetProperty("progress", out _));
        Assert.Equal("stopped-on-problem", done.RootElement.GetProperty("lastSuite").GetProperty("outcome").GetString());
        Assert.Equal("1 test stopped", done.RootElement.GetProperty("note").GetString());
    }
}
