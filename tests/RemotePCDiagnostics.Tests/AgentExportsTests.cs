using System.Text.Json;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Benchmarks;
using RemotePCDiagnostics.Core.History;
using RemotePCDiagnostics.Core.Security;

namespace RemotePCDiagnostics.Tests;

public class AgentExportsTests
{
    [Fact]
    public void Audit_lists_findings_that_did_not_pass_worst_first()
    {
        var report = new SecurityAuditReport(
        [
            new AuditFinding("1001", "Account", "Password length", "Medium", "8", "14", AuditOutcome.Warning),
            new AuditFinding("1002", "Defender", "Real-time protection", "High", "Off", "On", AuditOutcome.Failed),
            new AuditFinding("1003", "Firewall", "Domain profile", "Low", "On", "On", AuditOutcome.Passed),
            new AuditFinding("1004", "SMB", "SMBv1", "Medium", "", "Disabled", AuditOutcome.NotChecked),
        ]);

        using var doc = JsonDocument.Parse(AgentExports.Audit(report));
        var root = doc.RootElement;

        Assert.Equal(1, root.GetProperty("schema").GetInt32());
        Assert.Equal(1, root.GetProperty("failed").GetInt32());
        Assert.Equal(1, root.GetProperty("passed").GetInt32());
        Assert.Equal(3, root.GetProperty("attentionCount").GetInt32());
        var ids = root.GetProperty("findings").EnumerateArray().Select(f => f.GetProperty("id").GetString()).ToList();
        Assert.Equal(["1002", "1001", "1004"], ids);
        Assert.Equal("failed", root.GetProperty("findings")[0].GetProperty("outcome").GetString());
        Assert.Equal("On", root.GetProperty("findings")[0].GetProperty("recommended").GetString());
    }

    [Fact]
    public void History_lists_entries_newest_first_with_measurements_and_fixes()
    {
        var older = new HistoryEntry(DateTimeOffset.Parse("2026-11-15T10:00:00Z"), "DriveHealth", "Drive health", "Passed",
            "All drives healthy", 4.2, null, [new HistoryMeasurement("Temperature", "41 °C")], "BUDSLAPTOP", "1.2.0");
        var newer = new HistoryEntry(DateTimeOffset.Parse("2026-11-16T10:00:00Z"), "Crashes", "Crashes", "Warning",
            "6 freezes", null, null, [], "BUDSLAPTOP", "1.2.0", ["Most: EXCEL.EXE"]);
        var fix = new FixHistoryItem(DateTimeOffset.Parse("2026-11-16T11:00:00Z"), "Storage", "Remote user", true, "Cleaned temp files", "2.1 GB");

        using var doc = JsonDocument.Parse(AgentExports.History([older, newer], [fix], "Week", available: true));
        var root = doc.RootElement;

        Assert.Equal("Week", root.GetProperty("range").GetString());
        // No filter given: the copy still names both, as "all".
        Assert.Equal("", root.GetProperty("testFilter").GetString());
        Assert.Equal("", root.GetProperty("outcomeFilter").GetString());
        var entries = root.GetProperty("entries");
        Assert.Equal("Crashes", entries[0].GetProperty("checkId").GetString());
        Assert.Equal("Most: EXCEL.EXE", entries[0].GetProperty("details")[0].GetString());
        Assert.Equal("Temperature", entries[1].GetProperty("measurements")[0].GetProperty("name").GetString());
        Assert.Equal("Cleaned temp files", root.GetProperty("fixes")[0].GetProperty("summary").GetString());
    }

    [Fact]
    public void History_names_the_test_and_result_filters_the_page_has()
    {
        using var doc = JsonDocument.Parse(AgentExports.History([], [], "All", available: true, "DriveHealth", "Warning"));
        var root = doc.RootElement;

        Assert.Equal("DriveHealth", root.GetProperty("testFilter").GetString());
        Assert.Equal("Warning", root.GetProperty("outcomeFilter").GetString());
        Assert.Equal(0, root.GetProperty("entryCount").GetInt32());
    }

    [Fact]
    public void Benchmark_reports_phase_passes_and_deltas()
    {
        var at = DateTimeOffset.Parse("2026-11-16T10:00:00Z");
        var before = new BenchmarkRun(BenchmarkPhase.Before, at, new BenchmarkConditions(false, 50, "Balanced"),
            [new BenchmarkMeasurement(BenchmarkKind.ProgramStart, [400, 410, 420])]);
        var after = new BenchmarkRun(BenchmarkPhase.After, at.AddHours(1), new BenchmarkConditions(false, 50, "Balanced"),
            [new BenchmarkMeasurement(BenchmarkKind.ProgramStart, [200, 205, 210])]);
        var cmp = BenchmarkComparison.Build(before, after);

        var none = JsonDocument.Parse(JsonSerializer.Serialize(AgentExports.BuildBenchmark(new BenchmarkSettings(), null, null,
            BenchmarkComparison.Build(null, null), null, false, null, false, false, null))).RootElement;
        Assert.Equal("no-baseline", none.GetProperty("phase").GetString());

        var baseline = JsonDocument.Parse(JsonSerializer.Serialize(AgentExports.BuildBenchmark(new BenchmarkSettings(), before, null,
            BenchmarkComparison.Build(before, null), null, false, null, false, false, null))).RootElement;
        Assert.Equal("baseline-ready", baseline.GetProperty("phase").GetString());
        Assert.Equal(410, baseline.GetProperty("before").GetProperty("measurements")[0].GetProperty("median").GetDouble());

        var restart = JsonDocument.Parse(JsonSerializer.Serialize(AgentExports.BuildBenchmark(new BenchmarkSettings(), before, null,
            BenchmarkComparison.Build(before, null), null, false, null, false, true, null))).RootElement;
        Assert.Equal("restart-pending-after", restart.GetProperty("phase").GetString());

        var compared = JsonDocument.Parse(JsonSerializer.Serialize(AgentExports.BuildBenchmark(new BenchmarkSettings(), before, after,
            cmp, null, false, null, false, false, null))).RootElement;
        Assert.Equal("compared", compared.GetProperty("phase").GetString());
        var delta = compared.GetProperty("deltas").EnumerateArray().Single(d => d.GetProperty("kind").GetString() == "ProgramStart");
        Assert.Equal("better", delta.GetProperty("verdict").GetString());
        Assert.Equal("ms", delta.GetProperty("unit").GetString());
    }

    [Fact]
    public void Checks_list_carries_kind_start_scan_and_result()
    {
        var run = Guid.NewGuid();
        var json = AgentExports.Checks(
        [
            new("DriveHealth", "Drive health", "check", false, "run-one", "passed", run, DateTimeOffset.Parse("2026-11-17T10:00:00Z"), "All drives healthy"),
            new("DiskSpace", "Large files & folders", "on-demand", true, "run-one", "notrun", null, null, null),
            new("NpuTest", "NPU (AI accelerator) test", "on-demand", false, "own-page", "running", Guid.NewGuid(), null, null),
        ]);

        using var doc = JsonDocument.Parse(json);
        var checks = doc.RootElement.GetProperty("checks");
        Assert.Equal(3, doc.RootElement.GetProperty("checkCount").GetInt32());
        Assert.Equal(run.ToString(), checks[0].GetProperty("runId").GetString());
        Assert.Equal("All drives healthy", checks[0].GetProperty("summary").GetString());
        Assert.True(checks[1].GetProperty("scan").GetBoolean());
        Assert.False(checks[1].TryGetProperty("runId", out _));
        Assert.Equal("own-page", checks[2].GetProperty("start").GetString());
    }

    [Fact]
    public void Activity_is_idle_when_nothing_runs()
    {
        using var doc = JsonDocument.Parse(AgentExports.Activity(new AgentExports.ActivitySnapshot([],
            Workflow: new AgentExports.WorkflowActivity(Core.Workflow.WorkflowStage.Done, false, null))));
        var root = doc.RootElement;

        Assert.False(root.GetProperty("busy").GetBoolean());
        Assert.Empty(root.GetProperty("checks").EnumerateArray());
        Assert.False(root.TryGetProperty("sequence", out _));
        Assert.False(root.TryGetProperty("workflow", out _));
        Assert.False(root.TryGetProperty("control", out _));
        Assert.False(root.TryGetProperty("finished", out _));
    }

    [Fact]
    public void Activity_keeps_who_holds_control_and_finished_results_while_another_check_runs()
    {
        var finishedAt = DateTimeOffset.Parse("2026-11-20T21:00:00Z");
        var moved = DateTimeOffset.Parse("2026-11-20T21:04:00Z");
        var runningId = Guid.NewGuid();
        var finishedId = Guid.NewGuid();
        var snapshot = new AgentExports.ActivitySnapshot(
            [new AgentExports.RunningCheck("Osquery", "Hardware inventory", runningId, new CheckProgress(2, 7, "Reading processor details…"))],
            Control: new AgentExports.ControlMark("owner", "remote", "restored", moved),
            Finished:
            [
                new AgentExports.FinishedCheck("DriveHealth", "ok", "All drives healthy", finishedId, finishedAt),
                new AgentExports.FinishedCheck("Sensors", "cancelled", "Cancelled", null, finishedAt),
            ]);

        using var doc = JsonDocument.Parse(AgentExports.Activity(snapshot));
        var root = doc.RootElement;
        var control = root.GetProperty("control");
        Assert.Equal("owner", control.GetProperty("actual").GetString());
        Assert.Equal("remote", control.GetProperty("keptWith").GetString());
        Assert.Equal("restored", control.GetProperty("reason").GetString());
        Assert.Equal(moved.ToString("O"), control.GetProperty("movedAt").GetString());

        var finished = root.GetProperty("finished");
        Assert.Equal(2, finished.GetArrayLength());
        Assert.Equal("DriveHealth", finished[0].GetProperty("id").GetString());
        Assert.Equal("ok", finished[0].GetProperty("status").GetString());
        Assert.Equal(finishedId.ToString(), finished[0].GetProperty("runId").GetString());
        Assert.Equal("cancelled", finished[1].GetProperty("status").GetString());
        Assert.False(finished[1].TryGetProperty("runId", out _));

        Assert.Equal("Reading processor details…", root.GetProperty("checks")[0].GetProperty("progress").GetProperty("message").GetString());
    }

    [Fact]
    public void Activity_lists_the_running_scan_and_the_steps_left_of_run_all()
    {
        var runId = Guid.NewGuid();
        var snapshot = new AgentExports.ActivitySnapshot(
            [new AgentExports.RunningCheck("DismScanHealth", "Windows image health", runId, new CheckProgress(2, 5, "Scanning 40%"))],
            new AgentExports.SequenceRun(CheckGroup.Checks, RunAll: true, new GroupRunProgress(CheckGroup.Checks, 3, 9, "Windows image health"),
                ["SfcVerifyOnly", "MemoryScan", "StorageScan"]),
            Fix: new FixRun(new AreaAction(RemediationKind.InstallUpdate, "Install", "upd-1", "Driver"), "Install driver", "DeviceDrivers",
                DateTimeOffset.Parse("2026-11-18T10:00:00Z")),
            BenchmarkRunning: BenchmarkPhase.Before);

        using var doc = JsonDocument.Parse(AgentExports.Activity(snapshot));
        var root = doc.RootElement;

        Assert.True(root.GetProperty("busy").GetBoolean());
        var check = root.GetProperty("checks")[0];
        Assert.Equal("DismScanHealth", check.GetProperty("id").GetString());
        Assert.Equal(runId.ToString(), check.GetProperty("runId").GetString());
        Assert.Equal(2, check.GetProperty("progress").GetProperty("step").GetInt32());
        var sequence = root.GetProperty("sequence");
        Assert.Equal("run-all", sequence.GetProperty("kind").GetString());
        Assert.Equal(3, sequence.GetProperty("index").GetInt32());
        Assert.Equal(["SfcVerifyOnly", "MemoryScan", "StorageScan"],
            sequence.GetProperty("remaining").EnumerateArray().Select(e => e.GetString()).ToList());
        Assert.Equal("DeviceDrivers", root.GetProperty("fix").GetProperty("origin").GetString());
        Assert.Equal("running-before", root.GetProperty("benchmark").GetProperty("phase").GetString());
    }

    [Fact]
    public void Activity_lists_the_stress_tests_still_to_run()
    {
        var progress = new StressSuiteProgress(StressSuiteMode.Short, 2, 3, "Memory",
        [
            new StressSuiteStep("CpuStress", "CPU", StressSuiteStepState.Passed),
            new StressSuiteStep("MemoryStress", "Memory", StressSuiteStepState.Running),
            new StressSuiteStep("DiskStress", "Disk", StressSuiteStepState.Pending),
        ], Finished: false, Message: null);

        using var doc = JsonDocument.Parse(AgentExports.Activity(new AgentExports.ActivitySnapshot([], StressSuite: progress,
            Workflow: new AgentExports.WorkflowActivity(Core.Workflow.WorkflowStage.Review, false, null))));
        var root = doc.RootElement;

        Assert.True(root.GetProperty("busy").GetBoolean());
        var stress = root.GetProperty("stressSuite");
        Assert.Equal("Memory", stress.GetProperty("current").GetString());
        Assert.Equal(["DiskStress"], stress.GetProperty("remaining").EnumerateArray().Select(e => e.GetString()).ToList());
        Assert.Equal("Review", root.GetProperty("workflow").GetProperty("stage").GetString());
    }
}
