using System.Text.Json;
using System.Text.Json.Serialization;
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
    public void Benchmark_developer_build_failure_includes_exit_code_and_error_text()
    {
        const string note = "Could not run: cold dotnet build failed (exit 1). error NETSDK1004: Assets file 'project.assets.json' not found.";
        var dev = new DeveloperBuildResult(
            DeveloperLanguage.CSharp, DeveloperCSharpPin.PinId, "ABC", "9.0.200", 9,
            1.2, null, [], null, [], Note: note, ToolExitCode: 1);
        var run = new BenchmarkRun(BenchmarkPhase.Before, DateTimeOffset.Parse("2026-11-20T10:00:00Z"),
            new BenchmarkConditions(false, 40, "Balanced"),
            [new BenchmarkMeasurement(BenchmarkKind.DeveloperCSharp, [], note, DeveloperBuild: dev)]);

        using var doc = JsonDocument.Parse(JsonSerializer.Serialize(AgentExports.BuildBenchmark(
            new BenchmarkSettings(), run, null, BenchmarkComparison.Build(run, null), null, false, null, false, false, null,
            detectedToolchains: [new DetectedToolchain(DeveloperLanguage.CSharp, ".NET SDK (C#)", "dotnet", "9.0.200", 9)])));
        var measurement = doc.RootElement.GetProperty("before").GetProperty("measurements")[0];
        Assert.Equal(note, measurement.GetProperty("note").GetString());
        var built = measurement.GetProperty("developerBuild");
        Assert.Equal(note, built.GetProperty("note").GetString());
        Assert.Equal(1, built.GetProperty("toolExitCode").GetInt32());
        var unavailable = doc.RootElement.GetProperty("developer").GetProperty("csharpUnavailableReason");
        Assert.Equal(JsonValueKind.Null, unavailable.ValueKind);
    }

    [Fact]
    public void Benchmark_hides_csharp_reason_when_the_sdk_is_too_old_to_build()
    {
        using var doc = JsonDocument.Parse(JsonSerializer.Serialize(AgentExports.BuildBenchmark(
            new BenchmarkSettings(), null, null, BenchmarkComparison.Build(null, null), null, false, null, false, false, null,
            detectedToolchains: [new DetectedToolchain(DeveloperLanguage.CSharp, ".NET SDK (C#)", "dotnet", "6.0.428", 6)])));
        var reason = doc.RootElement.GetProperty("developer").GetProperty("csharpUnavailableReason").GetString();
        Assert.Contains(".NET SDK 8 or newer", reason);
        Assert.Contains("6.0.428", reason);
    }

    [Fact]
    public void Benchmark_names_the_blocking_setting_and_leaves_it_out_when_the_pass_can_start()
    {
        var at = DateTimeOffset.Parse("2026-11-16T10:00:00Z");
        var before = new BenchmarkRun(BenchmarkPhase.Before, at, new BenchmarkConditions(false, 50, "Balanced"),
            [new BenchmarkMeasurement(BenchmarkKind.ProgramStart, [400])]);
        var starts = new BenchmarkStartChoice[]
        {
            new("before", false, "bench-run-before", true),
            new("before", true, "bench-restart-before", false, BenchmarkStartRules.RestartSetting, "Restarting isn't available from here."),
            new("after", false, "bench-run-after", true),
            new("after", true, "bench-restart-after", false, BenchmarkStartRules.RestartSetting, "Restarting isn't available from here."),
        };
        var blocked = new BenchmarkBlock(BenchmarkStartRules.RestartSetting, "Restarting isn't available from here.");

        using var doc = JsonDocument.Parse(JsonSerializer.Serialize(AgentExports.BuildBenchmark(
            new BenchmarkSettings { RestartBeforeAfter = false }, before, null, BenchmarkComparison.Build(before, null),
            null, false, null, false, false, null, starts: starts, blocked: blocked), AgentJson()));
        var root = doc.RootElement;

        Assert.False(root.GetProperty("settings").GetProperty("restartBeforeAfter").GetBoolean());
        Assert.Equal("restartBeforeAfter", root.GetProperty("blocked").GetProperty("setting").GetString());
        Assert.Equal("Restarting isn't available from here.", root.GetProperty("blocked").GetProperty("reason").GetString());
        var restart = root.GetProperty("starts").EnumerateArray().Single(s => s.GetProperty("control").GetString() == "bench-restart-before");
        Assert.False(restart.GetProperty("available").GetBoolean());
        Assert.Equal("restartBeforeAfter", restart.GetProperty("setting").GetString());
        Assert.Equal("Restarting isn't available from here.", restart.GetProperty("reason").GetString());
        var run = root.GetProperty("starts").EnumerateArray().Single(s => s.GetProperty("control").GetString() == "bench-run-before");
        Assert.True(run.GetProperty("available").GetBoolean());
        Assert.False(run.TryGetProperty("setting", out _));
        Assert.False(run.TryGetProperty("reason", out _));
    }

    [Fact]
    public void Benchmark_page_does_not_write_the_restart_choice_from_the_checkbox()
    {
        var page = File.ReadAllText(Path.Combine(FindRepoRoot(), "src", "RemotePCDiagnostics.UI", "Pages", "BenchmarkPage.razor"));

        Assert.Contains("data-testid=\"bench-restart\" checked=\"@s.RestartBeforeAfter\" disabled aria-readonly=\"true\"", page, StringComparison.Ordinal);
        Assert.DoesNotContain("@onchange=\"EchoCommittedRestart\"", page, StringComparison.Ordinal);
        Assert.DoesNotContain("RestartBeforeAfter = e.Value", page, StringComparison.Ordinal);
        Assert.Contains("BeginPassAsync", page, StringComparison.Ordinal);
        Assert.Contains("data-blocked-setting", page, StringComparison.Ordinal);
        Assert.Contains("data-blocked-reason", page, StringComparison.Ordinal);
        Assert.Contains("StartButton(BenchmarkPhase.Before, true", page, StringComparison.Ordinal);
        Assert.Contains("StartButton(BenchmarkPhase.Before, false", page, StringComparison.Ordinal);
        Assert.Contains("StartButton(BenchmarkPhase.Before, !s.RestartBeforeAfter", page, StringComparison.Ordinal);
        Assert.Contains("StartButton(BenchmarkPhase.After, true", page, StringComparison.Ordinal);
        Assert.Contains("StartButton(BenchmarkPhase.After, false", page, StringComparison.Ordinal);
        Assert.Contains("StartButton(BenchmarkPhase.After, !s.RestartBeforeAfter", page, StringComparison.Ordinal);
        Assert.Equal("bench-run-before", BenchmarkStartRules.Control(BenchmarkPhase.Before, false));
        Assert.Equal("bench-restart-before", BenchmarkStartRules.Control(BenchmarkPhase.Before, true));
        Assert.Equal("bench-run-after", BenchmarkStartRules.Control(BenchmarkPhase.After, false));
        Assert.Equal("bench-restart-after", BenchmarkStartRules.Control(BenchmarkPhase.After, true));
    }

    [Fact]
    public void Benchmark_lists_every_kind_and_withholds_a_control_when_the_pc_cannot_run_it()
    {
        var settings = new BenchmarkSettings { Enabled = [BenchmarkKind.Speedometer, BenchmarkKind.DeveloperCSharp] };
        var tests = BenchmarkTestRules.Choices(settings, kind => kind != BenchmarkKind.DeveloperCSharp);

        using var doc = JsonDocument.Parse(JsonSerializer.Serialize(AgentExports.BuildBenchmark(
            settings, null, null, BenchmarkComparison.Build(null, null), null, false, null, false, false, null, tests: tests), AgentJson()));
        var root = doc.RootElement;

        Assert.Equal(3, BrowserContract.Benchmark);
        var enabled = root.GetProperty("settings").GetProperty("enabled").EnumerateArray().Select(e => e.GetString()).ToList();
        Assert.Equal(["Speedometer", "DeveloperCSharp"], enabled);
        var rows = root.GetProperty("tests").EnumerateArray().ToList();
        Assert.Equal(Benchmarks.All.Select(i => i.Kind.ToString()), rows.Select(r => r.GetProperty("id").GetString()));

        var speed = rows.Single(r => r.GetProperty("id").GetString() == "Speedometer");
        Assert.True(speed.GetProperty("available").GetBoolean());
        Assert.True(speed.GetProperty("enabled").GetBoolean());
        Assert.Equal("bench-enable-Speedometer", speed.GetProperty("control").GetString());
        Assert.False(speed.TryGetProperty("reason", out _));

        var dev = rows.Single(r => r.GetProperty("id").GetString() == "DeveloperCSharp");
        Assert.False(dev.GetProperty("available").GetBoolean());
        Assert.True(dev.GetProperty("enabled").GetBoolean());
        Assert.False(dev.TryGetProperty("control", out _));
        Assert.Equal(BenchmarkTestRules.UnavailableReason, dev.GetProperty("reason").GetString());
    }

    [Fact]
    public void Benchmark_page_enables_a_test_through_the_same_saved_list_the_checkbox_uses()
    {
        Assert.Equal("bench-enable-Speedometer", BenchmarkTestRules.Control(BenchmarkKind.Speedometer));
        Assert.Equal("bench-enable-DeveloperCSharp", BenchmarkTestRules.Control(BenchmarkKind.DeveloperCSharp));

        var settings = new BenchmarkSettings();
        var withoutSpeed = BenchmarkTestRules.WithEnabled(settings, BenchmarkKind.Speedometer, on: false, available: true);
        Assert.DoesNotContain(BenchmarkKind.Speedometer, withoutSpeed);
        Assert.Contains(BenchmarkKind.BootTime, withoutSpeed);
        var restored = BenchmarkTestRules.WithEnabled(settings with { Enabled = withoutSpeed }, BenchmarkKind.Speedometer, on: true, available: true);
        Assert.Contains(BenchmarkKind.Speedometer, restored);
        Assert.Equal(Enum.GetValues<BenchmarkKind>().Where(restored.Contains).ToList(), restored);

        var hidden = BenchmarkTestRules.WithEnabled(settings, BenchmarkKind.DeveloperCSharp, on: true, available: false);
        Assert.DoesNotContain(BenchmarkKind.DeveloperCSharp, hidden);
        Assert.Equal(settings.Enabled, hidden);
        var turnedOff = BenchmarkTestRules.WithEnabled(
            settings with { Enabled = settings.Enabled.Append(BenchmarkKind.DeveloperCSharp).ToList() },
            BenchmarkKind.DeveloperCSharp, on: false, available: false);
        Assert.DoesNotContain(BenchmarkKind.DeveloperCSharp, turnedOff);

        var page = File.ReadAllText(Path.Combine(FindRepoRoot(), "src", "RemotePCDiagnostics.UI", "Pages", "BenchmarkPage.razor"));
        Assert.Contains("data-testid=\"bench-settings-toggle\"", page, StringComparison.Ordinal);
        Assert.Contains("aria-expanded=\"@(_customizeOpen ? \"true\" : \"false\")\"", page, StringComparison.Ordinal);
        Assert.Contains("open=\"@_customizeOpen\"", page, StringComparison.Ordinal);
        Assert.Contains("data-testid=\"@BenchmarkTestRules.Control(k)\"", page, StringComparison.Ordinal);
        Assert.Contains("data-bench-test=\"@k\"", page, StringComparison.Ordinal);
        Assert.Contains("data-enabled=\"@(s.IsEnabled(k) ? \"true\" : \"false\")\"", page, StringComparison.Ordinal);
        Assert.Contains("@onclick=\"() => Toggle(k, !s.IsEnabled(k))\" @onclick:preventDefault=\"true\"", page, StringComparison.Ordinal);
        Assert.Contains("BenchmarkTestRules.WithEnabled(Bench.Settings, k, on, Bench.IsKindAvailable(k))", page, StringComparison.Ordinal);
        Assert.Contains("Bench.UpdateSettings(Bench.Settings with { Enabled = BenchmarkTestRules.WithEnabled", page, StringComparison.Ordinal);
        Assert.DoesNotContain("bench-kind-", page, StringComparison.Ordinal);
        Assert.DoesNotContain("@onchange=\"e => Toggle", page, StringComparison.Ordinal);
    }

    private static JsonSerializerOptions AgentJson() => new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "RemotePCDiagnostics.sln")))
                return dir.FullName;
            dir = dir.Parent;
        }
        throw new DirectoryNotFoundException("Could not locate repository root containing RemotePCDiagnostics.sln.");
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
