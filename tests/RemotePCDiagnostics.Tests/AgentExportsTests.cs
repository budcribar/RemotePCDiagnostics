using System.Text.Json;
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
        var entries = root.GetProperty("entries");
        Assert.Equal("Crashes", entries[0].GetProperty("checkId").GetString());
        Assert.Equal("Most: EXCEL.EXE", entries[0].GetProperty("details")[0].GetString());
        Assert.Equal("Temperature", entries[1].GetProperty("measurements")[0].GetProperty("name").GetString());
        Assert.Equal("Cleaned temp files", root.GetProperty("fixes")[0].GetProperty("summary").GetString());
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
}
