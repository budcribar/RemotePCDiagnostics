using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Logging;
using RemotePCDiagnostics.Core.Security;
using RemotePCDiagnostics.Core.Stress;

namespace RemotePCDiagnostics.Tests;

internal sealed class RecordingSink : ILogSink
{
    public List<LogEntry> Entries { get; } = [];
    public bool Throw { get; set; }
    public void Write(LogEntry entry) { if (Throw) throw new InvalidOperationException("sink down"); lock (Entries) Entries.Add(entry); }
}

public class EventLoggingTests
{
    [Fact]
    public async Task EveryModuleOutcome_IsLoggedOnce()
    {
        var store = new ResultStore();
        var sink = new RecordingSink();
        _ = new ResultEventLogger(store, sink);
        var svc = new DiagnosticsService(store, [
            new FakeModule("A", _ => Task.FromResult(FakeModule.Ok("A"))),
            new FakeModule("B", _ => Task.FromResult(new DiagnosticResult("B", DiagnosticStatus.Warning, "meh", DateTimeOffset.Now))),
            new FakeModule("C", _ => throw new InvalidOperationException("boom")),
            new FakeModule("D", _ => Task.FromResult(FakeModule.Ok("D")), available: false),
        ]);
        await svc.RunAllAsync();
        Assert.Equal(4, sink.Entries.Count);
        Assert.All(sink.Entries, e => Assert.Equal(LogEventIds.TestResult, e.EventId));
        Assert.Contains(sink.Entries, e => e.Message.Contains("Test result: A") && e.Message.Contains("Outcome: OK") && e.Level == LogLevel.Information && e.Message.Contains("Duration:"));
        Assert.Contains(sink.Entries, e => e.Message.Contains("Test result: B") && e.Message.Contains("Outcome: Warning") && e.Level == LogLevel.Warning);
        Assert.Contains(sink.Entries, e => e.Message.Contains("Test result: C") && e.Message.Contains("Outcome: Critical") && e.Message.Contains("boom") && e.Level == LogLevel.Error);
        Assert.Contains(sink.Entries, e => e.Message.Contains("Test result: D") && e.Message.Contains("Outcome: Unavailable") && e.Message.Contains("missing tool"));
    }

    [Fact]
    public async Task Cancelled_IsLoggedAsCancelled()
    {
        var store = new ResultStore();
        var sink = new RecordingSink();
        _ = new ResultEventLogger(store, sink);
        using var cts = new CancellationTokenSource();
        var svc = new DiagnosticsService(store, [new FakeModule("X", async ct => { await Task.Delay(Timeout.Infinite, ct); return FakeModule.Ok("X"); })]);
        var t = svc.RunAsync("X", null, cts.Token);
        cts.Cancel();
        await t;
        var e = Assert.Single(sink.Entries);
        Assert.Contains("Outcome: Cancelled", e.Message);
        Assert.Equal(LogLevel.Warning, e.Level);
    }

    [Fact]
    public void RepeatedStoreUpdates_OfSameResult_AreNotDoubleLogged()
    {
        var store = new ResultStore();
        var sink = new RecordingSink();
        _ = new ResultEventLogger(store, sink);
        var r = FakeModule.Ok("A");
        store.Set(r); store.Set(r); store.Set(r with { });
        Assert.Single(sink.Entries);
        store.Set(r with { Timestamp = r.Timestamp.AddSeconds(1) });
        Assert.Equal(2, sink.Entries.Count);
    }

    [Fact]
    public void LiveSensorRefreshes_AreThrottled_UnlessStatusChanges()
    {
        var store = new ResultStore();
        var sink = new RecordingSink();
        _ = new ResultEventLogger(store, sink);
        var t0 = DateTimeOffset.Now;
        var name = RemotePCDiagnostics.Core.Sensors.LibreHardwareMonitorModule.ModuleName;
        for (var i = 0; i < 20; i++) store.Set(new DiagnosticResult(name, DiagnosticStatus.Ok, $"CPU {40 + i}°C", t0.AddSeconds(5 * i)));
        Assert.Single(sink.Entries);
        store.Set(new DiagnosticResult(name, DiagnosticStatus.Error, "CPU 99°C", t0.AddSeconds(200)));
        Assert.Equal(2, sink.Entries.Count);
        Assert.Equal(LogLevel.Error, sink.Entries[1].Level);
    }

    [Fact]
    public async Task FailingSink_DoesNotAffectRun()
    {
        var store = new ResultStore();
        _ = new ResultEventLogger(store, new RecordingSink { Throw = true });
        var svc = new DiagnosticsService(store, [new FakeModule("A", _ => Task.FromResult(FakeModule.Ok("A")))]);
        var r = await svc.RunAsync("A");
        Assert.Equal(DiagnosticStatus.Ok, r.Status);
        Assert.Equal(DiagnosticStatus.Ok, store.Get("A").Status);
    }

    [Fact]
    public void Truncation_RespectsEventLogLimit()
    {
        var big = new string('x', 100_000);
        var t = LogText.Truncate(big);
        Assert.Equal(LogText.MaxMessageLength, t.Length);
        Assert.EndsWith(LogText.TruncatedSuffix, t);
        Assert.Equal("short", LogText.Truncate("short"));
        Assert.Equal("", LogText.Truncate(null));
    }

    [Theory]
    [InlineData(DiagnosticStatus.Ok, "fine", "OK", LogLevel.Information)]
    [InlineData(DiagnosticStatus.Warning, "slow", "Warning", LogLevel.Warning)]
    [InlineData(DiagnosticStatus.Error, "broken", "Critical", LogLevel.Error)]
    [InlineData(DiagnosticStatus.Warning, "Cancelled", "Cancelled", LogLevel.Warning)]
    public void LevelMapping(DiagnosticStatus status, string msg, string outcome, LogLevel level)
    {
        var r = new DiagnosticResult("M", status, msg, DateTimeOffset.Now);
        Assert.Equal(outcome, ResultEventLogger.Outcome(r));
        Assert.Equal(level, ResultEventLogger.LevelFor(r));
    }

    [Fact]
    public void StoppedByUserPayload_IsCancelled_AndMeasurementsIncluded()
    {
        var payload = new { Outcome = CpuStressOutcome.StoppedByUser, MaxTemperature = 81.5, Errors = 0, Secret = "token-abc" };
        var r = new DiagnosticResult("CpuStress", DiagnosticStatus.Warning, "Stopped", DateTimeOffset.Now, payload);
        Assert.Equal("Cancelled", ResultEventLogger.Outcome(r));
        var text = ResultEventLogger.Format(r, TimeSpan.FromSeconds(60), "short run");
        Assert.Contains("MaxTemperature: 81.5", text);
        Assert.Contains("Duration: 60.0 s", text);
        Assert.Contains("Stress suite: short run", text);
        Assert.DoesNotContain("token-abc", text); // free-text payload fields are never logged
    }

    [Fact]
    public void SecurityAudit_LogsOnlyFailedAndWarningIds_Capped()
    {
        var findings = Enumerable.Range(1, 40).Select(i => new AuditFinding($"ID{i}", "Cat", $"Title {i}", "High", "cur-secret", "rec", AuditOutcome.Failed))
            .Append(new AuditFinding("OK1", "Cat", "Fine", "Low", "x", "x", AuditOutcome.Passed)).ToList();
        var d = ResultEventLogger.Details(new SecurityAuditReport(findings));
        Assert.Contains("Failed=40", d);
        Assert.Contains("Failed: ID1 Title 1", d);
        Assert.DoesNotContain("ID26 ", d);
        Assert.Contains("and 15 more", d);
        Assert.DoesNotContain("OK1", d);
        Assert.DoesNotContain("cur-secret", d);
    }

    [Theory]
    [InlineData("Fan diagnostic: first EC sample raw", LogEventIds.FanDiagnostic, LogLevel.Information)]
    [InlineData("Fan diagnostic: backing off EC reads for 30s", LogEventIds.FanDiagnostic, LogLevel.Warning)]
    [InlineData("CPU sensor driver (PawnIO, ...): registered", LogEventIds.SensorDriver, LogLevel.Information)]
    [InlineData("Stress suite (short run) started", LogEventIds.SuiteStarted, LogLevel.Information)]
    [InlineData("Stress suite (short run) finished: Completed", LogEventIds.SuiteFinished, LogLevel.Information)]
    [InlineData("Unhandled: System.Exception", LogEventIds.Error, LogLevel.Error)]
    public void Routing(string line, int id, LogLevel level)
    {
        var e = LogText.Route(line);
        Assert.NotNull(e);
        Assert.Equal(id, e!.EventId);
        Assert.Equal(level, e.Level);
    }

    [Fact]
    public void OtherLines_AreFileOnly() => Assert.Null(LogText.Route("ReadyToConnect url=https://x/app/123 id=abc"));
}
