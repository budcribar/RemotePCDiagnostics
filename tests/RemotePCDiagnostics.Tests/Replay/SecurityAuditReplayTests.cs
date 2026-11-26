using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Recording;
using RemotePCDiagnostics.Core.Security;

namespace RemotePCDiagnostics.Tests.Replay;

/// <summary>The security audit on recorded HardeningKitty runs (recorder v10 on, and the sample), as the app runs it in the Agent.</summary>
public sealed class SecurityAuditReplayTests
{
    public static TheoryData<string> Recordings => RecordingLibrary.Names();

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task MatchesApprovedSnapshot(string name)
    {
        var pc = new ReplayedPc(RecordingLibrary.Load(name));
        Assert.SkipUnless(pc.HasSecurityAudit, "Recorded before recorder v10: no security audit run.");
        var result = await pc.SecurityAudit().RefreshAsync(null, TestContext.Current.CancellationToken);
        Assert.Empty(pc.Replay.Misses);
        Assert.IsType<SecurityAuditReport>(result.Payload);
        Snapshot.Match(RecordingLibrary.Folder(name), "SecurityAudit", result);
    }

    /// <summary>
    /// Each whole-answer fault on the run's output and on its report: the audit ends with a clear failure or a report, never a
    /// report made from nothing, and never throws.
    /// </summary>
    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task Every_whole_answer_fault_ends_cleanly(string name)
    {
        var rec = RecordingLibrary.Load(name);
        Assert.SkipUnless(new ReplayedPc(rec).HasSecurityAudit, "Recorded before recorder v10: no security audit run.");
        foreach (var (source, match) in new[] { (RecordedCall.ProcessKind, SecurityAuditRecording.Argument), (RecordedCall.FileKind, SecurityAuditRecording.ReportName) })
            foreach (var fault in Faults.WholeAnswer.Append(Faults.ExitCode))
            {
                var plan = new FaultPlan([new FaultRule { Source = source, Match = match, Fault = fault, Ms = 1 }]);
                var r = await new ReplayedPc(rec, plan).SecurityAudit().RefreshAsync(null, TestContext.Current.CancellationToken);
                var context = $"{name}: {fault} on {source} {match}";
                Assert.NotEmpty(plan.Hits);
                Assert.False(string.IsNullOrWhiteSpace(r.Message), $"{context}: no message");
                if (r.Payload is SecurityAuditReport report) Assert.NotEmpty(report.Findings);
                else Assert.Equal(DiagnosticStatus.Error, r.Status);
            }
    }
}
