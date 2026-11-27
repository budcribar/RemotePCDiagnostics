using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Security;
using RemotePCDiagnostics.Core.Workflow;
using Xunit;

namespace RemotePCDiagnostics.Tests;

/// <summary>A failed audit setting fails the audit (and the QA row), offers its fix, and can be re-run on its own.</summary>
public sealed class SecurityAuditFixTests
{
    private static AuditFinding F(string id, AuditOutcome o, string severity = "Medium") => new(id, "Cat", "Setting " + id, severity, "now", "want", o);

    private static SecurityAuditReport Home(params AuditFinding[] f) => new(f, Profile: new PcProfile(false, false, false, "Professional"));

    [Fact]
    public void One_medium_failure_fails_the_audit_and_low_ones_are_a_warning()
    {
        Assert.Equal(DiagnosticStatus.Error, Home(F("1601", AuditOutcome.Failed), F("1704", AuditOutcome.Passed)).Status);
        Assert.Equal(DiagnosticStatus.Warning, Home(F("1100", AuditOutcome.Warning, "Low"), F("1704", AuditOutcome.Passed)).Status);
        Assert.Equal(DiagnosticStatus.Ok, Home(F("1704", AuditOutcome.Passed)).Status);
        // On a home PC an enterprise-only failure is hidden, so it doesn't fail the audit.
        Assert.Equal(DiagnosticStatus.Ok, Home(F("1500", AuditOutcome.Failed), F("1704", AuditOutcome.Passed)).Status);
    }

    [Theory]
    [InlineData("1601", RemediationKind.ApplySecuritySetting, SecurityFixes.Llmnr)]
    [InlineData("1602", RemediationKind.ApplySecuritySetting, SecurityFixes.GuestLogons)]
    [InlineData("1704", RemediationKind.ApplySecuritySetting, SecurityFixes.AutoRun)]
    [InlineData("1925", RemediationKind.ApplySecuritySetting, SecurityFixes.AsrRules)]
    [InlineData("1430", RemediationKind.OpenSettings, "windowsdefender://network")]
    [InlineData("1620", RemediationKind.OpenSettings, "windowsdefender://coreisolation")]
    [InlineData("1826", RemediationKind.OpenSettings, "windowsdefender://threatsettings")]
    [InlineData("1708", RemediationKind.OpenSettings, "ms-settings:deviceencryption")]
    public void Failed_settings_get_the_fix_for_them(string id, RemediationKind kind, string target)
    {
        var a = SecurityAuditFixes.For(F(id, AuditOutcome.Failed));
        Assert.NotNull(a);
        Assert.Equal((kind, target), (a!.Kind, a.Target));
        Assert.False(string.IsNullOrWhiteSpace(a.ButtonText));
    }

    [Fact]
    public void Passed_and_unknown_settings_get_no_fix_and_the_ASR_fix_is_offered_once()
    {
        Assert.Null(SecurityAuditFixes.For(F("1601", AuditOutcome.Passed)));
        Assert.Null(SecurityAuditFixes.For(F("1329", AuditOutcome.Failed)));
        var fixes = SecurityAuditFixes.ForReport(Home(F("1916", AuditOutcome.Failed), F("1921", AuditOutcome.Failed), F("1601", AuditOutcome.Failed), F("1329", AuditOutcome.Failed)));
        Assert.Equal([SecurityFixes.AsrRules, SecurityFixes.Llmnr], fixes.Select(x => x.Action.Target).Order());
        Assert.Equal(2, fixes.Single(x => x.Action.Target == SecurityFixes.AsrRules).Findings.Count);
    }

    [Fact]
    public void Merge_replaces_rechecked_findings_and_keeps_the_rest()
    {
        var rep = Home(F("1601", AuditOutcome.Failed), F("1704", AuditOutcome.Passed));
        var merged = rep.Merge([F("1601", AuditOutcome.Passed)]);
        Assert.Equal([("1601", AuditOutcome.Passed), ("1704", AuditOutcome.Passed)], merged.Findings.Select(f => (f.Id, f.Outcome)));
        Assert.Equal(DiagnosticStatus.Ok, merged.Status);
    }

    [Fact]
    public void Qa_row_shows_FAIL_for_a_failed_audit()
    {
        var store = new ResultStore();
        var now = DateTimeOffset.Now;
        var rep = Home(F("1601", AuditOutcome.Failed), F("1704", AuditOutcome.Passed));
        store.Set(new DiagnosticResult<SecurityAuditReport>(ModuleSlugs.SecurityAudit, rep.Status, rep.Summary, now, rep));
        var snap = HardwareQaCertificate.Capture(store, "BENCH", now);
        var item = snap.Items.Single(i => i.Id == "security");
        Assert.Equal(DiagnosticStatus.Error, item.Status);
        Assert.Equal(HardwareQaVerdict.AttentionRequired, snap.Verdict);
        Assert.Contains(">FAIL<", HardwareQaCertificate.BuildHtml(snap));
        Assert.Contains(snap.Items.Single(i => i.Id == "security"), BenchQaRunner.RerunnableProblems(snap));
    }

    [Theory]
    [InlineData("security", ModuleSlugs.SecurityAudit)]
    [InlineData("sensors", ModuleSlugs.Sensors)]
    [InlineData("cpu-stress", ModuleSlugs.CpuStress)]
    [InlineData("integrity", ModuleSlugs.DismScanHealth)]
    public void Rerun_maps_items_to_their_checks(string item, string slug) => Assert.Contains(slug, BenchQaRunner.SlugsForItem(item));

    [Theory]
    [InlineData("keyboard")]
    [InlineData("display")]
    [InlineData("nope")]
    public void Interactive_items_cannot_be_rerun_unattended(string item) => Assert.False(BenchQaRunner.CanRerun(item));
}
