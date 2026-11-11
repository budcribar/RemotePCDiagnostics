using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Security;

namespace RemotePCDiagnostics.Tests;

public class HomeAuditProfileTests
{
    private static AuditFinding F(string id, AuditOutcome o, string sev = "Medium") => new(id, "Cat", "Setting " + id, sev, "", "", o);

    private static readonly IReadOnlyList<AuditFinding> Findings =
    [
        F("1708", AuditOutcome.Failed, "High"),   // BitLocker: home-relevant
        F("1601", AuditOutcome.Failed),           // LLMNR: home-relevant
        F("1430", AuditOutcome.Passed),           // public firewall on: home-relevant
        F("1200", AuditOutcome.Failed),           // user rights: enterprise
        F("1500", AuditOutcome.Warning, "Low"),   // audit policy: enterprise
        F("1617", AuditOutcome.Failed),           // Credential Guard: enterprise
    ];

    private static readonly PcProfile Home = new(false, false, false, "Core");

    [Theory]
    [InlineData("RPD_PROFILE=domain=False;entra=False;mdm=False;edition=Core", false, "not managed by an organization")]
    [InlineData("noise\r\nRPD_PROFILE=domain=True;entra=False;mdm=False;edition=Professional\r\n", true, "joined to a domain")]
    [InlineData("RPD_PROFILE=domain=False;entra=True;mdm=True;edition=Professional", true, "joined to Microsoft Entra ID (work or school)")]
    [InlineData("RPD_PROFILE=domain=False;entra=False;mdm=True;edition=Professional", true, "managed by an organization (MDM)")]
    [InlineData("RPD_PROFILE=domain=False;entra=False;mdm=False;edition=Enterprise", true, "running Windows Enterprise")]
    public void Detects_managed_pcs(string stdout, bool managed, string reason)
    {
        var p = PcProfile.Parse(stdout)!;
        Assert.Equal(managed, p.Managed);
        Assert.Equal(reason, p.Reason);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("RPD_PROFILE=")]
    [InlineData("RPD_PROFILE=domain=maybe;entra=False;mdm=False")]
    public void Unreadable_profile_is_null(string? stdout) => Assert.Null(PcProfile.Parse(stdout));

    [Fact]
    public void Home_pc_counts_only_home_relevant_findings()
    {
        var rep = new SecurityAuditReport(Findings, null, Home);
        Assert.True(rep.HomePc);
        Assert.Equal(3, rep.Shown.Count);
        Assert.Equal(3, rep.Hidden);
        Assert.Equal(2, rep.Failed);
        Assert.Equal(0, rep.Warnings);
        Assert.Equal(1, rep.Passed);
        Assert.Equal("1 high-risk · 2 failed, 0 warnings, 1 passed · 3 enterprise-only settings hidden", rep.Summary);
        Assert.Equal(DiagnosticStatus.Error, rep.Status);
    }

    [Fact]
    public void Managed_or_unknown_pc_shows_everything()
    {
        foreach (var rep in new[] { new SecurityAuditReport(Findings, null, Home with { Domain = true }), new SecurityAuditReport(Findings) })
        {
            Assert.False(rep.HomePc);
            Assert.Equal(6, rep.Shown.Count);
            Assert.Equal(0, rep.Hidden);
            Assert.Equal(4, rep.Failed);
            Assert.DoesNotContain("hidden", rep.Summary);
        }
    }

    private static string FindRepoRoot()
    {
        for (var d = new DirectoryInfo(AppContext.BaseDirectory); d is not null; d = d.Parent)
            if (File.Exists(Path.Combine(d.FullName, "RemotePCDiagnostics.sln")))
                return d.FullName;
        throw new DirectoryNotFoundException("Could not find RemotePCDiagnostics.sln above " + AppContext.BaseDirectory);
    }

    [Fact]
    public void Every_relevant_id_is_in_the_bundled_baseline()
    {
        var csv = Path.Combine(FindRepoRoot(), "third_party", "HardeningKitty", "module", "lists", "finding_list_0x6d69636b_machine.csv");
        Assert.True(File.Exists(csv), $"Bundled HardeningKitty baseline missing at {csv}");
        var ids = File.ReadLines(csv).Skip(1).Select(l => l.Split(',')[0].Trim()).ToHashSet();
        foreach (var id in HomeAuditProfile.RelevantIds) Assert.Contains(id, ids);
    }

    [Fact]
    public void Audit_script_detects_the_profile()
    {
        var script = SecurityAuditModule.BuildScript(@"C:\hk\HardeningKitty.psd1", @"C:\t\r.csv");
        Assert.EndsWith(PcProfile.DetectScript, script);
        Assert.Contains("PartOfDomain", script);
    }
}
