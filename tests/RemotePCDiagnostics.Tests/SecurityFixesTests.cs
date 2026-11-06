using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Security;

namespace RemotePCDiagnostics.Tests;

public class SecurityFixesTests
{
    private static readonly TpmFacts Tpm2 = new(true, "2.0", true, "AMD", "Bound");
    private static AreaCard Card(AreaReport r, string id) => r.Cards.Single(c => c.Id == id);

    private const string ProbeOutput = """
        SecureBoot=0
        Firmware=UEFI
        Edition=Core
        SystemDrive=C:
        Encryption=0
        DefenderMode=Normal
        RealTime=True
        Tamper=True
        Pua=0
        NetworkProtection=0
        Asr=
        Antivirus=Windows Defender
        Firewall=Domain:True,Private:True,Public:False
        Llmnr=
        AutoRun=
        InsecureGuest=
        """;

    [Fact]
    public void Probe_output_becomes_fixable_cards()
    {
        var f = SecurityEssentialsModule.ParseProbe(ProbeOutput, Tpm2);
        Assert.True(f.DefenderActive);
        Assert.Equal(0, f.Pua);
        Assert.Empty(f.AsrRules!);
        Assert.False(f.Firewall["Public"]);
        Assert.Null(f.LlmnrPolicy);
        var rep = SecurityEssentialsModule.Build(f);
        Assert.Equal(AreaLevel.Error, Card(rep, "firewall").Level);
        Assert.Equal("Firewall is off for public networks", Card(rep, "firewall").Headline);
        foreach (var (id, key) in new[] { ("pua", SecurityFixes.Pua), ("networkprotection", SecurityFixes.NetworkProtection), ("asr", SecurityFixes.AsrRules), ("llmnr", SecurityFixes.Llmnr), ("autorun", SecurityFixes.AutoRun) })
        {
            var a = Assert.Single(Card(rep, id).Actions!);
            Assert.Equal(RemediationKind.ApplySecuritySetting, a.Kind);
            Assert.Equal(key, a.Target);
        }
        Assert.Equal(SecurityFixes.GuestLogons, Assert.Single(Card(rep, "guest").Actions!).Target);
        Assert.Null(Card(rep, "secureboot").Actions);
        Assert.Null(Card(rep, "encryption").Actions);
    }

    [Fact]
    public void Asr_rules_parse_and_count()
    {
        var f = SecurityEssentialsModule.ParseProbe("DefenderMode=Normal\nAsr=9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2:1,d4f940ab-401b-4efc-aadc-ad5f3c50688a:2", null);
        Assert.Equal(1, f.AsrRules!["9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"]);
        var card = Card(SecurityEssentialsModule.Build(f), "asr");
        Assert.Equal("1 of 5 protection rules on", card.Headline);
        Assert.Contains(card.Rows, r => r.Values[1] == "Audit only");
    }

    [Fact]
    public void Another_antivirus_means_no_defender_fixes()
    {
        var f = SecurityEssentialsModule.ParseProbe("DefenderMode=Passive mode\nPua=0\nNetworkProtection=0\nAsr=\nAntivirus=Windows Defender;Norton 360", Tpm2);
        var rep = SecurityEssentialsModule.Build(f);
        Assert.Equal("Protected by Norton 360", Card(rep, "antivirus").Headline);
        Assert.Equal(AreaLevel.Ok, Card(rep, "antivirus").Level);
        foreach (var id in new[] { "pua", "networkprotection", "asr" })
        {
            Assert.Equal(AreaLevel.Neutral, Card(rep, id).Level);
            Assert.Null(Card(rep, id).Actions);
        }
    }

    [Fact]
    public void Defender_real_time_off_is_critical()
    {
        var f = SecurityEssentialsModule.ParseProbe("DefenderMode=Normal\nRealTime=False\nTamper=True", Tpm2);
        var rep = SecurityEssentialsModule.Build(f);
        Assert.Equal(DiagnosticStatus.Error, rep.Status);
        Assert.Equal("Real-time protection is off", Card(rep, "antivirus").Headline);
    }

    [Fact]
    public void Every_fix_has_read_and_apply_scripts()
    {
        Assert.Equal(6, SecurityFixes.All.Count);
        foreach (var f in SecurityFixes.All)
        {
            Assert.NotNull(SecurityFixes.ReadScript(f.Key));
            Assert.NotNull(SecurityFixes.ApplyScript(f.Key));
        }
        Assert.Null(SecurityFixes.ReadScript("firewall"));
        Assert.Null(SecurityFixes.ApplyScript("x; Remove-Item C:\\"));
    }

    [Theory]
    [InlineData("pua", "0", true)]
    [InlineData("pua", "2", true)]
    [InlineData("pua", "", false)]
    [InlineData("pua", "1; Remove-Item C:\\", false)]
    [InlineData("llmnr", "", true)]
    [InlineData("llmnr", "1", true)]
    [InlineData("llmnr", "-1", false)]
    [InlineData("autorun", "145", true)]
    [InlineData("asr", "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2=;56a863a9-875e-4185-98a7-b882c64b5ce5=2", true)]
    [InlineData("asr", "01443614-cd74-433a-b99e-2ecdc07bfc25=1", false)]
    [InlineData("asr", "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2=x'", false)]
    [InlineData("unknown", "0", false)]
    public void Journaled_values_are_validated_before_restore(string key, string previous, bool valid)
    {
        Assert.Equal(valid, SecurityFixes.ParsePrevious(key, previous) is not null);
        Assert.Equal(valid, SecurityFixes.RestoreScript(key, previous) is not null);
    }

    [Fact]
    public void Restore_puts_back_or_removes()
    {
        Assert.EndsWith("Set-MpPreference -PUAProtection 2", SecurityFixes.RestoreScript(SecurityFixes.Pua, "2"));
        Assert.Contains("Remove-ItemProperty", SecurityFixes.RestoreScript(SecurityFixes.Llmnr, ""));
        Assert.Contains("-Value 1 ", SecurityFixes.RestoreScript(SecurityFixes.Llmnr, "1"));
        var asr = SecurityFixes.RestoreScript(SecurityFixes.AsrRules, "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2=;56a863a9-875e-4185-98a7-b882c64b5ce5=2")!;
        Assert.Contains("Remove-MpPreference -AttackSurfaceReductionRules_Ids '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'", asr);
        Assert.Contains("Add-MpPreference -AttackSurfaceReductionRules_Ids '56a863a9-875e-4185-98a7-b882c64b5ce5' -AttackSurfaceReductionRules_Actions 2", asr);
    }

    [Fact]
    public void Fixes_reach_the_fix_list_as_undoable_admin_fixes()
    {
        var f = SecurityEssentialsModule.ParseProbe("DefenderMode=Normal\nPua=0\nNetworkProtection=1\nAsr=\nLlmnr=0\nAutoRun=255", null);
        var rep = SecurityEssentialsModule.Build(f);
        var result = new DiagnosticResult<AreaReport>(ModuleSlugs.SecurityEssentials, rep.Status, rep.Summary, DateTimeOffset.Now, rep);
        var fixes = RemotePCDiagnostics.Core.Workflow.FixCatalog.Build([result], [], new RemediationService(new SystemCommandRunner()));
        Assert.Equal(["rem:applysecuritysetting:asr", "rem:applysecuritysetting:pua"], fixes.Select(x => x.Id).Order().ToArray());
        Assert.All(fixes, x =>
        {
            Assert.True(x.NeedsAdmin);
            Assert.Equal("Security", x.Area);
            Assert.Equal(RemotePCDiagnostics.Core.Changes.UndoSupport.Full, x.Undo);
        });
        Assert.Equal("Turn on PUA blocking", fixes.Single(x => x.Id.EndsWith(":pua")).Title);
    }

    [Fact]
    public void Guest_logon_fix_is_offered_on_home_but_not_ticked_and_plans_never_mention_admin()
    {
        var f = SecurityEssentialsModule.ParseProbe("Edition=Core\nDefaultMode=Normal\nLlmnr=0\nAutoRun=255\nInsecureGuest=", null);
        var rep = SecurityEssentialsModule.Build(f);
        var result = new DiagnosticResult<AreaReport>(ModuleSlugs.SecurityEssentials, rep.Status, rep.Summary, DateTimeOffset.Now, rep);
        var plans = new RemediationService(new SystemCommandRunner());
        var guest = RemotePCDiagnostics.Core.Workflow.FixCatalog.Build([result], [], plans).Single(x => x.Id == "rem:applysecuritysetting:guest-logons");
        Assert.False(guest.DefaultOn);
        Assert.True(guest.NeedsAdmin);
        foreach (var fix in SecurityFixes.All)
            Assert.DoesNotContain("administrator", plans.Plan(new AreaAction(RemediationKind.ApplySecuritySetting, fix.ButtonText, fix.Key)).Warning ?? "", StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Unknown_target_is_not_allowed()
    {
        var plan = new RemediationService(new SystemCommandRunner()).Plan(new AreaAction(RemediationKind.ApplySecuritySetting, "x", "disable-firewall"));
        Assert.False(plan.Allowed);
    }
}
