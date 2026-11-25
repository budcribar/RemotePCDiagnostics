using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Security;
using RemotePCDiagnostics.Legacy;

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
        CloudProtection=0
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
        var f = PowerShellSecurityEssentialsSource.ParseProbe(ProbeOutput, Tpm2);
        Assert.True(f.DefenderActive);
        Assert.Equal(0, f.Pua);
        Assert.Equal(0, f.CloudProtection);
        Assert.Empty(f.AsrRules!);
        Assert.False(f.Firewall["Public"]);
        Assert.Null(f.LlmnrPolicy);
        var rep = SecurityEssentialsModule.Build(f);
        Assert.Equal(AreaLevel.Error, Card(rep, "firewall").Level);
        Assert.Equal("Firewall is off for public networks", Card(rep, "firewall").Headline);
        foreach (var (id, key) in new[] { ("pua", SecurityFixes.Pua), ("networkprotection", SecurityFixes.NetworkProtection), ("cloudprotection", SecurityFixes.CloudProtection), ("asr", SecurityFixes.AsrRules), ("llmnr", SecurityFixes.Llmnr), ("autorun", SecurityFixes.AutoRun) })
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
        var f = PowerShellSecurityEssentialsSource.ParseProbe("DefenderMode=Normal\nAsr=9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2:1,d4f940ab-401b-4efc-aadc-ad5f3c50688a:2", null);
        Assert.Equal(1, f.AsrRules!["9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"]);
        var card = Card(SecurityEssentialsModule.Build(f), "asr");
        Assert.Equal("1 of 5 protection rules on", card.Headline);
        Assert.Contains(card.Rows, r => r.Values[1] == "Audit only");
    }

    [Fact]
    public void Why_it_matters_never_says_off_when_the_setting_is_on()
    {
        // #71: the explanation row said "It's off" under an "on" headline.
        var asr = string.Join(",", SecurityFixes.SafeAsrRules.Select(r => r.Id + ":1"));
        var f = PowerShellSecurityEssentialsSource.ParseProbe($"DefenderMode=Normal\nPua=1\nNetworkProtection=1\nCloudProtection=2\nAsr={asr}", Tpm2);
        var rep = SecurityEssentialsModule.Build(f);
        foreach (var id in new[] { "pua", "networkprotection", "cloudprotection", "asr" })
        {
            var card = Card(rep, id);
            Assert.Equal(AreaLevel.Ok, card.Level);
            var why = card.Rows.Single(r => r.Values[0] == "Why it matters").Values[1];
            Assert.DoesNotContain(" off", why, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Another_antivirus_means_no_defender_fixes()
    {
        var f = PowerShellSecurityEssentialsSource.ParseProbe("DefenderMode=Passive mode\nPua=0\nNetworkProtection=0\nCloudProtection=0\nAsr=\nAntivirus=Windows Defender;Norton 360", Tpm2) with
        {
            AntivirusProducts = [new("Norton 360", AntivirusProductState.On, AntivirusSignatureStatus.UpToDate)],
            AntivirusInventoryStatus = AntivirusInventoryStatus.Ok,
        };
        var rep = SecurityEssentialsModule.Build(f);
        Assert.Equal("Protected by Norton 360", Card(rep, "antivirus").Headline);
        Assert.Equal(AreaLevel.Ok, Card(rep, "antivirus").Level);
        foreach (var id in new[] { "pua", "networkprotection", "cloudprotection", "asr" })
        {
            Assert.Equal(AreaLevel.Neutral, Card(rep, id).Level);
            Assert.Null(Card(rep, id).Actions);
        }
    }

    [Fact]
    public void Defender_real_time_off_is_critical()
    {
        var f = PowerShellSecurityEssentialsSource.ParseProbe("DefenderMode=Normal\nRealTime=False\nTamper=True", Tpm2);
        var rep = SecurityEssentialsModule.Build(f);
        Assert.Equal(DiagnosticStatus.Error, rep.Status);
        Assert.Equal("Real-time protection is off", Card(rep, "antivirus").Headline);
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
    }

    [Fact]
    public void Fixes_reach_the_fix_list_as_undoable_admin_fixes()
    {
        var f = PowerShellSecurityEssentialsSource.ParseProbe("DefenderMode=Normal\nPua=0\nNetworkProtection=1\nAsr=\nLlmnr=0\nAutoRun=255", null);
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
        var f = PowerShellSecurityEssentialsSource.ParseProbe("Edition=Core\nDefaultMode=Normal\nLlmnr=0\nAutoRun=255\nInsecureGuest=", null);
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
