using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Security;
using RemotePCDiagnostics.Legacy;

namespace RemotePCDiagnostics.Tests.Replay;

/// <summary>Security essentials as the app runs it and as the Store edition without an Agent runs it, on a recorded PC.</summary>
internal static class SecurityEssentialsReplay
{
    /// <summary>WMI (the Agent's), the registry and tpmtool (the app's).</summary>
    public static SecurityEssentialsModule SecurityEssentials(this ReplayedPc pc) => new(new WmiSecurityEssentialsSource(pc.Wmi, pc.Registry, pc.Commands));
    /// <summary>The Store edition without an Agent: the PowerShell probe and tpmtool.</summary>
    public static SecurityEssentialsModule SecurityEssentialsOld(this ReplayedPc pc) => new(new PowerShellSecurityEssentialsSource(pc.Commands));

    public static bool HasSecurityEssentials(this ReplayedPc pc) => pc.HasWmi(WmiSecurityEssentialsSource.OsSql);
    public static bool HasSecurityEssentialsOld(this ReplayedPc pc) =>
        pc.Has(c => c.Kind == Core.Recording.RecordedCall.ProcessKind && c.Args?.LastOrDefault() == PowerShellSecurityEssentialsSource.ProbeScript);
}

/// <summary>Security essentials, replayed: the approved snapshot, the same verdicts as the PowerShell probe, and damaged answers.</summary>
public sealed class SecurityEssentialsReplayTests
{
    public static TheoryData<string> Recordings => RecordingLibrary.Names();

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task MatchesApprovedSnapshot(string name)
    {
        var pc = new ReplayedPc(RecordingLibrary.Load(name));
        Assert.SkipUnless(pc.HasSecurityEssentials(), "This recording has no WMI security answers.");
        var result = await pc.SecurityEssentials().RefreshAsync(null, TestContext.Current.CancellationToken);
        Assert.Empty(pc.Replay.Misses);
        Snapshot.Match(RecordingLibrary.Folder(name), "SecurityEssentials", result);
    }

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task WmiAndPowerShellAgree(string name)
    {
        var rec = RecordingLibrary.Load(name);
        var pc = new ReplayedPc(rec);
        Assert.SkipUnless(pc.HasSecurityEssentials() && pc.HasSecurityEssentialsOld(), "This recording doesn't hold both the WMI and the PowerShell security answers.");
        var ct = TestContext.Current.CancellationToken;
        var now = (AreaReport)(await pc.SecurityEssentials().RefreshAsync(null, ct)).Payload!;
        var oldPc = new ReplayedPc(rec);
        var old = (AreaReport)(await oldPc.SecurityEssentialsOld().RefreshAsync(null, ct)).Payload!;
        Assert.Empty(oldPc.Replay.Misses);
        var diffs = ReportDiff.Between(old, now);
        Assert.True(diffs.Count == 0, $"{diffs.Count} differences:\n" + string.Join("\n", diffs));
    }

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task SurvivesDamagedAnswers(string name)
    {
        var rec = RecordingLibrary.Load(name);
        Assert.SkipUnless(new ReplayedPc(rec).HasSecurityEssentials(), "This recording has no WMI security answers.");
        await DamagedRuns.AssertSurvivesAsync(rec, r => r.Payload is AreaReport a ? DamagedRuns.CommonProblems(a) : ["no report"], maxRows: 3,
            ("WMI", pc => pc.SecurityEssentials()), ("PowerShell", pc => pc.SecurityEssentialsOld()));
    }

    /// <summary>With nothing answering (no Agent, no registry, no tpmtool) the check fails, rather than passing on no data.</summary>
    [Fact]
    public async Task Fails_when_nothing_can_be_read()
    {
        var pc = new ReplayedPc(new Core.Recording.MachineRecording { Machine = new(), Calls = [] });
        var r = await pc.SecurityEssentials().RefreshAsync(null, TestContext.Current.CancellationToken);
        Assert.Equal(Core.DiagnosticStatus.Error, r.Status);
    }

    /// <summary>Only the registry and tpmtool answer (the Agent isn't connected): those cards still show; the WMI ones say "not reported".</summary>
    [Fact]
    public async Task Without_the_Agent_the_registry_cards_still_show()
    {
        var rec = RecordingLibrary.Load("sample/sample-laptop").FailWmi("FROM", "The Agent isn't connected, so WMI can't be read.");
        var report = (AreaReport)(await new ReplayedPc(rec).SecurityEssentials().RefreshAsync(null, TestContext.Current.CancellationToken)).Payload!;
        AreaCard Card(string id) => report.Cards.Single(c => c.Id == id);
        Assert.Equal("Secure Boot is on", Card("secureboot").Headline);
        Assert.Equal("Antivirus not reported", Card("antivirus").Headline);
        Assert.Equal("Firewall not reported", Card("firewall").Headline);
        Assert.Equal("Encryption not reported", Card("encryption").Headline);
    }
}

/// <summary>The WMI reader's translations, on single answers.</summary>
public sealed class WmiSecurityEssentialsSourceTests
{
    private static Core.DataSources.WmiRow Row(params (string Name, object? Value)[] values) =>
        Core.DataSources.WmiRow.From(values.Select(v => new KeyValuePair<string, object?>(v.Name, v.Value)));

    [Theory]
    [InlineData(1, 1, true, 1)]      // on
    [InlineData(1, 2, true, 3)]      // encrypting, protected
    [InlineData(0, 2, false, 3)]     // encrypting (Device encryption on its way)
    [InlineData(0, 1, true, 5)]      // encrypted, protection suspended
    [InlineData(0, 1, false, 8)]     // encrypted, waiting for activation
    [InlineData(0, 0, false, 2)]     // not encrypted
    [InlineData(0, 3, true, 4)]      // decrypting
    [InlineData(2, 1, true, 6)]      // locked
    public void Encryption_reads_as_the_Shell_property(int protection, int conversion, bool initialized, int expected) =>
        Assert.Equal(expected, WmiSecurityEssentialsSource.Protection(Row(("ProtectionStatus", protection), ("ConversionStatus", conversion),
            ("IsVolumeInitializedForProtection", initialized))));

    [Fact]
    public void Encryption_without_a_status_is_not_reported() =>
        Assert.Null(WmiSecurityEssentialsSource.Protection(Row(("DriveLetter", "C:"))));

    [Fact]
    public void Asr_pairs_ids_with_actions()
    {
        var asr = WmiSecurityEssentialsSource.Asr(Row(("AttackSurfaceReductionRules_Ids", new[] { "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2", "", "d4f940ab-401b-4efc-aadc-ad5f3c50688a" }),
            ("AttackSurfaceReductionRules_Actions", new[] { 1, 2 })));
        Assert.Equal(2, asr.Count);
        Assert.Equal(1, asr["9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"]);
        Assert.Equal(0, asr["d4f940ab-401b-4efc-aadc-ad5f3c50688a"]); // no action: off
        Assert.Empty(WmiSecurityEssentialsSource.Asr(Row(("AttackSurfaceReductionRules_Ids", null))));
    }

    /// <summary>WMI gives the actions as bytes, which a WMI answer holds as base64 (as recorded on BUDSLAPTOP: five rules, all block).</summary>
    [Fact]
    public void Asr_actions_as_bytes_are_read()
    {
        var asr = WmiSecurityEssentialsSource.Asr(Row(("AttackSurfaceReductionRules_Ids", new[] { "56a863a9-875e-4185-98a7-b882c64b5ce5", "d4f940ab-401b-4efc-aadc-ad5f3c50688a" }),
            ("AttackSurfaceReductionRules_Actions", new byte[] { 1, 2 })));
        Assert.Equal(new Dictionary<string, int> { ["56a863a9-875e-4185-98a7-b882c64b5ce5"] = 1, ["d4f940ab-401b-4efc-aadc-ad5f3c50688a"] = 2 }, asr);
        Assert.Equal(0, WmiSecurityEssentialsSource.Asr(Row(("AttackSurfaceReductionRules_Ids", new[] { "x" }), ("AttackSurfaceReductionRules_Actions", "@@ not base64")))["x"]);
    }

    [Fact]
    public void Firewall_not_configured_is_Windows_default_on()
    {
        var fw = WmiSecurityEssentialsSource.Firewall([Row(("Name", "Domain"), ("Enabled", 1)), Row(("Name", "Private"), ("Enabled", 2)), Row(("Name", "Public"), ("Enabled", 0)),
            Row(("Name", "Odd"), ("Enabled", 7)), Row(("Enabled", 1))]);
        Assert.Equal(new Dictionary<string, bool> { ["Domain"] = true, ["Private"] = true, ["Public"] = false }, fw);
    }

    [Fact]
    public void Drives_keep_letters_and_known_types()
    {
        var drives = WmiSecurityEssentialsSource.Drives([Row(("DeviceID", "c:"), ("DriveType", 3)), Row(("DeviceID", "D:"), ("DriveType", 5)),
            Row(("DeviceID", @"\\?\Volume"), ("DriveType", 3)), Row(("DeviceID", "E:"), ("DriveType", 4294967295L))]);
        Assert.Equal(new Dictionary<char, int> { ['C'] = 3, ['D'] = 5 }, drives);
    }

    [Theory]
    [InlineData(@"HKLM:\SOFTWARE\Policies\X", Core.DataSources.RegistryRoot.LocalMachine, @"SOFTWARE\Policies\X")]
    [InlineData(@"HKCU:\SOFTWARE\X", Core.DataSources.RegistryRoot.CurrentUser, @"SOFTWARE\X")]
    public void Policy_keys_map_to_registry_reads(string psKey, Core.DataSources.RegistryRoot root, string path) =>
        Assert.Equal((root, path), WmiSecurityEssentialsSource.PsKey(psKey));

    [Fact]
    public void Every_policy_key_the_fixes_name_can_be_read() =>
        Assert.All(new[] { SecurityFixes.LlmnrKey, SecurityFixes.AutoRunKey, SecurityFixes.AutoRunUserKey, SecurityFixes.GuestKey },
            k => Assert.NotNull(WmiSecurityEssentialsSource.PsKey(k)));

    [Fact]
    public void The_Agent_runs_every_query()
    {
        (string Ns, string Sql)[] queries =
        [
            (WmiSecurityEssentialsSource.Cimv2, WmiSecurityEssentialsSource.OsSql), (WmiSecurityEssentialsSource.Cimv2, WmiSecurityEssentialsSource.DrivesSql),
            (WmiSecurityEssentialsSource.BitLockerNamespace, WmiSecurityEssentialsSource.EncryptionSql),
            (WmiSecurityEssentialsSource.DefenderNamespace, WmiSecurityEssentialsSource.DefenderStatusSql),
            (WmiSecurityEssentialsSource.DefenderNamespace, WmiSecurityEssentialsSource.DefenderPreferenceSql),
            (WmiSecurityEssentialsSource.SecurityCenterNamespace, WmiSecurityEssentialsSource.AntivirusSql),
            (WmiSecurityEssentialsSource.FirewallNamespace, WmiSecurityEssentialsSource.FirewallSql),
        ];
        Assert.All(queries, q => Assert.Null(Core.DataSources.WmiQueryPolicy.Problem(q.Ns, q.Sql)));
    }
}
