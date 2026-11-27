using System.Text.Json;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Battery;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Tests.Battery;

public sealed class HpBatteryChargeTests
{
    private static readonly HpBatterySetting Manager = new(HpBatteryCharge.HealthManager, "Let HP manage my battery charging",
        ["Let HP manage my battery charging", "Maximize my battery health", "Maximize my battery duration"]);
    private static readonly HpBatterySetting Care = new(HpBatteryCharge.CareFunction, "100%", ["100%", "90%", "80%", "50%"]);

    private sealed class FakeBios(HpBatterySetting? setting, bool password = false, uint code = 0) : IHpBiosSettings
    {
        public List<(string, string)> Sets { get; } = [];
        public HpBatterySetting? Read(string name) => setting?.Name == name ? setting : null;
        public bool SetupPasswordSet() => password;
        public uint Set(string name, string value) { Sets.Add((name, value)); return code; }
    }

    private sealed class FakeWmi(WmiQueryResult result) : IWmiSource
    {
        public Task<WmiQueryResult> QueryAsync(string wmiNamespace, string wql, CancellationToken ct = default) => Task.FromResult(result);
    }

    [Fact]
    public void Limit_values_are_the_80_percent_ones()
    {
        Assert.Equal("Maximize my battery health", Manager.LimitValue);
        Assert.False(Manager.IsLimited);
        Assert.Equal("80%", Care.LimitValue);
        Assert.True((Care with { CurrentValue = "80%" }).IsLimited);
        Assert.Null(new HpBatterySetting(HpBatteryCharge.CareFunction, "100%", ["100%"]).LimitValue);
    }

    [Fact]
    public void Card_offers_the_fix_only_when_charging_isnt_limited()
    {
        var card = BatteryPowerModule.ChargeLimitCard([Care, Manager])!;
        Assert.Equal("charge-limit", card.Id);
        Assert.Equal("Charges to 100%", card.Headline);
        Assert.Equal(AreaLevel.Neutral, card.Level);
        var fix = Assert.Single(card.Actions!);
        Assert.Equal(RemediationKind.SetHpBatteryChargeLimit, fix.Kind);
        // Battery Health Manager wins when a PC has both.
        Assert.Equal("Battery Health Manager|Maximize my battery health", fix.Target);

        var done = BatteryPowerModule.ChargeLimitCard([Manager with { CurrentValue = "Maximize my battery health" }])!;
        Assert.Equal("Charging stops at about 80%", done.Headline);
        Assert.Equal(AreaLevel.Ok, done.Level);
        Assert.Null(done.Actions);

        Assert.Null(BatteryPowerModule.ChargeLimitCard([]));
        Assert.Null(BatteryPowerModule.ChargeLimitCard(null));
    }

    [Fact]
    public async Task Reads_hp_settings_from_wmi_and_nothing_elsewhere()
    {
        var row = WmiRow.From([new("Name", HpBatteryCharge.CareFunction), new("CurrentValue", "100%"), new("PossibleValues", new[] { "100%", "80%" })]);
        var read = await HpBatteryCharge.ReadAsync(new FakeWmi(new(HpBatteryCharge.Namespace, HpBatteryCharge.ReadSql, [row])), default);
        var s = Assert.Single(read);
        Assert.Equal(["100%", "80%"], s.PossibleValues);

        var none = await HpBatteryCharge.ReadAsync(new FakeWmi(WmiQueryResult.Failed(HpBatteryCharge.Namespace, HpBatteryCharge.ReadSql, "Invalid namespace")), default);
        Assert.Empty(none);
    }

    [Fact]
    public void Agent_sets_only_a_listed_value_and_never_with_a_setup_password()
    {
        var bios = new FakeBios(Manager);
        Assert.Equal(0, AgentHpBatteryCharge.Run(bios, new HpBatterySetAction(Manager.Name, "Maximize my battery health")).ExitCode);
        Assert.Equal([(Manager.Name, "Maximize my battery health")], bios.Sets);

        var unlisted = AgentHpBatteryCharge.Run(bios, new HpBatterySetAction(Manager.Name, "Charge forever"));
        Assert.Equal(1, unlisted.ExitCode);
        Assert.Single(bios.Sets);

        var locked = new FakeBios(Manager, password: true);
        var refused = AgentHpBatteryCharge.Run(locked, new HpBatterySetAction(Manager.Name, "Maximize my battery health"));
        Assert.Equal(1, refused.ExitCode);
        Assert.Contains("setup password", refused.StdErr);
        Assert.Empty(locked.Sets);

        var failed = AgentHpBatteryCharge.Run(new FakeBios(Manager, code: 6), new HpBatterySetAction(Manager.Name, "Maximize my battery health"));
        Assert.Contains("denied access", failed.StdErr);

        var read = AgentHpBatteryCharge.Run(bios, new HpBatteryReadAction(Manager.Name));
        Assert.Equal((0, "Let HP manage my battery charging"), (read.ExitCode, read.StdOut));
        Assert.Equal(1, AgentHpBatteryCharge.Run(new FakeBios(null), new HpBatteryReadAction(Manager.Name)).ExitCode);
    }

    [Theory]
    [InlineData(AgentScripts.HpBatteryRead, new[] { "Battery Health Manager" }, true)]
    [InlineData(AgentScripts.HpBatterySet, new[] { "Battery Care Function", "80%" }, true)]
    [InlineData(AgentScripts.HpBatterySet, new[] { "Secure Boot", "Disable" }, false)]
    [InlineData(AgentScripts.HpBatterySet, new[] { "Battery Care Function", "" }, false)]
    [InlineData(AgentScripts.HpBatterySet, new[] { "Battery Care Function", "80%\n" }, false)]
    [InlineData(AgentScripts.HpBatteryRead, new[] { "Setup Password" }, false)]
    public void Agent_plans_only_hp_battery_settings(string name, string[] args, bool allowed)
    {
        var plan = AgentScripts.Plan(AgentScripts.Of(name, args), null, out var refusal);
        Assert.Equal(allowed, plan?.Native is HpBatteryReadAction or HpBatterySetAction);
        Assert.Equal(allowed, refusal is null);
    }

    [Theory]
    [InlineData("Battery Care Function|80%", true)]
    [InlineData("Battery Health Manager|Maximize my battery health", true)]
    [InlineData("Battery Care Function|", false)]
    [InlineData("Boot Order|80%", false)]
    [InlineData("", false)]
    public void Fix_target_parses(string target, bool ok) => Assert.Equal(ok, HpBatteryCharge.TryParseTarget(target, out _, out _));

    [Fact]
    public void Undo_groups_and_names_the_change()
    {
        Assert.Equal(UndoSupport.Full, Undoability.Of(RemediationKind.SetHpBatteryChargeLimit));
        Assert.True(FixAccess.NeedsAgent(RemediationKind.SetHpBatteryChargeLimit));
        var c = ChangeRecord.New(ChangeKind.HpBiosSetting, HpBatteryCharge.HealthManager, "Let HP manage my battery charging", "Battery charging limited to about 80%", "test", true);
        Assert.Equal("Battery charging limited to about 80% (was Let HP manage my battery charging)", Undoability.Describe(c));
        Assert.Equal("battery charge limit", UndoAllResult.RestartName(c));
    }
}
