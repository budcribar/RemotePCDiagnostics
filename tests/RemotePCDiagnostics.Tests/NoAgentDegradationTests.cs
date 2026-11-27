using RemotePCDiagnostics.Agent.Core;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Sensors;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Modules.SecurityEssentials;
using RemotePCDiagnostics.Tests.Bios.E2E;
using Xunit;

namespace RemotePCDiagnostics.Tests;

/// <summary>The Microsoft Store app with no Agent installed: fewer features, no errors, warnings or "turn on Admin Repair Mode" hints.</summary>
public class NoAgentDegradationTests
{
    private static readonly StubElevationContext NoAdmin = new(isProcessElevated: false, isAdminHelperConnected: false);
    private static readonly StubElevationContext Admin = new(isProcessElevated: false, isAdminHelperConnected: true);

    [Fact]
    public void NoAgent_only_when_none_is_installed_and_none_does_admin_work()
    {
        Assert.True(AgentShopPillState.NoAgent(NoAdmin, AgentModeKind.LocalOnly));
        Assert.False(AgentShopPillState.NoAgent(NoAdmin, AgentModeKind.InstalledNotConnected));
        Assert.False(AgentShopPillState.NoAgent(Admin, AgentModeKind.LocalOnly));
        Assert.False(AgentShopPillState.NoAgent(null, AgentModeKind.LocalOnly));
        Assert.False(AgentShopPillState.NoAgent(NoAdmin, null));
    }

    [Fact]
    public void Restricted_badge_shows_only_for_an_installed_agent_without_admin()
    {
        Assert.False(AgentShopPillState.ShowRestrictedBadge(NoAdmin, AgentModeKind.LocalOnly));
        Assert.True(AgentShopPillState.ShowRestrictedBadge(NoAdmin, AgentModeKind.InstalledNotConnected));
        Assert.False(AgentShopPillState.ShowRestrictedBadge(Admin, AgentModeKind.InstalledNotConnected));
    }

    [Fact]
    public void Agent_only_fixes_are_left_out_without_an_agent()
    {
        var dism = new AreaAction(RemediationKind.RepairComponentStore, "Repair");
        var settings = new AreaAction(RemediationKind.OpenSettings, "Open Settings", "ms-settings:sound");
        Assert.True(FixAccess.NeedsAgent(RemediationKind.RepairComponentStore));
        Assert.False(FixAccess.NeedsAgent(RemediationKind.OpenSettings));

        Assert.Equal([settings], FixAccess.Offerable([dism, settings], agent: false));
        Assert.Null(FixAccess.Offerable([dism], agent: false));
        Assert.Equal(2, FixAccess.Offerable([dism, settings], agent: true)!.Count);

        var card = new AreaCard("c", "Card", AreaLevel.Warning, "h", "m", ["A"],
            [new AreaRow(AreaLevel.Warning, ["x"], Actions: [dism]), new AreaRow(AreaLevel.Ok, ["y"], Actions: [settings])], Actions: [dism]);
        var report = new AreaReport([card], "s", DiagnosticStatus.Warning);
        var quiet = FixAccess.Offerable(report, agent: false)!.Cards[0];
        Assert.Null(quiet.Actions);
        Assert.Null(quiet.Rows[0].Actions);
        Assert.Equal([settings], quiet.Rows[1].Actions);
        Assert.Same(report, FixAccess.Offerable(report, agent: true));
    }

    [Fact]
    public void Admin_repair_hint_is_dropped_from_cards_only_when_no_agent_is_installed()
    {
        var card = new AreaCard("restore-points", "System Restore points", AreaLevel.Neutral, "h",
            "Could not read it. " + ElevationService.AdminRepairHint, ["A"], []);
        var report = new AreaReport([card], "s", DiagnosticStatus.Ok);
        Assert.Equal("Could not read it.", FixAccess.WithoutAgentHints(report, noAgent: true)!.Cards[0].Meta);
        Assert.Same(report, FixAccess.WithoutAgentHints(report, noAgent: false));
    }

    [Fact]
    public void Sensors_without_agent_report_what_was_read_without_a_warning()
    {
        var none = LibreHardwareMonitorModule.BuildReport(new SensorSnapshot([], IsElevated: false));
        Assert.Equal(DiagnosticStatus.Warning, LibreHardwareMonitorModule.ToStatus(none));
        Assert.Equal(DiagnosticStatus.Ok, LibreHardwareMonitorModule.ToStatus(none, noAgent: true));
        Assert.DoesNotContain("Admin Repair Mode", LibreHardwareMonitorModule.Summarize(none, noAgent: true));

        var some = LibreHardwareMonitorModule.BuildReport(new SensorSnapshot([
            new("AMD Ryzen 7 5700U", HardwareKind.Cpu, "Core (Tctl/Tdie)", SensorKind.Temperature, 50, 40, 60, "°C"),
        ], IsElevated: false));
        Assert.Equal("CPU 50°C", LibreHardwareMonitorModule.Summarize(some, noAgent: true));
    }

    [Fact]
    public async Task Agent_or_local_wmi_reads_locally_until_the_agent_connects()
    {
        var local = new LocalWmi();
        var r = await new AgentOrLocalWmiSource(new NotConnected(), local).QueryAsync(@"root\cimv2", "SELECT * FROM Win32_Battery", TestContext.Current.CancellationToken);
        Assert.Null(r.Error);
        Assert.Equal(1, local.Calls);
    }

    private sealed class LocalWmi : IWmiSource
    {
        public int Calls;
        public Task<WmiQueryResult> QueryAsync(string ns, string wql, CancellationToken ct = default)
        {
            Calls++;
            return Task.FromResult(new WmiQueryResult(ns, wql, []));
        }
    }

    private sealed class NotConnected : IElevatedCommandBridge
    {
        public bool IsConnected => false;
        public Task<RemotePCDiagnostics.Core.Osquery.ProcessResult?> RunElevatedAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct, Action<string>? outputLine = null) =>
            throw new InvalidOperationException("not connected");
        public Task<SensorSnapshot?> ReadSensorsAsync(CancellationToken ct = default) => throw new InvalidOperationException();
        public Task<IReadOnlyList<DriveHealth>?> ReadDrivesAsync(CancellationToken ct = default) => throw new InvalidOperationException();
        public Task<WmiQueryResult> QueryWmiAsync(string wmiNamespace, string wql, CancellationToken ct = default) => throw new InvalidOperationException("must not be asked");
    }
}
