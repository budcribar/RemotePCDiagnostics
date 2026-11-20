using RemotePCDiagnostics.Agent.Core;
using RemotePCDiagnostics.Core.Session;
using Xunit;

namespace RemotePCDiagnostics.Tests;

public class AgentShopPillStateTests
{
    [Fact]
    public void AgentJoined_WithBrandingAndActiveUsers_ReadsAgentConnected()
    {
        var label = AgentShopPillState.FormatLabel(SessionMode.Remote, AgentModeKind.Connected, 2);
        Assert.Equal("Agent connected", label);

        var css = AgentShopPillState.FormatCssClass(SessionMode.Remote, AgentModeKind.Connected, 2);
        Assert.Contains("agent-connected", css);
        Assert.Contains("badge-remote", css);
        Assert.DoesNotContain("agent-waiting", css);

        var tooltip = AgentShopPillState.FormatTooltip(SessionMode.Remote, AgentModeKind.Connected, "Apex PC Repair", 2);
        Assert.Equal("Agent connected · Apex PC Repair · 2 Remote Users active. Click for shop details & contact info.", tooltip);
    }

    [Fact]
    public void ShopLinked_NobodyJoined_ReadsWaitingForAgent()
    {
        Assert.True(AgentShopPillState.IsConnected(SessionMode.Remote, AgentModeKind.Connected));
        Assert.False(AgentShopPillState.IsAgentJoined(SessionMode.Remote, AgentModeKind.Connected, 0));

        var label = AgentShopPillState.FormatLabel(SessionMode.Remote, AgentModeKind.Connected, 0);
        Assert.Equal("Waiting for agent", label);

        var css = AgentShopPillState.FormatCssClass(SessionMode.Remote, AgentModeKind.Connected, 0);
        Assert.Contains("agent-waiting", css);

        var tooltip = AgentShopPillState.FormatTooltip(SessionMode.Remote, AgentModeKind.Connected, "Apex PC Repair", 0);
        Assert.Equal("Waiting for agent · Apex PC Repair. Click for shop details & contact info.", tooltip);
    }

    [Fact]
    public void WithoutBranding_FormatsCleanlyWithoutRawGroupTags()
    {
        var tooltipWaiting = AgentShopPillState.FormatTooltip(SessionMode.Remote, AgentModeKind.Connected, null, 0);
        Assert.Equal("Waiting for agent. Click for shop details.", tooltipWaiting);

        var tooltipActive = AgentShopPillState.FormatTooltip(SessionMode.Remote, AgentModeKind.Connected, "", 1);
        Assert.Equal("Agent connected · 1 Remote User active. Click for shop details.", tooltipActive);
    }

    [Fact]
    public void ConnectedViaAgentService_WhenSessionModeIsLocal_WaitsUntilSomeoneJoins()
    {
        Assert.True(AgentShopPillState.IsConnected(SessionMode.Local, AgentModeKind.Connected));
        Assert.Equal("Waiting for agent", AgentShopPillState.FormatLabel(SessionMode.Local, AgentModeKind.Connected, 0));
        Assert.Equal("Agent connected", AgentShopPillState.FormatLabel(SessionMode.Local, AgentModeKind.Connected, 1));
    }

    [Fact]
    public void RemoteUsersWithoutShopLink_DoNotReadAgentConnected()
    {
        Assert.False(AgentShopPillState.IsAgentJoined(SessionMode.Local, AgentModeKind.LocalOnly, 3));
        Assert.Equal("Local only", AgentShopPillState.FormatLabel(SessionMode.Local, AgentModeKind.LocalOnly, 3));
    }

    [Fact]
    public void InstalledNotConnected_FormatsCorrectly()
    {
        var isConn = AgentShopPillState.IsConnected(SessionMode.Local, AgentModeKind.InstalledNotConnected);
        Assert.False(isConn);

        var isInstalled = AgentShopPillState.IsInstalledNotConnected(SessionMode.Local, AgentModeKind.InstalledNotConnected);
        Assert.True(isInstalled);

        var label = AgentShopPillState.FormatLabel(SessionMode.Local, AgentModeKind.InstalledNotConnected, 0);
        Assert.Equal("Agent installed, not connected", label);

        var css = AgentShopPillState.FormatCssClass(SessionMode.Local, AgentModeKind.InstalledNotConnected, 0);
        Assert.Contains("agent-installed", css);

        var tooltip = AgentShopPillState.FormatTooltip(SessionMode.Local, AgentModeKind.InstalledNotConnected, null, 0);
        Assert.Equal("Agent installed, not connected · Not connected to a repair shop.", tooltip);
    }

    [Fact]
    public void LocalOnly_FormatsCorrectly()
    {
        var isConn = AgentShopPillState.IsConnected(SessionMode.Local, AgentModeKind.LocalOnly);
        Assert.False(isConn);

        var label = AgentShopPillState.FormatLabel(SessionMode.Local, AgentModeKind.LocalOnly, 0);
        Assert.Equal("Local only", label);

        var css = AgentShopPillState.FormatCssClass(SessionMode.Local, AgentModeKind.LocalOnly, 0);
        Assert.Contains("agent-local", css);
        Assert.Contains("badge-local", css);

        var tooltip = AgentShopPillState.FormatTooltip(SessionMode.Local, AgentModeKind.LocalOnly, null, 0);
        Assert.Equal("Local only · Not connected to a repair shop.", tooltip);
    }
}
