using RemotePCDiagnostics.Agent.Core;
using RemotePCDiagnostics.Core.Session;
using Xunit;

namespace RemotePCDiagnostics.Tests;

public class AgentShopPillStateTests
{
    [Fact]
    public void Connected_WithBrandingAndActiveUsers_FormatsCorrectly()
    {
        var label = AgentShopPillState.FormatLabel(SessionMode.Remote, AgentModeKind.Connected);
        Assert.Equal("Agent connected", label);

        var css = AgentShopPillState.FormatCssClass(SessionMode.Remote, AgentModeKind.Connected);
        Assert.Contains("agent-connected", css);
        Assert.Contains("badge-remote", css);

        var tooltip = AgentShopPillState.FormatTooltip(SessionMode.Remote, AgentModeKind.Connected, "Apex PC Repair", 2);
        Assert.Equal("Agent connected · Apex PC Repair · 2 Remote Users active. Click for shop details & contact info.", tooltip);
    }

    [Fact]
    public void Connected_WithBrandingAndZeroUsers_FormatsWaitingForTechnician()
    {
        var tooltip = AgentShopPillState.FormatTooltip(SessionMode.Remote, AgentModeKind.Connected, "Apex PC Repair", 0);
        Assert.Equal("Agent connected · Apex PC Repair (Waiting for technician to join). Click for shop details & contact info.", tooltip);
    }

    [Fact]
    public void Connected_WithoutBranding_FormatsCleanlyWithoutRawGroupTags()
    {
        var label = AgentShopPillState.FormatLabel(SessionMode.Remote, AgentModeKind.Connected);
        Assert.Equal("Agent connected", label);

        var tooltipWaiting = AgentShopPillState.FormatTooltip(SessionMode.Remote, AgentModeKind.Connected, null, 0);
        Assert.Equal("Agent connected (Waiting for technician to join). Click for shop details.", tooltipWaiting);

        var tooltipActive = AgentShopPillState.FormatTooltip(SessionMode.Remote, AgentModeKind.Connected, "", 1);
        Assert.Equal("Agent connected · 1 Remote User active. Click for shop details.", tooltipActive);
    }

    [Fact]
    public void Connected_ViaAgentService_WhenSessionModeIsLocal_StillReportsConnected()
    {
        var isConn = AgentShopPillState.IsConnected(SessionMode.Local, AgentModeKind.Connected);
        Assert.True(isConn);

        var label = AgentShopPillState.FormatLabel(SessionMode.Local, AgentModeKind.Connected);
        Assert.Equal("Agent connected", label);
    }

    [Fact]
    public void InstalledNotConnected_FormatsCorrectly()
    {
        var isConn = AgentShopPillState.IsConnected(SessionMode.Local, AgentModeKind.InstalledNotConnected);
        Assert.False(isConn);

        var isInstalled = AgentShopPillState.IsInstalledNotConnected(SessionMode.Local, AgentModeKind.InstalledNotConnected);
        Assert.True(isInstalled);

        var label = AgentShopPillState.FormatLabel(SessionMode.Local, AgentModeKind.InstalledNotConnected);
        Assert.Equal("Agent installed, not connected", label);

        var css = AgentShopPillState.FormatCssClass(SessionMode.Local, AgentModeKind.InstalledNotConnected);
        Assert.Contains("agent-installed", css);

        var tooltip = AgentShopPillState.FormatTooltip(SessionMode.Local, AgentModeKind.InstalledNotConnected, null, 0);
        Assert.Equal("Agent installed, not connected · Not connected to a repair shop.", tooltip);
    }

    [Fact]
    public void LocalOnly_FormatsCorrectly()
    {
        var isConn = AgentShopPillState.IsConnected(SessionMode.Local, AgentModeKind.LocalOnly);
        Assert.False(isConn);

        var label = AgentShopPillState.FormatLabel(SessionMode.Local, AgentModeKind.LocalOnly);
        Assert.Equal("Local only", label);

        var css = AgentShopPillState.FormatCssClass(SessionMode.Local, AgentModeKind.LocalOnly);
        Assert.Contains("agent-local", css);
        Assert.Contains("badge-local", css);

        var tooltip = AgentShopPillState.FormatTooltip(SessionMode.Local, AgentModeKind.LocalOnly, null, 0);
        Assert.Equal("Local only · Not connected to a repair shop.", tooltip);
    }
}
