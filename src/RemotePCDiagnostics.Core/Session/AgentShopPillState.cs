namespace RemotePCDiagnostics.Core.Session;

using RemotePCDiagnostics.Agent.Core;

/// <summary>
/// State and formatting helper for the unified top-bar agent &amp; repair shop pill.
/// Replaces separate agent mode badges and shop connection buttons with a single interactive pill.
/// </summary>
public static class AgentShopPillState
{
    public static bool IsConnected(SessionMode sessionMode, AgentModeKind agentModeKind) =>
        sessionMode == SessionMode.Remote || agentModeKind == AgentModeKind.Connected;

    public static bool IsInstalledNotConnected(SessionMode sessionMode, AgentModeKind agentModeKind) =>
        !IsConnected(sessionMode, agentModeKind) && agentModeKind == AgentModeKind.InstalledNotConnected;

    public static string FormatLabel(SessionMode sessionMode, AgentModeKind agentModeKind) =>
        IsConnected(sessionMode, agentModeKind) ? "Agent connected" :
        IsInstalledNotConnected(sessionMode, agentModeKind) ? "Agent installed, not connected" :
        "Local only";

    public static string FormatCssClass(SessionMode sessionMode, AgentModeKind agentModeKind) =>
        IsConnected(sessionMode, agentModeKind) ? "agent-connected badge badge-remote" :
        IsInstalledNotConnected(sessionMode, agentModeKind) ? "agent-installed badge" :
        "agent-local badge badge-local";

    public static string FormatTooltip(
        SessionMode sessionMode,
        AgentModeKind agentModeKind,
        string? brandName,
        int remoteUserCount)
    {
        if (IsConnected(sessionMode, agentModeKind))
        {
            if (!string.IsNullOrWhiteSpace(brandName))
            {
                return remoteUserCount > 0
                    ? $"Agent connected · {brandName.Trim()} · {RemoteUsers.Label(remoteUserCount)} active. Click for shop details & contact info."
                    : $"Agent connected · {brandName.Trim()} (Waiting for technician to join). Click for shop details & contact info.";
            }

            return remoteUserCount > 0
                ? $"Agent connected · {RemoteUsers.Label(remoteUserCount)} active. Click for shop details."
                : "Agent connected (Waiting for technician to join). Click for shop details.";
        }

        if (IsInstalledNotConnected(sessionMode, agentModeKind))
        {
            return "Agent installed, not connected · Not connected to a repair shop.";
        }

        return "Local only · Not connected to a repair shop.";
    }
}
