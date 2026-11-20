namespace RemotePCDiagnostics.Core.Session;

using RemotePCDiagnostics.Agent.Core;

/// <summary>
/// State and formatting helper for the unified top-bar agent &amp; repair shop pill.
/// Replaces separate agent mode badges and shop connection buttons with a single interactive pill.
/// Linked to a shop but nobody has joined yet reads "Waiting for agent"; it reads "Agent connected" only once a
/// technician or AI agent has actually opened the session (a remote page is attached).
/// </summary>
public static class AgentShopPillState
{
    /// <summary>This PC is linked to a repair shop (a remote session is up, or the agent service is connected).</summary>
    public static bool IsConnected(SessionMode sessionMode, AgentModeKind agentModeKind) =>
        sessionMode == SessionMode.Remote || agentModeKind == AgentModeKind.Connected;

    /// <summary>Linked to a shop and at least one technician or AI agent has joined the session.</summary>
    public static bool IsAgentJoined(SessionMode sessionMode, AgentModeKind agentModeKind, int remoteUserCount) =>
        IsConnected(sessionMode, agentModeKind) && remoteUserCount > 0;

    public static bool IsInstalledNotConnected(SessionMode sessionMode, AgentModeKind agentModeKind) =>
        !IsConnected(sessionMode, agentModeKind) && agentModeKind == AgentModeKind.InstalledNotConnected;

    public static string FormatLabel(SessionMode sessionMode, AgentModeKind agentModeKind, int remoteUserCount) =>
        IsAgentJoined(sessionMode, agentModeKind, remoteUserCount) ? "Agent connected" :
        IsConnected(sessionMode, agentModeKind) ? "Waiting for agent" :
        IsInstalledNotConnected(sessionMode, agentModeKind) ? "Agent installed, not connected" :
        "Local only";

    public static string FormatCssClass(SessionMode sessionMode, AgentModeKind agentModeKind, int remoteUserCount) =>
        IsAgentJoined(sessionMode, agentModeKind, remoteUserCount) ? "agent-connected badge badge-remote" :
        IsConnected(sessionMode, agentModeKind) ? "agent-connected agent-waiting badge badge-remote" :
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
            var label = FormatLabel(sessionMode, agentModeKind, remoteUserCount);
            var shop = string.IsNullOrWhiteSpace(brandName) ? "" : $" · {brandName.Trim()}";
            var users = remoteUserCount > 0 ? $" · {RemoteUsers.Label(remoteUserCount)} active" : "";
            var click = string.IsNullOrWhiteSpace(brandName)
                ? "Click for shop details."
                : "Click for shop details & contact info.";
            return $"{label}{shop}{users}. {click}";
        }

        if (IsInstalledNotConnected(sessionMode, agentModeKind))
        {
            return "Agent installed, not connected · Not connected to a repair shop.";
        }

        return "Local only · Not connected to a repair shop.";
    }
}
