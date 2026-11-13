namespace RemotePCDiagnostics.Agent.Core;

/// <summary>
/// Shared names for the agent install. The desktop app and the agent both use these so a status file written by the
/// service is the file the mode badge reads. The enrollment key stays in <c>agent.json</c> and is not one of the
/// files the desktop user is expected to read.
/// </summary>
public static class AgentLayout
{
    public const string ServiceName = "RemotePCDiagnosticsAgent";
    public const string InstallFolderName = "RemotePCDiagnosticsAgent";
    public const string AgentExeName = "RemotePCDiagnostics.Agent.exe";
    public const string DataFolderName = "RemotePCDiagnostics";
    public const string ConfigFileName = "agent.json";
    public const string StatusFileName = "agent-status.json";
    public const string HostWatchFileName = "agent-host.json";
    public const string AppCacheFolderName = "app";
    public const string AgentLogFileName = "RemotePCDiagnostics.Agent.log";
    public const string ConfigPathEnvVar = "RPD_AGENT_CONFIG_PATH";

    /// <summary>Inno Setup AppId, without braces. The agent MSI upgrade code is a different id and must not match.</summary>
    public const string DesktopUninstallAppId = "8F6D4A2E-5C91-4B73-9E18-3A7C2D9F41B0";
    public const string AgentMsiUpgradeCode = "D4B8E7A2-91F3-4C65-8E12-7F3A9C5D21E4";

    /// <summary>Default Store identity from <c>msix/Build-Msix.ps1</c>. Partner Center may prefix it.</summary>
    public const string DefaultMsixPackageName = "BudCribar.RemotePCDiagnostics";

    public const string RunValueName = "RemotePCDiagnosticsAgent";
    public const string ScheduledTaskName = "RemotePCDiagnostics Agent";

    public static string ProgramDataDirectory()
    {
        var customConfig = Environment.GetEnvironmentVariable(ConfigPathEnvVar)?.Trim();
        if (!string.IsNullOrEmpty(customConfig))
        {
            var parent = Path.GetDirectoryName(Path.GetFullPath(customConfig));
            if (!string.IsNullOrEmpty(parent))
                return parent;
        }
        return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), DataFolderName);
    }

    public static string ConfigPath()
    {
        var custom = Environment.GetEnvironmentVariable(ConfigPathEnvVar)?.Trim();
        if (!string.IsNullOrEmpty(custom))
            return Path.GetFullPath(custom);
        return Path.Combine(ProgramDataDirectory(), ConfigFileName);
    }

    public static string StatusPath() => Path.Combine(ProgramDataDirectory(), StatusFileName);
    public static string HostWatchPath() => Path.Combine(ProgramDataDirectory(), HostWatchFileName);
    public static string AppCacheDirectory() => Path.Combine(ProgramDataDirectory(), AppCacheFolderName);
    public static string AgentLogPath() => Path.Combine(ProgramDataDirectory(), "logs", AgentLogFileName);

    public static string DefaultInstallDirectory() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), InstallFolderName);

    public static string DefaultAgentExe() => Path.Combine(DefaultInstallDirectory(), AgentExeName);

    /// <summary>Shop slug as stored and shown. Null when it is empty or not safe to put on the badge.</summary>
    public static string? NormalizeShopGroup(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var trimmed = value.Trim().Trim('"').Trim().ToLowerInvariant();
        if (trimmed.Length is 0 or > 64) return null;
        foreach (var ch in trimmed)
        {
            if (char.IsControl(ch) || ch is '"' or '\\' or '/' or '<' or '>') return null;
        }
        return trimmed;
    }
}
