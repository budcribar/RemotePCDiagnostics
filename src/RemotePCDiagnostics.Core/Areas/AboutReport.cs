using System.Diagnostics;
using System.Runtime.Versioning;
using System.Globalization;
using System.ServiceProcess;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using RemotePCDiagnostics.Agent.Core;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>
/// Facts the About page can show a remote mirror (docs/agent-guides/browser-contract.md, <c>about-report-data</c>).
/// Unknown facts are null. The enrollment key, shop API key, relay URL and contact details are never fields of this report.
/// </summary>
public sealed record AboutReportInput
{
    public string? AppVersion { get; init; }
    public string? InformationalVersion { get; init; }
    public string? ProcessArchitecture { get; init; }
    public string? OsArchitecture { get; init; }
    public string? OsVersion { get; init; }
    public string? MachineName { get; init; }
    public SessionMode SessionMode { get; init; } = SessionMode.Local;
    public bool AgentConnected { get; init; }
    public string? AgentVersion { get; init; }
    public string? AgentServiceStatus { get; init; }
    public string? ShopGroup { get; init; }
    public string? ShopName { get; init; }
    public string? AgentId { get; init; }
    public string? InstallPath { get; init; }
    /// <summary>Used only to mask <see cref="InstallPath"/>. Not written to the report.</summary>
    public string? UserName { get; init; }
    /// <summary>Used only to mask <see cref="InstallPath"/>. Not written to the report.</summary>
    public string? UserProfile { get; init; }
    public DateTimeOffset? LastUpdateCheck { get; init; }
    public bool UpdateAvailable { get; init; }
    public string? LatestVersion { get; init; }
    public string? UpdateError { get; init; }
}

/// <summary>What the agent install can tell the desktop app without opening the enrollment key.</summary>
public sealed record AboutMachineFacts(string? AgentVersion, string? AgentServiceStatus, string? AgentId, string? ShopGroup)
{
    public static AboutMachineFacts Empty { get; } = new(null, null, null, null);

    /// <summary>
    /// Reads the installed agent executable's version, the Windows service state, and the public enrollment facts
    /// (<c>machineId</c> and <c>group</c> only). A missing file or a failed query is null, not an error.
    /// </summary>
    public static AboutMachineFacts Read(string? agentExePath = null, string? configPath = null, Func<string?>? serviceStatus = null)
    {
        var enrollment = ReadEnrollment(ReadText(configPath ?? AgentLayout.ConfigPath()));
        return enrollment with
        {
            AgentVersion = ReadVersion(agentExePath ?? AgentLayout.DefaultAgentExe()),
            AgentServiceStatus = ReadServiceStatus(serviceStatus),
        };
    }

    /// <summary>Parses agent.json for the machine id and shop group. The key and the server URL are ignored.</summary>
    public static AboutMachineFacts ReadEnrollment(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return Empty;
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return Empty;
            string? id = null;
            if (doc.RootElement.TryGetProperty("machineId", out var mid) && mid.ValueKind == JsonValueKind.String
                && Guid.TryParse(mid.GetString(), out var guid) && guid != Guid.Empty)
                id = guid.ToString("D");
            string? group = null;
            if (doc.RootElement.TryGetProperty("group", out var g) && g.ValueKind == JsonValueKind.String)
                group = AgentLayout.NormalizeShopGroup(g.GetString());
            return new(null, null, id, group);
        }
        catch (JsonException)
        {
            return Empty;
        }
    }

    private static string? ReadText(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            return File.ReadAllText(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static string? ReadVersion(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            var info = FileVersionInfo.GetVersionInfo(path);
            var version = string.IsNullOrWhiteSpace(info.ProductVersion) ? info.FileVersion : info.ProductVersion;
            return AreaReportExport.Text(version, 120);
        }
        catch
        {
            return null;
        }
    }

    private static string? ReadServiceStatus(Func<string?>? serviceStatus)
    {
        if (serviceStatus is not null)
        {
            try { return CleanStatus(serviceStatus()); }
            catch { return null; }
        }
        if (!OperatingSystem.IsWindows()) return null;
        return ReadWindowsServiceStatus();
    }

    [SupportedOSPlatform("windows")]
    private static string? ReadWindowsServiceStatus()
    {
        try
        {
            using var controller = new ServiceController(AgentLayout.ServiceName);
            return CleanStatus(controller.Status.ToString());
        }
        catch (InvalidOperationException)
        {
            return "Not installed";
        }
        catch
        {
            return null;
        }
    }

    /// <summary>Service Controller status names, plus "Not installed". Anything else (a path, an error) is unknown.</summary>
    private static string? CleanStatus(string? status)
    {
        var text = AreaReportExport.Text(status, 40);
        return text is "Running" or "Stopped" or "StartPending" or "StopPending" or "ContinuePending" or "PausePending" or "Paused" or "Not installed"
            ? text : null;
    }
}

/// <summary>Schema 1 JSON for <c>[data-testid="about-report-data"]</c>.</summary>
public static class AboutReport
{
    public const int SchemaVersion = 1;

    /// <summary>Route and <c>data-rpcd-page</c> value. Admin opens it by clicking <c>nav-about</c>, the same way it opens <c>interactive</c>.</summary>
    public const string NavigationTarget = "about";

    public const string ReportTestId = "about-report-data";

    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
    };

    public static string ChannelFor(string? informationalVersion) =>
        AppVersionComparer.DefaultChannelFor(informationalVersion) == AppUpdateChannel.Prerelease ? "prerelease" : "stable";

    /// <summary><c>local</c> for a session at the PC, <c>agent</c> for a session the agent opened (<see cref="SessionMode.Remote"/>).</summary>
    public static string ModeFor(SessionMode mode) => mode == SessionMode.Remote ? "agent" : "local";

    /// <summary>The first shop group that is safe to show. Later candidates fill in only when earlier ones are empty.</summary>
    public static string? FirstShopGroup(params string?[] candidates)
    {
        foreach (var candidate in candidates)
        {
            var group = AgentLayout.NormalizeShopGroup(candidate);
            if (group is not null) return group;
        }
        return null;
    }

    /// <summary>
    /// Hides the Windows or Linux account name in an install path. The profile prefix becomes <c>%USERPROFILE%</c>,
    /// and a <c>Users</c> or <c>home</c> directory's next folder becomes <c>&lt;user&gt;</c>.
    /// </summary>
    public static string? MaskInstallPath(string? path, string? userName = null, string? userProfile = null)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        var text = path.Trim().TrimEnd('\\', '/');
        if (text.Length == 0) return null;

        var profile = userProfile?.Trim().TrimEnd('\\', '/');
        if (!string.IsNullOrEmpty(profile) && profile.Length >= 3
            && text.StartsWith(profile, StringComparison.OrdinalIgnoreCase)
            && (text.Length == profile.Length || text[profile.Length] is '\\' or '/'))
            text = "%USERPROFILE%" + text[profile.Length..];

        text = MaskHomeFolder(text, "Users");
        text = MaskHomeFolder(text, "home");
        if (!string.IsNullOrEmpty(userName) && userName.Length >= 3 && userName.IndexOfAny(['\\', '/', '<', '>', ':']) < 0)
            text = ReplacePathSegment(text, userName, "<user>");
        return AreaReportExport.Text(text, AreaReportExport.MaxTextLength);
    }

    public static string ToJson(AboutReportInput input)
    {
        var informational = Public(input.InformationalVersion, 200);
        var checkedAt = input.LastUpdateCheck;
        var document = new AboutReportDocument(
            SchemaVersion,
            Public(input.AppVersion, 80),
            informational,
            informational,
            ChannelFor(input.InformationalVersion),
            new AboutArchitecture(Public(input.ProcessArchitecture, 32), Public(input.OsArchitecture, 32)),
            Public(input.AgentVersion, 120),
            AllowedServiceStatus(input.AgentServiceStatus),
            input.AgentConnected,
            ModeFor(input.SessionMode),
            new AboutShop(AgentLayout.NormalizeShopGroup(input.ShopGroup), Public(input.ShopName, 120), AgentId(input.AgentId)),
            Public(input.MachineName, 80),
            Public(input.OsVersion, 200),
            MaskInstallPath(input.InstallPath, input.UserName, input.UserProfile),
            checkedAt?.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture),
            checkedAt is null ? null : new AboutUpdate(input.UpdateAvailable, Public(input.LatestVersion, 80), Public(input.UpdateError, 200)));
        return JsonSerializer.Serialize(document, Json);
    }

    private static string? AllowedServiceStatus(string? status)
    {
        var text = AreaReportExport.Text(status, 40);
        return text is "Running" or "Stopped" or "StartPending" or "StopPending" or "ContinuePending" or "PausePending" or "Paused" or "Not installed"
            ? text : null;
    }

    private static string? AgentId(string? value) =>
        Guid.TryParse(value, out var id) && id != Guid.Empty ? id.ToString("D") : null;

    /// <summary>Drops blank text, shop API keys and URLs so a secret cannot ride along in a name or a version.</summary>
    private static string? Public(string? value, int max)
    {
        var text = AreaReportExport.Text(value, max);
        if (text is null) return null;
        if (text.Contains("rpd_live", StringComparison.OrdinalIgnoreCase)) return null;
        if (text.Contains("://", StringComparison.Ordinal)) return null;
        return text;
    }

    private static string MaskHomeFolder(string text, string folder)
    {
        var sb = new StringBuilder(text.Length);
        var i = 0;
        while (i < text.Length)
        {
            var idx = IndexOfFolder(text, folder, i);
            if (idx < 0)
            {
                sb.Append(text, i, text.Length - i);
                break;
            }
            var nameStart = idx + 1 + folder.Length + 1;
            if (nameStart > text.Length)
            {
                sb.Append(text, i, text.Length - i);
                break;
            }
            var nameEnd = nameStart;
            while (nameEnd < text.Length && text[nameEnd] is not ('\\' or '/')) nameEnd++;
            sb.Append(text, i, nameStart - i);
            if (nameEnd > nameStart) sb.Append("<user>");
            i = nameEnd;
        }
        return sb.ToString();
    }

    private static int IndexOfFolder(string text, string folder, int start)
    {
        var needle = folder.Length;
        for (var i = start; i < text.Length; i++)
        {
            if (text[i] is not ('\\' or '/')) continue;
            var folderStart = i + 1;
            if (folderStart + needle >= text.Length) return -1;
            if (!text.AsSpan(folderStart, needle).Equals(folder, StringComparison.OrdinalIgnoreCase)) continue;
            if (text[folderStart + needle] is not ('\\' or '/')) continue;
            return i;
        }
        return -1;
    }

    private static string ReplacePathSegment(string text, string segment, string replacement)
    {
        var sb = new StringBuilder(text.Length);
        var start = 0;
        for (var i = 0; i <= text.Length; i++)
        {
            if (i != text.Length && text[i] is not ('\\' or '/')) continue;
            var part = text[start..i];
            sb.Append(part.Equals(segment, StringComparison.OrdinalIgnoreCase) ? replacement : part);
            if (i < text.Length) sb.Append(text[i]);
            start = i + 1;
        }
        return sb.ToString();
    }

    private sealed record AboutReportDocument(
        int Schema,
        string? AppVersion,
        string? InformationalVersion,
        string? Build,
        string Channel,
        AboutArchitecture Architecture,
        string? AgentVersion,
        string? AgentServiceStatus,
        bool AgentConnected,
        string Mode,
        AboutShop Shop,
        string? MachineName,
        string? OsVersion,
        string? InstallPath,
        string? LastUpdateCheck,
        AboutUpdate? LastUpdateResult);

    private sealed record AboutArchitecture(string? Process, string? Os);

    private sealed record AboutShop(string? Group, string? Name, string? AgentId);

    private sealed record AboutUpdate(bool UpdateAvailable, string? LatestVersion, string? Error);
}
