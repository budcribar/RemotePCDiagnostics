using System.Globalization;
using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Core.Memory;

/// <summary>Physical memory and commit charge at one moment.</summary>
public sealed record MemoryReading(long TotalBytes, long AvailableBytes, long? CommitBytes = null, long? CommitLimitBytes = null)
{
    public long UsedBytes => Math.Max(0, TotalBytes - AvailableBytes);
    public int UsedPercent => TotalBytes <= 0 ? 0 : (int)Math.Round(100.0 * UsedBytes / TotalBytes);
}

/// <summary>All running processes with the same executable name, combined.</summary>
/// <param name="Name">Process name without ".exe" (e.g. "chrome").</param>
/// <param name="HasWindow">At least one instance has a visible main window (a user app the person can see).</param>
/// <param name="IsService">At least one instance hosts a Windows service.</param>
public sealed record AppUsage(string Name, int Instances, long MemoryBytes, bool HasWindow = false, bool IsService = false, TimeSpan? RunningFor = null, string? FriendlyName = null)
{
    public string Label => FriendlyName ?? MemoryText.FriendlyAppName(Name);
}

public enum BrowserKind { Chrome, Edge }

/// <summary>Browser memory-saving state read from its Local State file (null = setting not found / unknown).</summary>
public sealed record BrowserInfo(BrowserKind Kind, bool Installed, bool Running, bool? MemorySaverOn, bool CanWrite);

public sealed record VsExtension(string Name, long SizeBytes);

public sealed record VisualStudioInfo(bool LiveShareInstalled, IReadOnlyList<VsExtension> Extensions);

/// <summary>A per-user Run-key startup app (HKCU\...\Run) and its Task Manager enabled state (StartupApproved).</summary>
public sealed record StartupEntry(string Name, string Command, bool Enabled)
{
    public string ExeName => StartupParsing.ExeName(Command);
}

/// <summary>A running service with the memory of its hosting process.</summary>
/// <param name="ProcessMemoryBytes">Working set of the hosting process (null = unknown).</param>
/// <param name="ServicesInProcess">How many services share that process (svchost groups); &gt;1 means memory can't be attributed exactly.</param>
public sealed record ServiceUsage(ServiceInfo Info, long? ProcessMemoryBytes, int ServicesInProcess = 1)
{
    public bool Shared => ServicesInProcess > 1;
}

/// <summary>Hardware facts used to decide whether a service is needed (null = unknown, so the service isn't suggested).</summary>
public sealed record DeviceFacts(bool? HasPrinter = null, bool? HasBluetoothDevices = null, bool? HasFingerprintReader = null);

/// <summary>Everything the suggestion engine looks at. Built by the Host; tests build it by hand.</summary>
public sealed record MemorySnapshot(
    MemoryReading Memory,
    IReadOnlyList<AppUsage> Apps,
    TimeSpan? Uptime = null,
    bool? FastStartup = null,
    IReadOnlyList<BrowserInfo>? Browsers = null,
    VisualStudioInfo? VisualStudio = null,
    IReadOnlyList<StartupEntry>? Startup = null,
    IReadOnlyList<ServiceUsage>? Services = null,
    DeviceFacts? Devices = null)
{
    public AppUsage? App(string name) => Apps.FirstOrDefault(a => a.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
}

public enum SuggestionKind { Automated, Guided, Info }
public enum SuggestionRisk { Low, Medium, High }

public enum MemoryActionType
{
    CloseApp, ForceCloseApp, ShutdownBuildServers, DisableStartup, EnableBrowserMemorySaver, OpenSettings,
    StopService, SetServiceManual, SetServiceDisabled,
}

/// <summary>One button on a suggestion card. <see cref="Confirm"/> non-null = ask once inline before running.</summary>
public sealed record MemoryAction(MemoryActionType Type, string Target, string Label, string? Confirm = null);

public sealed record MemorySuggestion(
    string Id, string Title, string Why, long? SavingBytes, SuggestionRisk Risk, SuggestionKind Kind,
    IReadOnlyList<string> Steps, IReadOnlyList<MemoryAction> Actions, string Category = "General", string? Note = null);

public static class MemoryText
{
    public static string Size(long bytes) => bytes >= 1L << 30
        ? (bytes / (double)(1L << 30)).ToString("0.0", CultureInfo.InvariantCulture) + " GB"
        : Math.Max(0, bytes / (1L << 20)).ToString(CultureInfo.InvariantCulture) + " MB";

    public static string Gb(long bytes) => (bytes / (double)(1L << 30)).ToString("0.0", CultureInfo.InvariantCulture);

    public static string Plural(int n, string one, string? many = null) => n == 1 ? $"1 {one}" : $"{n} {many ?? one + "s"}";

    private static readonly Dictionary<string, string> Friendly = new(StringComparer.OrdinalIgnoreCase)
    {
        ["chrome"] = "Chrome", ["msedge"] = "Microsoft Edge", ["firefox"] = "Firefox", ["devenv"] = "Visual Studio",
        ["Code"] = "VS Code", ["slack"] = "Slack", ["ms-teams"] = "Microsoft Teams", ["Teams"] = "Microsoft Teams",
        ["Discord"] = "Discord", ["Spotify"] = "Spotify", ["ChatGPT"] = "ChatGPT", ["Grok"] = "Grok", ["Antigravity"] = "Antigravity",
        ["OUTLOOK"] = "Outlook", ["olk"] = "Outlook", ["WINWORD"] = "Word", ["EXCEL"] = "Excel", ["POWERPNT"] = "PowerPoint",
        ["MsMpEng"] = "Microsoft Defender", ["VBCSCompiler"] = "C# compiler server", ["MSBuild"] = "MSBuild",
        ["Memory Compression"] = "Memory compression", ["Zoom"] = "Zoom", ["steam"] = "Steam", ["OneDrive"] = "OneDrive",
        ["claude"] = "Claude", ["PhoneExperienceHost"] = "Phone Link", ["msedgewebview2"] = "Edge WebView2",
        ["Grok Bot"] = "Grok", ["notepad"] = "Notepad", ["explorer"] = "File Explorer",
    };

    /// <summary>Known apps get their product name; other all-lowercase process names are capitalized ("claude" → "Claude").</summary>
    public static string FriendlyAppName(string processName)
    {
        if (string.IsNullOrEmpty(processName)) return processName;
        if (Friendly.TryGetValue(processName, out var f)) return f;
        return processName.All(c => !char.IsLetter(c) || char.IsLower(c)) && char.IsLetter(processName[0])
            ? char.ToUpperInvariant(processName[0]) + processName[1..] : processName;
    }
}

public static class StartupParsing
{
    /// <summary>Executable file name (without extension) from a Run-key command line, e.g. "\"C:\\x\\Slack.exe\" --startup" → "Slack".</summary>
    public static string ExeName(string command)
    {
        var c = (command ?? "").Trim();
        if (c.Length == 0) return "";
        string path;
        if (c[0] == '"')
        {
            var end = c.IndexOf('"', 1);
            path = end > 0 ? c[1..end] : c[1..];
        }
        else
        {
            var exe = c.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
            path = exe > 0 ? c[..(exe + 4)] : c.Split(' ', 2)[0];
        }
        var file = path.Replace('/', '\\').Split('\\').Last();
        return file.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? file[..^4] : file;
    }

    /// <summary>Task Manager's StartupApproved value: first byte even (02/06) = enabled, odd (03/07) = disabled; missing = enabled.</summary>
    public static bool IsEnabled(byte[]? approved) => approved is null || approved.Length == 0 || (approved[0] & 1) == 0;

    /// <summary>The 12-byte StartupApproved value Task Manager writes when you disable an app (03 00 00 00 + FILETIME).</summary>
    public static byte[] DisabledValue(DateTime utcNow)
    {
        var v = new byte[12];
        v[0] = 3;
        BitConverter.GetBytes(utcNow.ToFileTimeUtc()).CopyTo(v, 4);
        return v;
    }
}
