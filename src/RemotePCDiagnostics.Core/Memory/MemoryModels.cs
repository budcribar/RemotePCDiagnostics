using System.Globalization;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;

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

public enum StartupScope { CurrentUser, LocalMachine, LocalMachine32, PackagedUwp }

/// <summary>A startup app (HKCU/HKLM/WOW6432Node Run key or packaged UWP StartupTask) and its enabled state.</summary>
public sealed record StartupEntry(string Name, string Command, bool Enabled, StartupScope Scope = StartupScope.CurrentUser)
{
    public string ExeName => Scope == StartupScope.PackagedUwp ? StartupParsing.UwpAppName(Name, Command) : StartupParsing.ExeName(Command);
}

/// <summary>A running service with the memory of its hosting process.</summary>
/// <param name="ProcessMemoryBytes">Working set of the hosting process (null = unknown).</param>
/// <param name="ServicesInProcess">How many services share that process (svchost groups); &gt;1 means memory can't be attributed exactly.</param>
/// <param name="UsersCanStart">The service's security descriptor lets a signed-in, non-admin user start it (null = not read / unknown).
/// Read by the Host only for <see cref="AiVmServices"/>.</param>
public sealed record ServiceUsage(ServiceInfo Info, long? ProcessMemoryBytes, int ServicesInProcess = 1, bool? UsersCanStart = null)
{
    public bool Shared => ServicesInProcess > 1;
}

/// <summary>Hardware facts used to decide whether a service or app is needed (null = unknown, so the service isn't suggested).</summary>
/// <param name="HasClassicOutlook">Classic Outlook (OUTLOOK.EXE, which searches through the Windows Search index) is installed. New Outlook (olk.exe) doesn't count.</param>
public sealed record DeviceFacts(
    bool? HasPrinter = null,
    bool? HasBluetoothDevices = null,
    bool? HasFingerprintReader = null,
    bool? HasPenDigitizer = null,
    bool? HasPairedCrossDevice = null,
    bool? HasNetworkOrWsdPrinter = null,
    bool? HasLocalPdfPrinter = null,
    bool? HasClassicOutlook = null);

/// <summary>Reads Office Click-to-Run's product list (registry values, read by the Host) to tell whether classic Outlook is part of it.</summary>
public static class ClassicOutlook
{
    /// <summary>Click-to-Run products that never include Outlook (single apps, Visio, Project, Home &amp; Student, language packs).</summary>
    private static readonly string[] NoOutlookProducts =
        ["HomeStudent", "Visio", "Project", "Word", "Excel", "PowerPoint", "OneNote", "Access", "Publisher", "Language", "Proofing", "SkypeForBusiness", "Lync", "Teams", "OneDrive", "Groove"];

    /// <summary>
    /// <paramref name="productReleaseIds"/> = <c>ClickToRun\Configuration\ProductReleaseIds</c> (comma list, e.g. "O365ProPlusRetail,VisioProRetail");
    /// <paramref name="excludedApps"/> = that product's <c>&lt;id&gt;.ExcludedApps</c> value. Unknown products count as including Outlook.
    /// </summary>
    public static bool InClickToRun(string? productReleaseIds, Func<string, string?> excludedApps) =>
        (productReleaseIds ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Any(id =>
            (id.Contains("Outlook", StringComparison.OrdinalIgnoreCase) || !NoOutlookProducts.Any(n => id.Contains(n, StringComparison.OrdinalIgnoreCase)))
            && !(excludedApps(id) ?? "").Split(',', StringSplitOptions.TrimEntries).Contains("outlook", StringComparer.OrdinalIgnoreCase));
}

/// <summary>A removable cache or bloatware item discovered on disk with its exact measured byte size.</summary>
public sealed record StorageCleanupItem(string Id, string Title, string Description, long SizeBytes, bool AutoCheckedByDefault = true, string Category = "Storage");

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
    DeviceFacts? Devices = null,
    bool? TransparencyOn = null,
    bool? AutoPageFile = null,
    MemorySlots? Slots = null,
    BrowserKind? DefaultBrowser = null,
    DefenderInfo? Defender = null,
    WindowsFeedsInfo? Feeds = null,
    HibernateInfo? Hibernate = null,
    OfficeStartInfo? OfficeStart = null, DefaultPrinterInfo? DefaultPrinter = null, OfficePrivacyInfo? OfficePrivacy = null, BrowserExtensionsInfo? Extensions = null, IReadOnlyList<BrowserBackgroundInfo>? BrowserBackground = null, AppRemovalInfo? RemovableApps = null)
{
    public AppUsage? App(string name) => Apps.FirstOrDefault(a => a.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
}

/// <summary>Memory slots from Windows (SMBIOS): how many there are, how many are filled, and the most the board supports.</summary>
public sealed record MemorySlots(int Total, int Used, long? MaxCapacityBytes, long? InstalledBytes)
{
    public int Free => Math.Max(0, Total - Used);

    /// <summary>"1 of 2 memory slots used · up to 32 GB supported. …" (laptops often have soldered memory, so it's a hint to check).</summary>
    public string Text
    {
        get
        {
            if (Total <= 0) return "";
            var max = MaxCapacityBytes is long m and > 0 ? $" · up to {MemoryText.Size(m)} supported" : "";
            var tail = Free > 0
                ? " A free slot means more memory can usually be added (check the PC model's specs; some laptops have memory soldered on)."
                : " All slots are in use, so adding memory means replacing a module with a bigger one (if the PC allows it).";
            return $"{Used} of {Total} memory slot{(Total == 1 ? "" : "s")} used{max}.{tail}";
        }
    }
}

/// <summary>Parses the Host's one-shot CIM probe: page file mode and memory slots.</summary>
public static class MemoryProbe
{
    public const string Script =
        "$ErrorActionPreference='SilentlyContinue';" +
        "$c=Get-CimInstance Win32_ComputerSystem;" +
        "$a=@(Get-CimInstance Win32_PhysicalMemoryArray | Where-Object { $_.Use -eq 3 });" +
        "$m=@(Get-CimInstance Win32_PhysicalMemory);" +
        "[pscustomobject]@{Auto=[string]$c.AutomaticManagedPagefile;Slots=[string](($a | Measure-Object MemoryDevices -Sum).Sum);" +
        "Used=[string]$m.Count;MaxKB=[string](($a | Measure-Object MaxCapacityEx -Sum).Sum);Installed=[string](($m | Measure-Object Capacity -Sum).Sum)} | ConvertTo-Json -Compress";

    public const string EnableAutoPageFileScript =
        "$ErrorActionPreference='Stop';$c=Get-CimInstance Win32_ComputerSystem;Set-CimInstance -InputObject $c -Property @{AutomaticManagedPagefile=$true}";

    public static (bool? AutoPageFile, MemorySlots? Slots) Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return (null, null);
        try
        {
            var row = OsqueryJson.ParseRows("[" + json.Trim().TrimStart('[').TrimEnd(']') + "]").FirstOrDefault();
            if (row is null) return (null, null);
            bool? auto = row.Str("Auto") switch { "True" => true, "False" => false, _ => null };
            var total = (int)(row.Long("Slots") ?? 0);
            var used = (int)(row.Long("Used") ?? 0);
            MemorySlots? slots = total > 0 ? new(total, Math.Min(used, total), row.Long("MaxKB") is long kb and > 0 ? kb * 1024 : null, row.Long("Installed")) : null;
            return (auto, slots);
        }
        catch (FormatException) { return (null, null); }
    }
}

public enum SuggestionKind { Automated, Guided, Info }
public enum SuggestionRisk { Low, Medium, High }

public enum MemoryActionType
{
    CloseApp, ForceCloseApp, ShutdownBuildServers, DisableStartup, EnableBrowserMemorySaver, OpenSettings,
    StopService, SetServiceManual, SetServiceDisabled,
    RestartPc, DisableFastStartup, DisableTransparency, AutoManagePageFile,
    AddDefenderExclusions, DisableWidgets, DisableSearchHighlights, ReduceHibernateFile,
    SkipOfficeStartScreen,
    SetPdfDefaultPrinter,
    DisableOfficeOptionalExperiences,
    ShutdownWsl,
    BlockBrowserExtension,
    StopBrowserBackground,
    RemoveApp, RemoveXboxApps, StopSilentAppInstalls,
    /// <summary>Deletes one storage cleanup category (Target = its id in <see cref="Storage.StorageCleanupCatalog"/>). Permanent.</summary>
    CleanStorage,
}

/// <summary>One button on a suggestion card. <see cref="Confirm"/> non-null = ask once inline before running.</summary>
public sealed record MemoryAction(MemoryActionType Type, string Target, string Label, string? Confirm = null);

/// <param name="DefaultOn">False = opt-in: the service workflow lists its fix unticked.</param>
public sealed record MemorySuggestion(
    string Id, string Title, string Why, long? SavingBytes, SuggestionRisk Risk, SuggestionKind Kind,
    IReadOnlyList<string> Steps, IReadOnlyList<MemoryAction> Actions, string Category = "General", string? Note = null, bool DefaultOn = true);

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
        ["Code"] = "VS Code", ["slack"] = "Slack", ["ms-teams"] = "Microsoft Teams", ["msteams"] = "Microsoft Teams (free)", ["Teams"] = "Microsoft Teams (classic)",
        ["Discord"] = "Discord", ["Spotify"] = "Spotify", ["ChatGPT"] = "ChatGPT", ["Grok"] = "Grok", ["Antigravity"] = "Antigravity",
        ["OUTLOOK"] = "Outlook", ["olk"] = "Outlook", ["WINWORD"] = "Word", ["EXCEL"] = "Excel", ["POWERPNT"] = "PowerPoint",
        ["MsMpEng"] = "Microsoft Defender", ["VBCSCompiler"] = "C# compiler server", ["MSBuild"] = "MSBuild",
        ["Memory Compression"] = "Memory compression", ["Zoom"] = "Zoom", ["steam"] = "Steam", ["OneDrive"] = "OneDrive",
        ["claude"] = "Claude", ["PhoneExperienceHost"] = "Phone Link", ["msedgewebview2"] = "Edge WebView2",
        ["Grok Bot"] = "Grok", ["notepad"] = "Notepad", ["explorer"] = "File Explorer",
        ["CrossDeviceService"] = "Cross Device Experience", ["RadeonSoftware"] = "AMD Radeon Software",
        ["Codex"] = "OpenAI Codex", ["LenovoUtility"] = "Lenovo Hotkeys Utility", ["MicrosoftOfficeHub"] = "Microsoft 365 Copilot App",
        ["BrStMonW"] = "Brother Status Monitor", ["BrCcBoot"] = "Brother ControlCenter4",
        ["LenovoVantage"] = "Lenovo Vantage",
        ["AGCInvokerUtility"] = "Adobe GC Invoker Utility", ["acrotray"] = "Adobe AcroTray",
        ["UpdaterStartupUtility"] = "Adobe Updater Startup Utility",
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
    /// <summary>Executable file name (without extension) from a Run-key command line, e.g. "\"C:\\x\\Slack.exe\" --startup" → "Slack".
    /// Squirrel launchers ("...\\Update.exe --processStart \"Teams.exe\"", used by classic Teams, Discord, older Slack) give the app they start.</summary>
    public static string ExeName(string command)
    {
        var exe = RawExeName(command);
        if (!exe.Equals("Update", StringComparison.OrdinalIgnoreCase)) return exe;
        var c = command.Trim();
        var at = c.IndexOf("--processStart", StringComparison.OrdinalIgnoreCase);
        if (at < 0) return exe;
        var rest = c[(at + "--processStart".Length)..].TrimStart(' ', '=');
        var started = RawExeName(rest);
        return started.Length > 0 ? started : exe;
    }

    private static string RawExeName(string command)
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

    public static string UwpAppName(string name, string packageFamilyOrTask)
    {
        var s = packageFamilyOrTask.Length > 0 ? packageFamilyOrTask : name;
        if (s.Contains("YourPhone", StringComparison.OrdinalIgnoreCase)) return "PhoneExperienceHost";
        if (s.Contains("CrossDevice", StringComparison.OrdinalIgnoreCase)) return "CrossDeviceService";
        if (s.Contains("AMDRadeonSoftware", StringComparison.OrdinalIgnoreCase)) return "RadeonSoftware";
        if (s.Contains("OpenAI.Codex", StringComparison.OrdinalIgnoreCase)) return "Codex";
        if (s.Contains("LenovoUtility", StringComparison.OrdinalIgnoreCase)) return "LenovoUtility";
        if (s.Contains("MicrosoftOfficeHub", StringComparison.OrdinalIgnoreCase)) return "MicrosoftOfficeHub";
        // New Teams (work or school, and personal accounts since 2024): MSTeams_8wekyb3d8bbwe\TeamsTfwStartupTask, process ms-teams.exe.
        if (s.Contains("MSTeams", StringComparison.OrdinalIgnoreCase)) return "ms-teams";
        // Teams (free) / Windows 11 Chat: MicrosoftTeams_8wekyb3d8bbwe\TeamsStartupTask, process msteams.exe.
        if (s.Contains("MicrosoftTeams", StringComparison.OrdinalIgnoreCase)) return "msteams";
        if (s.Contains("Teams", StringComparison.OrdinalIgnoreCase)) return "ms-teams";
        if (s.Contains("Spotify", StringComparison.OrdinalIgnoreCase)) return "Spotify";
        if (s.Contains("Discord", StringComparison.OrdinalIgnoreCase)) return "Discord";
        var prefix = s.Split('_', '\\', '/')[0];
        var dot = prefix.LastIndexOf('.');
        return dot >= 0 && dot + 1 < prefix.Length ? prefix[(dot + 1)..] : prefix;
    }
}
