using RemotePCDiagnostics.Core.Changes;

namespace RemotePCDiagnostics.Core.Memory;

/// <summary>
/// One Office 16.x app (Microsoft 365 / 2016–2024) and its per-account start screen setting, read from the registry by the Host.
/// </summary>
/// <param name="App">"Word", "Excel" or "PowerPoint" (the Office registry key name).</param>
/// <param name="DisableBootToOfficeStart">HKCU\Software\Microsoft\Office\16.0\&lt;App&gt;\Options\DisableBootToOfficeStart; null = not set (Office default: start screen on).</param>
public sealed record OfficeStartApp(string App, int? DisableBootToOfficeStart);

/// <summary>#23: the Office 16.x apps installed on this PC (only Word, Excel, PowerPoint) with their start screen setting. Empty when Office 16 isn't installed.</summary>
public sealed record OfficeStartInfo(IReadOnlyList<OfficeStartApp> Apps);

/// <summary>When to offer skipping the Office start screen (#23), and which values that writes.</summary>
public static class OfficeStartScreen
{
    /// <summary>The apps with a start screen, in display order.</summary>
    public static readonly IReadOnlyList<string> AppNames = ["Word", "Excel", "PowerPoint"];

    /// <summary>The allowlisted HKCU value for an app (the one its Options checkbox "Show the Start screen when this application starts" writes), or null.</summary>
    public static RegistrySetting? Setting(string app) => app.ToLowerInvariant() switch
    {
        "word" => RegistryAllowlist.WordStartScreen,
        "excel" => RegistryAllowlist.ExcelStartScreen,
        "powerpoint" => RegistryAllowlist.PowerPointStartScreen,
        _ => null,
    };

    /// <summary>The start screen is still on: the value is absent or 0.</summary>
    public static bool IsOn(OfficeStartApp a) => a.DisableBootToOfficeStart is null or 0;

    /// <summary>Installed Office 16 apps whose start screen is still on (only known apps), in display order.</summary>
    public static IReadOnlyList<OfficeStartApp> StillOn(MemorySnapshot s) =>
        s.OfficeStart is { } o
            ? AppNames.Select(n => o.Apps.FirstOrDefault(a => a.App.Equals(n, StringComparison.OrdinalIgnoreCase))).OfType<OfficeStartApp>().Where(IsOn).ToList()
            : [];

    public static bool Offer(MemorySnapshot s) => StillOn(s).Count > 0;

    /// <summary>The app's executable, as registered under App Paths.</summary>
    public static string Exe(string app) => app.ToLowerInvariant() switch { "word" => "WINWORD.EXE", "excel" => "EXCEL.EXE", "powerpoint" => "POWERPNT.EXE", _ => "" };

    /// <summary>An App Paths / InstallRoot path from Office 16.x (Microsoft 365, 2016–2024): "...\root\Office16\WINWORD.EXE" or "...\Office16\...".</summary>
    public static bool IsOffice16Path(string? path) =>
        path is not null && path.Replace('/', '\\').Contains(@"\Office16\", StringComparison.OrdinalIgnoreCase);

    /// <summary>Click-to-Run's <c>Configuration\VersionToReport</c> is 16.x.</summary>
    public static bool IsOffice16Version(string? versionToReport) =>
        versionToReport?.Trim().StartsWith("16.", StringComparison.Ordinal) == true;

    /// <summary>Click-to-Run products that are a single app or don't include Word, Excel and PowerPoint.</summary>
    private static readonly string[] SingleOrOtherProducts =
        ["Word", "Excel", "PowerPoint", "Visio", "Project", "Access", "OneNote", "Publisher", "Outlook", "Language", "Proofing", "SkypeForBusiness", "Lync", "Teams", "OneDrive", "Groove"];

    /// <summary>
    /// Whether a Click-to-Run product includes <paramref name="app"/>: its own single-app product ("WordRetail"), or a suite
    /// (O365ProPlusRetail, HomeStudent2021Retail, …) that doesn't list it in <c>&lt;id&gt;.ExcludedApps</c> ("word", "excel", "powerpoint").
    /// </summary>
    public static bool InClickToRun(string app, string? productReleaseIds, Func<string, string?> excludedApps) =>
        (productReleaseIds ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Any(id =>
            (id.Contains(app, StringComparison.OrdinalIgnoreCase) || !SingleOrOtherProducts.Any(n => id.Contains(n, StringComparison.OrdinalIgnoreCase)))
            && !(excludedApps(id) ?? "").Split(',', StringSplitOptions.TrimEntries).Contains(app, StringComparer.OrdinalIgnoreCase));

    /// <summary>"Word", "Word and Excel", "Word, Excel and PowerPoint".</summary>
    public static string Join(IReadOnlyList<string> names) => names.Count switch
    {
        0 => "",
        1 => names[0],
        _ => string.Join(", ", names.Take(names.Count - 1)) + " and " + names[^1],
    };
}
