namespace RemotePCDiagnostics.Core.Optimizations;

/// <summary>
/// Windows 11 Widgets (#16) and Search highlights (#17) state, read from the registry by the Host.
/// DWORD fields are null when the value doesn't exist (Windows default: on).
/// </summary>
/// <param name="WindowsBuild">Windows build number (22000+ = Windows 11; 19044 = Windows 10 21H2).</param>
/// <param name="WidgetsPolicy">HKLM\SOFTWARE\Policies\Microsoft\Dsh\AllowNewsAndInterests.</param>
/// <param name="WidgetsInstalled">The Widgets package (MicrosoftWindows.Client.WebExperience) is registered for this account.</param>
/// <param name="TaskbarWidgetsButton">HKCU ...\Explorer\Advanced\TaskbarDa (read only: UCPD blocks writing it).</param>
/// <param name="HighlightsPolicy">HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search\EnableDynamicContentInWSB.</param>
/// <param name="HighlightsToggle">HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings\IsDynamicSearchBoxEnabled.</param>
/// <param name="WidgetsPolicyBlocked">
/// Windows refuses the Widgets policy write (<see cref="WindowsFeeds.PolicyBlockedByUcpd"/>): on Windows 11 builds with the User Choice Protection
/// Driver running, even an elevated write to HKLM\SOFTWARE\Policies\Microsoft\Dsh is denied, so the card isn't offered.
/// </param>
public sealed record WindowsFeedsInfo(
    int WindowsBuild,
    int? WidgetsPolicy = null,
    bool WidgetsInstalled = false,
    int? TaskbarWidgetsButton = null,
    int? HighlightsPolicy = null,
    int? HighlightsToggle = null,
    bool WidgetsPolicyBlocked = false);

/// <summary>When to offer turning off Widgets and Search highlights.</summary>
public static class WindowsFeeds
{
    public const int Windows11Build = 22000;
    /// <summary>Windows 10 21H2: the first Windows 10 release with Search highlights (and the policy that turns it off).</summary>
    public const int Windows10Highlights = 19044;

    /// <summary>The Widgets processes ended right after the policy is set. Never msedgewebview2 by name: other apps use it too
    /// (Widgets' own web views are its child processes and end with it).</summary>
    public static readonly IReadOnlyList<string> WidgetProcesses = ["WidgetBoard", "WidgetService", "MicrosoftStartFeedProvider", "Widgets"];

    public static IReadOnlyList<AppUsage> RunningWidgets(MemorySnapshot s) => WidgetProcesses.Select(s.App).OfType<AppUsage>().ToList();

    /// <summary>The User Choice Protection Driver's service (a system driver); HKLM\SYSTEM\CurrentControlSet\Services\UCPD.</summary>
    public const string UcpdService = "UCPD";
    public const string UcpdServiceKey = @"SYSTEM\CurrentControlSet\Services\" + UcpdService;

    /// <summary>
    /// Whether UCPD blocks the Widgets policy write (seen on Windows 11 26H2, build 26300: access denied even elevated, and the key it leaves
    /// can't be deleted). Blocked while the driver is running (even if its Start was just set to 4 = disabled: it stays loaded until a restart).
    /// When its state couldn't be read: blocked unless the driver isn't installed (<paramref name="start"/> null) or is disabled (4).
    /// </summary>
    /// <param name="start">UCPD's Start value; null = the service doesn't exist (older Windows).</param>
    /// <param name="running">The driver is running; null = couldn't tell.</param>
    public static bool PolicyBlockedByUcpd(int? start, bool? running) => running switch
    {
        true => true,
        false => false,
        null => start is not null and not 4,
    };

    /// <summary>Windows 11, the policy isn't already 0, Windows doesn't block it (UCPD), and Widgets is there: running, or installed with its taskbar button not hidden.</summary>
    public static bool OfferWidgets(MemorySnapshot s) =>
        s.Feeds is { } f && f.WindowsBuild >= Windows11Build && f.WidgetsPolicy != 0 && !f.WidgetsPolicyBlocked
        && (RunningWidgets(s).Count > 0 || (f.WidgetsInstalled && f.TaskbarWidgetsButton != 0));

    /// <summary>Windows 10 21H2+ / Windows 11 and highlights are on (neither the policy nor the Settings toggle is 0).</summary>
    public static bool OfferHighlights(MemorySnapshot s) =>
        s.Feeds is { } f && f.WindowsBuild >= Windows10Highlights && f.HighlightsPolicy != 0 && f.HighlightsToggle != 0;
}
