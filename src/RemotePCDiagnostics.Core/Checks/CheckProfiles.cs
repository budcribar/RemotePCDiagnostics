namespace RemotePCDiagnostics.Core.Checks;

/// <summary>
/// One cross-cutting user profile (Developer, Gamer, Office worker, Home user, Performance).
/// Profiles are additive: selecting multiple profiles (e.g. Gamer + Developer) enables the union of their checks.
/// </summary>
public sealed record CheckProfile(
    string Id,
    string DisplayName,
    string Summary,
    IReadOnlyList<string> CheckIds,
    string? RelatedLinkHref = null,
    string? RelatedLinkLabel = null,
    bool RelatedLinkRequiresDevEnvironment = false);

public static class CheckProfiles
{
    public const string Developer = "developer";
    public const string Gamer = "gamer";
    public const string Office = "office";
    public const string Home = "home";
    public const string Performance = "performance";

    public static readonly IReadOnlyList<CheckProfile> All =
    [
        new(
            Developer,
            "Developer",
            "Dev Drive caches, WSL, long paths, RAM floor, and build benchmark",
            [ModuleSlugs.DeveloperSetup, ModuleSlugs.Osquery, ModuleSlugs.DriveHealth, ModuleSlugs.ResourceHogs],
            "/benchmark?goal=build",
            "Build speed benchmark →",
            RelatedLinkRequiresDevEnvironment: true),
        new(
            Gamer,
            "Gamer",
            "Power mode, CPU throttling, temperatures, GPU driver & resets, Wi-Fi & bufferbloat",
            [ModuleSlugs.BatteryPower, ModuleSlugs.Sensors, ModuleSlugs.DeviceDrivers, ModuleSlugs.Crashes, ModuleSlugs.Network],
            "/stress",
            "Bufferbloat & GPU tests →"),
        new(
            Office,
            "Office worker",
            "Wi-Fi, clock sync, printers/services, sound & mic, docks & USB, and sleep",
            [ModuleSlugs.Network, ModuleSlugs.Sound, ModuleSlugs.WindowsMaintenance, ModuleSlugs.Services, ModuleSlugs.SleepWake, ModuleSlugs.UsbPorts],
            "/stress",
            "Mic, speaker & webcam tests →"),
        new(
            Home,
            "Home user",
            "Security & antivirus, updates, Storage Sense, browser clutter, and restore points",
            [ModuleSlugs.SecurityEssentials, ModuleSlugs.Programs, ModuleSlugs.DriveHealth, ModuleSlugs.ResourceHogs, ModuleSlugs.WindowsMaintenance]),
        new(
            Performance,
            "Performance",
            "Resource hogs, startup apps, services, crashes, HDD boot drive, power throttling, and benchmarks",
            [ModuleSlugs.ResourceHogs, ModuleSlugs.Services, ModuleSlugs.Crashes, ModuleSlugs.DriveHealth, ModuleSlugs.BatteryPower, ModuleSlugs.Osquery],
            "/benchmark?goal=tuneup",
            "Full tune-up benchmark →"),
    ];

    public static CheckProfile? Find(string? id) =>
        string.IsNullOrWhiteSpace(id) ? null : All.FirstOrDefault(p => string.Equals(p.Id, id.Trim(), StringComparison.OrdinalIgnoreCase));

    /// <summary>Known profile ids only, lower case, without duplicates, in catalog order.</summary>
    public static List<string> Normalize(IEnumerable<string>? ids)
    {
        var wanted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (ids is not null)
            foreach (var id in ids)
                if (Find(id) is { } p) wanted.Add(p.Id);
        return All.Where(p => wanted.Contains(p.Id)).Select(p => p.Id).ToList();
    }

    /// <summary>Computes the additive union of check ids across all active profiles, intersected with available checks.</summary>
    public static IReadOnlySet<string> ResolveEnabledCheckIds(IEnumerable<string> activeProfileIds, IEnumerable<string> availableCheckIds)
    {
        var available = new HashSet<string>(availableCheckIds, StringComparer.OrdinalIgnoreCase);
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var id in activeProfileIds)
        {
            if (Find(id) is not { } profile) continue;
            foreach (var checkId in profile.CheckIds)
            {
                if (available.Contains(checkId))
                    result.Add(checkId);
            }
        }
        return result;
    }
}
