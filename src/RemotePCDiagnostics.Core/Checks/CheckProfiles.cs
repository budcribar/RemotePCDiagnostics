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
            [ModuleSlugs.DeveloperSetup, ModuleSlugs.Osquery, ModuleSlugs.DriveHealth],
            "/benchmark?goal=build",
            "Build speed benchmark →",
            RelatedLinkRequiresDevEnvironment: true),
        new(
            Gamer,
            "Gamer",
            "Power mode, CPU throttling, GPU driver & resets, Wi-Fi & bufferbloat",
            [ModuleSlugs.BatteryPower, ModuleSlugs.DeviceDrivers, ModuleSlugs.Crashes, ModuleSlugs.Network],
            "/stress",
            "Bufferbloat & GPU tests →"),
        new(
            Office,
            "Office worker",
            "Wi-Fi & VPN, clock sync, printers/services, and audio/mic/camera",
            [ModuleSlugs.Network, ModuleSlugs.WindowsMaintenance, ModuleSlugs.Services],
            "/stress",
            "Mic, speaker & webcam tests →"),
        new(
            Home,
            "Home user",
            "Security & antivirus, Storage Sense, browser clutter, and restore points",
            [ModuleSlugs.SecurityEssentials, ModuleSlugs.DriveHealth, ModuleSlugs.ResourceHogs, ModuleSlugs.WindowsMaintenance]),
        new(
            Performance,
            "Performance",
            "Resource hogs, startup apps, HDD boot drive, power throttling, and benchmarks",
            [ModuleSlugs.ResourceHogs, ModuleSlugs.DriveHealth, ModuleSlugs.BatteryPower],
            "/benchmark?goal=tuneup",
            "Full tune-up benchmark →"),
    ];

    public static CheckProfile? Find(string? id) =>
        string.IsNullOrWhiteSpace(id) ? null : All.FirstOrDefault(p => string.Equals(p.Id, id.Trim(), StringComparison.OrdinalIgnoreCase));

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
