namespace RemotePCDiagnostics.Core.Changes;

/// <summary>A user-facing category used to organize undoable changes in a tree.</summary>
public sealed record UndoChangeCategory(string Key, string Title, string Description, int Order);

/// <summary>One branch in the Undo changes tree containing all matching journal entries (newest first).</summary>
public sealed record UndoChangeGroup(string Key, string Title, string Description, IReadOnlyList<ChangeRecord> Items);

/// <summary>
/// Organizes <see cref="ChangeRecord"/> entries into logical categories (removed Store apps, Defender exclusions,
/// startup/services, Dev Drive, browsers, power/sleep, network, security/privacy, audio/devices, system settings)
/// so users can inspect and select whole groups at once.
/// </summary>
public static class UndoChangeGroups
{
    public static readonly UndoChangeCategory RemovedApps = new(
        "removed-apps", "Removed programs & Store apps",
        "Reinstalls from the Microsoft Store (needs internet)", 10);

    public static readonly UndoChangeCategory DefenderExclusions = new(
        "defender-exclusions", "Windows Defender exclusions",
        "Folders and processes Defender no longer scans", 20);

    public static readonly UndoChangeCategory StartupAndServices = new(
        "startup-services", "Startup apps, services & tasks",
        "Startup programs, Windows services, and scheduled tasks", 30);

    public static readonly UndoChangeCategory DevDriveAndCaches = new(
        "dev-drive", "Dev Drive & package caches",
        "Persistent Dev Drive and relocated developer caches", 40);

    public static readonly UndoChangeCategory Browsers = new(
        "browsers", "Browsers & extensions",
        "Browser settings, background mode, and blocked extensions", 50);

    public static readonly UndoChangeCategory PowerAndSleep = new(
        "power-sleep", "Power, sleep & wake",
        "Power plan, processor limits, Fast Startup, hibernation, and wake settings", 60);

    public static readonly UndoChangeCategory Network = new(
        "network", "Network & DNS",
        "Adapter DNS servers and system proxy settings", 70);

    public static readonly UndoChangeCategory SecurityAndPrivacy = new(
        "security-privacy", "Security & privacy",
        "Windows security settings and camera/microphone privacy", 80);

    public static readonly UndoChangeCategory AudioAndDevices = new(
        "audio-devices", "Audio & devices",
        "Sound devices, app mute state, and default printer", 90);

    public static readonly UndoChangeCategory SystemSettings = new(
        "system-settings", "Windows & system settings",
        "Registry tweaks, visual effects, and virtual memory", 100);

    public static readonly UndoChangeCategory Permanent = new(
        "permanent", "Permanent changes",
        "Cannot be undone automatically", 999);

    public static UndoChangeCategory CategoryFor(ChangeKind kind) => kind switch
    {
        ChangeKind.StoreReinstall => RemovedApps,
        ChangeKind.DefenderExclusion => DefenderExclusions,
        ChangeKind.StartupApp or ChangeKind.ScheduledTask or ChangeKind.ServiceStartType or ChangeKind.ServiceRunning => StartupAndServices,
        ChangeKind.PersistentDevDrive or ChangeKind.UserEnvironmentVariable => DevDriveAndCaches,
        ChangeKind.BrowserSettings or ChangeKind.BrowserLocalStateValue or ChangeKind.ExtensionBlock => Browsers,
        ChangeKind.PowerPlan or ChangeKind.PowerSetting or ChangeKind.FastStartup or ChangeKind.HiberFileType or ChangeKind.DeviceWake or ChangeKind.WakeTimer => PowerAndSleep,
        ChangeKind.AdapterDns or ChangeKind.SystemProxy => Network,
        ChangeKind.SecuritySetting or ChangeKind.CapturePrivacy => SecurityAndPrivacy,
        ChangeKind.AudioEndpoint or ChangeKind.AudioSession or ChangeKind.DefaultPrinter => AudioAndDevices,
        ChangeKind.RegistryValue or ChangeKind.Transparency or ChangeKind.PageFile => SystemSettings,
        ChangeKind.TempFiles or ChangeKind.NotUndoable => Permanent,
        _ => SystemSettings,
    };

    /// <summary>Groups <paramref name="records"/> by category in deterministic order, keeping items newest-first inside each group.</summary>
    public static IReadOnlyList<UndoChangeGroup> Group(IEnumerable<ChangeRecord> records) =>
        records
            .Select(r => (Record: r, Category: CategoryFor(r.Kind)))
            .GroupBy(x => x.Category.Key, StringComparer.Ordinal)
            .Select(g =>
            {
                var cat = g.First().Category;
                var items = g.Select(x => x.Record).OrderByDescending(r => r.TimeUtc).ToList();
                return (cat.Order, Group: new UndoChangeGroup(cat.Key, cat.Title, cat.Description, items));
            })
            .OrderBy(x => x.Order)
            .Select(x => x.Group)
            .ToList();
}
