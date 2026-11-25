using System.Globalization;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Benchmarks;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Optimizations;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Modules.DeveloperSetup;

/// <summary>
/// Fast, read-only Developer setup check (<see cref="ModuleKind.Check"/>, <see cref="ModuleGroups.Apps"/>, included in Run All).
/// Inspects installed toolchains, temp-volume free space, Defender real-time AV &amp; exclusions (via Agent), Windows Dev Drive
/// status, package caches, LongPathsEnabled / .wslconfig, and power plan / AC power. Builds nothing and applies no fixes automatically.
/// </summary>
public sealed class DeveloperSetupModule(
    IDeveloperEnvironmentProbe? probe = null,
    SystemCommandRunner? commands = null,
    IRegistrySource? registry = null,
    IUserEnvironmentStore? envStore = null)
    : AreaModuleBase(commands?.Log)
{
    public const string ModuleName = ModuleSlugs.DeveloperSetup;

    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.DeveloperSetup;
    public override string DisplayName => "Developer setup";
    protected override string FailedMessage => "Couldn't read developer setup details on this PC.";

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        if (probe is null)
            return Build([], null, null, new(false, false, false, null, "Developer environment probe unavailable."), new(null, null, null));

        progress.ReportStep(1, 5, "Detecting installed developer toolchains…");
        var toolchains = await probe.DetectToolchainsAsync(ct).ConfigureAwait(false);

        progress.ReportStep(2, 5, "Checking temp volume free space and Dev Drive status…");
        var freeGb = probe.ReadTempVolumeFreeGb();
        var (devDrive, devDriveRoot) = await DetectDevDriveAsync(probe, ct).ConfigureAwait(false);

        progress.ReportStep(3, 5, "Checking Microsoft Defender status and exclusions…");
        var defender = await probe.ReadDefenderAsync(ct).ConfigureAwait(false);

        progress.ReportStep(4, 5, "Checking package caches and developer system settings…");
        var caches = await Task.Run(
            () => DevDrivePackageCaches.CollectCaches(toolchains, devDriveRoot, envStore),
            ct).ConfigureAwait(false);
        var longPaths = registry is null ? null : await DevDrivePackageCaches.ReadLongPathsEnabledAsync(registry, ct).ConfigureAwait(false);
        var (wslInstalled, wslMemory) = ReadWslConfig();

        progress.ReportStep(5, 5, "Checking power plan and AC power…");
        var conditions = probe.ReadConditions();

        return Build(toolchains, freeGb, defender, devDrive, conditions, caches, devDriveRoot, longPaths, wslInstalled, wslMemory);
    }

    private static async Task<(DevDriveVolumeStatus Status, string? Root)> DetectDevDriveAsync(IDeveloperEnvironmentProbe probe, CancellationToken ct)
    {
        var tempStatus = await probe.QueryDevDriveAsync(null, ct).ConfigureAwait(false);
        if (!tempStatus.SupportedByOs) return (tempStatus, null);
        if (tempStatus.IsDevDrive)
            return (tempStatus, DevDrivePackageCaches.NormalizeDriveRoot(Path.GetPathRoot(Path.GetTempPath())));

        if (OperatingSystem.IsWindows())
        {
            var tempRoot = DevDrivePackageCaches.NormalizeDriveRoot(Path.GetPathRoot(Path.GetTempPath()));
            foreach (var d in DriveInfo.GetDrives())
            {
                try
                {
                    if (d.DriveType != DriveType.Fixed || !d.IsReady) continue;
                    var root = DevDrivePackageCaches.NormalizeDriveRoot(d.Name);
                    if (root.Length == 0 || string.Equals(root, tempRoot, StringComparison.OrdinalIgnoreCase)) continue;
                    var q = await probe.QueryDevDriveAsync(root, ct).ConfigureAwait(false);
                    if (q.IsDevDrive) return (q, root);
                }
                catch { }
            }
        }

        return (tempStatus, null);
    }

    private static (bool Installed, string? Memory) ReadWslConfig()
    {
        try
        {
            var wslExe = Path.Combine(Environment.SystemDirectory, "wsl.exe");
            var configPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".wslconfig");
            var hasConfig = File.Exists(configPath);
            var installed = hasConfig || (OperatingSystem.IsWindows() && File.Exists(wslExe));
            if (!installed) return (false, null);
            var memory = hasConfig ? DevDrivePackageCaches.ParseWslConfigMemory(File.ReadAllText(configPath)) : null;
            return (true, memory);
        }
        catch
        {
            return (false, null);
        }
    }

    /// <summary>Pure report builder so tests can verify every combination of toolchains, disk, Defender, Dev Drive, caches, and power plan.</summary>
    public static AreaReport Build(
        IReadOnlyList<DetectedToolchain> toolchains,
        double? freeSpaceGb,
        DefenderProbe.Status? defender,
        DevDriveVolumeStatus devDrive,
        BenchmarkConditions conditions,
        IReadOnlyList<PackageCacheInfo>? packageCaches = null,
        string? devDriveRoot = null,
        bool? longPathsEnabled = null,
        bool wslInstalled = false,
        string? wslConfigMemory = null)
    {
        var cards = new List<AreaCard>();
        var summaryParts = new List<string>();

        // 1. Installed toolchains (only installed languages — no empty rows for absent ones)
        if (toolchains.Count == 0)
        {
            cards.Add(new("toolchains", "Developer toolchains", AreaLevel.Neutral, "No developer toolchains found",
                "Installed compilers and SDKs appear here automatically; absent languages stay hidden.",
                ["Toolchain", "Version"],
                []));
            summaryParts.Add("No toolchains found");
        }
        else
        {
            var csharp = toolchains.FirstOrDefault(t => t.Language == DeveloperLanguage.CSharp);
            var csharpBlocked = csharp is null ? null : DeveloperCSharpPin.UnsupportedSdkReason(csharp.Version, csharp.MajorVersion);
            var rows = toolchains.Select(t =>
            {
                var blocked = t.Language == DeveloperLanguage.CSharp ? DeveloperCSharpPin.UnsupportedSdkReason(t.Version, t.MajorVersion) : null;
                return new AreaRow(blocked is null ? AreaLevel.Ok : AreaLevel.Warning, [t.DisplayName, t.Version], Detail: blocked);
            }).ToList();
            var meta = csharpBlocked is null
                ? string.Join(", ", toolchains.Select(t => t.DisplayName))
                : csharpBlocked + " The C# clean-build benchmark stays hidden on this PC.";
            cards.Add(new("toolchains", "Developer toolchains", csharpBlocked is null ? AreaLevel.Ok : AreaLevel.Warning,
                $"{toolchains.Count} toolchain{(toolchains.Count == 1 ? "" : "s")} installed",
                meta,
                ["Toolchain", "Version"],
                rows));
            summaryParts.Add($"{toolchains.Count} toolchain{(toolchains.Count == 1 ? "" : "s")}");
            if (csharpBlocked is not null) summaryParts.Add("C# SDK older than the clean-build benchmark needs");
        }

        // 2. Temp volume free space (10 GB floor: warns, never fails)
        var lowDisk = freeSpaceGb is { } gb && gb < DeveloperScoring.MinFreeDiskGb;
        var diskLevel = freeSpaceGb is null ? AreaLevel.Neutral : lowDisk ? AreaLevel.Warning : AreaLevel.Ok;
        var diskHeadline = freeSpaceGb is { } free
            ? string.Create(CultureInfo.InvariantCulture, $"{free:0.0} GB free")
            : "Free space unknown";
        var diskMeta = lowDisk
            ? string.Create(CultureInfo.InvariantCulture, $"Below the {DeveloperScoring.MinFreeDiskGb:0} GB floor for clean-build benchmarks (builds will report \"could not run\").")
            : "Enough free space for clean-build benchmarks.";
        cards.Add(new("disk", "Build temp volume free space", diskLevel, diskHeadline, diskMeta,
            ["Detail", "Value"],
            [new(diskLevel, ["Free space", diskHeadline])]));
        if (lowDisk) summaryParts.Add("low disk space");

        // 3. Microsoft Defender real-time AV & exclusions (read through Agent)
        AreaLevel defLevel;
        string defHeadline;
        string defMeta;
        var defRows = new List<AreaRow>();
        if (defender is null)
        {
            defLevel = AreaLevel.Neutral;
            defHeadline = "Defender exclusions not readable";
            defMeta = "Could not read Defender exclusions. " + ElevationService.AdminRepairHint;
            defRows.Add(new(AreaLevel.Neutral, ["Exclusions", "Not readable (Agent required)"]));
        }
        else if (!defender.ExclusionsReadable)
        {
            defLevel = AreaLevel.Neutral;
            defHeadline = defender.Active ? "Real-time protection on (exclusions not readable)" : "Defender not active (exclusions not readable)";
            defMeta = "Defender exclusions are only readable through the Agent. " + ElevationService.AdminRepairHint;
            defRows.Add(new(AreaLevel.Neutral, ["Real-time protection", defender.Active ? "On" : "Off / passive"]));
            defRows.Add(new(AreaLevel.Neutral, ["Exclusions", "Not readable"]));
        }
        else
        {
            defLevel = AreaLevel.Ok;
            defHeadline = defender.Active
                ? $"Real-time protection on ({defender.Paths.Count} path, {defender.Processes.Count} process exclusions)"
                : "Defender real-time protection not active";
            defMeta = defender.Active
                ? "Approval-gated Defender exclusions for code folders and build tools are available under Optimize (AddDefenderExclusions)."
                : "Another antivirus or passive mode is active.";
            defRows.Add(new(AreaLevel.Ok, ["Real-time protection", defender.Active ? "On" : "Off / passive"]));
            defRows.Add(new(AreaLevel.Ok, ["Path exclusions", defender.Paths.Count.ToString(CultureInfo.InvariantCulture)]));
            defRows.Add(new(AreaLevel.Ok, ["Process exclusions", defender.Processes.Count.ToString(CultureInfo.InvariantCulture)]));
        }
        cards.Add(new("defender", "Antivirus & build exclusions", defLevel, defHeadline, defMeta, ["Detail", "Value"], defRows));

        // 4. Windows Dev Drive status
        AreaLevel ddLevel = AreaLevel.Neutral;
        string ddHeadline;
        string ddMeta;
        var normDevDrive = DevDrivePackageCaches.NormalizeDriveRoot(devDriveRoot);
        if (!devDrive.SupportedByOs)
        {
            ddHeadline = "Dev Drive not available on this Windows version";
            ddMeta = devDrive.RawSummary ?? "Windows 11 (build 22621.2338 or later) is required for Dev Drive.";
        }
        else if (devDrive.IsDevDrive)
        {
            ddLevel = AreaLevel.Ok;
            ddHeadline = normDevDrive.Length > 0 ? $"Dev Drive in use ({normDevDrive})" : "Dev Drive in use";
            ddMeta = devDrive.DefenderPerformanceModeActive == true
                ? "Defender performance mode is active on this Dev Drive."
                : "Volume is formatted as a Windows Dev Drive.";
        }
        else
        {
            ddHeadline = "Dev Drive not used";
            ddMeta = "Dev Drive not used; the opt-in test can show how much it would help.";
        }
        cards.Add(new("devdrive", "Windows Dev Drive", ddLevel, ddHeadline, ddMeta,
            ["Detail", "Value"],
            [new(ddLevel, ["Status", ddHeadline])]));

        // 4b. Package caches & Dev Drive
        if (packageCaches is { Count: > 0 })
        {
            var cacheRows = new List<AreaRow>();
            var cacheActions = new List<AreaAction>();
            var movableOffDevDrive = 0;

            foreach (var c in packageCaches)
            {
                var sizeText = FormatCacheSize(c.SizeBytes);
                if (!c.Spec.PureCache)
                {
                    var statusText = c.OnDevDrive ? "On Dev Drive (move by hand)" : "Move by hand";
                    cacheRows.Add(new(
                        c.OnDevDrive ? AreaLevel.Ok : AreaLevel.Neutral,
                        [c.Spec.ToolName, c.CurrentPath, sizeText, statusText],
                        Detail: $"{c.Spec.EnvVar} holds binaries and config in addition to caches — move it by hand if you want it on a Dev Drive."));
                }
                else
                {
                    var statusText = c.OnDevDrive
                        ? "On Dev Drive"
                        : normDevDrive.Length > 0 ? "Not on Dev Drive" : "Standard volume";
                    var rowLevel = c.OnDevDrive ? AreaLevel.Ok : normDevDrive.Length > 0 ? AreaLevel.Warning : AreaLevel.Neutral;
                    cacheRows.Add(new(rowLevel, [c.Spec.ToolName, c.CurrentPath, sizeText, statusText]));

                    if (!c.OnDevDrive && normDevDrive.Length > 0)
                    {
                        movableOffDevDrive++;
                        cacheActions.Add(new(
                            RemediationKind.MovePackageCacheToDevDrive,
                            $"Use the Dev Drive for {c.Spec.ToolName} cache",
                            DevDrivePackageCaches.MakeActionTarget(c.Spec.EnvVar, normDevDrive),
                            c.Spec.ToolName));
                    }
                }
            }

            var cacheLevel = movableOffDevDrive > 0 ? AreaLevel.Warning
                : packageCaches.All(c => c.OnDevDrive) ? AreaLevel.Ok
                : AreaLevel.Neutral;
            var cacheHeadline = movableOffDevDrive > 0
                ? $"{movableOffDevDrive} package cache{(movableOffDevDrive == 1 ? "" : "s")} can move to {normDevDrive}"
                : packageCaches.All(c => c.OnDevDrive)
                    ? "Detected package caches are on the Dev Drive"
                    : $"{packageCaches.Count} package cache{(packageCaches.Count == 1 ? "" : "s")} detected";
            var cacheMeta = normDevDrive.Length > 0
                ? "Moving pure package caches to a Dev Drive avoids Defender overhead without adding antivirus exclusions. CARGO_HOME and GRADLE_USER_HOME stay info-only."
                : "Package caches live on standard volumes until a Dev Drive is available.";

            cards.Add(new("caches", "Package caches & Dev Drive", cacheLevel, cacheHeadline, cacheMeta,
                ["Tool", "Location", "Size", "Status"],
                cacheRows,
                Actions: cacheActions.Count > 0 ? cacheActions : null));
        }

        // 4c. Read-only developer system settings (LongPathsEnabled, .wslconfig memory=)
        if (longPathsEnabled is not null || wslInstalled)
        {
            var sysRows = new List<AreaRow>();
            if (longPathsEnabled is { } lp)
            {
                sysRows.Add(new(
                    lp ? AreaLevel.Ok : AreaLevel.Neutral,
                    ["Windows long paths (LongPathsEnabled)", lp ? "Enabled" : "Disabled"],
                    Detail: lp ? null : "Enabling LongPathsEnabled avoids 260-character path errors in deep node_modules / C++ / NuGet trees."));
            }
            if (wslInstalled)
            {
                var wslText = string.IsNullOrWhiteSpace(wslConfigMemory) ? "Default (not set in .wslconfig)" : wslConfigMemory;
                sysRows.Add(new(AreaLevel.Neutral, ["WSL 2 memory limit (.wslconfig)", wslText]));
            }

            cards.Add(new("dev-system", "Developer system settings", AreaLevel.Neutral,
                longPathsEnabled == true ? "Long paths enabled" : "Read-only system settings",
                "Read-only check of Windows long paths and WSL 2 memory configuration.",
                ["Setting", "Value"],
                sysRows));
        }

        // 5. Power plan & AC power
        var isPowerSaver = !string.IsNullOrWhiteSpace(conditions.PowerPlan)
            && conditions.PowerPlan.Contains("Power saver", StringComparison.OrdinalIgnoreCase);
        var onBattery = conditions.OnBattery == true;
        var powerLevel = isPowerSaver || onBattery ? AreaLevel.Warning : AreaLevel.Ok;
        var powerPlanName = string.IsNullOrWhiteSpace(conditions.PowerPlan) ? "Unknown" : conditions.PowerPlan;
        var powerSource = conditions.OnBattery switch { true => "On battery", false => "AC power (plugged in)", null => "Unknown" };
        var powerMeta = isPowerSaver
            ? "Power saver throttles build speed. Switch to the Balanced power plan for comparable scores."
            : onBattery
                ? "Running on battery. A comparable developer benchmark score wants the PC plugged in."
                : "Ready for comparable developer benchmark runs.";
        var powerActions = isPowerSaver
            ? new List<AreaAction> { new(RemediationKind.SetBalancedPowerPlan, "Switch to Balanced power plan", RemediationService.BalancedPlanGuid, "Balanced power plan") }
            : null;
        cards.Add(new("power", "Power plan & AC power", powerLevel, $"{powerPlanName} · {powerSource}", powerMeta,
            ["Detail", "Value"],
            [
                new(isPowerSaver ? AreaLevel.Warning : AreaLevel.Ok, ["Active power plan", powerPlanName]),
                new(onBattery ? AreaLevel.Warning : AreaLevel.Ok, ["Power source", powerSource]),
            ],
            Actions: powerActions));
        if (isPowerSaver) summaryParts.Add("Power saver active");
        else if (onBattery) summaryParts.Add("on battery");

        var status = AreaReport.Worst(cards.Select(c => c.ErrorText is not null ? AreaLevel.Warning : c.Level));
        return new AreaReport(cards, string.Join(" · ", summaryParts), status);
    }

    private static string FormatCacheSize(long? bytes)
    {
        if (bytes is null) return "Not created yet";
        if (bytes == 0) return "Empty";
        if (bytes >= 1L << 30) return string.Create(CultureInfo.InvariantCulture, $"{bytes.Value / (double)(1L << 30):0.1} GB");
        if (bytes >= 1L << 20) return string.Create(CultureInfo.InvariantCulture, $"{bytes.Value / (double)(1L << 20):0.0} MB");
        if (bytes >= 1L << 10) return string.Create(CultureInfo.InvariantCulture, $"{bytes.Value / (double)(1L << 10):0.0} KB");
        return $"{bytes.Value} B";
    }
}
