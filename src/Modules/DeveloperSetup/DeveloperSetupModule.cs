using System.Globalization;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Benchmarks;
using RemotePCDiagnostics.Core.Optimizations;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Modules.DeveloperSetup;

/// <summary>
/// Fast, read-only Developer setup check (<see cref="ModuleKind.Check"/>, <see cref="ModuleGroups.Apps"/>, included in Run All).
/// Inspects installed toolchains, temp-volume free space, Defender real-time AV &amp; exclusions (via Agent), Windows Dev Drive
/// status, and power plan / AC power. Builds nothing and applies no fixes automatically.
/// </summary>
public sealed class DeveloperSetupModule(IDeveloperEnvironmentProbe? probe = null, SystemCommandRunner? commands = null)
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

        progress.ReportStep(1, 4, "Detecting installed developer toolchains…");
        var toolchains = await probe.DetectToolchainsAsync(ct).ConfigureAwait(false);

        progress.ReportStep(2, 4, "Checking temp volume free space and Dev Drive status…");
        var freeGb = probe.ReadTempVolumeFreeGb();
        var devDrive = await probe.QueryDevDriveAsync(null, ct).ConfigureAwait(false);

        progress.ReportStep(3, 4, "Checking Microsoft Defender status and exclusions…");
        var defender = await probe.ReadDefenderAsync(ct).ConfigureAwait(false);

        progress.ReportStep(4, 4, "Checking power plan and AC power…");
        var conditions = probe.ReadConditions();

        return Build(toolchains, freeGb, defender, devDrive, conditions);
    }

    /// <summary>Pure report builder so tests can verify every combination of toolchains, disk, Defender, Dev Drive, and power plan.</summary>
    public static AreaReport Build(
        IReadOnlyList<DetectedToolchain> toolchains,
        double? freeSpaceGb,
        DefenderProbe.Status? defender,
        DevDriveVolumeStatus devDrive,
        BenchmarkConditions conditions)
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
            var rows = toolchains.Select(t => new AreaRow(AreaLevel.Ok, [t.DisplayName, t.Version])).ToList();
            cards.Add(new("toolchains", "Developer toolchains", AreaLevel.Ok,
                $"{toolchains.Count} toolchain{(toolchains.Count == 1 ? "" : "s")} installed",
                string.Join(", ", toolchains.Select(t => t.DisplayName)),
                ["Toolchain", "Version"],
                rows));
            summaryParts.Add($"{toolchains.Count} toolchain{(toolchains.Count == 1 ? "" : "s")}");
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
        if (!devDrive.SupportedByOs)
        {
            ddHeadline = "Dev Drive not available on this Windows version";
            ddMeta = devDrive.RawSummary ?? "Windows 11 (build 22621.2338 or later) is required for Dev Drive.";
        }
        else if (devDrive.IsDevDrive)
        {
            ddLevel = AreaLevel.Ok;
            ddHeadline = "Dev Drive in use";
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
}
