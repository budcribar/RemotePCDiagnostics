using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Changes;

namespace RemotePCDiagnostics.Core.Benchmarks;

/// <summary>One selectable improvement that can be applied between the Before and After benchmark passes.</summary>
public sealed record BenchmarkImprovement(
    string Id,
    string Goal,
    string Title,
    string Description,
    AreaAction Action,
    bool AlreadyApplied = false,
    string? AlreadyAppliedNote = null,
    bool RequiresDevDrive = false)
{
    public bool Reversible => Undoability.Of(Action.Kind) == UndoSupport.Full;
}

/// <summary>Outcome of applying one checked improvement during a closed-loop benchmark experiment.</summary>
public sealed record BenchmarkImprovementOutcome(
    string Id,
    string Title,
    bool Succeeded,
    bool Skipped,
    string Message);

/// <summary>Result of a closed-loop Before → Apply checked improvements → After benchmark experiment.</summary>
public sealed record BenchmarkExperimentResult(
    string? Goal,
    BenchmarkRun? Before,
    BenchmarkRun? After,
    IReadOnlyList<BenchmarkImprovementOutcome> Outcomes,
    bool Completed,
    string? Error = null);

/// <summary>Observed PC state used to build the applicable improvements checklist for a benchmark goal.</summary>
public sealed record BenchmarkImprovementContext(
    bool HasDevEnvironment = false,
    string? ExistingDevDriveRoot = null,
    IReadOnlyList<PackageCacheInfo>? PackageCaches = null,
    int? AcMaxProcessorStatePercent = null,
    string? ActivePowerPlan = null,
    bool? StorageSenseEnabled = null,
    int? DotNetSdkMajorVersion = null,
    IReadOnlyList<int>? InstalledDotNetSdkMajors = null);

/// <summary>
/// Builds the goal-specific list of improvements that can be checked before clicking Start
/// (Before benchmark → Apply checked improvements → After benchmark).
/// </summary>
public static class BenchmarkImprovements
{
    public const string CreateDevDriveId = "devdrive:create";
    public const string InstallDotNet10SdkId = "sdk:dotnet10";
    public const string InstallDotNet11SdkId = "sdk:dotnet11";
    public const string NewDevDriveToken = "<NEW_DEVDRIVE>";

    public static IReadOnlyList<BenchmarkImprovement> ForGoal(string? goal, BenchmarkImprovementContext ctx)
    {
        var normalized = BenchmarkGoals.Normalize(goal) ?? BenchmarkGoals.TuneUp;
        var list = new List<BenchmarkImprovement>();

        if (normalized == BenchmarkGoals.Build)
        {
            if (!ctx.HasDevEnvironment)
                return list;

            var hasDevDrive = !string.IsNullOrWhiteSpace(ctx.ExistingDevDriveRoot);
            var devRoot = hasDevDrive ? DevDrivePackageCaches.NormalizeDriveRoot(ctx.ExistingDevDriveRoot!) : null;

            // Only offer to create a persistent Dev Drive when the PC doesn't already have one.
            if (!hasDevDrive)
            {
                list.Add(new BenchmarkImprovement(
                    CreateDevDriveId,
                    BenchmarkGoals.Build,
                    "Create persistent Dev Drive (50 GB ReFS)",
                    "Creates a 50 GB dynamically expanding ReFS Dev Drive with Defender Performance Mode for faster builds and package restores.",
                    new AreaAction(RemediationKind.CreatePersistentDevDrive, "Create Dev Drive", "50", "Persistent Dev Drive")));
            }

            var caches = ctx.PackageCaches ?? [];
            foreach (var c in caches.Where(c => c.Spec.PureCache))
            {
                var targetRoot = devRoot ?? NewDevDriveToken;
                var target = hasDevDrive
                    ? DevDrivePackageCaches.MakeActionTarget(c.Spec.EnvVar, targetRoot)
                    : $"{c.Spec.EnvVar}|{NewDevDriveToken}";
                list.Add(new BenchmarkImprovement(
                    $"devcache:{c.Spec.EnvVar}",
                    BenchmarkGoals.Build,
                    $"Move {c.Spec.ToolName} package cache to Dev Drive",
                    $"Sets user environment variable {c.Spec.EnvVar} to a folder on the Dev Drive so restores benefit from Dev Drive performance mode.",
                    new AreaAction(RemediationKind.MovePackageCacheToDevDrive, $"Move {c.Spec.ToolName} cache", target, c.Spec.ToolName),
                    AlreadyApplied: c.OnDevDrive,
                    AlreadyAppliedNote: c.OnDevDrive ? $"Already on Dev Drive ({c.CurrentPath})" : null,
                    RequiresDevDrive: !hasDevDrive));
            }

            AddCommonPerformanceImprovements(list, BenchmarkGoals.Build, ctx, includeStorageAndDisk: true, includeDns: false);
            return list;
        }

        if (normalized == BenchmarkGoals.Browsing)
        {
            AddCommonPerformanceImprovements(list, BenchmarkGoals.Browsing, ctx, includeStorageAndDisk: false, includeDns: true);
            return list;
        }

        // Full tune-up
        AddCommonPerformanceImprovements(list, BenchmarkGoals.TuneUp, ctx, includeStorageAndDisk: true, includeDns: true);
        return list;
    }

    private static void AddCommonPerformanceImprovements(
        List<BenchmarkImprovement> list,
        string goal,
        BenchmarkImprovementContext ctx,
        bool includeStorageAndDisk,
        bool includeDns)
    {
        if (ctx.AcMaxProcessorStatePercent is >= 0 and < 100)
        {
            list.Add(new BenchmarkImprovement(
                "power:ac-max-cpu",
                goal,
                $"Raise AC maximum processor state from {ctx.AcMaxProcessorStatePercent}% to 100%",
                "Removes the Windows power-scheme CPU cap on AC power so builds and benchmarks can use full clock speed.",
                new AreaAction(RemediationKind.ResetMaxProcessorState, "Set AC max processor to 100%", "", "Maximum processor state")));
        }

        if (ctx.ActivePowerPlan?.Contains("Power saver", StringComparison.OrdinalIgnoreCase) == true)
        {
            list.Add(new BenchmarkImprovement(
                "power:balanced",
                goal,
                "Switch power plan from Power saver to Balanced",
                "Prevents Power saver throttling during builds, browsing, and disk work.",
                new AreaAction(RemediationKind.SetBalancedPowerPlan, "Switch to Balanced", "", "Power plan")));
        }

        if (includeStorageAndDisk)
        {
            list.Add(new BenchmarkImprovement(
                "disk:storage-sense",
                goal,
                "Turn on Windows Storage Sense",
                "Automatically keeps temporary files trimmed so SSD headroom and disk response time stay healthy.",
                new AreaAction(RemediationKind.EnableStorageSense, "Turn on Storage Sense", "", "Windows Storage Sense"),
                AlreadyApplied: ctx.StorageSenseEnabled == true,
                AlreadyAppliedNote: ctx.StorageSenseEnabled == true ? "Already turned on" : null));

            list.Add(new BenchmarkImprovement(
                "disk:clean-temp",
                goal,
                "Clean temporary files",
                "Clears Windows and user temp folders to free disk headroom before measuring disk response time.",
                new AreaAction(RemediationKind.CleanTempFiles, "Clean temp files", "", "Temporary files")));
        }

        if (includeDns)
        {
            list.Add(new BenchmarkImprovement(
                "net:public-dns",
                goal,
                "Switch to fast public DNS (Cloudflare / Google)",
                "Can speed up website lookup time (DNS) and page loads when ISP DNS is slow.",
                new AreaAction(RemediationKind.SetPublicDns, "Use public DNS", "", "DNS servers")));
        }
    }

    /// <summary>Orders selected improvements so persistent Dev Drive creation always runs before dependent package cache moves.</summary>
    public static IReadOnlyList<BenchmarkImprovement> OrderForExecution(IEnumerable<BenchmarkImprovement> selected) =>
        selected
            .OrderBy(i => i.Action.Kind == RemediationKind.CreatePersistentDevDrive ? 0 : i.RequiresDevDrive ? 2 : 1)
            .ToList();

    /// <summary>Substitutes the newly created Dev Drive root into dependent package cache action targets.</summary>
    public static AreaAction ResolveAction(AreaAction action, string? devDriveRoot)
    {
        if (action.Kind != RemediationKind.MovePackageCacheToDevDrive || string.IsNullOrWhiteSpace(devDriveRoot))
            return action;
        if (!action.Target.Contains(NewDevDriveToken, StringComparison.Ordinal))
            return action;
        var envVar = DevDrivePackageCaches.TargetEnvVar(action.Target);
        var resolvedTarget = DevDrivePackageCaches.MakeActionTarget(envVar, devDriveRoot);
        return action with { Target = resolvedTarget };
    }
}
