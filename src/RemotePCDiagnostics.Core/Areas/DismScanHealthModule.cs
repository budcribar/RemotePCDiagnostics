namespace RemotePCDiagnostics.Core.Areas;

/// <summary>Windows component store check: <c>dism /Online /Cleanup-Image /ScanHealth</c> (read-only).</summary>
public sealed class DismScanHealthModule(SystemCommandRunner commands) : WindowsIntegrityModule(commands)
{
    public const string ModuleName = ModuleSlugs.DismScanHealth;
    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.DismScanHealth;
    public override string DisplayName => "Windows component store (DISM)";

    /// <summary>The DISM ScanHealth message when the store is corrupt but DISM says it can't be repaired.</summary>
    public const string CannotBeRepairedSummary = "DISM found component store corruption and reports that the store cannot be repaired.";

    protected override string ToolExe => "dism.exe";
    protected override string[] Arguments => ["/English", "/Online", "/Cleanup-Image", "/ScanHealth"];
    protected override bool InterpretWithoutResult => true;

    private readonly string _cbsPath = WindowsLog("CBS", "CBS.log");
    private readonly string _dismPath = WindowsLog("DISM", "dism.log");
    private long? _cbsOffset, _dismOffset;

    protected override void OnScanStarting()
    {
        _cbsOffset = LogLength(_cbsPath);
        _dismOffset = LogLength(_dismPath);
    }

    // DISM draws "[====  42.0%  ====]" progress bars into its output; drop those lines.
    protected override string CleanOutput(string output) =>
        System.Text.RegularExpressions.Regex.Replace(output,
            @"(?m)^[ \t]*\[[= \t]*\d{1,3}(?:[.,]\d+)?%[= \t]*\][ \t]*\r?(?:\n|$)", "").Trim();

    protected override (DiagnosticStatus Status, string Summary) Interpret(string output, RemotePCDiagnostics.Core.Osquery.ProcessResult? result)
    {
        var cannotRepair = Contains(output, "component store cannot be repaired");
        var status = Classify(Contains(output, "component store is repairable") || cannotRepair,
            Contains(output, "No component store corruption detected"), result);
        return (status, status switch
        {
            DiagnosticStatus.Ok => "No corruption detected",
            DiagnosticStatus.Warning when cannotRepair => CannotBeRepairedSummary,
            DiagnosticStatus.Warning => "DISM found repairable corruption in the Windows component store.",
            _ when result is null => FailedMessage,
            _ => "Integrity scan could not confirm a result"
        });
    }

    /// <summary>Finds Windows images to repair from (mounted ISOs, USB install media). Replaceable for tests.</summary>
    public Func<IReadOnlyList<string>> FindImages { get; init; } = WindowsImages.FindOnDrives;

    /// <summary>
    /// The single steps for this result. Analyze and cleanup are offered for any finished scan; the repairs and the restart only when
    /// the scan found corruption. One repair-from-image button per Windows image found on this PC's drives.
    /// </summary>
    protected override IReadOnlyList<AreaAction>? CardActions(DiagnosticStatus status) => Actions(status, status == DiagnosticStatus.Warning ? FindImages() : []);

    public static IReadOnlyList<AreaAction>? Actions(DiagnosticStatus status, IReadOnlyList<string> images)
    {
        if (status is not (DiagnosticStatus.Ok or DiagnosticStatus.Warning)) return null;
        var actions = new List<AreaAction>
        {
            new(RemediationKind.AnalyzeComponentStore, "Analyze store", "", "Windows component store"),
            new(RemediationKind.CleanUpComponentStore, "Clean up store", "", "Windows component store"),
        };
        if (status != DiagnosticStatus.Warning) return actions;
        actions.Add(new(RemediationKind.RepairComponentStore, "Repair from Windows Update", "", "Windows component store"));
        actions.AddRange(images.Where(WindowsRepair.IsImagePath).Take(4)
            .Select(path => new AreaAction(RemediationKind.RepairComponentStoreFromImage, $"Repair from {path}", path, path)));
        actions.Add(PendingUpdates.RestartAction);
        return actions;
    }

    protected override void AddProblemEvidence(List<AreaRow> rows)
    {
        var cbs = ReadLogEvidence(_cbsPath, _cbsOffset);
        var dism = ReadLogEvidence(_dismPath, _dismOffset);
        rows.Add(new(AreaLevel.Neutral, ["CBS summary", SummarizeCbs(cbs)]));
        rows.Add(new(AreaLevel.Neutral, ["CBS findings during scan", cbs]));
        rows.Add(new(AreaLevel.Neutral, ["DISM summary", WindowsRepair.SummarizeDism(dism)]));
        rows.Add(new(AreaLevel.Neutral, ["DISM log errors during scan", dism]));
    }
}
