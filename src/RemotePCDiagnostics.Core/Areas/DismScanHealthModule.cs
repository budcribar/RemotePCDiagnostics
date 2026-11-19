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
            _ => "Integrity scan could not confirm a result"
        });
    }

    /// <summary>
    /// ScanHealth reports corruption or a clean store; any other ending (an "Error:" code, another servicing operation, a pending restart,
    /// no output) means DISM gave no verdict, so it is recorded as "Couldn't run" with the reason, never as Critical.
    /// </summary>
    protected override string? CouldNotRunReason(string output, RemotePCDiagnostics.Core.Osquery.ProcessResult? result) =>
        NoResultReason(output, result?.ExitCode, result is not null);

    /// <summary>Why <c>DISM /ScanHealth</c> gave no verdict. <paramref name="returned"/> false: the tool didn't start or timed out.</summary>
    public static string NoResultReason(string output, int? exitCode, bool returned = true)
    {
        if (!returned)
            return "DISM did not start or did not finish within 30 minutes, so no scan result is available. Run RemotePCDiagnostics as administrator and try again.";
        if (Contains(output, "another servicing") || Contains(output, "0x800700b7") || Contains(output, "0x80070020"))
            return "DISM did not run because another servicing or repair operation is running (for example SFC or Windows Update). Run the scan again when it has finished.";
        if (Contains(output, WindowsRepair.PendingOperationsCode) || Contains(output, "0x800f082f") || exitCode == WindowsRepair.RebootRequiredExitCode)
            return "DISM did not run because a servicing operation is waiting for a restart. Restart the PC, then run the scan again.";
        if (Contains(output, "Elevated permissions") || exitCode == 740)
            return "DISM did not run because it needs administrator rights. Run RemotePCDiagnostics as administrator and try again.";
        var lines = output.Split(['\r', '\n'], StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        var errorAt = Array.FindLastIndex(lines, l => l.StartsWith("Error:", StringComparison.OrdinalIgnoreCase));
        if (errorAt >= 0)
        {
            var message = errorAt + 1 < lines.Length && !lines[errorAt + 1].Contains("dism.log", StringComparison.OrdinalIgnoreCase) ? " " + lines[errorAt + 1] : "";
            return $"DISM stopped before it could report a result ({lines[errorAt]}).{message} See the DISM log details below.";
        }
        var lastLine = LastMessageLine(output);
        return lastLine is null
            ? $"DISM ended without any output (exit code {exitCode}), so no scan took place. Run it again; if this repeats, check whether SFC or Windows Update is running."
            : $"DISM ended without a scan result (exit code {exitCode}). Its last message was: \"{lastLine}\"";
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
