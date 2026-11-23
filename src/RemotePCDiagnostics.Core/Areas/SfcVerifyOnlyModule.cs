using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>Protected system files check: <c>sfc /verifyonly</c> (read-only).</summary>
public sealed class SfcVerifyOnlyModule(SystemCommandRunner commands) : WindowsIntegrityModule(commands)
{
    public const string ModuleName = ModuleSlugs.SfcVerifyOnly;
    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.SfcVerifyOnly;
    public override string DisplayName => "Protected system files (SFC)";

    protected override string ToolExe => "sfc.exe";
    protected override string[] Arguments => ["/verifyonly"];

    // SFC prints "Verification 1% complete." .. "Verification 100% complete." with blank padding; strip those progress lines.
    protected override string CleanOutput(string output)
    {
        var lines = output.Split(['\r', '\n'])
            .Select(l => l.Trim())
            .Where(l => !System.Text.RegularExpressions.Regex.IsMatch(l, @"^Verification\s+\d{1,3}%\s+complete\.?$",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase))
            .ToList();
        var compact = new List<string>(lines.Count);
        foreach (var line in lines)
        {
            if (line.Length == 0 && (compact.Count == 0 || compact[^1].Length == 0)) continue;
            compact.Add(line);
        }
        return string.Join("\n", compact).Trim();
    }

    /// <summary>Violations found: offer the repair, and the restart that can be needed to finish it.</summary>
    protected override IReadOnlyList<AreaAction>? CardActions(DiagnosticStatus status) => status == DiagnosticStatus.Warning
        ? [new(RemediationKind.RepairSystemFiles, "Repair system files", "", "Protected system files"), PendingUpdates.RestartAction]
        : null;

    protected override (DiagnosticStatus Status, string Summary) Interpret(string output, RemotePCDiagnostics.Core.Osquery.ProcessResult? result)
    {
        var status = Classify(Contains(output, "found integrity violations"), Contains(output, "did not find any integrity violations"), result);
        return (status, status switch
        {
            DiagnosticStatus.Ok => "No corruption detected",
            DiagnosticStatus.Warning => "SFC found integrity violations in protected system files.",
            _ => "Integrity scan could not confirm a result"
        });
    }

    /// <summary>
    /// SFC reports corruption only with "found integrity violations". Any other ending (another repair or DISM scan running, a restart
    /// pending, no administrator rights, no output at all) means no scan took place, so it is recorded as "Couldn't run" with the reason,
    /// never as Critical.
    /// </summary>
    protected override string? CouldNotRunReason(string output, RemotePCDiagnostics.Core.Osquery.ProcessResult? result) =>
        NoResultReason(output, result?.ExitCode, result is not null);

    /// <summary>Why <c>sfc /verifyonly</c> gave no verdict. <paramref name="returned"/> false: the tool didn't start or timed out.</summary>
    public static string NoResultReason(string output, int? exitCode, bool returned = true)
    {
        if (!returned)
            return "SFC did not start or did not finish within 30 minutes, so no scan result is available. " + ElevationService.AdminRepairHint;
        if (Contains(output, "servicing or repair operation"))
            return "SFC did not run because another servicing or repair operation is running (for example a DISM scan or Windows Update). Run SFC again when it has finished.";
        if (Contains(output, "system repair pending") || exitCode == WindowsRepair.RebootRequiredExitCode)
            return "SFC did not run because a system repair is waiting for a restart. Restart the PC, then run SFC again.";
        if (Contains(output, "must be an administrator"))
            return "SFC did not run because it needs administrator rights. " + ElevationService.AdminRepairHint;
        if (Contains(output, "could not start the repair service"))
            return "SFC did not run because Windows Resource Protection could not start its repair service (Windows Modules Installer). Restart the PC and try again.";
        if (Contains(output, "could not perform the requested operation"))
            return "SFC could not perform the scan, so no result is available. Run the DISM check, restart, then run SFC again.";
        var lastLine = LastMessageLine(output);
        if (lastLine is null)
            return $"SFC ended without any output (exit code {exitCode}), so no scan took place. Run it again; if this repeats, check whether a DISM scan or Windows Update is running.";
        return $"SFC ended without a scan result (exit code {exitCode}). Its last message was: \"{lastLine}\"";
    }
}
