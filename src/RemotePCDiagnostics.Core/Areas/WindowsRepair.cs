using System.Text.RegularExpressions;
using RemotePCDiagnostics.Core.Osquery;

using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>Result of a DISM RestoreHealth or SFC /scannow repair, in the same shape as a check finding.</summary>
public sealed record RepairResult(
    string Id, string Title, DiagnosticStatus Status, string Summary, string Evidence, bool RebootRequired,
    IReadOnlyList<(string Label, string Value)> Details)
{
    public bool Success => Status == DiagnosticStatus.Ok;
}

/// <summary>One Windows repair step. Each runs alone, so a repair can be done step by step with a restart in between.</summary>
public enum RepairStep
{
    /// <summary>Read-only: <c>DISM /AnalyzeComponentStore</c>.</summary>
    AnalyzeStore,
    /// <summary><c>DISM /StartComponentCleanup</c>: removes superseded component versions.</summary>
    CleanUpStore,
    /// <summary><c>DISM /RestoreHealth</c> from Windows Update.</summary>
    RestoreHealth,
    /// <summary><c>DISM /RestoreHealth /Source:… /LimitAccess</c> from a Windows image.</summary>
    RestoreHealthFromImage,
    /// <summary><c>SFC /scannow</c>.</summary>
    SfcScanNow,
}

/// <summary>One image inside an install.wim / install.esd, as <c>DISM /Get-WimInfo /Index:n</c> reports it.</summary>
public sealed record WimImageInfo(int Index, string Name, string Edition, string Version);

/// <summary>
/// Windows repair steps: <c>DISM /RestoreHealth</c> (component store) and <c>SFC /scannow</c> (protected files) for the service workflow,
/// plus the single steps offered on the DISM and SFC checks (analyze, cleanup, repair from a Windows image).
/// Parsing is pure (<see cref="ParseDism"/>, <see cref="ParseSfc"/>) so it can be tested with sample output. DISM is run with /English;
/// SFC output is localized, so SFC also relies on its exit code and the CBS.log "[SR]" lines (English in every language).
/// </summary>
public static class WindowsRepair
{
    public const string DismId = "dism-restorehealth", SfcId = "sfc-scannow";
    public const string AnalyzeId = "dism-analyzecomponentstore", CleanupId = "dism-startcomponentcleanup", ImageId = "dism-restorehealth-image";
    public const string DismTitle = "Repair Windows component store (DISM RestoreHealth)", SfcTitle = "Repair protected system files (SFC /scannow)";
    public const string AnalyzeTitle = "Analyze Windows component store", CleanupTitle = "Clean up Windows component store",
        ImageTitle = "Repair Windows component store from a Windows image";
    public static readonly string[] DismArgs = ["/English", "/Online", "/Cleanup-Image", "/RestoreHealth"];
    public static readonly string[] AnalyzeArgs = ["/English", "/Online", "/Cleanup-Image", "/AnalyzeComponentStore"];
    public static readonly string[] CleanupArgs = ["/English", "/Online", "/Cleanup-Image", "/StartComponentCleanup"];
    public static readonly string[] SfcArgs = ["/scannow"];
    public static readonly TimeSpan DismTimeout = TimeSpan.FromMinutes(45), SfcTimeout = TimeSpan.FromMinutes(45);
    public static readonly TimeSpan AnalyzeTimeout = TimeSpan.FromMinutes(15), ImageInfoTimeout = TimeSpan.FromMinutes(2);
    /// <summary>DISM refuses a cleanup or repair while an earlier servicing operation waits for a restart.</summary>
    public const string PendingOperationsCode = "0x800f0806";

    public static string IdOf(RepairStep step) => step switch
    {
        RepairStep.AnalyzeStore => AnalyzeId, RepairStep.CleanUpStore => CleanupId, RepairStep.RestoreHealth => DismId,
        RepairStep.RestoreHealthFromImage => ImageId, _ => SfcId,
    };

    public static string TitleOf(RepairStep step) => step switch
    {
        RepairStep.AnalyzeStore => AnalyzeTitle, RepairStep.CleanUpStore => CleanupTitle, RepairStep.RestoreHealth => DismTitle,
        RepairStep.RestoreHealthFromImage => ImageTitle, _ => SfcTitle,
    };

    /// <summary>The <c>/Source</c> argument for one image in a .wim or .esd file.</summary>
    public static string ImageSourceArg(string imagePath, int index) =>
        $"/Source:{(imagePath.EndsWith(".esd", StringComparison.OrdinalIgnoreCase) ? "ESD" : "WIM")}:{imagePath}:{index}";

    /// <summary>A path this app passes to DISM as a repair source: a rooted path to a .wim or .esd file, with nothing a command line could misread.</summary>
    public static bool IsImagePath(string? path) =>
        !string.IsNullOrWhiteSpace(path) && path.Length <= 260 && path.IndexOfAny(['"', '\r', '\n', '<', '>', '|', '*', '?']) < 0
        && (path.EndsWith(".wim", StringComparison.OrdinalIgnoreCase) || path.EndsWith(".esd", StringComparison.OrdinalIgnoreCase))
        && (path.Length > 3 && char.IsAsciiLetter(path[0]) && path[1] == ':' && path[2] == '\\' || path.StartsWith(@"\\", StringComparison.Ordinal));

    /// <summary>"Current Edition : Professional" from <c>DISM /Online /Get-CurrentEdition</c>; null when absent.</summary>
    public static string? ParseCurrentEdition(string? output) =>
        Regex.Match(output ?? "", @"(?im)^\s*Current Edition\s*:\s*(\S+)") is { Success: true } m ? m.Groups[1].Value : null;

    /// <summary>The index numbers <c>DISM /Get-WimInfo /WimFile:…</c> lists.</summary>
    public static IReadOnlyList<int> ParseWimIndexes(string? output) =>
        Regex.Matches(output ?? "", @"(?im)^\s*Index\s*:\s*(\d+)").Select(m => int.Parse(m.Groups[1].Value)).Distinct().ToList();

    /// <summary>One image's name, edition and version from <c>DISM /Get-WimInfo /WimFile:… /Index:n</c>; null when the edition is absent.</summary>
    public static WimImageInfo? ParseWimImage(int index, string? output)
    {
        string Field(string name) => Regex.Match(output ?? "", $@"(?im)^\s*{name}\s*:\s*(.+?)\s*$") is { Success: true } m ? m.Groups[1].Value : "";
        var edition = Field("Edition");
        if (edition.Length == 0) return null;
        var version = Field("Version");
        var build = Field("ServicePack Build");
        return new(index, Field("Name"), edition, build.Length > 0 && version.Length > 0 ? $"{version}.{build}" : version);
    }

    /// <summary>DISM /AnalyzeComponentStore output (English) + exit code → status and plain summary.</summary>
    public static (DiagnosticStatus Status, string Summary, bool Reboot) ParseAnalyze(string output, int? exitCode)
    {
        var o = output ?? "";
        string Field(string name) => Regex.Match(o, $@"(?im)^\s*{name}\s*:\s*(.+?)\s*$") is { Success: true } m ? m.Groups[1].Value : "";
        var size = Field("Actual Size of Component Store");
        if (exitCode != 0 || size.Length == 0)
            return (DiagnosticStatus.Error, exitCode is null ? "DISM didn't finish (no exit code). " + ElevationService.AdminRepairHint
                : $"DISM couldn't analyze the component store (exit code {ExitCodeText(exitCode.Value)}).", false);
        var parts = new List<string> { $"Component store size: {size}" };
        if (Field("Backups and Disabled Features") is { Length: > 0 } backups) parts.Add($"backups and disabled features: {backups}");
        if (Field("Number of Reclaimable Packages") is { Length: > 0 } packages) parts.Add($"reclaimable packages: {packages}");
        if (Field("Date of Last Cleanup") is { Length: > 0 } last) parts.Add($"last cleanup: {last}");
        var recommended = Field("Component Store Cleanup Recommended");
        parts.Add(recommended.StartsWith("Yes", StringComparison.OrdinalIgnoreCase) ? "cleanup recommended"
            : recommended.Length > 0 ? "cleanup not needed" : "no cleanup recommendation reported");
        return (DiagnosticStatus.Ok, string.Join("; ", parts) + ".", false);
    }

    /// <summary>DISM /StartComponentCleanup output (English) + exit code → status and plain summary.</summary>
    public static (DiagnosticStatus Status, string Summary, bool Reboot) ParseCleanup(string output, int? exitCode)
    {
        var o = output ?? "";
        var reboot = exitCode == RebootRequiredExitCode || RebootText(o);
        if (Has(o, PendingOperationsCode) || exitCode == unchecked((int)0x800f0806))
            return (DiagnosticStatus.Error, "Windows is waiting for a restart to finish an earlier update or repair (0x800F0806). Restart the PC, then clean up again.", true);
        if (exitCode is 0 or RebootRequiredExitCode && (Has(o, "operation completed successfully") || o.Length == 0))
            return (DiagnosticStatus.Ok, reboot ? "Component store cleaned up; a restart finishes it." : "Component store cleaned up. Restart the PC before repairing the store again.", reboot);
        if (exitCode is null) return (DiagnosticStatus.Error, "DISM didn't finish (no exit code). " + ElevationService.AdminRepairHint, reboot);
        return (DiagnosticStatus.Error, $"DISM couldn't clean up the component store (exit code {ExitCodeText(exitCode.Value)}). See the output.", reboot);
    }

    private static string ExitCodeText(int exitCode) => exitCode < 0 ? $"0x{unchecked((uint)exitCode):X8}" : exitCode.ToString();
    public const int RebootRequiredExitCode = 3010; // ERROR_SUCCESS_REBOOT_REQUIRED

    /// <summary>Removes progress bars and "NN% complete" lines (DISM's [====  50.0%  ] bars, SFC's "Verification 45% complete.").</summary>
    public static string CleanOutput(string? raw)
    {
        var s = (raw ?? "").Replace("\0", "").Replace("\r\n", "\n").Replace('\r', '\n');
        s = Regex.Replace(s, @"(?m)^[ \t]*\[[= \t]*\d{1,3}(?:[.,]\d+)?%[= \t]*\][ \t]*$\n?", "");
        s = Regex.Replace(s, @"(?m)^[^\n%]{0,60}\b\d{1,3}(?:[.,]\d+)?\s*%[^\n%]{0,30}$\n?", "");
        s = Regex.Replace(s, @"\n{3,}", "\n\n");
        return s.Trim();
    }

    private static bool Has(string s, string t) => s.Contains(t, StringComparison.OrdinalIgnoreCase);

    private static bool RebootText(string s) => Has(s, "reboot") || Has(s, "restart the computer") || Has(s, "restart your computer") || Has(s, "pending") && Has(s, "restart");

    public static string? ExtractFailedPackage(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        var m = Regex.Match(text, @"(?im)(?:Failed to download payload for package|The repair content could not be found anywhere|Failed to finalize and optimize the package|Failed to restore package|Failed processing package)\s*:?\s*(?<pkg>[A-Za-z0-9_\.~-]+)");
        if (m.Success) return m.Groups["pkg"].Value.Trim();
        var fallback = Regex.Match(text, @"(?im)\b(?<pkg>(?:Package_for_|Microsoft-Windows-)[A-Za-z0-9_\.~-]+)");
        return fallback.Success ? fallback.Groups["pkg"].Value.Trim() : null;
    }

    public static string SummarizeDism(string? dismExcerpt)
    {
        if (string.IsNullOrWhiteSpace(dismExcerpt)) return "No DISM log excerpt available.";

        var findings = new List<string>();

        var packageMatches = Regex.Matches(dismExcerpt,
            @"(?im)(?:Failed to download payload for package|The repair content could not be found anywhere|Failed to finalize and optimize the package|Failed to restore package|Failed processing package)\s*:?\s*(?<pkg>[A-Za-z0-9_\.~-]+)");
        var packages = packageMatches
            .Select(m => m.Groups["pkg"].Value.Trim())
            .Where(p => p.StartsWith("Package_", StringComparison.OrdinalIgnoreCase) || p.StartsWith("Microsoft-Windows-", StringComparison.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var errorLineMatches = Regex.Matches(dismExcerpt,
            @"(?im)\b(?<msg>The repair content could not be found anywhere|Failed to download payload for package[^\r\n,]+|Failed to get provider[^\r\n,]+|Failed to find directory[^\r\n,]+)")
            .Select(m => m.Groups["msg"].Value.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (packages.Count > 0)
        {
            var pkgList = string.Join(", ", packages.Take(3)) + (packages.Count > 3 ? $" (+{packages.Count - 3} more)" : "");
            if (errorLineMatches.Any(m => m.Contains("repair content could not be found", StringComparison.OrdinalIgnoreCase) || m.Contains("Failed to download payload", StringComparison.OrdinalIgnoreCase)))
            {
                findings.Add($"Missing repair payload for package: {pkgList}");
            }
            else
            {
                findings.Add($"Package repair failed: {pkgList}");
            }
        }
        else if (errorLineMatches.Count > 0)
        {
            findings.AddRange(errorLineMatches.Take(3));
        }

        var codes = Regex.Matches(dismExcerpt, @"(?i)\b0x8[0-9a-f]{7}\b")
            .Select(m => m.Value.ToUpperInvariant())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(5)
            .ToList();

        if (findings.Count > 0)
        {
            var summary = string.Join("; ", findings);
            if (codes.Count > 0 && !summary.Contains("0x", StringComparison.OrdinalIgnoreCase))
                summary += $" ({string.Join(", ", codes)})";
            return summary;
        }

        if (codes.Count > 0)
            return $"DISM recorded servicing errors ({string.Join(", ", codes)}). The excerpt did not identify a specific package.";

        return dismExcerpt.Contains('\n')
            ? "The DISM excerpt did not identify a specific failed package. See the log excerpts for context."
            : dismExcerpt;
    }

    /// <summary>DISM couldn't find the repair payload (DISM_E_SOURCE_NOT_FOUND / CBS_E_SOURCE_MISSING).</summary>
    public const string PayloadNotFoundCode = "0x800F0915", SourceFilesNotFoundCode = "0x800F081F";

    /// <summary>
    /// The error code when DISM RestoreHealth stopped because the files to repair from were missing, read from its output, exit code or
    /// the dism.log lines written during the run (dism.log names the missing payload even when the console shows a generic failure).
    /// Null for any other ending.
    /// </summary>
    public static string? MissingPayloadCode(string? output, int? exitCode, string? dismExcerpt = null)
    {
        var o = output ?? "";
        var log = dismExcerpt ?? "";
        if (exitCode == unchecked((int)0x800f0915) || Has(o, PayloadNotFoundCode)) return PayloadNotFoundCode;
        if (exitCode == unchecked((int)0x800f081f) || Has(o, SourceFilesNotFoundCode) || Has(o, "source files could not be found")) return SourceFilesNotFoundCode;
        if (Has(o, "repair content could not be found") || Has(log, "repair content could not be found") || Has(log, "Failed to download payload")
            || Has(log, PayloadNotFoundCode))
            return PayloadNotFoundCode;
        return Has(log, SourceFilesNotFoundCode) ? SourceFilesNotFoundCode : null;
    }

    /// <summary>The reason and the next step when the repair payload is missing (see <see cref="MissingPayloadCode"/>).</summary>
    public static string MissingPayloadSummary(string code, bool fromImage)
    {
        var what = code == PayloadNotFoundCode ? "repair payload not found" : "repair source not found";
        return fromImage
            ? $"The Windows image doesn't have the files needed to repair the component store ({code}, {what}), so the store wasn't repaired. "
                + "Next step: use an ISO of exactly this PC's Windows version and edition (an older or newer build doesn't match), "
                + "or install the latest Windows cumulative update and repair from Windows Update again."
            : $"Windows Update doesn't have the files needed to repair the component store ({code}, {what}), so the store wasn't repaired. "
                + "Next step: mount a Windows ISO of the same version and edition as this PC, run the component store check again, "
                + "then choose Repair from that image. Installing the latest Windows cumulative update, then repairing again, can also work.";
    }

    /// <summary>DISM /RestoreHealth output (English) + exit code → status and plain summary.</summary>
    /// <param name="fromImage">True for a repair from a Windows image (<c>/Source … /LimitAccess</c>), which changes the advice when files are missing.</param>
    public static (DiagnosticStatus Status, string Summary, bool Reboot) ParseDism(string output, int? exitCode, string? dismExcerpt = null, bool fromImage = false)
    {
        var o = output ?? "";
        var reboot = exitCode == RebootRequiredExitCode || RebootText(o);
        var pkg = ExtractFailedPackage(dismExcerpt) ?? ExtractFailedPackage(o);
        var pkgSuffix = pkg is not null ? $" Failed package: {pkg}." : "";

        string? Hint()
        {
            // dism.log can mention a payload that failed from one source and then came from another, so it only counts when DISM failed.
            var failed = exitCode is not (0 or RebootRequiredExitCode);
            if (MissingPayloadCode(o, exitCode, failed ? dismExcerpt : null) is { } code) return MissingPayloadSummary(code, fromImage);
            if (Has(o, "0x800f0906") || exitCode == unchecked((int)0x800f0906))
                return "Windows couldn't download the repair files (0x800f0906). Check the internet connection and that Windows Update is reachable, then try again.";
            if (Has(o, "0x800f0907") || exitCode == unchecked((int)0x800f0907))
                return "The repair source is blocked by Group Policy (0x800F0907). Network access to Windows Update or the specified repair source is prohibited by policy.";
            if (Has(o, "0x800f0954") || exitCode == unchecked((int)0x800f0954))
                return "Downloading repair files is blocked by policy (0x800f0954), e.g. WSUS or Group Policy. Allow Windows Update as a repair source or supply a /Source.";
            if (Has(o, "0x80073712") || exitCode == unchecked((int)0x80073712))
                return "The Windows component store is corrupted (0x80073712). A required component manifest is missing or damaged. Repair needs a matching Windows installation source (ISO / /Source).";
            if (Has(o, "0x80070002") || exitCode == unchecked((int)0x80070002) || Has(o, "0x80070003") || exitCode == unchecked((int)0x80070003))
                return "Windows could not find the specified file or path for repair (0x80070002/0x80070003). Check that the repair source path is valid and accessible.";
            return null;
        }

        if (Hint() is { } h) return (DiagnosticStatus.Error, h + pkgSuffix, reboot);
        if ((exitCode is 0 or RebootRequiredExitCode) && Has(o, "restore operation completed successfully"))
            return (DiagnosticStatus.Ok, reboot ? "Windows component store repaired; a restart finishes the repair." : "Windows component store repaired. No restart needed.", reboot);
        if ((exitCode is 0 or RebootRequiredExitCode) && o.Length == 0)
            return (DiagnosticStatus.Ok, "DISM reported success.", reboot);
        if (exitCode is null) return (DiagnosticStatus.Error, "DISM didn't finish (no exit code). " + ElevationService.AdminRepairHint, reboot);

        var codeStr = exitCode.Value < 0 ? $"0x{unchecked((uint)exitCode.Value):X8}" : exitCode.Value.ToString();
        var dismSummary = !string.IsNullOrWhiteSpace(dismExcerpt) ? SummarizeDism(dismExcerpt) : null;
        var summary = dismSummary is not null
            && !dismSummary.StartsWith("No DISM log", StringComparison.OrdinalIgnoreCase)
            && !dismSummary.StartsWith("The DISM excerpt did not", StringComparison.OrdinalIgnoreCase)
            ? $"DISM couldn't repair the component store (exit code {codeStr}): {dismSummary}"
            : $"DISM couldn't repair the component store (exit code {codeStr}).{pkgSuffix} See the DISM log excerpt.";

        return (DiagnosticStatus.Error, summary, reboot);
    }

    /// <summary>SFC /scannow output (may be localized), exit code and the CBS.log [SR] lines written during the run → status and summary.</summary>
    public static (DiagnosticStatus Status, string Summary, bool Reboot) ParseSfc(string output, int? exitCode, IEnumerable<string>? cbsSrLines = null)
    {
        var o = output ?? "";
        var sr = (cbsSrLines ?? []).ToList();
        var cannot = Has(o, "unable to fix") || sr.Any(l => Has(l, "Cannot repair member file") || Has(l, "Could not reproject corrupted file"));
        var repaired = Has(o, "successfully repaired") || sr.Any(l => Has(l, "Repairing corrupted file") || Has(l, "Repaired file"));
        var clean = Has(o, "did not find any integrity violations");
        var pending = Has(o, "system repair pending") || exitCode == RebootRequiredExitCode;
        var reboot = pending || RebootText(o) && (repaired || cannot);
        if (cannot) return (DiagnosticStatus.Error, "SFC found corrupt files but was unable to fix some of them. Run DISM RestoreHealth, restart, then run SFC again.", reboot);
        if (pending) return (DiagnosticStatus.Warning, "A system repair is waiting for a restart; SFC runs again after the restart.", true);
        if (repaired) return (DiagnosticStatus.Ok, reboot ? "SFC found corrupt files and repaired them (repaired; a restart completes it)." : "SFC found corrupt files and repaired them (repaired).", reboot);
        if (clean) return (DiagnosticStatus.Ok, "SFC did not find any integrity violations.", reboot);
        // Localized output: trust the exit code plus CBS showing a finished verify without repairs.
        if (exitCode == 0 && sr.Any(l => Has(l, "Verify complete"))) return (DiagnosticStatus.Ok, "SFC finished and found nothing to repair (from CBS.log).", reboot);
        if (exitCode is null) return (DiagnosticStatus.Error, "SFC didn't finish (no exit code). " + ElevationService.AdminRepairHint, reboot);
        return (DiagnosticStatus.Error, $"SFC couldn't confirm the repair (exit code {exitCode}). See the CBS.log excerpt.", reboot);
    }

    /// <summary>Runs the repair. <paramref name="progress"/> gets "Repair 45% complete" lines.</summary>
    public static Task<RepairResult> RunAsync(SystemCommandRunner commands, bool componentStore, IProgress<string>? progress, CancellationToken ct) =>
        RunStepAsync(commands, componentStore ? RepairStep.RestoreHealth : RepairStep.SfcScanNow, null, progress, ct);

    /// <summary>Runs one repair step. <paramref name="imagePath"/> is the install.wim / install.esd for <see cref="RepairStep.RestoreHealthFromImage"/>.</summary>
    public static async Task<RepairResult> RunStepAsync(SystemCommandRunner commands, RepairStep step, string? imagePath, IProgress<string>? progress, CancellationToken ct)
    {
        var sfc = step == RepairStep.SfcScanNow;
        var restore = step is RepairStep.RestoreHealth or RepairStep.RestoreHealthFromImage;
        var exe = SystemCommandRunner.SystemTool(sfc ? "sfc.exe" : "dism.exe");
        var id = IdOf(step);
        var title = TitleOf(step);
        var details = new List<(string, string)>();
        string[] args;
        switch (step)
        {
            case RepairStep.AnalyzeStore: args = AnalyzeArgs; break;
            case RepairStep.CleanUpStore: args = CleanupArgs; break;
            case RepairStep.RestoreHealth: args = DismArgs; break;
            case RepairStep.SfcScanNow: args = SfcArgs; break;
            default:
                var (image, problem) = await FindImageAsync(commands, exe, imagePath, details, ct).ConfigureAwait(false);
                if (image is null) return new(id, title, DiagnosticStatus.Error, problem!, "Not started", false, details);
                args = [.. DismArgs, ImageSourceArg(imagePath!, image.Index), "/LimitAccess"];
                break;
        }

        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var cbsPath = Path.Combine(windows, "Logs", "CBS", "CBS.log");
        var dismPath = Path.Combine(windows, "Logs", "DISM", "dism.log");
        var cbsOffset = WindowsIntegrityModule.LogLength(cbsPath);
        var dismOffset = sfc ? null : WindowsIntegrityModule.LogLength(dismPath);
        double last = -1;
        long lastEmitTickMs = 0;
        var verb = step switch { RepairStep.AnalyzeStore => "Analysis", RepairStep.CleanUpStore => "Cleanup", _ => "Repair" };
        progress?.Report(step switch
        {
            RepairStep.AnalyzeStore => "Analyzing the Windows component store. This can take a few minutes.",
            RepairStep.CleanUpStore => "Cleaning up the Windows component store. This can take 10–30 minutes.",
            RepairStep.SfcScanNow => "Repairing protected system files. This can take 10–20 minutes.",
            _ => "Repairing the Windows component store. This can take 10–30 minutes.",
        });
        var timeout = step switch { RepairStep.AnalyzeStore => AnalyzeTimeout, RepairStep.SfcScanNow => SfcTimeout, _ => DismTimeout };
        ProcessResult? pr = await commands.RunAsync(exe, args, timeout, ct, line =>
        {
            if (!WindowsIntegrityModule.TryAcceptProgressPercent(line, ref last, ref lastEmitTickMs, out var p)) return;
            progress?.Report($"{verb} {p:0.#}% complete");
        }).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();
        var output = CleanOutput(pr?.StdOut + "\n" + pr?.StdErr);
        var srLines = sfc ? WindowsIntegrityModule.ReadNewLines(cbsPath, cbsOffset).Where(l => l.Contains("[SR]", StringComparison.Ordinal)).ToList() : [];
        var dismExcerpt = sfc ? null : WindowsIntegrityModule.ReadLogEvidence(dismPath, dismOffset);
        var (status, summary, reboot) = step switch
        {
            RepairStep.AnalyzeStore => ParseAnalyze(output, pr?.ExitCode),
            RepairStep.CleanUpStore => ParseCleanup(output, pr?.ExitCode),
            RepairStep.SfcScanNow => ParseSfc(output, pr?.ExitCode, srLines),
            _ => ParseDism(output, pr?.ExitCode, dismExcerpt, step == RepairStep.RestoreHealthFromImage),
        };
        details.Insert(0, ("Command", $"{Path.GetFileName(exe)} {string.Join(' ', args)}"));
        details.Insert(1, ("Output", output.Length > 12000 ? output[^12000..] : output));
        if (sfc && srLines.Count > 0) details.Add(("CBS [SR] lines", string.Join("\n", srLines.TakeLast(30))));
        if (status != DiagnosticStatus.Ok)
        {
            var cbs = WindowsIntegrityModule.ReadLogEvidence(cbsPath, cbsOffset);
            details.Add(("CBS summary", WindowsIntegrityModule.SummarizeCbs(cbs)));
            details.Add(("CBS log excerpt", cbs));
            if (!sfc && dismExcerpt is not null)
            {
                details.Add(("DISM summary", SummarizeDism(dismExcerpt)));
                details.Add(("DISM log excerpt", dismExcerpt));
            }
        }
        if (reboot) details.Add(("Restart", "Windows asked for a restart to finish."));
        var exitCodeDisplay = pr is null
            ? "No exit code (didn't finish)"
            : pr.ExitCode < 0
                ? $"Exit code 0x{unchecked((uint)pr.ExitCode):X8}"
                : $"Exit code {pr.ExitCode}";
        return new(id, title, status, summary, exitCodeDisplay, reboot, details);
    }

    /// <summary>
    /// Picks the image in <paramref name="imagePath"/> that matches the running Windows edition: DISM needs the index of the matching
    /// edition as its repair source. Returns the image, or the reason none could be used.
    /// </summary>
    private static async Task<(WimImageInfo? Image, string? Problem)> FindImageAsync(SystemCommandRunner commands, string dism, string? imagePath,
        List<(string, string)> details, CancellationToken ct)
    {
        if (!IsImagePath(imagePath)) return (null, "The Windows image path isn't a .wim or .esd file this app can use.");
        if (!commands.IsScripted && !File.Exists(imagePath))
            return (null, "The Windows image is no longer there. Mount the Windows ISO again, run the check again, then repair.");
        var current = ParseCurrentEdition((await commands.RunAsync(dism, ["/English", "/Online", "/Get-CurrentEdition"], ImageInfoTimeout, ct).ConfigureAwait(false))?.StdOut);
        if (current is null) return (null, "Couldn't read this PC's Windows edition. " + ElevationService.AdminRepairHint);
        var list = await commands.RunAsync(dism, ["/English", "/Get-WimInfo", $"/WimFile:{imagePath}"], ImageInfoTimeout, ct).ConfigureAwait(false);
        var indexes = ParseWimIndexes(list?.StdOut);
        if (indexes.Count == 0) return (null, "Couldn't read the Windows image. It may be damaged or not a Windows installation image.");
        var seen = new List<WimImageInfo>();
        foreach (var index in indexes)
        {
            var one = await commands.RunAsync(dism, ["/English", "/Get-WimInfo", $"/WimFile:{imagePath}", $"/Index:{index}"], ImageInfoTimeout, ct).ConfigureAwait(false);
            if (ParseWimImage(index, one?.StdOut) is not { } info) continue;
            seen.Add(info);
            if (!string.Equals(info.Edition, current, StringComparison.OrdinalIgnoreCase)) continue;
            details.Add(("Repair source", $"{imagePath}, image {info.Index}: {info.Name} ({info.Edition}), version {info.Version}"));
            return (info, null);
        }
        var editions = string.Join(", ", seen.Select(i => i.Edition).Distinct(StringComparer.OrdinalIgnoreCase));
        return (null, $"The Windows image has no {current} edition (it has: {(editions.Length > 0 ? editions : "none readable")}). Use an image of the same edition and version as this PC.");
    }
}
