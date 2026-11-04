using System.Text.RegularExpressions;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>Result of a DISM RestoreHealth or SFC /scannow repair, in the same shape as a check finding.</summary>
public sealed record RepairResult(
    string Id, string Title, DiagnosticStatus Status, string Summary, string Evidence, bool RebootRequired,
    IReadOnlyList<(string Label, string Value)> Details)
{
    public bool Success => Status == DiagnosticStatus.Ok;
}

/// <summary>
/// Windows repair for the service workflow: <c>DISM /RestoreHealth</c> (component store) and <c>SFC /scannow</c> (protected files).
/// Parsing is pure (<see cref="ParseDism"/>, <see cref="ParseSfc"/>) so it can be tested with sample output. DISM is run with /English;
/// SFC output is localized, so SFC also relies on its exit code and the CBS.log "[SR]" lines (English in every language).
/// </summary>
public static class WindowsRepair
{
    public const string DismId = "dism-restorehealth", SfcId = "sfc-scannow";
    public const string DismTitle = "Repair Windows component store (DISM RestoreHealth)", SfcTitle = "Repair protected system files (SFC /scannow)";
    public static readonly string[] DismArgs = ["/English", "/Online", "/Cleanup-Image", "/RestoreHealth"];
    public static readonly string[] SfcArgs = ["/scannow"];
    public static readonly TimeSpan DismTimeout = TimeSpan.FromMinutes(45), SfcTimeout = TimeSpan.FromMinutes(45);
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

    /// <summary>DISM /RestoreHealth output (English) + exit code → status and plain summary.</summary>
    public static (DiagnosticStatus Status, string Summary, bool Reboot) ParseDism(string output, int? exitCode)
    {
        var o = output ?? "";
        var reboot = exitCode == RebootRequiredExitCode || RebootText(o);
        string? Hint()
        {
            if (Has(o, "0x800f081f") || exitCode == unchecked((int)0x800f081f)) return "Windows couldn't find the files it needs to repair itself (0x800f081f). Repair needs a matching Windows installation source (ISO / /Source) or Windows Update.";
            if (Has(o, "0x800f0906") || exitCode == unchecked((int)0x800f0906)) return "Windows couldn't download the repair files (0x800f0906). Check the internet connection and that Windows Update is reachable, then try again.";
            if (Has(o, "0x800f0954") || exitCode == unchecked((int)0x800f0954)) return "Downloading repair files is blocked by policy (0x800f0954), e.g. WSUS or Group Policy. Allow Windows Update as a repair source or supply a /Source.";
            return null;
        }
        if (Hint() is { } h) return (DiagnosticStatus.Error, h, reboot);
        if ((exitCode is 0 or RebootRequiredExitCode) && Has(o, "restore operation completed successfully"))
            return (DiagnosticStatus.Ok, reboot ? "Windows component store repaired; a restart finishes the repair." : "Windows component store repaired.", reboot);
        if ((exitCode is 0 or RebootRequiredExitCode) && o.Length == 0)
            return (DiagnosticStatus.Ok, "DISM reported success.", reboot);
        if (exitCode is null) return (DiagnosticStatus.Error, "DISM didn't finish (no exit code). Run the app as administrator and try again.", reboot);
        return (DiagnosticStatus.Error, $"DISM couldn't repair the component store (exit code {exitCode}). See the DISM log excerpt.", reboot);
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
        if (exitCode is null) return (DiagnosticStatus.Error, "SFC didn't finish (no exit code). Run the app as administrator and try again.", reboot);
        return (DiagnosticStatus.Error, $"SFC couldn't confirm the repair (exit code {exitCode}). See the CBS.log excerpt.", reboot);
    }

    /// <summary>Runs the repair. <paramref name="progress"/> gets "Repair 45% complete" lines.</summary>
    public static async Task<RepairResult> RunAsync(SystemCommandRunner commands, bool componentStore, IProgress<string>? progress, CancellationToken ct)
    {
        var exe = SystemCommandRunner.SystemTool(componentStore ? "dism.exe" : "sfc.exe");
        var args = componentStore ? DismArgs : SfcArgs;
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var cbsPath = Path.Combine(windows, "Logs", "CBS", "CBS.log");
        var dismPath = Path.Combine(windows, "Logs", "DISM", "dism.log");
        var cbsOffset = WindowsIntegrityModule.LogLength(cbsPath);
        var dismOffset = componentStore ? WindowsIntegrityModule.LogLength(dismPath) : null;
        double last = -1;
        progress?.Report(componentStore ? "Repairing the Windows component store. This can take 10–30 minutes." : "Repairing protected system files. This can take 10–20 minutes.");
        ProcessResult? pr = await commands.RunAsync(exe, args, componentStore ? DismTimeout : SfcTimeout, ct, line =>
        {
            var m = Regex.Match(line.Replace("\0", ""), @"(?<![\d.])(\d{1,3}(?:[.,]\d+)?)\s*%");
            if (!m.Success || !double.TryParse(m.Groups[1].Value.Replace(',', '.'), System.Globalization.NumberStyles.AllowDecimalPoint,
                    System.Globalization.CultureInfo.InvariantCulture, out var p) || p > 100 || p <= last) return;
            last = p;
            progress?.Report($"Repair {p:0.#}% complete");
        }).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();
        var output = CleanOutput(pr?.StdOut + "\n" + pr?.StdErr);
        var srLines = componentStore ? [] : WindowsIntegrityModule.ReadNewLines(cbsPath, cbsOffset).Where(l => l.Contains("[SR]", StringComparison.Ordinal)).ToList();
        var (status, summary, reboot) = componentStore ? ParseDism(output, pr?.ExitCode) : ParseSfc(output, pr?.ExitCode, srLines);
        var details = new List<(string, string)>
        {
            ("Command", $"{Path.GetFileName(exe)} {string.Join(' ', args)}"),
            ("Output", output.Length > 12000 ? output[^12000..] : output),
        };
        if (!componentStore && srLines.Count > 0) details.Add(("CBS [SR] lines", string.Join("\n", srLines.TakeLast(30))));
        if (status != DiagnosticStatus.Ok)
        {
            var cbs = WindowsIntegrityModule.ReadLogEvidence(cbsPath, cbsOffset);
            details.Add(("CBS summary", WindowsIntegrityModule.SummarizeCbs(cbs)));
            details.Add(("CBS log excerpt", cbs));
            if (componentStore) details.Add(("DISM log excerpt", WindowsIntegrityModule.ReadLogEvidence(dismPath, dismOffset)));
        }
        if (reboot) details.Add(("Restart", "Windows asked for a restart to finish; the workflow's restart after the fixes covers it."));
        return new(componentStore ? DismId : SfcId, componentStore ? DismTitle : SfcTitle, status, summary,
            pr is null ? "No exit code (didn't finish)" : $"Exit code {pr.ExitCode}", reboot, details);
    }
}
