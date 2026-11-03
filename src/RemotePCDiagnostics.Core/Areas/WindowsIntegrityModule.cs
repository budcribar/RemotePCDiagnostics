namespace RemotePCDiagnostics.Core.Areas;

public sealed class WindowsIntegrityModule(SystemCommandRunner commands, bool componentStore) : AreaModuleBase(commands.Log)
{
    public override string Name => componentStore ? "DismScanHealth" : "SfcVerifyOnly";
    public override string DisplayName => componentStore ? "Windows component store (DISM)" : "Protected system files (SFC)";
    public bool IncludeInRunAll => false;
    private readonly object _scanGate = new();
    private CancellationTokenSource? _scan;

    public void Cancel()
    {
        lock (_scanGate) _scan?.Cancel();
    }

    protected override string FailedMessage => "The integrity scan could not complete. Run RemotePCDiagnostics as administrator and try again.";

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        progress?.Report("Checking Windows integrity. This can take several minutes.");
        var exe = SystemCommandRunner.SystemTool(componentStore ? "dism.exe" : "sfc.exe");
        string[] args = componentStore ? ["/English", "/Online", "/Cleanup-Image", "/ScanHealth"] : ["/verifyonly"];
        using var scan = CancellationTokenSource.CreateLinkedTokenSource(ct);
        lock (_scanGate) _scan = scan;
        var started = DateTimeOffset.Now;
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var cbsPath = Path.Combine(windows, "Logs", "CBS", "CBS.log");
        var dismPath = Path.Combine(windows, "Logs", "DISM", "dism.log");
        var cbsOffset = componentStore ? LogLength(cbsPath) : null;
        var dismOffset = componentStore ? LogLength(dismPath) : null;
        double lastPercent = -1;
        RemotePCDiagnostics.Core.Osquery.ProcessResult? result;
        try
        {
            result = await commands.RunAsync(exe, args, TimeSpan.FromMinutes(30), scan.Token, line =>
            {
                if (scan.IsCancellationRequested) return;
                var match = System.Text.RegularExpressions.Regex.Match(line.Replace("\0", ""), @"(?<![\d.])(\d{1,3}(?:[.,]\d+)?)\s*%");
                if (!match.Success || !double.TryParse(match.Groups[1].Value.Replace(',', '.'),
                    System.Globalization.NumberStyles.AllowDecimalPoint, System.Globalization.CultureInfo.InvariantCulture, out var percent)
                    || percent > 100 || percent <= lastPercent) return;
                lastPercent = percent;
                RaiseUpdated(new DiagnosticResult<double>(Name, DiagnosticStatus.Running, $"Scan {percent:0.#}% complete", started, percent));
            }).ConfigureAwait(false);
            scan.Token.ThrowIfCancellationRequested();
        }
        catch (OperationCanceledException) when (scan.IsCancellationRequested && !ct.IsCancellationRequested)
        {
            return new([], "Scan cancelled", DiagnosticStatus.Warning, Cancelled: true);
        }
        finally
        {
            lock (_scanGate) _scan = null;
        }
        if (result is null && !componentStore) return AreaReport.Failed(FailedMessage);

        var output = (result?.StdOut + "\n" + result?.StdErr).Replace("\0", "").Trim();
        if (componentStore)
            output = System.Text.RegularExpressions.Regex.Replace(output,
                @"(?m)^[ \t]*\[[= \t]*\d{1,3}(?:[.,]\d+)?%[= \t]*\][ \t]*\r?(?:\n|$)", "").Trim();
        bool Has(string text) => output.Contains(text, StringComparison.OrdinalIgnoreCase);
        var clean = componentStore ? Has("No component store corruption detected") : Has("did not find any integrity violations");
        var corrupt = componentStore ? Has("component store is repairable") || Has("component store cannot be repaired")
            : Has("found integrity violations");
        var status = corrupt ? DiagnosticStatus.Warning : clean && result?.ExitCode == 0 ? DiagnosticStatus.Ok : DiagnosticStatus.Error;
        var summary = status switch
        {
            DiagnosticStatus.Ok => "No corruption detected",
            DiagnosticStatus.Warning when !componentStore => "SFC found integrity violations in protected system files.",
            DiagnosticStatus.Warning when Has("component store cannot be repaired") => "DISM found component store corruption and reports that the store cannot be repaired.",
            DiagnosticStatus.Warning => "DISM found repairable corruption in the Windows component store.",
            _ when result is null => FailedMessage,
            _ => "Integrity scan could not confirm a result"
        };
        var rows = new List<AreaRow>
        {
            new(AreaLevel.Neutral, ["Command", $"{Path.GetFileName(exe)} {string.Join(' ', args)}"]),
            new(AreaLevel.Neutral, ["Output", output.Length > 12000 ? output[^12000..] : output])
        };
        if (componentStore && status != DiagnosticStatus.Ok)
        {
            var cbs = ReadLogEvidence(cbsPath, cbsOffset);
            rows.Add(new(AreaLevel.Neutral, ["CBS summary", SummarizeCbs(cbs)]));
            rows.Add(new(AreaLevel.Neutral, ["CBS findings during scan", cbs]));
            rows.Add(new(AreaLevel.Neutral, ["DISM log errors during scan", ReadLogEvidence(dismPath, dismOffset)]));
        }

        return new([new("integrity", DisplayName, status switch
            {
                DiagnosticStatus.Ok => AreaLevel.Ok,
                DiagnosticStatus.Warning => AreaLevel.Warning,
                _ => AreaLevel.Error
            }, summary, result is null ? "Scan did not return an exit code" : $"Exit code {result.ExitCode}",
            ["Detail", "Value"], rows)], summary, status);
    }

    private static long? LogLength(string path)
    {
        try { return new FileInfo(path).Length; }
        catch (FileNotFoundException) { return 0; }
        catch (DirectoryNotFoundException) { return 0; }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return null; }
    }

    private static string SummarizeCbs(string excerpt)
    {
        var findings = System.Text.RegularExpressions.Regex.Matches(excerpt,
            @"(?im)\b(?<kind>CSI (?:Payload|Manifest|Metadata) Corrupt(?:ion)?|CBS (?:MUM|CAT) (?:Missing|Corrupt))\s+(?:\([nw]\)\s*)?(?<item>[^\r\n]+)")
            .Select(match => $"{match.Groups["kind"].Value} · {match.Groups["item"].Value.Trim()}")
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (findings.Count > 0)
            return string.Join("\n", findings.Take(8)) + (findings.Count > 8 ? "\nMore entries are available in the excerpt below." : "");

        var codes = System.Text.RegularExpressions.Regex.Matches(excerpt, @"(?i)\b0x8[0-9a-f]{7}\b")
            .Select(match => match.Value).Distinct(StringComparer.OrdinalIgnoreCase).Take(5).ToList();
        return codes.Count > 0
            ? $"CBS recorded servicing errors ({string.Join(", ", codes)}). The excerpt did not identify a specific corrupt file or package."
            : excerpt.Contains('\n')
                ? "The CBS excerpt did not identify a specific corrupt file or package. See the log excerpts for context."
                : excerpt;
    }

    private static string ReadLogEvidence(string path, long? offset)
    {
        if (offset is null) return "The log could not be read before the scan.";
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (stream.Length < offset.Value) return "The log rotated during the scan. Check the archived servicing logs.";
            const int maxBytes = 1024 * 1024;
            var end = stream.Length;
            var start = Math.Max(offset.Value, end - maxBytes);
            stream.Position = start;
            var bytes = new byte[(int)(end - start)];
            var count = stream.ReadAtLeast(bytes, bytes.Length, throwOnEndOfStream: false);
            var lines = System.Text.Encoding.UTF8.GetString(bytes, 0, count).Split('\n', StringSplitOptions.TrimEntries);
            var findings = lines.Where(line =>
                System.Text.RegularExpressions.Regex.IsMatch(line, @"(?i)\b(?:corrupt(?:ion|ed)?|missing|error|failed|HRESULT)\b")
                && !line.Contains("No component store corruption", StringComparison.OrdinalIgnoreCase))
                .Distinct().TakeLast(30).Select(line => line.Length > 500 ? line[..500] + "…" : line).ToList();
            return findings.Count == 0 ? "No matching details in the log excerpt." : string.Join("\n", findings);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return "The servicing log is missing or inaccessible.";
        }
    }
}
