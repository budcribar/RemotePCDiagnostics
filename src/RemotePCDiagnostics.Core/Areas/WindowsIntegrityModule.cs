namespace RemotePCDiagnostics.Core.Areas;

/// <summary>
/// Read-only Windows integrity scan (one run of a system tool, live percent, cancel). <see cref="DismScanHealthModule"/> and
/// <see cref="SfcVerifyOnlyModule"/> supply the tool, its arguments and how to read its output. The log helpers here are shared
/// with <see cref="WindowsRepair"/>.
/// </summary>
public abstract class WindowsIntegrityModule(SystemCommandRunner commands) : AreaModuleBase(commands.Log)
{
    public bool IncludeInRunAll => false;
    private readonly object _scanGate = new();
    private CancellationTokenSource? _scan;

    /// <summary>Executable in the Windows system directory ("dism.exe", "sfc.exe").</summary>
    protected abstract string ToolExe { get; }
    protected abstract string[] Arguments { get; }
    /// <summary>Status and summary for the scan's (NUL-free, trimmed) output. <paramref name="result"/> is null when the tool didn't return.</summary>
    protected abstract (DiagnosticStatus Status, string Summary) Interpret(string output, RemotePCDiagnostics.Core.Osquery.ProcessResult? result);
    /// <summary>False: a scan that didn't return (start failure, timeout) is reported as failed straight away.</summary>
    protected virtual bool InterpretWithoutResult => false;
    /// <summary>Strips tool noise (progress bars) from the output shown to the user.</summary>
    protected virtual string CleanOutput(string output) => output;
    /// <summary>Called just before the tool starts (e.g. to note where the servicing logs end).</summary>
    protected virtual void OnScanStarting() { }
    /// <summary>Extra detail rows when the scan didn't come back clean.</summary>
    protected virtual void AddProblemEvidence(List<AreaRow> rows) { }

    public void Cancel()
    {
        lock (_scanGate) _scan?.Cancel();
    }

    protected override string FailedMessage => "The integrity scan could not complete. Run RemotePCDiagnostics as administrator and try again.";

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        progress?.Report("Checking Windows integrity. This can take several minutes.");
        var exe = SystemCommandRunner.SystemTool(ToolExe);
        var args = Arguments;
        using var scan = CancellationTokenSource.CreateLinkedTokenSource(ct);
        lock (_scanGate) _scan = scan;
        var started = DateTimeOffset.Now;
        OnScanStarting();
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
        if (result is null && !InterpretWithoutResult) return AreaReport.Failed(FailedMessage);

        var output = CleanOutput((result?.StdOut + "\n" + result?.StdErr).Replace("\0", "").Trim());
        var (status, summary) = Interpret(output, result);
        var rows = new List<AreaRow>
        {
            new(AreaLevel.Neutral, ["Command", $"{Path.GetFileName(exe)} {string.Join(' ', args)}"]),
            new(AreaLevel.Neutral, ["Output", output.Length > 12000 ? output[^12000..] : output])
        };
        if (status != DiagnosticStatus.Ok) AddProblemEvidence(rows);

        return new([new("integrity", DisplayName, status switch
            {
                DiagnosticStatus.Ok => AreaLevel.Ok,
                DiagnosticStatus.Warning => AreaLevel.Warning,
                _ => AreaLevel.Error
            }, summary, result is null ? "Scan did not return an exit code" : $"Exit code {result.ExitCode}",
            ["Detail", "Value"], rows)], summary, status);
    }

    /// <summary>Warning when corruption was reported, Ok when the clean message came with exit code 0, otherwise Error.</summary>
    protected static DiagnosticStatus Classify(bool corrupt, bool clean, RemotePCDiagnostics.Core.Osquery.ProcessResult? result) =>
        corrupt ? DiagnosticStatus.Warning : clean && result?.ExitCode == 0 ? DiagnosticStatus.Ok : DiagnosticStatus.Error;

    protected static bool Contains(string output, string text) => output.Contains(text, StringComparison.OrdinalIgnoreCase);

    /// <summary>%windir%\Logs\<paramref name="folder"/>\<paramref name="file"/>.</summary>
    internal static string WindowsLog(string folder, string file) =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Logs", folder, file);

    internal static long? LogLength(string path)
    {
        try { return new FileInfo(path).Length; }
        catch (FileNotFoundException) { return 0; }
        catch (DirectoryNotFoundException) { return 0; }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return null; }
    }

    internal static string SummarizeCbs(string excerpt)
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

    internal static string ReadLogEvidence(string path, long? offset)
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

    /// <summary>Lines appended to a log since <paramref name="offset"/> (last 1 MB at most); empty when unreadable.</summary>
    internal static IReadOnlyList<string> ReadNewLines(string path, long? offset)
    {
        if (offset is null) return [];
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (stream.Length < offset.Value) return [];
            var start = Math.Max(offset.Value, stream.Length - 1024 * 1024);
            stream.Position = start;
            var bytes = new byte[(int)(stream.Length - start)];
            var count = stream.ReadAtLeast(bytes, bytes.Length, throwOnEndOfStream: false);
            return System.Text.Encoding.UTF8.GetString(bytes, 0, count).Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return []; }
    }
}
