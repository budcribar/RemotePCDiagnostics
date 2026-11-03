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
        if (result is null) return AreaReport.Failed(FailedMessage);

        var output = (result.StdOut + "\n" + result.StdErr).Replace("\0", "").Trim();
        bool Has(string text) => output.Contains(text, StringComparison.OrdinalIgnoreCase);
        var clean = componentStore ? Has("No component store corruption detected") : Has("did not find any integrity violations");
        var corrupt = componentStore ? Has("component store is repairable") || Has("component store cannot be repaired")
            : Has("found integrity violations");
        var status = corrupt ? DiagnosticStatus.Warning : clean && result.ExitCode == 0 ? DiagnosticStatus.Ok : DiagnosticStatus.Error;
        var summary = status switch
        {
            DiagnosticStatus.Ok => "No corruption detected",
            DiagnosticStatus.Warning when !componentStore => "SFC found integrity violations in protected system files.",
            DiagnosticStatus.Warning when Has("component store cannot be repaired") => "DISM found component store corruption and reports that the store cannot be repaired.",
            DiagnosticStatus.Warning => "DISM found repairable corruption in the Windows component store.",
            _ => "Integrity scan could not confirm a result"
        };
        return new([new("integrity", DisplayName, status switch
            {
                DiagnosticStatus.Ok => AreaLevel.Ok,
                DiagnosticStatus.Warning => AreaLevel.Warning,
                _ => AreaLevel.Error
            }, summary, $"Exit code {result.ExitCode}", ["Detail", "Value"],
            [new(AreaLevel.Neutral, ["Command", $"{Path.GetFileName(exe)} {string.Join(' ', args)}"]),
             new(AreaLevel.Neutral, ["Output", output.Length > 12000 ? output[^12000..] : output])])], summary, status);
    }
}
