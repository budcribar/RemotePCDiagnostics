namespace RemotePCDiagnostics.Core.Areas;

/// <summary>Base for card/drawer diagnostic areas. Never lets a collection exception reach the UI as raw text.</summary>
public abstract class AreaModuleBase(Action<string>? log) : IDiagnosticModule
{
    public abstract string Name { get; }
    public abstract Guid Id { get; }
    public abstract string DisplayName { get; }
    /// <summary>Friendly text used when collection fails unexpectedly.</summary>
    protected abstract string FailedMessage { get; }
    public event EventHandler<DiagnosticResult>? Updated;

    public virtual Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult(ModuleAvailability.Available);

    public async Task<DiagnosticResult> RefreshAsync(IProgress<string>? progress, CancellationToken cancellationToken = default)
    {
        AreaReport report;
        try { report = await CollectAsync(progress, cancellationToken).ConfigureAwait(false); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            Log($"{Name}: collection failed: {ex}");
            report = AreaReport.Failed(FailedMessage);
        }
        return new DiagnosticResult<AreaReport>(Name, report.Status, report.Summary, DateTimeOffset.Now, report) { Cancelled = report.Cancelled };
    }

    protected abstract Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct);

    protected void Log(string message) { try { log?.Invoke(message); } catch { /* logging never breaks a run */ } }

    protected internal void RaiseUpdated(DiagnosticResult r) => Updated?.Invoke(this, r);

    public static string Plural(int n, string one, string? many = null) => n == 1 ? $"1 {one}" : $"{n} {many ?? one + "s"}";
}

