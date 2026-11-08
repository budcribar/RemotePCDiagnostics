namespace RemotePCDiagnostics.Core;

/// <summary>
/// Shared plumbing for on-demand interactive diagnostic modules (<see cref="IncludeInRunAll"/> is false): linked cancellation token source
/// with <see cref="Cancel"/>, standard <see cref="DiagnosticResult.Cancelled"/> mapping, <see cref="Updated"/> event, and logger helpers.
/// </summary>
public abstract class OnDemandModuleBase(ILogger? log) : IDiagnosticModule
{
    private CancellationTokenSource? _runCts;
    protected readonly object Gate = new();

    protected ILogger? Logger => log;

    public abstract string Name { get; }
    public abstract Guid Id { get; }
    public abstract string DisplayName { get; }
    public bool IncludeInRunAll => false;
    public event EventHandler<DiagnosticResult>? Updated;

    protected internal void RaiseUpdated(DiagnosticResult r) => Updated?.Invoke(this, r);
    protected void Log(string m) => log.Info(m);
    protected void LogWarn(string m) => log.Warn(m);
    protected void LogError(string m) => log.Error(m);

    public void Cancel()
    {
        lock (Gate) { try { _runCts?.Cancel(); } catch (ObjectDisposedException) { } }
    }

    public virtual Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult(ModuleAvailability.Available);

    protected virtual string CancelledMessage => $"The {DisplayName.ToLowerInvariant()} was cancelled.";

    protected async Task<DiagnosticResult> RunGuardedAsync(Func<CancellationToken, Task<DiagnosticResult>> work, CancellationToken cancellationToken = default)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        lock (Gate) _runCts = cts;
        try { return await work(cts.Token).ConfigureAwait(false); }
        catch (OperationCanceledException) when (cts.IsCancellationRequested)
        {
            return new DiagnosticResult(Name, DiagnosticStatus.Warning, CancelledMessage, DateTimeOffset.Now) { Cancelled = true };
        }
        finally { lock (Gate) _runCts = null; }
    }

    public virtual Task<DiagnosticResult> RefreshAsync(IProgress<string>? progress, CancellationToken cancellationToken = default) =>
        RunGuardedAsync(ct => RunCoreAsync(progress, ct), cancellationToken);

    protected abstract Task<DiagnosticResult> RunCoreAsync(IProgress<string>? progress, CancellationToken ct);
}
