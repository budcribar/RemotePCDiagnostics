namespace RemotePCDiagnostics.Core;

/// <summary>Registers modules and runs them independently, recording results in the store.</summary>
public sealed class DiagnosticsService
{
    private readonly List<IDiagnosticModule> _modules = new();
    private readonly ResultStore _store;

    public DiagnosticsService(ResultStore store, IEnumerable<IDiagnosticModule>? modules = null)
    {
        _store = store;
        foreach (var m in modules ?? []) Register(m);
    }

    public IReadOnlyList<IDiagnosticModule> Modules => _modules;

    public void Register(IDiagnosticModule module)
    {
        if (_modules.Any(m => string.Equals(m.Name, module.Name, StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException($"Module '{module.Name}' already registered.");
        _modules.Add(module);
        module.Updated += (_, r) => _store.Set(r);
        _store.Set(DiagnosticResult.NotRun(module.Name));
    }

    public async Task<DiagnosticResult> RunAsync(string moduleName, IProgress<string>? progress = null, CancellationToken ct = default)
    {
        var module = _modules.FirstOrDefault(m => string.Equals(m.Name, moduleName, StringComparison.OrdinalIgnoreCase))
            ?? throw new ArgumentException($"Unknown module '{moduleName}'.", nameof(moduleName));
        return await RunAsync(module, progress, ct).ConfigureAwait(false);
    }

    /// <summary>Runs every module concurrently; a slow or failing module does not block the others.</summary>
    public Task<DiagnosticResult[]> RunAllAsync(CancellationToken ct = default) =>
        Task.WhenAll(_modules.Select(m => Task.Run(() => RunAsync(m, null, ct), CancellationToken.None)));

    private async Task<DiagnosticResult> RunAsync(IDiagnosticModule module, IProgress<string>? progress, CancellationToken ct)
    {
        _store.Set(new DiagnosticResult(module.Name, DiagnosticStatus.Running, "Running…", DateTimeOffset.Now));
        DiagnosticResult result;
        try
        {
            var availability = await module.CheckAvailabilityAsync(ct).ConfigureAwait(false);
            result = availability.IsAvailable
                ? await module.RefreshAsync(progress, ct).ConfigureAwait(false)
                : new DiagnosticResult(module.Name, DiagnosticStatus.Error, availability.Reason ?? "Unavailable", DateTimeOffset.Now);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            result = new DiagnosticResult(module.Name, DiagnosticStatus.Warning, "Cancelled", DateTimeOffset.Now);
        }
        catch (Exception ex)
        {
            result = new DiagnosticResult(module.Name, DiagnosticStatus.Error, ex.Message, DateTimeOffset.Now, ex);
        }
        _store.Set(result);
        return result;
    }
}
