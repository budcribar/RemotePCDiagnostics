using System.Collections.Concurrent;

namespace RemotePCDiagnostics.Core;

/// <summary>Registers modules and runs them independently, recording results in the store.</summary>
public sealed class DiagnosticsService
{
    private readonly List<IDiagnosticModule> _modules = new();
    private readonly ResultStore _store;
    private readonly ConcurrentDictionary<string, Task<DiagnosticResult>> _inFlight = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

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

    /// <summary>Runs every module concurrently; a slow or failing module does not block the others.
    /// On-demand modules (<see cref="IDiagnosticModule.IncludeInRunAll"/> false, e.g. stress tests) are skipped.</summary>
    public Task<DiagnosticResult[]> RunAllAsync(CancellationToken ct = default)
    {
        var modules = _modules.Where(m => m.IncludeInRunAll).ToArray();
        return Task.WhenAll(modules.Select(m => RunAsync(m, null, ct)));
    }

    private void MarkRunning(IDiagnosticModule module) =>
        _store.Set(new DiagnosticResult(module.Name, DiagnosticStatus.Running, "Running…", DateTimeOffset.Now));

    /// <summary>True while a run of the module is in flight.</summary>
    public bool IsRunning(string moduleName) => _inFlight.ContainsKey(moduleName);

    /// <summary>Starts a run unless one is already in progress, in which case the in-flight task is returned (no double-runs).</summary>
    private Task<DiagnosticResult> RunAsync(IDiagnosticModule module, IProgress<string>? progress, CancellationToken ct)
    {
        lock (_gate)
        {
            if (_inFlight.TryGetValue(module.Name, out var existing)) return existing;
            MarkRunning(module);
            var tcs = new TaskCompletionSource<DiagnosticResult>(TaskCreationOptions.RunContinuationsAsynchronously);
            _inFlight[module.Name] = tcs.Task;
            _ = Task.Run(async () =>
            {
                try { tcs.SetResult(await RunCoreAsync(module, progress, ct).ConfigureAwait(false)); }
                catch (Exception ex) { tcs.SetException(ex); }
                finally { _inFlight.TryRemove(module.Name, out _); }
            }, CancellationToken.None);
            return tcs.Task;
        }
    }

    private async Task<DiagnosticResult> RunCoreAsync(IDiagnosticModule module, IProgress<string>? progress, CancellationToken ct)
    {
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
