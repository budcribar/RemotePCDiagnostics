using System.Collections.Concurrent;

namespace RemotePCDiagnostics.Core;

/// <summary>Latest result snapshot per module.</summary>
public sealed class ResultStore
{
    private readonly ConcurrentDictionary<string, DiagnosticResult> _results = new(StringComparer.OrdinalIgnoreCase);

    public event EventHandler<DiagnosticResult>? Changed;

    public IReadOnlyDictionary<string, DiagnosticResult> Snapshot => new Dictionary<string, DiagnosticResult>(_results);

    public DiagnosticResult Get(string moduleName) =>
        _results.TryGetValue(moduleName, out var r) ? r : DiagnosticResult.NotRun(moduleName);

    public void Set(DiagnosticResult result)
    {
        _results[result.ModuleName] = result;
        Changed?.Invoke(this, result);
    }
}
