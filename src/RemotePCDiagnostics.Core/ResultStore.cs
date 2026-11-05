using System.Collections.Concurrent;

namespace RemotePCDiagnostics.Core;

/// <summary>Latest result snapshot per module, and per (module, hardware instance) for per-device modules.</summary>
public sealed class ResultStore
{
    private readonly ConcurrentDictionary<string, DiagnosticResult> _results = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DiagnosticResult> _instances = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>A module's result changed (never an instance result: pages keyed on the module name stay as they are).</summary>
    public event EventHandler<DiagnosticResult>? Changed;
    /// <summary>One instance's result changed (<see cref="DiagnosticResult.InstanceKey"/> set).</summary>
    public event EventHandler<DiagnosticResult>? InstanceChanged;

    private static string Key(string module, string instance) => module + "\u001f" + instance;

    /// <summary>The latest result for each instance of a module (in the order they were first stored).</summary>
    public IReadOnlyList<DiagnosticResult> InstancesOf(string moduleName) =>
        _instances.Where(kv => kv.Key.StartsWith(moduleName + "\u001f", StringComparison.OrdinalIgnoreCase)).Select(kv => kv.Value)
            .OrderBy(r => r.InstanceLabel, StringComparer.CurrentCultureIgnoreCase).ToList();

    public DiagnosticResult? GetInstance(string moduleName, string instanceKey) => _instances.GetValueOrDefault(Key(moduleName, instanceKey));

    public IReadOnlyDictionary<string, DiagnosticResult> Snapshot => new Dictionary<string, DiagnosticResult>(_results);

    public DiagnosticResult Get(string moduleName) =>
        _results.TryGetValue(moduleName, out var r) ? r : DiagnosticResult.NotRun(moduleName);

    public void Set(DiagnosticResult result)
    {
        if (result.InstanceKey is { } instance)
        {
            _instances[Key(result.ModuleName, instance)] = result;
            InstanceChanged?.Invoke(this, result);
            return;
        }
        _results[result.ModuleName] = result;
        Changed?.Invoke(this, result);
    }
}
