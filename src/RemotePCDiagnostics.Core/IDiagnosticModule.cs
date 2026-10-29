namespace RemotePCDiagnostics.Core;

public interface IDiagnosticModule
{
    string Name { get; }
    /// <summary>User-visible label (nav, dashboard). Defaults to <see cref="Name"/>.</summary>
    string DisplayName => Name;
    /// <summary>False for on-demand modules (stress tests) that must only run when the user presses Start; excluded from Run All.</summary>
    bool IncludeInRunAll => true;
    Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken cancellationToken = default);
    Task<DiagnosticResult> RefreshAsync(IProgress<string>? progress, CancellationToken cancellationToken = default);
    /// <summary>Raised when the module pushes an unsolicited update (e.g. live sensors).</summary>
    event EventHandler<DiagnosticResult>? Updated;
}
