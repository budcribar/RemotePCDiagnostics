namespace RemotePCDiagnostics.Core;

public interface IDiagnosticModule
{
    string Name { get; }
    Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken cancellationToken = default);
    Task<DiagnosticResult> RefreshAsync(IProgress<string>? progress, CancellationToken cancellationToken = default);
    /// <summary>Raised when the module pushes an unsolicited update (e.g. live sensors).</summary>
    event EventHandler<DiagnosticResult>? Updated;
}
