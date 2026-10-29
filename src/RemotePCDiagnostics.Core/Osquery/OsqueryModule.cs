namespace RemotePCDiagnostics.Core.Osquery;

/// <summary>Stub module: reports osquery availability and returns placeholder data.</summary>
public sealed class OsqueryModule(OsqueryRunner runner) : IDiagnosticModule
{
    public string Name => "Osquery";
    public event EventHandler<DiagnosticResult>? Updated;

    public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult(runner.CheckAvailability());

    public Task<DiagnosticResult> RefreshAsync(IProgress<string>? progress, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        progress?.Report("Placeholder: no osquery queries implemented yet");
        var data = new Dictionary<string, string> { ["osqueryi"] = runner.ResolvedPath, ["note"] = "placeholder" };
        return Task.FromResult<DiagnosticResult>(new DiagnosticResult<Dictionary<string, string>>(
            Name, DiagnosticStatus.Ok, "osquery found (placeholder data)", DateTimeOffset.Now, data));
    }

    internal void RaiseUpdated(DiagnosticResult r) => Updated?.Invoke(this, r);
}
