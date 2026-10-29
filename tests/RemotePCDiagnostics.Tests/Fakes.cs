using RemotePCDiagnostics.Core;

namespace RemotePCDiagnostics.Tests;

internal sealed class FakeModule(string name, Func<CancellationToken, Task<DiagnosticResult>> run, bool available = true) : IDiagnosticModule
{
    public string Name => name;
    public event EventHandler<DiagnosticResult>? Updated;
    public void Push(DiagnosticResult r) => Updated?.Invoke(this, r);
    public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken ct = default) =>
        Task.FromResult(available ? ModuleAvailability.Available : ModuleAvailability.Unavailable("missing tool"));
    public Task<DiagnosticResult> RefreshAsync(IProgress<string>? p, CancellationToken ct = default) => run(ct);

    public static DiagnosticResult Ok(string n) => new(n, DiagnosticStatus.Ok, "fine", DateTimeOffset.Now);
}
