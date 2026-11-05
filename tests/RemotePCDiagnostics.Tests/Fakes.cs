using System.Security.Cryptography;
using System.Text;
using RemotePCDiagnostics.Core;

namespace RemotePCDiagnostics.Tests;

internal sealed class FakeModule(string name, Func<IProgress<string>?, CancellationToken, Task<DiagnosticResult>> run, bool available = true) : IDiagnosticModule
{
    public FakeModule(string name, Func<CancellationToken, Task<DiagnosticResult>> run, bool available = true) : this(name, (_, ct) => run(ct), available) { }
    public string Name => name;
    public Guid Id => TestIds.For(name);
    public event EventHandler<DiagnosticResult>? Updated;
    public void Push(DiagnosticResult r) => Updated?.Invoke(this, r);
    public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken ct = default) =>
        Task.FromResult(available ? ModuleAvailability.Available : ModuleAvailability.Unavailable("missing tool"));
    public Task<DiagnosticResult> RefreshAsync(IProgress<string>? p, CancellationToken ct = default) => run(p, ct);

    public static DiagnosticResult Ok(string n) => new(n, DiagnosticStatus.Ok, "fine", DateTimeOffset.Now);
}

/// <summary>Ids for test modules: the built-in id when the name is a built-in slug, otherwise a stable id made from the name.</summary>
internal static class TestIds
{
    public static Guid For(string name) => ModuleIds.FromSlug(name) ?? new Guid(MD5.HashData(Encoding.UTF8.GetBytes(name)));
}
