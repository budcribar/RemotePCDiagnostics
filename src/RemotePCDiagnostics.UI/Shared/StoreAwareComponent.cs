using Microsoft.AspNetCore.Components;
using RemotePCDiagnostics.Core;

namespace RemotePCDiagnostics.UI.Shared;

/// <summary>Base component that re-renders when the ResultStore changes.</summary>
public abstract class StoreAwareComponent : ComponentBase, IDisposable
{
    [Inject] protected ResultStore Store { get; set; } = default!;
    [Inject] protected DiagnosticsService Diagnostics { get; set; } = default!;

    protected override void OnInitialized() => Store.Changed += OnChanged;
    private void OnChanged(object? s, DiagnosticResult r) => _ = InvokeAsync(StateHasChanged);
    public void Dispose() => Store.Changed -= OnChanged;

    protected static string DotClass(DiagnosticStatus s) => "dot dot-" + s.ToString().ToLowerInvariant();
}
