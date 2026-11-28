using Microsoft.AspNetCore.Components;
using RemotePCDiagnostics.Core;

namespace RemotePCDiagnostics.UI.Shared;

/// <summary>Base component that re-renders when the ResultStore changes.</summary>
public abstract class StoreAwareComponent : ComponentBase, IDisposable
{
    [Inject] protected ResultStore Store { get; set; } = default!;
    [Inject] protected DiagnosticsService Diagnostics { get; set; } = default!;

    private int _renderQueued;
    private bool _disposed;

    protected virtual bool ShouldReactTo(DiagnosticResult r) => true;

    protected override void OnInitialized() => Store.Changed += OnChanged;
    private void OnChanged(object? s, DiagnosticResult r)
    {
        if (_disposed || !ShouldReactTo(r) || Interlocked.Exchange(ref _renderQueued, 1) != 0) return;
        try
        {
            _ = InvokeAsync(() =>
            {
                Interlocked.Exchange(ref _renderQueued, 0);
                if (!_disposed) StateHasChanged();
            });
        }
        catch { Interlocked.Exchange(ref _renderQueued, 0); }
    }
    public virtual void Dispose()
    {
        _disposed = true;
        Store.Changed -= OnChanged;
    }

    protected internal static string DotClass(DiagnosticStatus s) => "dot dot-" + s.ToString().ToLowerInvariant();
}
