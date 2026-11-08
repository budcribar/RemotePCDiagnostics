using Microsoft.AspNetCore.Components;
using RemotePCDiagnostics.Core;

namespace RemotePCDiagnostics.UI.Shared;

/// <summary>
/// Base for a module's own details UI (<see cref="ModuleDescriptor.DetailsComponent"/>). The shell (the module page or the Checks and
/// Stress tests lists) passes the module in, so a details component never looks modules up by type.
/// </summary>
public abstract class ModuleDetailsBase : StoreAwareComponent
{
    /// <summary>The module this UI shows.</summary>
    [Parameter] public IDiagnosticModule? DiagnosticModule { get; set; }

    /// <summary>The app's services, for one a page may use when the app has it (<c>GetService</c>), such as the history store. A page
    /// that renders in the app from results only (resultOnlyUi) uses these instead of injecting its own.</summary>
    [Inject] protected IServiceProvider Services { get; set; } = default!;

    /// <summary>The module's latest result.</summary>
    protected DiagnosticResult? LatestResult => DiagnosticModule is { } m ? Store.Get(m.Name) : null;

    /// <summary>Runs the module through <see cref="DiagnosticsService"/> (no-op when no module was passed).</summary>
    protected Task RunModuleAsync() => DiagnosticModule is { } m ? Diagnostics.RunAsync(m.Name) : Task.CompletedTask;
}
