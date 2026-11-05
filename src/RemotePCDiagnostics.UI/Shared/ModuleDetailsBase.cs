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

    /// <summary>The module's latest result.</summary>
    protected DiagnosticResult? LatestResult => DiagnosticModule is { } m ? Store.Get(m.Name) : null;

    /// <summary>Runs the module through <see cref="DiagnosticsService"/> (no-op when no module was passed).</summary>
    protected Task RunModuleAsync() => DiagnosticModule is { } m ? Diagnostics.RunAsync(m.Name) : Task.CompletedTask;
}
