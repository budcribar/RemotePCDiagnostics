using PeakSWC.RemoteBlazorWebView.RemoteComponents;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Plugins;

namespace RemotePCDiagnostics.ModuleUi;

/// <summary>
/// What the app hands an unsigned module's UI process: the module's latest result, so its details UI shows the app's last run
/// (<see cref="ModuleDetails.LastResult"/>) instead of starting blank. The generator writes <c>ModuleUiFrame</c> (the module page's
/// sandboxed iframe, which sends the value whenever it changes) and <c>ModuleUiReceiver</c> (the UI process's copy).
/// </summary>
[RemoteComponentContract]
public interface IModuleUi
{
    /// <summary>The module's latest result in the app; null until the app has sent one.</summary>
    ModuleUiResult? LastResult { get; }

    /// <summary>The app's theme choice ("dark", "light" or "system"), so the module's UI matches the page it is framed on. The UI host
    /// loads the app's own stylesheet, so a module UI that uses the app's classes looks the same in and out of process.</summary>
    string? Theme { get; }
}

/// <summary>A module result as it crosses to the UI process. One-click actions are removed, as everywhere for unsigned modules.</summary>
public sealed record ModuleUiResult(DiagnosticStatus Status, string Message, DateTimeOffset When, bool Cancelled = false, AreaReport? Report = null)
{
    public static ModuleUiResult From(DiagnosticResult result) =>
        new(result.Status, result.Message, result.Timestamp, result.Cancelled, result.Payload is AreaReport r ? UserModeModuleProxy.WithoutActions(r) : null);

    public DiagnosticResult ToResult(string moduleName) =>
        new DiagnosticResult<AreaReport>(moduleName, Status, Message ?? "", When, Report) { Cancelled = Cancelled };
}

/// <summary>
/// Shows an unsigned module's own UI (<see cref="ModuleManifest.HasUi"/>). The UI runs in its own user-mode process and reaches the
/// module page through the app's relay, in a sandboxed frame with an opaque origin (<see cref="RemoteComponentFrame.DefaultSandbox"/>):
/// it can't read the app's page, storage or cookies. Registered by the host only where it can do this (Local mode); the module page
/// shows the generic report otherwise.
/// </summary>
public interface IModuleUiFrames
{
    /// <summary>Starts the module's UI process (replacing one already open for it) and returns its session: the address to frame and the
    /// connection to the process. Disposing the session stops the process.</summary>
    Task<RemoteComponentSession> OpenAsync(UserModeModule module, CancellationToken cancellationToken = default);

    /// <summary>This host can show <paramref name="module"/>'s UI (a remote session shows only those of modules that ship with the app).</summary>
    bool CanOpen(UserModeModule module) => true;
}
