namespace RemotePCDiagnostics.Core.Plugins;

/// <summary>
/// Shows an unsigned module's own UI (<see cref="ModuleManifest.HasUi"/>). The UI runs in its own user-mode process and reaches the
/// module page through the app's relay, in a sandboxed frame with an opaque origin: it can't read the app's page, storage or cookies.
/// Registered by the host only where it can do this (Local mode); the module page shows the generic report otherwise.
/// </summary>
public interface IModuleUiFrames
{
    /// <summary>Starts the module's UI process if it isn't running and returns the address to frame.</summary>
    Task<Uri> OpenAsync(UserModeModule module, CancellationToken cancellationToken = default);
}

/// <summary>What the module page needs to frame an unsigned module's UI safely.</summary>
public static class ModuleUiFrame
{
    /// <summary>No allow-same-origin: the frame gets an opaque origin, so modules can't reach each other or the relay's storage.</summary>
    public const string Sandbox = "allow-scripts allow-forms";

    /// <summary>The only message a module's UI may post to the app: its content height, for sizing the frame.</summary>
    public const string HeightMessage = "rpcd-module-height";
    public const int MinHeight = 120, MaxHeight = 4000;

    /// <summary>The frame height for a height a module's UI asked for (any number, clamped; anything else gets the minimum).</summary>
    public static int ClampHeight(double requested) =>
        double.IsFinite(requested) ? (int)Math.Clamp(Math.Ceiling(requested), MinHeight, MaxHeight) : MinHeight;
}
