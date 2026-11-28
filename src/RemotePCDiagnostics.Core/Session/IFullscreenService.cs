namespace RemotePCDiagnostics.Core.Session;

/// <summary>
/// Allows the UI or active inspection modes to request the host window enter or exit borderless fullscreen.
/// </summary>
public interface IFullscreenService
{
    event Action<bool>? FullscreenChanged;
    bool IsFullscreen { get; }
    void RequestFullscreen(bool enable);

    /// <summary>The screen (<see cref="Display.ScreenInfo.Id"/>) the window goes full screen on; null for the screen it is on.</summary>
    string? ScreenId => null;

    /// <summary>Full screen on a given screen (the display test moves through each monitor). A host that can't place it ignores the screen.</summary>
    void RequestFullscreen(bool enable, string? screenId) => RequestFullscreen(enable);
}

public sealed class FullscreenService : IFullscreenService
{
    public event Action<bool>? FullscreenChanged;
    public bool IsFullscreen { get; private set; }
    public string? ScreenId { get; private set; }

    public void RequestFullscreen(bool enable) => RequestFullscreen(enable, null);

    public void RequestFullscreen(bool enable, string? screenId)
    {
        IsFullscreen = enable;
        ScreenId = enable ? screenId : null;
        FullscreenChanged?.Invoke(enable);
    }
}
