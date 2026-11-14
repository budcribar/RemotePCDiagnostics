namespace RemotePCDiagnostics.Core.Session;

/// <summary>
/// Allows the UI or active inspection modes to request the host window enter or exit borderless fullscreen.
/// </summary>
public interface IFullscreenService
{
    event Action<bool>? FullscreenChanged;
    bool IsFullscreen { get; }
    void RequestFullscreen(bool enable);
}

public sealed class FullscreenService : IFullscreenService
{
    public event Action<bool>? FullscreenChanged;
    public bool IsFullscreen { get; private set; }

    public void RequestFullscreen(bool enable)
    {
        IsFullscreen = enable;
        FullscreenChanged?.Invoke(enable);
    }
}
