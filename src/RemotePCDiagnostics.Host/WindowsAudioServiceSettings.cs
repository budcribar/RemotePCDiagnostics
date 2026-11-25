using System.ServiceProcess;
using RemotePCDiagnostics.Core.Audio;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Host;

/// <summary>
/// <see cref="IAudioServiceSettings"/>: the start-up type is read here with ServiceController (no rights needed) and written by the Agent
/// (<paramref name="admin"/>, over the admin pipe), which only allows the two Windows Audio services among the protected ones.
/// </summary>
public sealed class WindowsAudioServiceSettings(IAdminSettingsBackend admin) : IAudioServiceSettings
{
    public string? StartType(string service)
    {
        try
        {
            using var sc = new ServiceController(service);
            return sc.StartType switch
            {
                ServiceStartMode.Automatic => "Automatic",
                ServiceStartMode.Disabled => "Disabled",
                _ => "Manual",
            };
        }
        catch (InvalidOperationException) { return null; }
    }

    public void SetStartType(string service, string startType) => admin.SetServiceStartType(service, startType);
}
