namespace RemotePCDiagnostics.Core.Sensors;

/// <summary>Hardware sensor source. The LibreHardwareMonitorLib implementation lives in the Windows Host project.</summary>
public interface ISensorProvider
{
    ModuleAvailability CheckAvailability();
    /// <summary>Updates hardware and returns current temperature and fan readings.</summary>
    SensorSnapshot Read();
}

/// <summary>Used where no hardware provider is registered (non-Windows, tests).</summary>
public sealed class UnavailableSensorProvider(string reason = "Sensor provider not available on this platform") : ISensorProvider
{
    public ModuleAvailability CheckAvailability() => ModuleAvailability.Unavailable(reason);
    public SensorSnapshot Read() => throw new PlatformNotSupportedException(reason);
}
