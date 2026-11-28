using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.DeviceSensors;

namespace RemotePCDiagnostics.Modules.DeviceSensors;

/// <summary>
/// Motion, light &amp; presence sensors: every sensor Windows lists (accelerometer, gyroscope, compass, inclinometer, orientation, ambient
/// light, proximity and human presence, hinge angle, and any other) with its type, state (ready, not available, no data, access denied,
/// error), maker, connection and one live reading; and the sensor devices, sensor hubs and lid switch in Device Manager with their problem
/// codes. Flags a sensor in an error state and a sensor device whose driver has a problem. The sensors are read in the app with the Windows
/// Sensor API (no administrator rights), so the check also answers on a PC no one is looking at; the hands-on part (tilt, cover the light
/// sensor, presence) is the Sensor test on the Interactive tests page. Nothing is changed.
/// </summary>
public sealed class DeviceSensorsModule(IDeviceSensorSource sensors, IWmiSource wmi, ILogger? log = null) : AreaModuleBase(log)
{
    public const string ModuleName = ModuleSlugs.DeviceSensors;
    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.DeviceSensors;
    public override string DisplayName => "Motion, light & presence sensors";
    protected override string FailedMessage => "Couldn't check the sensors on this PC.";

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        progress.ReportStep(1, 2, "Reading the sensors…");
        var snapshot = await sensors.ReadAsync(ct).ConfigureAwait(false);
        if (snapshot.Error is { } err) LogWarn($"{Name}: sensors unreadable: {err}");
        else Log($"{Name}: {snapshot.Sensors.Count} sensors: {string.Join(", ", snapshot.Sensors.Select(s => $"{s.Kind} {s.State}"))}");

        progress.ReportStep(2, 2, "Reading the sensor drivers in Device Manager…");
        var devices = await SensorDevices.ReadAsync(wmi, ct).ConfigureAwait(false);
        if (devices.Error is { } derr) LogWarn($"{Name}: {derr}");
        return DeviceSensorAnalysis.Build(snapshot, devices);
    }
}
