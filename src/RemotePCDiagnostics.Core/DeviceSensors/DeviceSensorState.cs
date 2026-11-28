using System.Text.Json;
using System.Text.Json.Serialization;

namespace RemotePCDiagnostics.Core.DeviceSensors;

/// <summary>What kind of sensor Windows reports (its sensor type id, <see cref="DeviceSensorTypes"/>).</summary>
public enum DeviceSensorKind
{
    Unknown, Accelerometer, Gyrometer, Compass, Magnetometer, Inclinometer, Orientation, SimpleOrientation, AmbientLight,
    Proximity, HumanPresence, HingeAngle, Gravity, LinearAccelerometer, ActivityDetection, Pedometer, Barometer, Temperature, Humidity,
    Location, Switch, Custom, Other,
}

/// <summary>The sensor's state (<c>SensorState</c> in SensorsApi.h): Ready, NotAvailable, NoData, Initializing, AccessDenied, Error.</summary>
public enum DeviceSensorStatus { Ready = 0, NotAvailable = 1, NoData = 2, Initializing = 3, AccessDenied = 4, Error = 5, Unknown = 99 }

/// <summary>How the sensor is connected (<c>SENSOR_CONNECTION_TYPES</c>): built into the PC, attached to it, or external.</summary>
public enum DeviceSensorConnection { Integrated = 0, Attached = 1, External = 2, Unknown = 99 }

/// <summary>
/// One reading of a sensor. Only the fields the sensor reports are set: acceleration in g, angular velocity in degrees a second, heading in
/// degrees from magnetic north, tilt (pitch, roll, yaw) in degrees, light in lux, presence and distance, the hinge angle in degrees, the
/// simple orientation (<c>SimpleDeviceOrientation</c>: 0 not rotated, 1 90°, 2 180°, 3 270°, 4 face up, 5 face down), a switch state.
/// </summary>
public sealed record DeviceSensorReading(
    double? X = null, double? Y = null, double? Z = null,
    double? HeadingDegrees = null,
    double? Lux = null,
    bool? Detected = null,
    double? DistanceMm = null,
    double? AngleDegrees = null,
    int? SimpleOrientation = null,
    bool? SwitchOn = null)
{
    [JsonIgnore] public bool IsEmpty => X is null && Y is null && Z is null && HeadingDegrees is null && Lux is null && Detected is null
        && DistanceMm is null && AngleDegrees is null && SimpleOrientation is null && SwitchOn is null;
}

/// <summary>
/// One sensor as the Windows Sensor API lists it (read in the app as the signed-in user: no administrator rights). <see cref="TypeId"/> is
/// Windows' sensor type GUID; <see cref="InstanceId"/> the device instance it belongs to (from its device path), to match Device Manager.
/// <see cref="ReadError"/>: the sensor is listed but its data couldn't be read.
/// </summary>
public sealed record DeviceSensor(
    string Id,
    Guid TypeId,
    string? Name = null,
    DeviceSensorStatus State = DeviceSensorStatus.Unknown,
    string? Manufacturer = null,
    string? Model = null,
    DeviceSensorConnection Connection = DeviceSensorConnection.Unknown,
    string? InstanceId = null,
    DeviceSensorReading? Reading = null,
    string? ReadError = null)
{
    [JsonIgnore] public DeviceSensorKind Kind => DeviceSensorTypes.KindOf(TypeId);
}

/// <summary>A device in Device Manager that belongs to the sensors (the Sensor class, a sensor hub, the lid switch), with its problem code.</summary>
public sealed record SensorDevice(string Name, string Class, string DeviceId, int ProblemCode, string? Manufacturer = null)
{
    [JsonIgnore] public bool IsLid => DeviceId.StartsWith(@"ACPI\PNP0C0D", StringComparison.OrdinalIgnoreCase);
}

/// <summary>The sensors as read once. <see cref="Error"/> says why they couldn't be read (then <see cref="Sensors"/> is empty).</summary>
public sealed record DeviceSensorSnapshot(IReadOnlyList<DeviceSensor> Sensors, string? Error = null)
{
    public static DeviceSensorSnapshot Unavailable(string reason) => new([], reason);

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() },
    };

    public string ToJson() => JsonSerializer.Serialize(this, Json);

    public static DeviceSensorSnapshot FromJson(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return Unavailable("No sensor answer.");
        try
        {
            return JsonSerializer.Deserialize<DeviceSensorSnapshot>(json, Json) is { } s
                ? s with { Sensors = s.Sensors ?? [] } : Unavailable("No sensor answer.");
        }
        catch (JsonException ex) { return Unavailable("The sensor answer couldn't be read: " + ex.Message); }
    }

    /// <summary>The first sensor of a kind that is ready or reporting, else the first of that kind.</summary>
    public DeviceSensor? First(DeviceSensorKind kind) =>
        Sensors.FirstOrDefault(s => s.Kind == kind && s.Reading is { IsEmpty: false })
        ?? Sensors.FirstOrDefault(s => s.Kind == kind);
}

/// <summary>Reads the sensors (the app, as the signed-in user: no administrator rights needed).</summary>
public interface IDeviceSensorSource
{
    /// <summary>Lists every sensor with its state and one reading. Never throws except on cancellation.</summary>
    Task<DeviceSensorSnapshot> ReadAsync(CancellationToken ct = default);
}

/// <summary>No sensors here (CI, non-Windows).</summary>
public sealed class NullDeviceSensorSource : IDeviceSensorSource
{
    public Task<DeviceSensorSnapshot> ReadAsync(CancellationToken ct = default) =>
        Task.FromResult(DeviceSensorSnapshot.Unavailable("Sensors can't be read here."));
}

/// <summary>This PC's sensors, read in this process with the Windows Sensor API (<see cref="Platform.WindowsSensorReader"/>).</summary>
public sealed class WindowsDeviceSensorSource(ILogger? log = null) : IDeviceSensorSource
{
    public Task<DeviceSensorSnapshot> ReadAsync(CancellationToken ct = default) =>
        Task.Run(() =>
        {
            if (!OperatingSystem.IsWindows()) return DeviceSensorSnapshot.Unavailable("Sensors can only be read on Windows.");
            try { return Platform.WindowsSensorReader.Read(ct); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                log.Warn($"Sensors unreadable: {ex.GetType().Name}: {ex.Message}");
                return DeviceSensorSnapshot.Unavailable("The sensors couldn't be read: " + ex.Message);
            }
        }, ct);
}

/// <summary>
/// For a module in user mode (the module host): asks the app (<c>devicesensors.state</c>), which reads the sensors in the signed-in user's
/// session, so the read is recorded with the app's other answers.
/// </summary>
public sealed class HostDeviceSensorSource(Plugins.IHostQueries host, ILogger? log = null) : IDeviceSensorSource
{
    public async Task<DeviceSensorSnapshot> ReadAsync(CancellationToken ct = default)
    {
        try { return await host.ReadDeviceSensorsAsync(ct).ConfigureAwait(false); }
        catch (Plugins.HostQueryException ex)
        {
            log.Warn($"devicesensors.state refused ({ex.Error}): {ex.Message}");
            return DeviceSensorSnapshot.Unavailable(ex.Message);
        }
    }
}
