using System.Globalization;

namespace RemotePCDiagnostics.Core.DeviceSensors;

/// <summary>Windows' sensor type ids (sensors.h, sensorsdef.h) and the words the app shows for them.</summary>
public static class DeviceSensorTypes
{
    public static readonly Guid Accelerometer1D = new("C04D2387-7340-4CC2-991E-3B18CB8EF2F4");
    public static readonly Guid Accelerometer2D = new("B2C517A8-F6B5-4BA6-A423-5DF560B4CC07");
    public static readonly Guid Accelerometer3D = new("C2FB0F5F-E2D2-4C78-BCD0-352A9582819D");
    public static readonly Guid Gyrometer1D = new("FA088734-F552-4584-8324-EDFAF649652C");
    public static readonly Guid Gyrometer2D = new("31EF4F83-919B-48BF-8DE0-5D7A9D240556");
    public static readonly Guid Gyrometer3D = new("09485F5A-759E-42C2-BD4B-A349B75C8643");
    public static readonly Guid Compass1D = new("A415F6C5-CB50-49D0-8E62-A8270BD7A26C");
    public static readonly Guid Compass2D = new("15655CC0-997A-4D30-84DB-57CABA3648BB");
    public static readonly Guid Compass3D = new("76B5CE0D-17DD-414D-93A1-E127F40BDF6E");
    public static readonly Guid Magnetometer3D = new("55E5EFFB-15C7-40DF-8698-A84B7C863C53");
    public static readonly Guid Inclinometer1D = new("B96F98C5-7A75-4BA7-94E9-AC868C966DD8");
    public static readonly Guid Inclinometer2D = new("AB140F6D-83EB-4264-B70B-B16A5B256A01");
    public static readonly Guid Inclinometer3D = new("B84919FB-EA85-4976-8444-6F6F5C6D31DB");
    /// <summary>The fused device orientation (also GUID_SensorType_Orientation).</summary>
    public static readonly Guid DeviceOrientation = new("CDB5D8F7-3CFD-41C8-8542-CCE622CF5D6E");
    public static readonly Guid RelativeOrientation = new("40993B51-4706-44DC-98D5-C920C037FFAB");
    public static readonly Guid GeomagneticOrientation = new("E77195F8-2D1F-4823-971B-1C4467556C9D");
    public static readonly Guid SimpleDeviceOrientation = new("86A19291-0482-402C-BF4C-ADDAC52B1C39");
    public static readonly Guid QuadrantOrientation = new("9F81F1AF-C4AB-4307-9904-C828BFB90829");
    public static readonly Guid AmbientLight = new("97F115C8-599A-4153-8894-D2D12899918A");
    /// <summary>Human proximity (also GUID_SensorType_Proximity).</summary>
    public static readonly Guid Proximity = new("5220DAE9-3179-4430-9F90-06266D2A34DE");
    public static readonly Guid HumanPresence = new("C138C12B-AD52-451C-9375-87F518FF10C6");
    public static readonly Guid HingeAngle = new("82358065-F4C4-4DA1-B272-13C23332A207");
    public static readonly Guid GravityVector = new("03B52C73-BB76-463F-9524-38DE76EB700B");
    public static readonly Guid LinearAccelerometer = new("038B0283-97B4-41C8-BC24-5FF1AA48FEC7");
    public static readonly Guid ActivityDetection = new("9D9E0118-1807-4F2E-96E4-2CE57142E196");
    public static readonly Guid Pedometer = new("B19F89AF-E3EB-444B-8DEA-202575A71599");
    public static readonly Guid Barometer = new("0E903829-FF8A-4A93-97DF-3DCBDE402288");
    public static readonly Guid Temperature = new("04FD0EC4-D5DA-45FA-95A9-5DB38EE19306");
    public static readonly Guid Humidity = new("5C72BF67-BD7E-4257-990B-98A3BA3B400A");
    public static readonly Guid BooleanSwitch = new("9C7E371F-1041-460B-8D5C-71E4752E350C");
    public static readonly Guid Custom = new("E83AF229-8640-4D18-A213-E22675EBB2C3");

    private static readonly Guid[] LocationTypes =
    [
        new("ED4CA589-327A-4FF9-A560-91DA4B48275E"), new("095F8184-0FA9-4445-8E6E-B70F320B6B4C"), new("3B2EAE4A-72CE-436D-96D2-3C5B8570E987"),
        new("691C341A-5406-4FE1-942F-2246CBEB39E0"), new("9B2D0566-0368-4F71-B88D-533F132031DE"), new("D26988CF-5162-4039-BB17-4C58B698E44A"),
        new("1A37D538-F28B-42DA-9FCE-A9D0A2A6D829"),
    ];

    public static DeviceSensorKind KindOf(Guid type)
    {
        if (type == Accelerometer1D || type == Accelerometer2D || type == Accelerometer3D) return DeviceSensorKind.Accelerometer;
        if (type == Gyrometer1D || type == Gyrometer2D || type == Gyrometer3D) return DeviceSensorKind.Gyrometer;
        if (type == Compass1D || type == Compass2D || type == Compass3D) return DeviceSensorKind.Compass;
        if (type == Magnetometer3D) return DeviceSensorKind.Magnetometer;
        if (type == Inclinometer1D || type == Inclinometer2D || type == Inclinometer3D) return DeviceSensorKind.Inclinometer;
        if (type == DeviceOrientation || type == RelativeOrientation || type == GeomagneticOrientation) return DeviceSensorKind.Orientation;
        if (type == SimpleDeviceOrientation || type == QuadrantOrientation) return DeviceSensorKind.SimpleOrientation;
        if (type == AmbientLight) return DeviceSensorKind.AmbientLight;
        if (type == Proximity) return DeviceSensorKind.Proximity;
        if (type == HumanPresence) return DeviceSensorKind.HumanPresence;
        if (type == HingeAngle) return DeviceSensorKind.HingeAngle;
        if (type == GravityVector) return DeviceSensorKind.Gravity;
        if (type == LinearAccelerometer) return DeviceSensorKind.LinearAccelerometer;
        if (type == ActivityDetection) return DeviceSensorKind.ActivityDetection;
        if (type == Pedometer) return DeviceSensorKind.Pedometer;
        if (type == Barometer) return DeviceSensorKind.Barometer;
        if (type == Temperature) return DeviceSensorKind.Temperature;
        if (type == Humidity) return DeviceSensorKind.Humidity;
        if (type == BooleanSwitch) return DeviceSensorKind.Switch;
        if (type == Custom) return DeviceSensorKind.Custom;
        if (LocationTypes.Contains(type)) return DeviceSensorKind.Location;
        return type == Guid.Empty ? DeviceSensorKind.Unknown : DeviceSensorKind.Other;
    }

    /// <summary>The sensor's kind in words, and what Windows uses it for.</summary>
    public static string Title(DeviceSensorKind k) => k switch
    {
        DeviceSensorKind.Accelerometer => "Accelerometer",
        DeviceSensorKind.Gyrometer => "Gyroscope",
        DeviceSensorKind.Compass => "Compass",
        DeviceSensorKind.Magnetometer => "Magnetometer",
        DeviceSensorKind.Inclinometer => "Inclinometer",
        DeviceSensorKind.Orientation => "Orientation",
        DeviceSensorKind.SimpleOrientation => "Screen orientation",
        DeviceSensorKind.AmbientLight => "Ambient light",
        DeviceSensorKind.Proximity => "Proximity",
        DeviceSensorKind.HumanPresence => "Human presence",
        DeviceSensorKind.HingeAngle => "Hinge angle",
        DeviceSensorKind.Gravity => "Gravity",
        DeviceSensorKind.LinearAccelerometer => "Linear accelerometer",
        DeviceSensorKind.ActivityDetection => "Activity detection",
        DeviceSensorKind.Pedometer => "Step counter",
        DeviceSensorKind.Barometer => "Barometer",
        DeviceSensorKind.Temperature => "Temperature",
        DeviceSensorKind.Humidity => "Humidity",
        DeviceSensorKind.Location => "Location",
        DeviceSensorKind.Switch => "Switch",
        DeviceSensorKind.Custom => "Custom sensor",
        DeviceSensorKind.Other => "Other sensor",
        _ => "Sensor",
    };

    public static string Use(DeviceSensorKind k) => k switch
    {
        DeviceSensorKind.Accelerometer or DeviceSensorKind.SimpleOrientation or DeviceSensorKind.Orientation or DeviceSensorKind.Inclinometer
            or DeviceSensorKind.Gravity => "Auto-rotate",
        DeviceSensorKind.Gyrometer => "Motion and rotation",
        DeviceSensorKind.Compass or DeviceSensorKind.Magnetometer => "Heading (maps)",
        DeviceSensorKind.AmbientLight => "Auto-brightness",
        DeviceSensorKind.Proximity or DeviceSensorKind.HumanPresence => "Wake on approach, lock on leave",
        DeviceSensorKind.HingeAngle => "Tablet and tent modes",
        DeviceSensorKind.Location => "Location",
        _ => "",
    };

    public static string StateText(DeviceSensorStatus s) => s switch
    {
        DeviceSensorStatus.Ready => "Ready",
        DeviceSensorStatus.NotAvailable => "Not available",
        DeviceSensorStatus.NoData => "No data yet",
        DeviceSensorStatus.Initializing => "Starting",
        DeviceSensorStatus.AccessDenied => "Access denied",
        DeviceSensorStatus.Error => "Error",
        _ => "Unknown",
    };

    public static string ConnectionText(DeviceSensorConnection c) => c switch
    {
        DeviceSensorConnection.Integrated => "Built in",
        DeviceSensorConnection.Attached => "Attached",
        DeviceSensorConnection.External => "External",
        _ => "",
    };

    private static string N(double v, int decimals) => Math.Round(v, decimals).ToString(decimals == 0 ? "0" : "0." + new string('0', decimals), CultureInfo.InvariantCulture);

    public static string OrientationText(int o) => o switch
    {
        0 => "Upright",
        1 => "Rotated 90°",
        2 => "Upside down",
        3 => "Rotated 270°",
        4 => "Face up",
        5 => "Face down",
        _ => "Unknown",
    };

    /// <summary>One reading in words ("X 0.02 g, Y -0.01 g, Z -1.00 g", "312 lux", "Someone present, 450 mm"); "" when there is none.</summary>
    public static string ReadingText(DeviceSensorKind k, DeviceSensorReading? r)
    {
        if (r is null || r.IsEmpty) return "";
        var parts = new List<string>();
        var unit = k switch
        {
            DeviceSensorKind.Accelerometer or DeviceSensorKind.Gravity or DeviceSensorKind.LinearAccelerometer => " g",
            DeviceSensorKind.Gyrometer => " °/s",
            DeviceSensorKind.Magnetometer => " mG",
            DeviceSensorKind.Inclinometer or DeviceSensorKind.Orientation => "°",
            _ => "",
        };
        var decimals = unit == " g" ? 2 : 1;
        if (r.X is { } x) parts.Add($"X {N(x, decimals)}{unit}");
        if (r.Y is { } y) parts.Add($"Y {N(y, decimals)}{unit}");
        if (r.Z is { } z) parts.Add($"Z {N(z, decimals)}{unit}");
        if (r.HeadingDegrees is { } h) parts.Add($"Heading {N(h, 0)}°");
        if (r.Lux is { } lux) parts.Add($"{N(lux, lux < 10 ? 1 : 0)} lux");
        if (r.Detected is { } d) parts.Add(d ? "Someone present" : "No one detected");
        if (r.DistanceMm is { } mm) parts.Add($"{N(mm, 0)} mm");
        if (r.AngleDegrees is { } a) parts.Add($"{N(a, 0)}°");
        if (r.SimpleOrientation is { } o) parts.Add(OrientationText(o));
        if (r.SwitchOn is { } on) parts.Add(on ? "On" : "Off");
        return string.Join(", ", parts);
    }

    /// <summary>Device Manager's instance id from a sensor's device path (<c>\\?\HID#VID_04F3&amp;...#7&amp;1&amp;0000#{guid}\...</c> to
    /// <c>HID\VID_04F3&amp;...\7&amp;1&amp;0000</c>); null when the path isn't that shape.</summary>
    public static string? InstanceIdFromPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        var p = path.Trim();
        if (p.StartsWith(@"\\?\", StringComparison.Ordinal) || p.StartsWith(@"\\.\", StringComparison.Ordinal)) p = p[4..];
        var guid = p.IndexOf("#{", StringComparison.Ordinal);
        if (guid <= 0) return null;
        return p[..guid].Replace('#', '\\').ToUpperInvariant();
    }
}
