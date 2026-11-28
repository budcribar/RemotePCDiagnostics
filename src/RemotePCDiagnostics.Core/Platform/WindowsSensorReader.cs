using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using RemotePCDiagnostics.Core.DeviceSensors;

namespace RemotePCDiagnostics.Core.Platform;

/// <summary>
/// Reads every sensor with the Windows Sensor API (<c>ISensorManager</c>, sensorsapi.dll): its type, state, maker, model, connection, device
/// path and one data report. Runs as the signed-in user (no administrator rights); a location sensor can answer Access denied when
/// location is turned off in privacy settings. Interfaces, ids and property keys are from SensorsApi.h, sensors.h and sensorsdef.h.
/// The read runs on its own STA thread, as the API's samples do.
/// </summary>
[SupportedOSPlatform("windows")]
public static class WindowsSensorReader
{
    private const int HResultNotFound = unchecked((int)0x80070490); // HRESULT_FROM_WIN32(ERROR_NOT_FOUND): no sensors at all
    private static readonly Guid CategoryAll = new("C317C286-C468-4288-9975-D4C4587C442C");

    // SENSOR_PROPERTY_* (sensors.h)
    private static readonly Guid PropertyFmt = new("7F8383EC-D3EC-495C-A8CF-B8BBE85C2920");
    private const uint PidManufacturer = 6, PidModel = 7, PidConnectionType = 11, PidDevicePath = 15;

    // Data fields: SENSOR_DATA_TYPE_* (sensors.h) and PKEY_SensorData_* (sensorsdef.h)
    private static readonly Guid MotionFmt = new("3F8A69A2-07C5-4E48-A965-CD797AAB56D5");      // acceleration 2-4 (g), angular velocity 10-12 (°/s)
    private static readonly Guid OrientationFmt = new("1637D8A2-4248-4275-865D-558DE84AEDFD"); // tilt 2-4, heading 11/13, simple orientation 18, field 19-21
    private static readonly Guid LightFmt = new("E4C77CE2-DCB7-46E9-8439-4FEC548833A6");      // lux 2
    private static readonly Guid PresenceFmt = new("2299288A-6D9E-4B0B-B7EC-3528F89E40AF");   // presence 2 (bool), proximity 3 (m)
    private static readonly Guid SensorDataFmt = new("C458F8A7-4AE8-4777-9607-2E9BDD65110A"); // proximity detection 90, distance 91 (mm), hinge 300
    private static readonly Guid SwitchFmt = new("38564A7C-F2F2-49BB-9B2B-BA60F66A58DF");     // boolean switch 2

    public static DeviceSensorSnapshot Read(CancellationToken ct)
    {
        DeviceSensorSnapshot? result = null;
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            try { result = ReadOnThisThread(ct); }
            catch (Exception ex) { failure = ex; }
        }) { IsBackground = true, Name = "RPCD sensor read" };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        while (!thread.Join(100)) ct.ThrowIfCancellationRequested();
        ct.ThrowIfCancellationRequested();
        if (failure is not null) throw failure;
        return result ?? DeviceSensorSnapshot.Unavailable("The sensors couldn't be read.");
    }

    private static DeviceSensorSnapshot ReadOnThisThread(CancellationToken ct)
    {
        ISensorManager manager;
        try { manager = (ISensorManager)new SensorManagerClass(); }
        catch (COMException ex) { return DeviceSensorSnapshot.Unavailable($"The Windows Sensor API isn't available (0x{ex.HResult:X8})."); }
        try
        {
            var category = CategoryAll;
            var hr = manager.GetSensorsByCategory(ref category, out var collection);
            if (hr == HResultNotFound) return new([]);
            if (hr < 0) return DeviceSensorSnapshot.Unavailable($"Windows couldn't list the sensors (0x{hr:X8}).");
            if (collection is null) return new([]);
            try
            {
                if (collection.GetCount(out var count) < 0) return DeviceSensorSnapshot.Unavailable("Windows couldn't count the sensors.");
                var list = new List<DeviceSensor>();
                for (uint i = 0; i < count; i++)
                {
                    ct.ThrowIfCancellationRequested();
                    if (collection.GetAt(i, out var sensor) < 0 || sensor is null) continue;
                    try { list.Add(ReadSensor(sensor)); }
                    finally { Marshal.ReleaseComObject(sensor); }
                }
                return new(list);
            }
            finally { Marshal.ReleaseComObject(collection); }
        }
        finally { Marshal.ReleaseComObject(manager); }
    }

    private static DeviceSensor ReadSensor(ISensor s)
    {
        s.GetID(out var id);
        s.GetSensorType(out var type);
        string? name = null;
        try { if (s.GetFriendlyName(out var n) >= 0) name = n; } catch (COMException) { }
        var state = s.GetState(out var st) >= 0 && Enum.IsDefined(typeof(DeviceSensorStatus), st) ? (DeviceSensorStatus)st : DeviceSensorStatus.Unknown;
        var connection = Property(s, PidConnectionType) is { } c && c.Number() is { } cn && cn is >= 0 and <= 2
            ? (DeviceSensorConnection)(int)cn : DeviceSensorConnection.Unknown;
        var sensor = new DeviceSensor(id.ToString("D"), type, Clean(name), state,
            Clean(Property(s, PidManufacturer)?.Text), Clean(Property(s, PidModel)?.Text), connection,
            DeviceSensorTypes.InstanceIdFromPath(Property(s, PidDevicePath)?.Text));
        if (state is DeviceSensorStatus.AccessDenied or DeviceSensorStatus.Error or DeviceSensorStatus.NotAvailable) return sensor;
        if (!ReadsData(sensor.Kind)) return sensor;
        var hr = s.GetData(out var report);
        if (hr < 0 || report is null) return sensor with { ReadError = $"No data report (0x{hr:X8})" };
        try { return sensor with { Reading = Reading(sensor.Kind, report) }; }
        finally { Marshal.ReleaseComObject(report); }
    }

    private static bool ReadsData(DeviceSensorKind kind) => kind is
        DeviceSensorKind.Accelerometer or DeviceSensorKind.Gravity or DeviceSensorKind.LinearAccelerometer
        or DeviceSensorKind.Gyrometer or DeviceSensorKind.Compass or DeviceSensorKind.Magnetometer
        or DeviceSensorKind.Inclinometer or DeviceSensorKind.Orientation or DeviceSensorKind.SimpleOrientation
        or DeviceSensorKind.AmbientLight or DeviceSensorKind.Proximity or DeviceSensorKind.HumanPresence
        or DeviceSensorKind.HingeAngle or DeviceSensorKind.Switch;

    private static string? Clean(string? v) => string.IsNullOrWhiteSpace(v) ? null : v.Trim();

    private static DeviceSensorReading? Reading(DeviceSensorKind kind, ISensorDataReport r)
    {
        double? D(Guid fmt, uint pid) => Value(r, fmt, pid)?.Number();
        bool? B(Guid fmt, uint pid) => Value(r, fmt, pid)?.Flag();
        return kind switch
        {
            DeviceSensorKind.Accelerometer or DeviceSensorKind.Gravity or DeviceSensorKind.LinearAccelerometer =>
                new(D(MotionFmt, 2), D(MotionFmt, 3), D(MotionFmt, 4)),
            DeviceSensorKind.Gyrometer => new(D(MotionFmt, 10), D(MotionFmt, 11), D(MotionFmt, 12)),
            DeviceSensorKind.Compass => new(HeadingDegrees: D(OrientationFmt, 11) ?? D(OrientationFmt, 13)),
            DeviceSensorKind.Magnetometer => new(D(OrientationFmt, 19), D(OrientationFmt, 20), D(OrientationFmt, 21)),
            DeviceSensorKind.Inclinometer or DeviceSensorKind.Orientation => new(D(OrientationFmt, 2), D(OrientationFmt, 3), D(OrientationFmt, 4)),
            DeviceSensorKind.SimpleOrientation => new(SimpleOrientation: D(OrientationFmt, 18) is { } o ? (int)o : null),
            DeviceSensorKind.AmbientLight => new(Lux: D(LightFmt, 2)),
            DeviceSensorKind.Proximity or DeviceSensorKind.HumanPresence => new(
                Detected: B(SensorDataFmt, 90) ?? B(PresenceFmt, 2),
                DistanceMm: D(SensorDataFmt, 91) ?? (D(PresenceFmt, 3) is { } m ? m * 1000 : null)),
            DeviceSensorKind.HingeAngle => new(AngleDegrees: D(SensorDataFmt, 300)),
            DeviceSensorKind.Switch => new(SwitchOn: B(SwitchFmt, 2)),
            _ => null,
        };
    }

    private static Variant? Property(ISensor s, uint pid)
    {
        var key = new PropertyKey(PropertyFmt, pid);
        try { return s.GetProperty(ref key, out var v) >= 0 ? Variant.Take(ref v) : null; }
        catch (COMException) { return null; }
    }

    private static Variant? Value(ISensorDataReport r, Guid fmt, uint pid)
    {
        var key = new PropertyKey(fmt, pid);
        try { return r.GetSensorValue(ref key, out var v) >= 0 ? Variant.Take(ref v) : null; }
        catch (COMException) { return null; }
    }

    /// <summary>A PROPVARIANT's value copied out, so the native one can be cleared at once.</summary>
    private sealed record Variant(double? NumberValue, bool? FlagValue, string? Text)
    {
        public double? Number() => NumberValue ?? (FlagValue is { } f ? (f ? 1 : 0) : null);
        public bool? Flag() => FlagValue ?? (NumberValue is { } n ? n != 0 : null);

        public static Variant Take(ref PropVariant v)
        {
            try
            {
                return v.Vt switch
                {
                    2 => new(v.I2, null, null),          // VT_I2
                    3 or 22 => new(v.I4, null, null),    // VT_I4, VT_INT
                    4 => new(double.IsFinite(v.R4) ? v.R4 : null, null, null), // VT_R4
                    5 => new(double.IsFinite(v.R8) ? v.R8 : null, null, null), // VT_R8
                    11 => new(null, v.I2 != 0, null),    // VT_BOOL
                    16 => new((sbyte)v.UI1, null, null), // VT_I1
                    17 => new(v.UI1, null, null),        // VT_UI1
                    18 => new((ushort)v.I2, null, null), // VT_UI2
                    19 or 23 => new(v.UI4, null, null),  // VT_UI4, VT_UINT
                    20 => new(v.I8, null, null),         // VT_I8
                    21 => new((ulong)v.I8, null, null),  // VT_UI8
                    31 => new(null, null, v.Ptr == IntPtr.Zero ? null : Marshal.PtrToStringUni(v.Ptr)), // VT_LPWSTR
                    8 => new(null, null, v.Ptr == IntPtr.Zero ? null : Marshal.PtrToStringBSTR(v.Ptr)), // VT_BSTR
                    _ => new(null, null, null),
                };
            }
            finally { _ = PropVariantClear(ref v); }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PropertyKey(Guid fmtid, uint pid)
    {
        public Guid FormatId = fmtid;
        public uint PropertyId = pid;
    }

    /// <summary>PROPVARIANT: the type at 0, the value at 8 (24 bytes on 64-bit Windows, 16 on 32-bit; the size covers both).</summary>
    [StructLayout(LayoutKind.Explicit, Size = 24)]
    private struct PropVariant
    {
        [FieldOffset(0)] public ushort Vt;
        [FieldOffset(8)] public short I2;
        [FieldOffset(8)] public byte UI1;
        [FieldOffset(8)] public int I4;
        [FieldOffset(8)] public uint UI4;
        [FieldOffset(8)] public long I8;
        [FieldOffset(8)] public float R4;
        [FieldOffset(8)] public double R8;
        [FieldOffset(8)] public IntPtr Ptr;
    }

    [DllImport("ole32.dll")]
    private static extern int PropVariantClear(ref PropVariant pvar);

    [ComImport, Guid("77A1C827-FCD2-4689-8915-9D613CC5FA3E")]
    private class SensorManagerClass;

    // Method order is the vtable order in SensorsApi.h; the names are ours.
    [ComImport, Guid("BD77DB67-45A8-42DC-8D00-6DCF15F8377A"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface ISensorManager
    {
        [PreserveSig] int GetSensorsByCategory(ref Guid category, out ISensorCollection? sensors);
        [PreserveSig] int GetSensorsByType(ref Guid type, out ISensorCollection? sensors);
        [PreserveSig] int GetSensorByID(ref Guid id, out ISensor? sensor);
        [PreserveSig] int SetEventSink(IntPtr events);
        [PreserveSig] int RequestPermissions(IntPtr parent, IntPtr sensors, int modal);
    }

    [ComImport, Guid("23571E11-E545-4DD8-A337-B89BF44B10DF"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface ISensorCollection
    {
        [PreserveSig] int GetAt(uint index, out ISensor? sensor);
        [PreserveSig] int GetCount(out uint count);
        [PreserveSig] int Add(IntPtr sensor);
        [PreserveSig] int Remove(IntPtr sensor);
        [PreserveSig] int RemoveByID(ref Guid id);
        [PreserveSig] int Clear();
    }

    [ComImport, Guid("5FA08F80-2657-458E-AF75-46F73FA6AC5C"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface ISensor
    {
        [PreserveSig] int GetID(out Guid id);
        [PreserveSig] int GetCategory(out Guid category);
        [PreserveSig] int GetSensorType(out Guid type);
        [PreserveSig] int GetFriendlyName([MarshalAs(UnmanagedType.BStr)] out string? name);
        [PreserveSig] int GetProperty(ref PropertyKey key, out PropVariant value);
        [PreserveSig] int GetProperties(IntPtr keys, out IntPtr values);
        [PreserveSig] int GetSupportedDataFields(out IntPtr fields);
        [PreserveSig] int SetProperties(IntPtr values, out IntPtr results);
        [PreserveSig] int SupportsDataField(ref PropertyKey key, out short supported);
        [PreserveSig] int GetState(out int state);
        [PreserveSig] int GetData(out ISensorDataReport? report);
        [PreserveSig] int SupportsEvent(ref Guid eventGuid, out short supported);
        [PreserveSig] int GetEventInterest(out IntPtr values, out uint count);
        [PreserveSig] int SetEventInterest(IntPtr values, uint count);
        [PreserveSig] int SetEventSink(IntPtr events);
    }

    [ComImport, Guid("0AB9DF9B-C4B5-4796-8898-0470706A2E1D"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface ISensorDataReport
    {
        [PreserveSig] int GetTimestamp(out SystemTime time);
        [PreserveSig] int GetSensorValue(ref PropertyKey key, out PropVariant value);
        [PreserveSig] int GetSensorValues(IntPtr keys, out IntPtr values);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SystemTime
    {
        public ushort Year, Month, DayOfWeek, Day, Hour, Minute, Second, Milliseconds;
    }
}
