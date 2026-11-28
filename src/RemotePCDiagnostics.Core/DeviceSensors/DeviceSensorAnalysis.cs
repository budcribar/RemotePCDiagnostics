using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.DataSources;

namespace RemotePCDiagnostics.Core.DeviceSensors;

/// <summary>What Device Manager says about the sensor devices, or why it couldn't be read. <see cref="NeedsAgent"/>: the read needs the
/// Agent and it isn't connected.</summary>
public sealed record SensorDeviceReading(IReadOnlyList<SensorDevice> Devices, string? Error = null, bool NeedsAgent = false)
{
    public bool Read => Error is null;
}

/// <summary>
/// Reads the sensor devices from Device Manager (<c>Win32_PnPEntity</c>): the Sensor class, sensor hubs (Intel Integrated Sensor Solution,
/// AMD Sensor Fusion Hub) and the lid switch (<c>ACPI\PNP0C0D</c>), with each one's problem code. WMI goes through the Agent in the Setup
/// edition; the Store edition reads it as the signed-in user, which Win32_PnPEntity allows.
/// </summary>
public static class SensorDevices
{
    public const string Sql = "SELECT Name, PNPClass, DeviceID, ConfigManagerErrorCode, Manufacturer FROM Win32_PnPEntity WHERE PNPClass = 'Sensor'"
        + @" OR DeviceID LIKE 'ACPI\\PNP0C0D%' OR ((PNPClass = 'System' OR PNPClass = 'HIDClass') AND Name LIKE '%Sensor%')";

    public static async Task<SensorDeviceReading> ReadAsync(IWmiSource wmi, CancellationToken ct)
    {
        var q = await wmi.QueryAsync(WmiHardwareInventorySource.Cimv2, Sql, ct).ConfigureAwait(false);
        if (!q.Success)
        {
            var needsAgent = q.Error?.Contains(AgentWmiSource.NotConnected, StringComparison.Ordinal) == true;
            return new([], needsAgent ? "Needs the Agent: Device Manager is read through the Agent." : "Device Manager couldn't be read: " + q.Error, needsAgent);
        }
        return new([.. q.Rows!.Select(r => new SensorDevice(
            r.Str("Name") is { Length: > 0 } n ? n : "Unknown sensor device", r.Str("PNPClass"), r.Str("DeviceID"),
            (int)(r.Long("ConfigManagerErrorCode") ?? 0), r.Str("Manufacturer") is { Length: > 0 } m ? m : null))
            .DistinctBy(d => d.DeviceId, StringComparer.OrdinalIgnoreCase)]);
    }

    public static string ProblemText(int code) =>
        code == 0 ? "Working" : new ProblemDevice("", "", "", code, "").FriendlyError;
}

/// <summary>Builds the Motion, light &amp; presence sensors report.</summary>
public static class DeviceSensorAnalysis
{
    private static string Plural(int n, string what) => AreaModuleBase.Plural(n, what);

    /// <summary>The kinds the interactive Sensor test can check.</summary>
    public static bool Testable(DeviceSensorKind k) => k is DeviceSensorKind.Accelerometer or DeviceSensorKind.AmbientLight
        or DeviceSensorKind.Proximity or DeviceSensorKind.HumanPresence;

    public static AreaLevel Level(DeviceSensor s) => s.State switch
    {
        DeviceSensorStatus.Error => AreaLevel.Error,
        DeviceSensorStatus.AccessDenied => AreaLevel.Warning,
        DeviceSensorStatus.Ready when s.ReadError is not null => AreaLevel.Warning,
        DeviceSensorStatus.Ready => AreaLevel.Ok,
        _ => AreaLevel.Neutral,
    };

    /// <summary>What to look at for one sensor, or null.</summary>
    public static string? Problem(DeviceSensor s, SensorDevice? device) =>
        device is { ProblemCode: not 0 } d ? "Driver problem: " + SensorDevices.ProblemText(d.ProblemCode)
        : s.State switch
        {
            DeviceSensorStatus.Error => "The sensor reports an error",
            DeviceSensorStatus.AccessDenied => s.Kind == DeviceSensorKind.Location
                ? "Access denied: location is turned off in Settings > Privacy & security > Location"
                : "Access denied to this app",
            DeviceSensorStatus.Ready when s.ReadError is not null => "Ready, but its reading couldn't be read",
            _ => null,
        };

    public static string Name(DeviceSensor s) => s.Name ?? DeviceSensorTypes.Title(s.Kind);

    public static AreaReport Build(DeviceSensorSnapshot snapshot, SensorDeviceReading devices)
    {
        if (snapshot.Error is not null && !devices.Read)
            return AreaReport.Failed("Couldn't check the sensors: " + snapshot.Error);
        var cards = new List<AreaCard>();
        var parts = new List<string>();
        var byInstance = devices.Devices.ToDictionary(d => d.DeviceId, StringComparer.OrdinalIgnoreCase);
        SensorDevice? DeviceOf(DeviceSensor s) => s.InstanceId is { } id && byInstance.TryGetValue(id, out var d) ? d : null;

        if (snapshot.Error is { } err)
        {
            cards.Add(AreaCard.Failed("sensors", "Sensors", "The sensors couldn't be read: " + err));
            parts.Add("Sensors couldn't be read");
        }
        else AddSensors(cards, parts, snapshot, DeviceOf);
        AddDevices(cards, parts, devices);

        var noSensors = snapshot.Error is null && snapshot.Sensors.Count == 0 && devices.Read && devices.Devices.Count(d => !d.IsLid) == 0;
        if (noSensors)
        {
            var lid = devices.Devices.FirstOrDefault(d => d.IsLid);
            return new(cards, "No motion, light or presence sensors on this PC" + (lid is { ProblemCode: 0 } ? " (lid switch working)" : ""),
                lid is { ProblemCode: not 0 } ? DiagnosticStatus.Warning : DiagnosticStatus.Ok) { NotOnThisPc = lid is null or { ProblemCode: 0 } };
        }
        var status = AreaReport.Worst(cards.Select(c => c.ErrorText is not null ? AreaLevel.Warning : c.Level));
        return new(cards, string.Join(" · ", parts), status);
    }

    private static void AddSensors(List<AreaCard> cards, List<string> parts, DeviceSensorSnapshot s, Func<DeviceSensor, SensorDevice?> deviceOf)
    {
        var rows = s.Sensors
            .OrderByDescending(x => Level(x) is AreaLevel.Error ? 2 : Level(x) is AreaLevel.Warning ? 1 : 0)
            .ThenBy(x => x.Kind).ThenBy(Name, StringComparer.CurrentCultureIgnoreCase)
            .Select(x =>
            {
                var device = deviceOf(x);
                var problem = Problem(x, device);
                var level = device is { ProblemCode: not 0 } ? AreaLevel.Error : Level(x);
                var detail = new List<string>();
                if (DeviceSensorTypes.Use(x.Kind) is { Length: > 0 } use) detail.Add("Used for: " + use);
                if (x.Model is { } model) detail.Add("Model: " + model);
                if (device is not null) detail.Add("Device: " + device.Name);
                if (x.InstanceId is { } id) detail.Add("Device instance: " + id);
                if (x.ReadError is { } re) detail.Add("Reading: " + re);
                if (problem is not null) detail.Add("Look at: " + problem);
                return new AreaRow(level,
                    [Name(x), DeviceSensorTypes.Title(x.Kind), DeviceSensorTypes.StateText(x.State), x.Manufacturer ?? "",
                     DeviceSensorTypes.ConnectionText(x.Connection), DeviceSensorTypes.ReadingText(x.Kind, x.Reading), problem ?? "OK"],
                    Key: x.Id, Detail: string.Join("\n", detail));
            }).ToList();
        var errors = rows.Count(r => r.Level == AreaLevel.Error);
        var warnings = rows.Count(r => r.Level == AreaLevel.Warning);
        var ready = s.Sensors.Count(x => x.State == DeviceSensorStatus.Ready);
        var kinds = s.Sensors.Select(x => x.Kind).Distinct().Order().Select(DeviceSensorTypes.Title).ToList();
        var headline = s.Sensors.Count == 0 ? "No sensors listed by Windows"
            : errors > 0 ? $"{Plural(errors, "sensor")} with an error"
            : warnings > 0 ? $"{Plural(warnings, "sensor")} to look at"
            : ready == s.Sensors.Count ? $"{Plural(s.Sensors.Count, "sensor")}, all ready"
            : $"{ready} of {Plural(s.Sensors.Count, "sensor")} ready";
        var testable = s.Sensors.Any(x => Testable(x.Kind));
        cards.Add(new AreaCard("sensors", "Sensors", errors > 0 ? AreaLevel.Error : warnings > 0 ? AreaLevel.Warning : s.Sensors.Count > 0 ? AreaLevel.Ok : AreaLevel.Neutral,
            headline,
            kinds.Count > 0 ? string.Join(", ", kinds) + (testable ? ". Use the Sensor test to try them by hand" : "")
                : "Motion, light, presence and hinge sensors that drive auto-rotate, auto-brightness and wake on approach",
            ["Sensor", "Type", "State", "Maker", "Connected", "Reading", "Status"], rows,
            EmptyText: "Windows lists no sensors on this PC. Most desktops and many laptops have none.", PreserveRowOrder: true)
            { OpenPage = testable ? new AreaPageLink("interactive?test=devicesensors", "Sensor test") : null });
        parts.Add(s.Sensors.Count == 0 ? "No sensors" : Plural(s.Sensors.Count, "sensor"));
        if (errors > 0) parts.Add(Plural(errors, "sensor error"));
        else if (warnings > 0) parts.Add(Plural(warnings, "sensor issue"));
    }

    private static void AddDevices(List<AreaCard> cards, List<string> parts, SensorDeviceReading r)
    {
        if (!r.Read)
        {
            cards.Add(r.NeedsAgent
                ? new AreaCard("devices", "Sensor drivers", AreaLevel.Neutral, "Needs the Agent", r.Error!, [], [], Note: r.Error)
                : AreaCard.Failed("devices", "Sensor drivers", r.Error!));
            return;
        }
        if (r.Devices.Count == 0) return;
        var rows = r.Devices.OrderByDescending(d => d.ProblemCode != 0).ThenBy(d => d.IsLid).ThenBy(d => d.Name, StringComparer.CurrentCultureIgnoreCase)
            .Select(d => new AreaRow(d.ProblemCode == 0 ? AreaLevel.Ok : d.ProblemCode == 22 ? AreaLevel.Warning : AreaLevel.Error,
                [d.Name, d.IsLid ? "Lid switch" : d.Class is "Sensor" ? "Sensor" : "Sensor hub", d.Manufacturer ?? "", SensorDevices.ProblemText(d.ProblemCode)],
                Key: d.DeviceId, Detail: "Device instance: " + d.DeviceId)).ToList();
        var bad = rows.Count(x => x.Level == AreaLevel.Error);
        var off = rows.Count(x => x.Level == AreaLevel.Warning);
        cards.Add(new AreaCard("devices", "Sensor drivers", bad > 0 ? AreaLevel.Error : off > 0 ? AreaLevel.Warning : AreaLevel.Ok,
            bad > 0 ? $"{Plural(bad, "sensor device")} with a driver problem"
                : off > 0 ? $"{Plural(off, "sensor device")} disabled"
                : $"{Plural(r.Devices.Count, "sensor device")}, all working",
            bad > 0 ? "A sensor hub or sensor that doesn't start stops auto-rotate, auto-brightness and presence. Device Manager & drivers can reinstall it"
                : "The sensors, sensor hubs and lid switch in Device Manager",
            ["Device", "Kind", "Maker", "Status"], rows, PreserveRowOrder: true)
            { RunCheck = bad > 0 ? new AreaCheckLink(ModuleSlugs.DeviceDrivers, "Device Manager & drivers") : null });
        if (bad > 0) parts.Add(Plural(bad, "sensor driver problem"));
        else if (off > 0) parts.Add(Plural(off, "sensor device") + " disabled");
    }
}
