using System.Text.Json;
using RemotePCDiagnostics.Core.DataSources;

namespace RemotePCDiagnostics.Core.Alerts;

/// <summary>
/// What the Agent's alerts read from the PC: the watched events (<see cref="AlertRules.EventIds"/>) and the three levels (free disk space,
/// memory commit charge, power). Each answer is rows, like WMI, so it can be recorded, replayed and broken by a fault plan the same way
/// (docs/fault-injection.md). The Agent reads the PC (<c>WindowsAlertReadings</c>); the replay tests read a recording.
/// </summary>
public interface IAlertReadings
{
    /// <param name="reading"><see cref="AlertReadings.Events"/> of a channel, <see cref="AlertReadings.Disks"/>,
    /// <see cref="AlertReadings.Memory"/> or <see cref="AlertReadings.Power"/>.</param>
    /// <param name="afterRecordId">Events only: newer than this record (0 for all).</param>
    /// <param name="lookBack">Events only: at most this old.</param>
    Task<WmiQueryResult> ReadAsync(string reading, long afterRecordId, TimeSpan lookBack, CancellationToken ct);
}

/// <summary>The readings' names and their rows, both ways. Rows that don't hold what they should (a damaged answer) are left out.</summary>
public static class AlertReadings
{
    public const string Namespace = "alerts";
    public const string Disks = "disks", Memory = "memory", Power = "power";
    public static string Events(string channel) => "events " + channel;
    public static IEnumerable<string> All => [.. AlertRules.EventIds.Keys.Select(Events), Disks, Memory, Power];

    /// <summary>At most this many events per channel and read, as the Agent's catch-up reads.</summary>
    public const int MaxEvents = 500;

    public static WmiQueryResult Result(string reading, IEnumerable<Dictionary<string, object?>> rows) =>
        new(Namespace, reading, [.. rows.Select(r => WmiRow.From(r))]);

    public static WmiQueryResult Failed(string reading, string error) => WmiQueryResult.Failed(Namespace, reading, error);

    // ------------------------------------------------------------------ events

    public static Dictionary<string, object?> Row(AlertEvent e) => new()
    {
        ["Provider"] = e.Provider, ["EventId"] = e.EventId, ["RecordId"] = e.RecordId, ["TimeUtc"] = e.TimeUtc.ToString("O"),
        ["Properties"] = e.Properties.ToArray(), ["Message"] = e.Message,
    };

    public static IReadOnlyList<AlertEvent> ToEvents(string channel, WmiQueryResult r)
    {
        var list = new List<AlertEvent>();
        foreach (var row in r.Rows ?? [])
        {
            if (row.Long("EventId") is not { } id || id is < 0 or > ushort.MaxValue) continue;
            if (!DateTimeOffset.TryParse(row.Str("TimeUtc"), out var time)) continue;
            var properties = row.Values.TryGetValue("Properties", out var p) && p.ValueKind == JsonValueKind.Array
                ? p.EnumerateArray().Select(v => v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : v.ToString()).ToList()
                : [];
            var message = row.Has("Message") ? row.Str("Message") : null;
            list.Add(new AlertEvent(channel, row.Str("Provider"), (int)id, row.Long("RecordId") ?? 0, time.ToUniversalTime(), properties, message));
        }
        return list;
    }

    // ------------------------------------------------------------------ levels

    public static Dictionary<string, object?> Row(DiskReading d) => new() { ["Drive"] = d.Drive, ["FreeGb"] = d.FreeGb, ["TotalGb"] = d.TotalGb };

    public static IReadOnlyList<DiskReading> ToDisks(WmiQueryResult r)
    {
        var list = new List<DiskReading>();
        foreach (var row in r.Rows ?? [])
        {
            var drive = row.Str("Drive");
            if (drive.Length == 0 || Number(row, "FreeGb") is not { } free || Number(row, "TotalGb") is not { } total) continue;
            if (total <= 0 || free < 0 || free > total) continue;
            list.Add(new DiskReading(drive, free, total));
        }
        return list;
    }

    public static Dictionary<string, object?> MemoryRow(double commitPercent) => new() { ["CommitPercent"] = commitPercent };

    public static double? ToCommitPercent(WmiQueryResult r) =>
        r.Rows?.FirstOrDefault() is { } row && Number(row, "CommitPercent") is { } v && v is >= 0 and <= 100 ? v : null;

    public static Dictionary<string, object?> Row(PowerReading p) => new()
    {
        ["OnBattery"] = p.OnBattery, ["Percent"] = p.Percent, ["Charging"] = p.Charging, ["HasBattery"] = p.HasBattery,
    };

    /// <summary>The reading as of <paramref name="now"/> (a recording's power is replayed as the current one).</summary>
    public static PowerReading? ToPower(WmiQueryResult r, DateTimeOffset now)
    {
        if (r.Rows?.FirstOrDefault() is not { } row) return null;
        if (row.Bool("OnBattery") is not { } onBattery || row.Bool("Charging") is not { } charging || row.Bool("HasBattery") is not { } hasBattery) return null;
        var percent = row.Long("Percent") is { } pc && pc is >= 0 and <= 100 ? (int)pc : (int?)null;
        return new PowerReading(now, onBattery, percent, charging, hasBattery);
    }

    private static double? Number(WmiRow row, string name) =>
        row.Values.TryGetValue(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetDouble(out var d) && double.IsFinite(d) ? d : null;
}
