using System.Globalization;
using System.Xml;
using System.Xml.Linq;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>One sleep (S3 "Suspend" or Modern Standby) period on battery, from the battery report's RecentUsage.</summary>
public sealed record StandbySession(DateTimeOffset Start, TimeSpan Duration, string EntryType, long DischargeMwh, long FullChargeMwh)
{
    /// <summary>Share of a full charge lost while asleep.</summary>
    public double DrainPercent => FullChargeMwh > 0 ? DischargeMwh * 100.0 / FullChargeMwh : 0;
    public double PercentPerHour => Duration.TotalHours > 0 ? DrainPercent / Duration.TotalHours : 0;
}

/// <summary>One sleep period from the battery report, on battery or on wall power.</summary>
public sealed record SleepPeriod(DateTimeOffset Start, TimeSpan Duration, bool OnBattery)
{
    public DateTimeOffset End => Start + Duration;
}

/// <summary>
/// Standby battery drain from <c>powercfg /batteryreport /xml</c> (no administrator rights needed; works on classic S3 sleep and on
/// Modern Standby). RecentUsage lists each period with its type (Active, Suspend, ConnectedStandby, ReportGenerated), whether it was on
/// wall power (Ac), its length in 100-ns ticks and the charge it used (Discharge, mWh; negative while charging).
/// </summary>
public static class StandbyDrain
{
    /// <summary>A sleep shorter than this says little about the drain rate (and rounding of the charge level dominates it).</summary>
    public static readonly TimeSpan MinSession = TimeSpan.FromMinutes(30);
    /// <summary>Drain at or above this many percent of a full charge per hour asleep is worth a look: about a third of the battery over a night.</summary>
    public const double WarnPercentPerHour = 1.5;
    /// <summary>At or above this rate a full battery is empty within a day asleep: something keeps the PC (or a device) awake.</summary>
    public const double ErrorPercentPerHour = 4.0;

    /// <summary>Days of history the report covers.</summary>
    public const int ReportDays = 7;

    public static IReadOnlyList<string> Args(string outputPath) =>
        ["/batteryreport", "/xml", "/output", outputPath, "/duration", ReportDays.ToString(CultureInfo.InvariantCulture)];

    /// <summary>The battery report's sleep periods on battery, oldest first. Null when the XML isn't a battery report.</summary>
    public static IReadOnlyList<StandbySession>? Parse(string? xml)
    {
        if (Load(xml) is not { Root: { } root }) return null;

        var entries = root.Elements().FirstOrDefault(e => e.Name.LocalName == "RecentUsage")?.Elements()
            .Where(e => e.Name.LocalName == "UsageEntry").ToList() ?? [];
        var list = new List<StandbySession>();
        for (var i = 0; i < entries.Count; i++)
        {
            var e = entries[i];
            var type = (string?)e.Attribute("EntryType") ?? "";
            if (!IsSleep(type) || (string?)e.Attribute("Ac") != "0") continue;
            if (SleepWakeParsers.Time((string?)e.Attribute("Timestamp")) is not { } start) continue;
            var ticks = Long(e, "Duration");
            if (ticks is not > 0) continue;
            var full = Long(e, "FullChargeCapacity") ?? 0;
            // Discharge is what this period used; when it's missing, the charge left at the start of the next period tells the same.
            var discharge = Long(e, "Discharge");
            if (discharge is null && i + 1 < entries.Count && Long(e, "ChargeCapacity") is { } c0 && Long(entries[i + 1], "ChargeCapacity") is { } c1)
                discharge = c0 - c1;
            if (discharge is null || full <= 0) continue;
            list.Add(new(start, TimeSpan.FromTicks(ticks.Value), type, Math.Max(0, discharge.Value), full));
        }
        return list.OrderBy(s => s.Start).ToList();
    }

    /// <summary>
    /// Every sleep period in the report, oldest first, on battery or not. The event log can miss sleeps the battery report
    /// has (it rolls over, or Windows didn't log the wake), so Recent wakes fills its gaps from these. Null when the XML isn't a battery report.
    /// </summary>
    public static IReadOnlyList<SleepPeriod>? ParseSleeps(string? xml)
    {
        if (Load(xml) is not { Root: { } root }) return null;
        var list = new List<SleepPeriod>();
        foreach (var e in root.Elements().FirstOrDefault(x => x.Name.LocalName == "RecentUsage")?.Elements().Where(x => x.Name.LocalName == "UsageEntry") ?? [])
        {
            if (!IsSleep((string?)e.Attribute("EntryType") ?? "")) continue;
            if (SleepWakeParsers.Time((string?)e.Attribute("Timestamp")) is not { } start) continue;
            if (Long(e, "Duration") is not { } ticks || ticks <= 0) continue;
            list.Add(new(start, TimeSpan.FromTicks(ticks), (string?)e.Attribute("Ac") == "0"));
        }
        return list.OrderBy(s => s.Start).ToList();
    }

    /// <summary>Whether the report says this PC has Modern Standby (SystemInformation/ConnectedStandby = 1). Null when not reported.</summary>
    public static bool? ConnectedStandby(string? xml)
    {
        var v = Load(xml)?.Root?.Elements().FirstOrDefault(e => e.Name.LocalName == "SystemInformation")?.Elements()
            .FirstOrDefault(e => e.Name.LocalName == "ConnectedStandby")?.Value.Trim();
        return v switch { "1" => true, "0" => false, _ => null };
    }

    /// <summary>The battery report document (elements are in its default namespace, so lookups go by local name), or null.</summary>
    private static XDocument? Load(string? xml)
    {
        if (string.IsNullOrWhiteSpace(xml)) return null;
        try
        {
            var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
            using var reader = XmlReader.Create(new StringReader(xml), settings);
            var doc = XDocument.Load(reader);
            return doc.Root?.Name.LocalName == "BatteryReport" ? doc : null;
        }
        catch (XmlException) { return null; }
    }

    /// <summary>Suspend (S3) and the Modern Standby entry types; Active and the ReportGenerated marker are not sleep.</summary>
    public static bool IsSleep(string entryType) =>
        entryType.Equals("Suspend", StringComparison.OrdinalIgnoreCase)
        || entryType.Contains("Standby", StringComparison.OrdinalIgnoreCase);

    /// <summary>Sessions long enough to rate.</summary>
    public static IReadOnlyList<StandbySession> Rated(IEnumerable<StandbySession> sessions) => sessions.Where(s => s.Duration >= MinSession).ToList();

    /// <summary>Average drain per hour over the rated sessions, weighted by their length. Null when none is long enough.</summary>
    public static double? AveragePercentPerHour(IReadOnlyList<StandbySession> sessions)
    {
        var rated = Rated(sessions);
        var hours = rated.Sum(s => s.Duration.TotalHours);
        return hours > 0 ? rated.Sum(s => s.DrainPercent) / hours : null;
    }

    public static AreaLevel LevelOf(double percentPerHour) =>
        percentPerHour >= ErrorPercentPerHour ? AreaLevel.Error : percentPerHour >= WarnPercentPerHour ? AreaLevel.Warning : AreaLevel.Ok;

    private static long? Long(XElement e, string name) =>
        long.TryParse((string?)e.Attribute(name), NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : null;
}
