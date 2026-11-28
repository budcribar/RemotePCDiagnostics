using System.Globalization;
using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Core.Cooling;

/// <summary>One second of the cooling test: when (seconds from the start), which phase, and what was read.</summary>
public sealed record CoolingSample(double At, string Phase, double? CpuC, double? LoadPercent, double? FanRpm);

/// <summary>The cooling test's thresholds and phase lengths (from the DiagnosticTest spec, issue #284).</summary>
public sealed record CoolingRules
{
    public const string Idle = "idle", Load = "load", Cool = "cool", FanMax = "fanmax";

    /// <summary>Tj max when the CPU reports none.</summary>
    public double DefaultTjMaxC { get; init; } = 100;
    /// <summary>A low-load sample fails above Tj max minus this.</summary>
    public double HotMarginC { get; init; } = 10;
    /// <summary>A sample counts as low load below this CPU busy percent.</summary>
    public double LowLoadPercent { get; init; } = 30;
    /// <summary>Hot low-load samples in a row for this long fail the test.</summary>
    public double HotForSeconds { get; init; } = 60;
    /// <summary>Warning when the typical low-load temperature is within this of the limit.</summary>
    public double WarmMarginC { get; init; } = 15;
    /// <summary>Fans must reach this many times their low-load speed under load.</summary>
    public double FanRiseRatio { get; init; } = 1.2;
    /// <summary>The CPU "climbs" when it warms at least this much under load.</summary>
    public double ClimbC { get; init; } = 5;
    /// <summary>The CPU must reach at least this temperature under load before a flat or stopped fan fails (avoids false fails on cool zero-RPM PCs).</summary>
    public double FanFailMinTempC { get; init; } = 60;
    /// <summary>The temperature has leveled off when it rose no more than this over <see cref="SettleSeconds"/> at the end of the load.</summary>
    public double SettledRiseC { get; init; } = 2;
    public double SettleSeconds { get; init; } = 30;
    /// <summary>The load stops early this close to Tj max, to protect the PC.</summary>
    public double StopMarginC { get; init; } = 3;

    public TimeSpan IdleQuick { get; init; } = TimeSpan.FromMinutes(2);
    public TimeSpan IdleFull { get; init; } = TimeSpan.FromMinutes(5);
    public TimeSpan LoadFor { get; init; } = TimeSpan.FromSeconds(90);
    public TimeSpan CoolFor { get; init; } = TimeSpan.FromSeconds(30);
    /// <summary>How long the fans run at max (HP Omen and Victus) while their speed is watched.</summary>
    public TimeSpan FanMaxFor { get; init; } = TimeSpan.FromSeconds(20);
    public TimeSpan SampleEvery { get; init; } = TimeSpan.FromSeconds(1);
    /// <summary>The temperature-and-load card keeps one sample in this many seconds (the chart and Admin read it).</summary>
    public int ChartEverySeconds { get; init; } = 5;

    public static readonly CoolingRules Default = new();
}

/// <summary>The verdicts, as cards. Pure functions of the samples, so every pass, warning and fail path is tested without hardware.</summary>
public static class CoolingJudge
{
    public const string IdleCard = "idle", FansCard = "fans", FanControlCard = "fan-control", ModesCard = "modes", SamplesCard = "samples";

    private static string C(double v) => $"{v.ToString("0", CultureInfo.InvariantCulture)}°C";
    private static string Rpm(double v) => $"{v.ToString("N0", CultureInfo.InvariantCulture)} RPM";
    private static string Pct(double v) => $"{v.ToString("0", CultureInfo.InvariantCulture)}%";
    private static string Secs(double s) => s >= 90 ? $"{(s / 60).ToString("0.#", CultureInfo.InvariantCulture)} min" : $"{s.ToString("0", CultureInfo.InvariantCulture)} s";

    public static double Limit(double? tjMax, CoolingRules r) => (tjMax ?? r.DefaultTjMaxC) - r.HotMarginC;

    public static double? Median(IEnumerable<double> values)
    {
        var v = values.OrderBy(x => x).ToList();
        if (v.Count == 0) return null;
        return v.Count % 2 == 1 ? v[v.Count / 2] : (v[v.Count / 2 - 1] + v[v.Count / 2]) / 2;
    }

    private static bool LowLoad(CoolingSample s, CoolingRules r) => s.LoadPercent is not { } l || l < r.LowLoadPercent;

    /// <summary>The longest run of samples that were both above the limit and at low load, in seconds.</summary>
    public static double LongestHotAtLowLoad(IReadOnlyList<CoolingSample> idle, double limit, CoolingRules r)
    {
        double best = 0, step = r.SampleEvery.TotalSeconds;
        double? start = null;
        foreach (var s in idle)
        {
            if (s.CpuC is { } t && t > limit && LowLoad(s, r))
            {
                start ??= s.At;
                best = Math.Max(best, s.At - start.Value + step);
            }
            else start = null;
        }
        return best;
    }

    /// <summary>Hot at low load: the passive part, from the idle phase.</summary>
    public static AreaCard IdleVerdict(IReadOnlyList<CoolingSample> idle, double? tjMax, bool approximate, CoolingRules r)
    {
        const string title = "Heat at low load";
        var columns = new[] { "Measure", "Value" };
        var limit = Limit(tjMax, r);
        var temps = idle.Where(s => s.CpuC is not null).ToList();
        var basis = tjMax is { } tj ? $"Tj max {C(tj)} reported by the CPU" : $"Tj max not reported, {C(r.DefaultTjMaxC)} assumed";
        var meta = $"Limit {C(limit)} ({basis}) · low load is under {Pct(r.LowLoadPercent)}";
        if (temps.Count == 0)
            return new(IdleCard, title, AreaLevel.Neutral, "Not supported: this PC reports no CPU temperature", meta, columns, [],
                EmptyText: "Without a CPU temperature the heat at low load can't be judged.");

        var low = temps.Where(s => LowLoad(s, r)).ToList();
        var typical = Median(low.Select(s => s.CpuC!.Value));
        var hottest = temps.Max(s => s.CpuC!.Value);
        var avgLoad = idle.Where(s => s.LoadPercent is not null).Select(s => s.LoadPercent!.Value).DefaultIfEmpty().Average();
        var hotFor = LongestHotAtLowLoad(idle, limit, r);
        var hotSamples = low.Count(s => s.CpuC > limit);
        var rows = new List<AreaRow>
        {
            Row(AreaLevel.Neutral, "Typical CPU temperature at low load", typical is { } ty ? C(ty) : "No low-load samples"),
            Row(AreaLevel.Neutral, "Hottest", C(hottest)),
            Row(AreaLevel.Neutral, "Average CPU load", Pct(avgLoad)),
            Row(hotFor >= r.HotForSeconds ? AreaLevel.Error : hotSamples > 0 ? AreaLevel.Warning : AreaLevel.Ok, "Longest time above the limit at low load", Secs(hotFor)),
            Row(AreaLevel.Neutral, "Watched for", Secs(idle.Count * r.SampleEvery.TotalSeconds)),
        };
        if (approximate) rows.Add(Row(AreaLevel.Neutral, "Temperature source", "Windows thermal zone (an estimate)"));
        var note = approximate ? "The CPU temperature is Windows' thermal zone estimate, which can read a few degrees off the chip." : null;

        if (hotFor >= r.HotForSeconds)
            return new(IdleCard, title, AreaLevel.Error, $"Hot at low load: above {C(limit)} for {Secs(hotFor)} while the CPU was under {Pct(r.LowLoadPercent)} busy (hottest {C(hottest)})",
                meta, columns, rows, Note: "A CPU this hot without work points to cooling: blocked vents, dust in the fan or heatsink, a fan that doesn't spin, or dried thermal paste.");
        if (typical is null)
            return new(IdleCard, title, AreaLevel.Warning, $"Too busy to judge: the CPU stayed busy the whole time (average {Pct(avgLoad)}), so its low-load heat couldn't be judged; close other apps and run it again",
                meta, columns, rows, Note: note);
        if (hotSamples > 0 || typical >= limit - r.WarmMarginC)
            return new(IdleCard, title, AreaLevel.Warning, $"Runs warm at low load: typically {C(typical.Value)}, limit {C(limit)}" + (hotSamples > 0 ? $"; above it for {Secs(hotFor)}" : ""),
                meta, columns, rows, Note: note ?? "Check that the vents aren't blocked and the PC isn't on a soft surface.");
        return new(IdleCard, title, AreaLevel.Ok, $"Passed: typically {C(typical.Value)} at low load (limit {C(limit)})", meta, columns, rows, Note: note);
    }

    /// <summary>Fan response: did the fans speed up and the temperature level off under load.</summary>
    public static AreaCard FanVerdict(IReadOnlyList<CoolingSample> idle, IReadOnlyList<CoolingSample> load, double? stoppedAtC, CoolingRules r)
    {
        const string title = "Fan response under load";
        var columns = new[] { "Measure", "Value" };
        var meta = $"{Secs(r.LoadFor.TotalSeconds)} of full CPU load · fans must rise {Pct((r.FanRiseRatio - 1) * 100)} over low load";
        var settleFrom = load.Count == 0 ? 0 : load[^1].At - r.SettleSeconds;
        var idleTail = idle.Where(s => s.At >= (idle.Count == 0 ? 0 : idle[^1].At - 30)).ToList();
        var idleFan = Median(idleTail.Where(s => s.FanRpm is not null).Select(s => s.FanRpm!.Value));
        var loadFans = load.Where(s => s.FanRpm is not null).Select(s => s.FanRpm!.Value).ToList();
        var peakFan = loadFans.Count == 0 ? (double?)null : loadFans.Max();
        var idleTemp = Median(idleTail.Where(s => s.CpuC is not null).Select(s => s.CpuC!.Value));
        var peakTemp = load.Where(s => s.CpuC is not null).Select(s => s.CpuC!.Value).DefaultIfEmpty(double.NaN).Max();
        var avgLoad = load.Where(s => s.LoadPercent is not null).Select(s => s.LoadPercent!.Value).DefaultIfEmpty().Average();
        var hasTemp = idleTemp is not null && !double.IsNaN(peakTemp);
        var climbed = hasTemp && peakTemp - idleTemp!.Value >= r.ClimbC;
        var hotEnoughForFan = hasTemp && peakTemp >= r.FanFailMinTempC;
        var tail = load.Where(s => s.At >= settleFrom && s.CpuC is not null).ToList();
        double? endRise = tail.Count >= 2 ? tail[^1].CpuC!.Value - tail.Min(s => s.CpuC!.Value) : null;

        var rows = new List<AreaRow>
        {
            Row(AreaLevel.Neutral, "Fan speed at low load", idleFan is { } f0 ? Rpm(f0) : "Not reported"),
            Row(AreaLevel.Neutral, "Fastest fan speed under load", peakFan is { } f1 ? Rpm(f1) : "Not reported"),
            Row(AreaLevel.Neutral, "CPU temperature at low load", idleTemp is { } t0 ? C(t0) : "Not reported"),
            Row(AreaLevel.Neutral, "Hottest under load", double.IsNaN(peakTemp) ? "Not reported" : C(peakTemp)),
            Row(AreaLevel.Neutral, $"Rise in the last {Secs(r.SettleSeconds)} of load", endRise is { } er ? $"{er.ToString("0.#", CultureInfo.InvariantCulture)} °C" : "Not reported"),
            Row(AreaLevel.Neutral, "Average CPU load", Pct(avgLoad)),
        };
        if (idleFan is > 0 && peakFan is { } pf) rows.Insert(2, Row(AreaLevel.Neutral, "Fan rise", Pct((pf / idleFan.Value - 1) * 100)));
        if (stoppedAtC is { } stop) rows.Add(Row(AreaLevel.Warning, "Load stopped early", $"at {C(stop)}, to protect the PC"));

        var heat = hasTemp ? $"the CPU heated from {C(idleTemp!.Value)} to {C(peakTemp)}" : "no CPU temperature was readable";
        if (peakFan is not { } loadPeakFan)
        {
            if (stoppedAtC is { } stopNoFan)
                return new(FansCard, title, AreaLevel.Warning, $"Runs hot under load: the CPU reached {C(stopNoFan)} and the load was stopped early (no fan readings were reported)",
                    meta, columns, rows, Note: "The cooling couldn't keep up with a full load. Clean the vents and heatsink, check the thermal paste, and listen for the fan.");
            // Many laptops (ARM ones especially) don't report fan speed at all: that's a missing sensor, not a cooling fault.
            return new(FansCard, title, AreaLevel.Neutral, $"No fan readings: this PC reports no fan speed, so the fan response can't be checked ({heat})",
                meta, columns, rows, Note: "Listen for the fan getting louder under load, or check it in the maker's own tool or BIOS.");
        }

        var allZero = loadFans.All(v => v <= 0);
        if (allZero && ((climbed && hotEnoughForFan) || !hasTemp))
            return new(FansCard, title, AreaLevel.Error, $"Fan not responding: it read 0 RPM the whole time while {heat}", meta, columns, rows,
                Note: "The fan may be stuck, unplugged or failed. Check it spins; a laptop that runs without its fan will slow down and can shut down hot.");
        if (idleFan is not { } idleRpm)
        {
            if (stoppedAtC is { } stopNoIdle)
                return new(FansCard, title, AreaLevel.Warning, $"Runs hot under load: fans reached {Rpm(loadPeakFan)} (no low-load fan reading to compare), but the CPU reached {C(stopNoIdle)} and the load was stopped early",
                    meta, columns, rows, Note: "The cooling couldn't keep up with a full load. Clean the vents and heatsink; check the thermal paste.");
            return new(FansCard, title, AreaLevel.Warning, $"No low-load fan reading: fans reached {Rpm(loadPeakFan)} under load ({heat}), so the fan rise couldn't be checked",
                meta, columns, rows);
        }

        var rose = idleRpm <= 0 ? loadPeakFan > 0 : loadPeakFan >= idleRpm * r.FanRiseRatio;
        if (!rose && climbed && hotEnoughForFan)
            return new(FansCard, title, AreaLevel.Error, $"Fan not responding: it stayed at about {Rpm(loadPeakFan)} while {heat}", meta, columns, rows,
                Note: "The fan didn't speed up for the heat. It may be failing, or the PC's fan control isn't working. Check the maker's BIOS fan settings, then the fan.");
        if (!rose && !hasTemp)
            return new(FansCard, title, AreaLevel.Warning, $"Fans didn't speed up: about {Rpm(loadPeakFan)} under load, and no CPU temperature was readable to compare", meta, columns, rows);
        if (!rose)
        {
            if (stoppedAtC is { } stopFlat)
                return new(FansCard, title, AreaLevel.Warning, $"Runs hot under load: the CPU reached {C(stopFlat)} and the load was stopped early (fan stayed at about {Rpm(loadPeakFan)})",
                    meta, columns, rows, Note: "The cooling couldn't keep up with a full load. Clean the vents and heatsink; check the thermal paste.");
            return new(FansCard, title, AreaLevel.Ok, $"Passed: {heat}, little enough that the fans didn't need to speed up", meta, columns, rows);
        }

        var fanText = idleRpm > 0 ? $"fans rose from {Rpm(idleRpm)} to {Rpm(loadPeakFan)}" : $"fans started and reached {Rpm(loadPeakFan)}";
        if (stoppedAtC is { } s2)
            return new(FansCard, title, AreaLevel.Warning, $"Runs hot under load: {fanText}, but the CPU reached {C(s2)} and the load was stopped early", meta, columns, rows,
                Note: "The fans respond, but the cooling can't keep up with a full load. Clean the vents and heatsink; check the thermal paste.");
        if (endRise is { } rise && rise > r.SettledRiseC && climbed)
            return new(FansCard, title, AreaLevel.Warning, $"Still heating: {fanText}, but the CPU hadn't leveled off by the end of the load (+{rise.ToString("0.#", CultureInfo.InvariantCulture)} °C in the last {Secs(r.SettleSeconds)})",
                meta, columns, rows, Note: "Healthy cooling levels the temperature off within a minute or so of full load.");
        var levelText = double.IsNaN(peakTemp) ? "" : $" and the CPU leveled off at {C(peakTemp)}";
        return new(FansCard, title, AreaLevel.Ok, $"Passed: {fanText}{levelText}", meta, columns, rows);
    }

    /// <summary>The maker's fan control: no maker this app knows lets Windows apps set fan speeds, so it is reported, not run.</summary>
    public static AreaCard FanControl(string? maker) =>
        new(FanControlCard, "Fan speed control", AreaLevel.Neutral,
            $"Not supported: {(maker is { Length: > 0 } ? maker + " doesn't" : "this PC's maker doesn't")} let Windows apps set the fan speed, so the 20% to 100% steps weren't run",
            "Fan steps need the maker's fan control", ["Measure", "Value"], [], EmptyText: "Fan response under load shows how the fans follow the heat on their own.");

    /// <summary>
    /// The maker's "fans at max" switch (HP Omen and Victus), run with the CPU idle after the cool-down: the fans should speed up well past
    /// where they were. <paramref name="before"/> is the cool-down's end, <paramref name="atMax"/> the samples while at max.
    /// </summary>
    public static AreaCard FanMaxVerdict(string setting, string? setError, bool readBack, IReadOnlyList<CoolingSample> before, IReadOnlyList<CoolingSample> atMax,
        double? loadPeakFan, CoolingRules r)
    {
        const string title = "Fan speed control";
        var columns = new[] { "Measure", "Value" };
        var meta = $"{setting} for {Secs(r.FanMaxFor.TotalSeconds)}, then back to automatic · fans must rise {Pct((r.FanRiseRatio - 1) * 100)}";
        if (setError is not null)
            return new(FanControlCard, title, AreaLevel.Warning, $"Couldn't set the fans to max: {setError}", meta, columns, [Row(AreaLevel.Warning, setting, setError)],
                Note: "Update the BIOS and OMEN Gaming Hub, then run the test again.");
        var baseline = Median(before.TakeLast(5).Where(s => s.FanRpm is not null).Select(s => s.FanRpm!.Value));
        var maxFans = atMax.Where(s => s.FanRpm is not null).Select(s => s.FanRpm!.Value).ToList();
        double? peak = maxFans.Count == 0 ? null : maxFans.Max();
        var rows = new List<AreaRow>
        {
            Row(readBack ? AreaLevel.Ok : AreaLevel.Warning, setting, readBack ? "Set and read back" : "Didn't read back as set"),
            Row(AreaLevel.Neutral, "Fan speed before", baseline is { } b ? Rpm(b) : "Not reported"),
            Row(AreaLevel.Neutral, "Fastest fan speed at max", peak is { } p ? Rpm(p) : "Not reported"),
        };
        if (loadPeakFan is { } lp) rows.Add(Row(AreaLevel.Neutral, "Fastest under full CPU load", Rpm(lp)));
        if (!readBack)
            return new(FanControlCard, title, AreaLevel.Warning, "Fans at max didn't stay set: HP's BIOS took the request but reads automatic", meta, columns, rows);
        if (peak is not { } top)
            return new(FanControlCard, title, AreaLevel.Ok, "Passed: the fans were set to max and back (this PC reports no fan speed, so listen for them getting louder)", meta, columns, rows);
        if (baseline is { } b0 && b0 > 0 ? top >= b0 * r.FanRiseRatio : top > 0)
            return new(FanControlCard, title, AreaLevel.Ok, baseline is { } b1 ? $"Passed: fans went from {Rpm(b1)} to {Rpm(top)} at max" : $"Passed: fans reached {Rpm(top)} at max", meta, columns, rows);
        return new(FanControlCard, title, AreaLevel.Warning, $"Fans didn't speed up at max: about {Rpm(top)}{(baseline is { } b2 ? $", from {Rpm(b2)}" : "")}", meta, columns, rows,
            Note: "Set to full speed, the fans should get much faster and louder. Check the fans aren't blocked or failing, and that OMEN Gaming Hub isn't overriding them.");
    }

    /// <summary>The temperature-and-load chart's points, one per <see cref="CoolingRules.ChartEverySeconds"/> (widened when needed to fit <see cref="AreaReportExport.MaxRowsPerCard"/>).</summary>
    public static AreaCard Samples(IReadOnlyList<CoolingSample> samples, CoolingRules r)
    {
        var stride = Math.Max(1, r.ChartEverySeconds);
        if (samples.Count > AreaReportExport.MaxRowsPerCard)
        {
            var span = samples[^1].At - samples[0].At;
            if (span > 0)
                stride = Math.Max(stride, (int)Math.Ceiling(span / (AreaReportExport.MaxRowsPerCard - 2)));
        }
        var rows = new List<AreaRow>();
        double next = 0;
        foreach (var s in samples)
        {
            if (s.At + 1e-6 < next && !ReferenceEquals(s, samples[^1])) continue;
            next = s.At + stride;
            rows.Add(new(AreaLevel.Neutral,
                [s.At.ToString("0", CultureInfo.InvariantCulture), PhaseName(s.Phase), N(s.CpuC), N(s.LoadPercent), N(s.FanRpm)],
                SortKeys: [s.At.ToString("00000", CultureInfo.InvariantCulture), null, null, null, null], Key: s.Phase));
        }
        var hottest = samples.Where(s => s.CpuC is not null).Select(s => s.CpuC!.Value).DefaultIfEmpty(double.NaN).Max();
        return new(SamplesCard, "Temperature and load", AreaLevel.Neutral,
            double.IsNaN(hottest) ? $"No CPU temperature: {samples.Count} samples" : $"Hottest {C(hottest)}: {samples.Count} samples",
            $"One row every {stride} s: CPU °C, CPU load %, fastest fan RPM", ["Seconds", "Phase", "CPU °C", "CPU load %", "Fan RPM"], rows,
            PreserveRowOrder: true);
    }

    public static string PhaseName(string phase) => phase switch
    {
        CoolingRules.Idle => "Low load", CoolingRules.Load => "Full load", CoolingRules.Cool => "Cooling down", CoolingRules.FanMax => "Fans at max", _ => phase,
    };

    private static string N(double? v) => v is { } x ? x.ToString("0.#", CultureInfo.InvariantCulture) : "";

    internal static AreaRow Row(AreaLevel level, string measure, string value) => new(level, [measure, value]);

    private static string Cap(string s) => s.Length == 0 ? s : char.ToUpperInvariant(s[0]) + s[1..];

    /// <summary>The whole verdict of a <see cref="Compact"/> card again ("label: sentence").</summary>
    public static string Verdict(AreaCard c)
    {
        var first = c.Meta.Split(" · ")[0];
        return c.Headline.Length <= MaxLabel && first.Length > 0 && !c.Headline.Contains(": ", StringComparison.Ordinal) ? $"{c.Headline}: {first}" : c.Headline;
    }

    /// <summary>The longest verdict label <see cref="Compact"/> keeps as a card's headline.</summary>
    public const int MaxLabel = 40;

    /// <summary>
    /// The card as the page shows it: the headline is the short verdict before the first ": " ("Hot at low load", "Passed") and the
    /// sentence after it leads the meta list, so a card's big headline text stays a few words, like the other checks' cards.
    /// </summary>
    public static AreaCard Compact(AreaCard c)
    {
        var i = c.Headline.IndexOf(": ", StringComparison.Ordinal);
        if (i <= 0 || i > MaxLabel) return c;
        var detail = c.Headline[(i + 2)..].Trim(); // the card list capitalizes it
        return c with { Headline = c.Headline[..i], Meta = string.IsNullOrWhiteSpace(c.Meta) ? detail : detail + " · " + c.Meta };
    }
}
