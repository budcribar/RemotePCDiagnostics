using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Core.Battery;

/// <summary>How hard the battery drain test works the PC.</summary>
public enum BatteryDrainMode
{
    /// <summary>Every processor core and a block of memory busy, the screen kept on: about 1 to 2 hours on a typical laptop.</summary>
    MaxLoad,
    /// <summary>A light load the person can keep working through: up to about 4 hours.</summary>
    Balanced,
}

/// <summary>One reading of the PC's batteries (all of them added up), as the drain test logs it every 30 seconds.</summary>
/// <param name="OnAc">The charger is connected (any battery reports power online).</param>
/// <param name="Percent">The charge Windows shows, 0 to 100.</param>
/// <param name="RemainingMWh">What the batteries' gauge says is left, in mWh.</param>
/// <param name="FullChargeMWh">What the gauge says a full charge holds now, in mWh.</param>
/// <param name="DischargeMw">How fast the batteries are being drained, in mW (null while charging or when not reported).</param>
/// <param name="VoltageMv">The battery voltage in mV (the first battery's when there are several).</param>
public sealed record BatteryDrainReading(bool OnAc, int? Percent, long? RemainingMWh, long? FullChargeMWh, int? DischargeMw, int? VoltageMv)
{
    /// <summary>The charge Windows shows, or one worked out from the gauge's capacities when Windows gave none.</summary>
    public int? PercentOrComputed => Percent ?? (RemainingMWh is { } r && FullChargeMWh is > 0 and var f ? (int)Math.Round(Math.Clamp(r * 100.0 / f, 0, 100)) : null);
}

/// <summary>A reading with when it was taken: <see cref="Seconds"/> since the run started.</summary>
public sealed record BatteryDrainSample(
    [property: JsonPropertyName("at")] DateTimeOffset At,
    [property: JsonPropertyName("s")] double Seconds,
    [property: JsonPropertyName("ac")] bool OnAc,
    [property: JsonPropertyName("pct")] int? Percent,
    [property: JsonPropertyName("mwh")] long? RemainingMWh,
    [property: JsonPropertyName("fullMwh")] long? FullChargeMWh,
    [property: JsonPropertyName("mw")] int? DischargeMw,
    [property: JsonPropertyName("mv")] int? VoltageMv)
{
    public static BatteryDrainSample Of(BatteryDrainReading r, DateTimeOffset at, double seconds) =>
        new(at, seconds, r.OnAc, r.PercentOrComputed, r.RemainingMWh, r.FullChargeMWh, r.DischargeMw, r.VoltageMv);
}

/// <summary>Why a drain run ended.</summary>
public enum BatteryDrainEnd
{
    /// <summary>Reached the stop level (5 %) with the shutdown confirmed: the Agent shuts the PC down.</summary>
    ReachedStop,
    /// <summary>Reached 15 % before anyone confirmed the shutdown at 5 %: stopped there, nothing shut down.</summary>
    NotConfirmed,
    /// <summary>The charger came back and stayed connected longer than the resume window.</summary>
    ChargerConnected,
    /// <summary>Stopped by the person, the Checks screen or Admin.</summary>
    Cancelled,
    /// <summary>Ran for the mode's longest time without reaching the stop level.</summary>
    TimeLimit,
    /// <summary>The batteries stopped answering, or the Agent stopped keeping the power settings.</summary>
    ReadingsLost,
    /// <summary>The PC turned off during the run (found at the next start): the last reading is where it stopped.</summary>
    PcShutOff,
    /// <summary>The app closed or crashed during the run while the PC kept running (found at the next start).</summary>
    AppClosed,
}

/// <summary>The fixed numbers of the drain test.</summary>
public static class BatteryDrainLimits
{
    public static readonly TimeSpan SampleEvery = TimeSpan.FromSeconds(30);
    /// <summary>The run stops (and, when confirmed, shuts the PC down) at this charge.</summary>
    public const int StopAtPercent = 5;
    /// <summary>Without the shutdown confirmed, the run stops here instead.</summary>
    public const int ConfirmByPercent = 15;
    /// <summary>A PC that turns off above this charge fails the test: the battery can't deliver what the gauge shows.</summary>
    public const int ShutOffFailAbovePercent = 10;
    /// <summary>Delivered energy under this share of the reported full charge (projected over 100 %) warns: the gauge needs calibrating.</summary>
    public const double DeliveredWarnBelow = 0.80;
    /// <summary>Fewer percentage points than this drained is too little to judge the gauge.</summary>
    public const int MinPercentToJudge = 20;
    /// <summary>How long the run waits for the charger to be unplugged again before it gives up.</summary>
    public static readonly TimeSpan ResumeWindow = TimeSpan.FromMinutes(10);
    /// <summary>Readings that may fail in a row before the run stops.</summary>
    public const int MaxMissedReadings = 4;

    /// <summary>The longest a run may last in each mode (a full drain takes about 1 to 2 hours at maximum load, about 4 balanced).</summary>
    public static TimeSpan MaxDuration(BatteryDrainMode mode) => mode == BatteryDrainMode.MaxLoad ? TimeSpan.FromHours(4) : TimeSpan.FromHours(8);
}

/// <summary>What a run measured, worked out from its readings. Only the time on battery counts.</summary>
public sealed record BatteryDrainMeasure(
    int? StartPercent, int? EndPercent, double BatterySeconds, double PausedSeconds,
    double DeliveredMWh, bool DeliveredFromRate, double? GaugeDropMWh,
    long? ReportedFullMWh, double? AverageWatts, double? PeakWatts, int? StartVoltageMv, int? EndVoltageMv)
{
    /// <summary>Percentage points drained while on battery (charge gained while plugged in during a pause doesn't count).</summary>
    public int PercentDrained { get; init; }

    /// <summary>What a full charge would deliver at this rate: the energy measured over the share of the charge it took.</summary>
    public double? ProjectedFullMWh => PercentDrained > 0 ? DeliveredMWh / (PercentDrained / 100.0) : null;

    /// <summary>The projected full charge as a share of what the gauge reported at the start (1.0 = the gauge is right).</summary>
    public double? DeliveredRatio => ProjectedFullMWh is { } p && ReportedFullMWh is > 0 and var f ? p / f : null;

    /// <summary>How far the gauge is off, in percent of what it reported (positive: it promises more than the battery delivers).</summary>
    public double? GaugeOffPercent => DeliveredRatio is { } r ? (1 - r) * 100 : null;

    /// <summary>How long a full charge would last at this load, from the time and the share of the charge it took.</summary>
    public double? ProjectedRuntimeSeconds => PercentDrained > 0 ? BatterySeconds / (PercentDrained / 100.0) : null;

    public bool CanJudge => PercentDrained >= BatteryDrainLimits.MinPercentToJudge && DeliveredRatio is not null;

    /// <summary>
    /// Adds up the readings: energy from the discharge rate (the trapezoid between two readings on battery), or from the gauge's drop in
    /// remaining capacity when a battery reports no rate. A pair of readings with the charger connected at either end is a pause.
    /// </summary>
    public static BatteryDrainMeasure From(IReadOnlyList<BatteryDrainSample> samples)
    {
        double battery = 0, paused = 0, fromRate = 0, fromGauge = 0, gaugeDrop = 0;
        var rateCovered = true;
        var anyGauge = false;
        var drained = 0;
        double? peak = null;
        for (var i = 1; i < samples.Count; i++)
        {
            var a = samples[i - 1];
            var b = samples[i];
            var dt = Math.Max(0, b.Seconds - a.Seconds);
            if (a.OnAc || b.OnAc) { paused += dt; continue; }
            battery += dt;
            if (a.DischargeMw is { } ra && b.DischargeMw is { } rb) fromRate += (ra + rb) / 2.0 * dt / 3600.0;
            else rateCovered = false;
            if (a.RemainingMWh is { } ca && b.RemainingMWh is { } cb)
            {
                anyGauge = true;
                gaugeDrop += ca - cb;
                fromGauge += Math.Max(0, ca - cb);
            }
            if (a.Percent is { } pa && b.Percent is { } pb && pa > pb) drained += pa - pb;
            foreach (var mw in new[] { a.DischargeMw, b.DischargeMw })
                if (mw is { } w && (peak is null || w / 1000.0 > peak)) peak = w / 1000.0;
        }
        var useRate = rateCovered && fromRate > 0;
        var delivered = useRate ? fromRate : fromGauge;
        var onBattery = samples.Where(s => !s.OnAc).ToList();
        return new(
            samples.FirstOrDefault(s => s.Percent is not null)?.Percent,
            samples.LastOrDefault(s => s.Percent is not null)?.Percent,
            battery, paused, delivered, useRate, anyGauge ? gaugeDrop : null,
            samples.FirstOrDefault(s => s.FullChargeMWh is > 0)?.FullChargeMWh,
            battery > 0 && delivered > 0 ? delivered / (battery / 3600.0) / 1000.0 : null,
            peak,
            onBattery.FirstOrDefault(s => s.VoltageMv is > 0)?.VoltageMv,
            onBattery.LastOrDefault(s => s.VoltageMv is > 0)?.VoltageMv)
        { PercentDrained = drained };
    }
}

/// <summary>One drain run as the app keeps it on disk while it runs, so a PC that turns off mid-run still has its readings at the next start.</summary>
public sealed record BatteryDrainRunLog
{
    [JsonPropertyName("schema")] public int Schema { get; init; } = 1;
    [JsonPropertyName("mode")] public string Mode { get; init; } = "max";
    [JsonPropertyName("startedUtc")] public DateTimeOffset StartedUtc { get; init; }
    /// <summary>When Windows last started, at the start of the run: a different boot at the next start means the PC turned off.</summary>
    [JsonPropertyName("bootUtc")] public DateTimeOffset BootUtc { get; init; }
    [JsonPropertyName("pid")] public int ProcessId { get; init; }
    [JsonPropertyName("confirmed")] public bool ShutdownConfirmed { get; init; }
    /// <summary>Null while the run is going; set when it ended the way the app meant it to.</summary>
    [JsonPropertyName("end")] public string? End { get; init; }
    [JsonPropertyName("samples")] public IReadOnlyList<BatteryDrainSample> Samples { get; init; } = [];

    private static readonly JsonSerializerOptions Json = new() { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull };

    public string ToJson() => JsonSerializer.Serialize(this, Json);

    public static BatteryDrainRunLog? Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try { return JsonSerializer.Deserialize<BatteryDrainRunLog>(json, Json) is { Schema: 1 } log ? log : null; }
        catch (JsonException) { return null; }
    }
}

/// <summary>Where the run log lives (the user's own app data: it holds only battery readings) and how it is read and written.</summary>
public interface IBatteryDrainLogStore
{
    BatteryDrainRunLog? Read();
    void Write(BatteryDrainRunLog? log);
}

public sealed class FileBatteryDrainLogStore(string? path = null, ILogger? log = null) : IBatteryDrainLogStore
{
    public string Path { get; } = path ?? System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RemotePCDiagnostics", "battery-drain-run.json");

    public BatteryDrainRunLog? Read()
    {
        try { return File.Exists(Path) ? BatteryDrainRunLog.Parse(File.ReadAllText(Path)) : null; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { log.Warn($"[battery-drain] Couldn't read {Path}: {ex.Message}"); return null; }
    }

    public void Write(BatteryDrainRunLog? run)
    {
        try
        {
            if (run is null) { if (File.Exists(Path)) File.Delete(Path); return; }
            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path)!);
            var tmp = Path + ".tmp";
            File.WriteAllText(tmp, run.ToJson());
            File.Move(tmp, Path, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { log.Warn($"[battery-drain] Couldn't save {Path}: {ex.Message}"); }
    }
}

/// <summary>The drain test's report: verdict, card and key metrics, from the readings and how the run ended.</summary>
public static class BatteryDrainReport
{
    public const string CardId = "battery-drain", SamplesCardId = "battery-drain-log";
    public const string NeedsAgentSummary = "Needs the Agent";
    /// <summary>A row in the log card every this many seconds of run time (the run log and batterydrain-data keep every 30 s reading).</summary>
    public const double LogRowEverySeconds = 120;

    public static string ModeArg(BatteryDrainMode mode) => mode == BatteryDrainMode.Balanced ? "balanced" : "max";
    public static BatteryDrainMode? ParseMode(string? arg) => arg switch { "max" => BatteryDrainMode.MaxLoad, "balanced" => BatteryDrainMode.Balanced, _ => null };
    public static string ModeText(BatteryDrainMode mode) => mode == BatteryDrainMode.Balanced ? "Balanced (light load)" : "Maximum load (all cores and memory, screen on)";

    /// <summary>The run's level: Failed when the PC turned off above 10 %; Warning when the projected full charge is under 80 % of the
    /// reported one (or too little was drained to judge, or the PC turned off before the 5 % stop); Passed otherwise.</summary>
    public static AreaLevel Verdict(BatteryDrainMeasure m, BatteryDrainEnd end)
    {
        if (end == BatteryDrainEnd.PcShutOff && m.EndPercent is > BatteryDrainLimits.ShutOffFailAbovePercent) return AreaLevel.Error;
        if (end == BatteryDrainEnd.PcShutOff) return AreaLevel.Warning;
        if (!m.CanJudge) return AreaLevel.Warning;
        return m.DeliveredRatio < BatteryDrainLimits.DeliveredWarnBelow ? AreaLevel.Warning : AreaLevel.Ok;
    }

    public static AreaReport Build(IReadOnlyList<BatteryDrainSample> samples, BatteryDrainMode mode, BatteryDrainEnd end, bool shutdownConfirmed,
        string? powerSettings = null, string? endDetail = null)
    {
        var m = BatteryDrainMeasure.From(samples);
        var level = Verdict(m, end);
        var cancelled = end is BatteryDrainEnd.Cancelled or BatteryDrainEnd.ChargerConnected && level != AreaLevel.Error && !m.CanJudge;
        var headline = Headline(m, end, level);
        var meta = $"{(mode == BatteryDrainMode.Balanced ? "Balanced" : "Maximum load")} · {Duration(m.BatterySeconds)} on battery"
                   + (m.StartPercent is { } s0 && m.EndPercent is { } s1 ? $" · {s0} % → {s1} %" : "");

        var rows = new List<AreaRow>
        {
            new(AreaLevel.Neutral, ["Mode", ModeText(mode)], Key: "mode"),
            new(EndLevel(end, m), ["Ended", EndText(end, m) + (endDetail is { Length: > 0 } d ? $" ({d})" : "")], Key: "end"),
            new(AreaLevel.Neutral, ["Charge", m.StartPercent is { } a && m.EndPercent is { } b ? $"{a} % → {b} % ({m.PercentDrained} points on battery)" : "Not reported"], Key: "charge"),
            new(AreaLevel.Neutral, ["Runtime on battery", Duration(m.BatterySeconds)], Key: "runtime"),
            new(AreaLevel.Neutral, ["Energy delivered", Wh(m.DeliveredMWh) + (m.DeliveredFromRate ? " (from the discharge rate)" : " (from the gauge's remaining capacity)")], Key: "delivered"),
            new(AreaLevel.Neutral, ["Reported full charge", m.ReportedFullMWh is { } f ? Wh(f) : "Not reported"], Key: "reported-full"),
        };
        if (m.ProjectedFullMWh is { } projected)
            rows.Add(new(AreaLevel.Neutral, ["Projected full charge from this run", Wh(projected)], Key: "projected-full",
                Detail: "The energy measured, divided by the share of the charge it used: what a drain from 100 % to 0 % would deliver at this load."));
        if (m.DeliveredRatio is { } ratio)
            rows.Add(new(!m.CanJudge ? AreaLevel.Neutral : ratio < BatteryDrainLimits.DeliveredWarnBelow ? AreaLevel.Warning : AreaLevel.Ok,
                ["Delivered vs reported", Pct(ratio * 100) + (m.CanJudge ? "" : $" (under {BatteryDrainLimits.MinPercentToJudge} points drained: too little to judge)")], Key: "delivered-ratio"));
        if (m.GaugeOffPercent is { } off)
            rows.Add(new(AreaLevel.Neutral, ["Gauge off by", off >= 0 ? $"{Pct(off)} (it promises more than the battery delivers)" : $"{Pct(-off)} (the battery delivers more than it shows)"], Key: "gauge-off"));
        if (m.GaugeDropMWh is { } drop)
            rows.Add(new(AreaLevel.Neutral, ["Gauge's remaining capacity used", Wh(drop)], Key: "gauge-drop"));
        if (m.AverageWatts is { } avg) rows.Add(new(AreaLevel.Neutral, ["Average power", $"{avg:0.0} W"], Key: "average-watts"));
        if (m.PeakWatts is { } peak) rows.Add(new(AreaLevel.Neutral, ["Highest power", $"{peak:0.0} W"], Key: "peak-watts"));
        if (m.ProjectedRuntimeSeconds is { } full) rows.Add(new(AreaLevel.Neutral, ["Full charge would last", $"about {Duration(full)} at this load"], Key: "projected-runtime"));
        if (m.StartVoltageMv is { } v0 && m.EndVoltageMv is { } v1)
            rows.Add(new(AreaLevel.Neutral, ["Voltage", $"{v0 / 1000.0:0.00} V → {v1 / 1000.0:0.00} V"], Key: "voltage"));
        if (m.PausedSeconds > 0) rows.Add(new(AreaLevel.Neutral, ["Paused with the charger connected", Duration(m.PausedSeconds)], Key: "paused"));
        rows.Add(new(AreaLevel.Neutral, ["Shutdown at 5 %", shutdownConfirmed ? "Confirmed" : "Not confirmed (the run stops at 15 % instead)"], Key: "shutdown"));
        if (powerSettings is { Length: > 0 }) rows.Add(new(powerSettings.StartsWith("Couldn't", StringComparison.Ordinal) ? AreaLevel.Warning : AreaLevel.Neutral,
            ["Power settings", powerSettings], Key: "power-settings"));
        rows.Add(new(AreaLevel.Neutral, ["Next step", "Charge to 100 % without unplugging, so the battery recalibrates its gauge. Then check Battery & power plan."], Key: "next-step"));

        var card = new AreaCard(CardId, "Battery drain & runtime", level, headline, meta, ["Reading", "Value"], rows, PreserveRowOrder: true,
            Note: "Measured on battery only: time with the charger connected is left out. The gauge's percentage comes from the battery itself, so a gauge that is off shows here as delivered energy that doesn't match the charge it used.")
        {
            RunCheck = new AreaCheckLink(ModuleSlugs.BatteryPower, "Check the battery"),
        };
        var cards = new List<AreaCard> { card };
        if (samples.Count > 0) cards.Add(LogCard(samples));

        var status = level switch { AreaLevel.Error => DiagnosticStatus.Error, AreaLevel.Warning => DiagnosticStatus.Warning, _ => DiagnosticStatus.Ok };
        return new AreaReport(cards, headline, status, Cancelled: cancelled)
        {
            KeyMetrics = KeyMetrics(m),
        };
    }

    public static IReadOnlyList<KeyMetric>? KeyMetrics(BatteryDrainMeasure m)
    {
        var list = new List<KeyMetric>();
        if (m.DeliveredMWh > 0) list.Add(new("batterydrain.deliveredWh", "Energy delivered", Math.Round(m.DeliveredMWh / 1000.0, 2), "Wh", MetricTrend.HigherIsBetter));
        if (m.DeliveredRatio is { } r && m.CanJudge) list.Add(new("batterydrain.deliveredPercent", "Delivered vs reported", Math.Round(r * 100, 1), "%", MetricTrend.HigherIsBetter));
        if (m.AverageWatts is { } w) list.Add(new("batterydrain.averageWatts", "Average power", Math.Round(w, 2), "W"));
        if (m.ProjectedRuntimeSeconds is { } s && m.CanJudge) list.Add(new("batterydrain.runtimeMinutes", "Full charge runtime", Math.Round(s / 60, 1), "min", MetricTrend.HigherIsBetter));
        return list.Count > 0 ? list : null;
    }

    private static string Headline(BatteryDrainMeasure m, BatteryDrainEnd end, AreaLevel level)
    {
        if (end == BatteryDrainEnd.PcShutOff)
            return level == AreaLevel.Error ? $"The PC turned off at {m.EndPercent} %: the battery can't deliver the charge it shows"
                : $"The PC turned off at {m.EndPercent} %, before the test's {BatteryDrainLimits.StopAtPercent} % stop";
        if (!m.CanJudge) return m.PercentDrained > 0 ? $"Drained {m.PercentDrained} points: too little to judge the gauge" : "Too little drained to judge the gauge";
        var text = $"Delivered {Wh(m.ProjectedFullMWh ?? 0)} per full charge, {Pct((m.DeliveredRatio ?? 0) * 100)} of the {Wh(m.ReportedFullMWh ?? 0)} reported";
        return level == AreaLevel.Warning ? text + ": the gauge needs calibrating" : text;
    }

    public static string EndText(BatteryDrainEnd end, BatteryDrainMeasure m) => end switch
    {
        BatteryDrainEnd.ReachedStop => $"Reached {BatteryDrainLimits.StopAtPercent} %: the PC was shut down",
        BatteryDrainEnd.NotConfirmed => $"Stopped at {m.EndPercent} %: the shutdown at {BatteryDrainLimits.StopAtPercent} % wasn't confirmed",
        BatteryDrainEnd.ChargerConnected => "Stopped: the charger was connected and stayed connected",
        BatteryDrainEnd.Cancelled => $"Stopped at {m.EndPercent} % before the end",
        BatteryDrainEnd.TimeLimit => "Stopped: the longest run for this mode was reached",
        BatteryDrainEnd.ReadingsLost => "Stopped: the battery or the Agent stopped answering",
        BatteryDrainEnd.PcShutOff => $"The PC turned off at {m.EndPercent} %",
        BatteryDrainEnd.AppClosed => $"The app closed during the run, at {m.EndPercent} %",
        _ => end.ToString(),
    };

    private static AreaLevel EndLevel(BatteryDrainEnd end, BatteryDrainMeasure m) => end switch
    {
        BatteryDrainEnd.PcShutOff when m.EndPercent is > BatteryDrainLimits.ShutOffFailAbovePercent => AreaLevel.Error,
        BatteryDrainEnd.PcShutOff or BatteryDrainEnd.ReadingsLost or BatteryDrainEnd.AppClosed => AreaLevel.Warning,
        _ => AreaLevel.Neutral,
    };

    private static AreaCard LogCard(IReadOnlyList<BatteryDrainSample> samples)
    {
        var rows = new List<AreaRow>();
        var next = 0.0;
        for (var i = 0; i < samples.Count; i++)
        {
            var s = samples[i];
            if (s.Seconds < next && i != samples.Count - 1) continue;
            next = s.Seconds + LogRowEverySeconds;
            rows.Add(new(s.OnAc ? AreaLevel.Warning : AreaLevel.Neutral,
                [Clock(s.Seconds), s.Percent is { } p ? $"{p} %" : "–", s.RemainingMWh is { } r ? Wh(r) : "–",
                 s.OnAc ? "charger connected" : s.DischargeMw is { } w ? $"{w / 1000.0:0.0} W" : "–", s.VoltageMv is { } v ? $"{v / 1000.0:0.00} V" : "–"],
                Key: "t" + ((int)s.Seconds).ToString(CultureInfo.InvariantCulture)));
        }
        return new AreaCard(SamplesCardId, "Drain log", AreaLevel.Neutral, $"{samples.Count} readings, one every {BatteryDrainLimits.SampleEvery.TotalSeconds:0} s",
            $"A row every {LogRowEverySeconds / 60:0} minutes", ["Time", "Charge", "Remaining", "Drain", "Voltage"], rows, PreserveRowOrder: true);
    }

    /// <summary>The report when the run never started: why, and nothing measured.</summary>
    public static AreaReport NotStarted(string headline, string why, bool needsAgent = false, bool notOnThisPc = false)
    {
        var card = new AreaCard(CardId, "Battery drain & runtime", AreaLevel.Neutral, headline, needsAgent ? "Skipped" : "", ["Reading", "Value"],
            [new(AreaLevel.Neutral, ["Why", why], Key: "why")]);
        return needsAgent || notOnThisPc
            ? new AreaReport([card], headline, DiagnosticStatus.Warning) { NotOnThisPc = true }
            : new AreaReport([card], headline, DiagnosticStatus.Error) { CouldNotRunReason = why };
    }

    public static string Wh(double mWh) => (mWh / 1000.0).ToString("0.0", CultureInfo.InvariantCulture) + " Wh";
    private static string Pct(double p) => p.ToString("0", CultureInfo.InvariantCulture) + " %";
    private static string Clock(double seconds) => $"{(int)(seconds / 3600)}:{(int)(seconds % 3600 / 60):00}:{(int)(seconds % 60):00}";

    public static string Duration(double seconds) =>
        seconds < 60 ? $"{seconds:0} s" : seconds < 3600 ? $"{(int)(seconds / 60)} min" : $"{(int)(seconds / 3600)} h {(int)(seconds % 3600 / 60)} min";
}
