using System.Globalization;

namespace RemotePCDiagnostics.Core.History;

/// <summary>
/// One "Key metrics:" line of a History event: <c>id=value|unit|better|label</c>. The label goes last so it may hold any text;
/// the value is invariant. Readers that don't know a metric still chart it from these fields alone (Admin does).
/// </summary>
public static class KeyMetricText
{
    public static string Format(KeyMetric k)
    {
        static string Clean(string s) => s.Replace("\r", " ").Replace("\n", " ").Replace("|", "/").Trim();
        var id = Clean(k.Id).Replace("=", "-");
        return $"{id}={k.Value.ToString("R", CultureInfo.InvariantCulture)}|{Clean(k.Unit)}|{k.Better}|{k.Label.Replace("\r", " ").Replace("\n", " ").Trim()}";
    }

    public static KeyMetric? Parse(string line)
    {
        var eq = line.IndexOf('=');
        if (eq <= 0) return null;
        var parts = line[(eq + 1)..].Split('|', 4);
        if (parts.Length < 4 || !double.TryParse(parts[0], NumberStyles.Float, CultureInfo.InvariantCulture, out var v) || !double.IsFinite(v)) return null;
        var better = Enum.TryParse<MetricTrend>(parts[2], ignoreCase: true, out var b) ? b : MetricTrend.Neutral;
        var label = parts[3].Trim();
        var id = line[..eq].Trim();
        return new KeyMetric(id, label.Length > 0 ? label : id, v, parts[1].Trim(), better);
    }

    /// <summary>"87%", "412.5 GB", "72°C", "318" (no unit).</summary>
    public static string Value(double value, string unit)
    {
        var n = Math.Abs(value) >= 100 || value == Math.Round(value) ? value.ToString("#,0", CultureInfo.CurrentCulture) : value.ToString("#,0.#", CultureInfo.CurrentCulture);
        return unit.Length == 0 ? n : unit is "%" or "°C" ? n + unit : n + " " + unit;
    }
}

/// <summary>A run on a trend chart.</summary>
public sealed record TrendPoint(DateTimeOffset TimeUtc, double Value, string Outcome);

/// <summary>One key metric of one check (and drive, for a per-drive check) across its runs, oldest first.</summary>
public sealed record TrendSeries(string Id, string Label, string Unit, MetricTrend Better, IReadOnlyList<TrendPoint> Points)
{
    public TrendPoint? First => Points.Count > 0 ? Points[0] : null;
    public TrendPoint? Last => Points.Count > 0 ? Points[^1] : null;

    /// <summary>Last minus first; null with fewer than two runs.</summary>
    public double? Change => Points.Count >= 2 ? Points[^1].Value - Points[0].Value : null;

    /// <summary>True when the change goes the bad way for this metric (health falling, temperature rising).</summary>
    public bool Worsening => Change is { } c && c != 0 && (Better == MetricTrend.HigherIsBetter ? c < 0 : Better == MetricTrend.LowerIsBetter && c > 0);

    /// <summary>"Down 4% since Oct 3", "Up 6°C since Nov 1", "No change since Oct 3"; null with fewer than two runs.</summary>
    public string? ChangeText()
    {
        if (Change is not { } c || First is not { } f) return null;
        var since = f.TimeUtc.ToLocalTime().ToString("MMM d", CultureInfo.CurrentCulture);
        if (Math.Abs(c) < 0.05) return $"No change since {since}";
        return $"{(c > 0 ? "Up" : "Down")} {KeyMetricText.Value(Math.Abs(c), Unit)} since {since}";
    }
}

/// <summary>Builds the History trend view of one check: its key metrics over time, and each run's key value for the run list.</summary>
public static class HistoryTrends
{
    /// <summary>At most this many runs per chart (a few months of daily runs); older ones drop off the left.</summary>
    public const int MaxPoints = 200;

    /// <summary>The run's key metrics. Stress tests written before key metrics existed have one, from their measurements.</summary>
    public static IReadOnlyList<KeyMetric> Metrics(HistoryEntry e)
    {
        if (e.KeyMetrics.Count > 0) return e.KeyMetrics;
        if (HistoryQuery.TrendKey(e.Module) is { } key
            && double.TryParse(e.Measurement(key.Name), NumberStyles.Float, CultureInfo.InvariantCulture, out var v))
            return [new KeyMetric("stress." + key.Name, key.Label, v, key.Unit, key.Unit == "°C" ? MetricTrend.LowerIsBetter : MetricTrend.HigherIsBetter)];
        return [];
    }

    /// <summary>The check's runs (one drive's, when <paramref name="instanceId"/> is set), newest first, cancelled runs left out.</summary>
    public static IReadOnlyList<HistoryEntry> Runs(IEnumerable<HistoryEntry> entries, string module, string? instanceId = null) =>
        HistoryQuery.WithoutCancelled(entries)
            .Where(e => string.Equals(e.Module, module, StringComparison.OrdinalIgnoreCase)
                && (instanceId is null || string.Equals(e.InstanceId, instanceId, StringComparison.OrdinalIgnoreCase)))
            .OrderByDescending(e => e.TimeUtc).ToList();

    /// <summary>One series per key metric the runs carry, in the order the check lists them; series of one drive when the check is per drive.</summary>
    public static IReadOnlyList<TrendSeries> Series(IReadOnlyList<HistoryEntry> runs)
    {
        var order = new List<string>();
        var byId = new Dictionary<string, (KeyMetric Latest, List<TrendPoint> Points)>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in runs.OrderBy(r => r.TimeUtc))
            foreach (var m in Metrics(e))
            {
                if (!byId.TryGetValue(m.Id, out var s)) { s = (m, []); byId[m.Id] = s; }
                s.Points.Add(new(e.TimeUtc, m.Value, e.Outcome));
                byId[m.Id] = (m, s.Points); // the newest run's label and unit win
            }
        // The check's own order: the newest run that has the most metrics names them first.
        foreach (var e in runs.OrderByDescending(r => Metrics(r).Count).ThenByDescending(r => r.TimeUtc).Take(1))
            order.AddRange(Metrics(e).Select(m => m.Id));
        order.AddRange(byId.Keys.Where(k => !order.Contains(k, StringComparer.OrdinalIgnoreCase)));
        return order.Where(byId.ContainsKey).Select(id =>
        {
            var (latest, points) = byId[id];
            return new TrendSeries(latest.Id, latest.Label, latest.Unit, latest.Better, points.TakeLast(MaxPoints).ToList());
        }).ToList();
    }

    /// <summary>The run's first key value for the run list ("87%"), or null when it has none.</summary>
    public static string? KeyValue(HistoryEntry e) =>
        Metrics(e) is { Count: > 0 } m ? KeyMetricText.Value(m[0].Value, m[0].Unit) : null;

    /// <summary>The distinct drives (or other instances) the runs cover, newest label first; empty for a system-wide check.</summary>
    public static IReadOnlyList<(string Id, string Label)> Instances(IEnumerable<HistoryEntry> runs) =>
        runs.Where(r => !string.IsNullOrEmpty(r.InstanceId)).OrderByDescending(r => r.TimeUtc)
            .GroupBy(r => r.InstanceId!, StringComparer.OrdinalIgnoreCase)
            .Select(g => (g.Key, g.First().Instance is { Length: > 0 } l ? l : g.Key)).ToList();
}
