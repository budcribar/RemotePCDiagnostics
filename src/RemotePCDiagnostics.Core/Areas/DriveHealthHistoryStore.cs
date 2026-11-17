using System.Text.Json;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>One point-in-time health snapshot for a physical drive.</summary>
public sealed record DriveHealthRecord(
    DateTimeOffset When,
    string RawId,
    string Name,
    string Serial,
    long? ReadErrors,
    long? WriteErrors,
    int? Wear,
    int? TemperatureC,
    long? PowerOnHours,
    string Health);

/// <summary>Summary of historical trend analysis for a drive across visits.</summary>
public sealed record DriveTrendAnalysis(
    bool HasHistory,
    int TotalVisits,
    DateTimeOffset? FirstSeen,
    DateTimeOffset? PreviousVisit,
    long ReadErrorDelta,
    long WriteErrorDelta,
    int WearDelta,
    bool IsDegrading,
    string SummaryText,
    string? HistoryDetail = null);

public interface IDriveHealthHistoryStore
{
    void Record(IEnumerable<DriveHealth> drives, DateTimeOffset now);
    IReadOnlyList<DriveHealthRecord> GetHistory(string rawId);
    DriveTrendAnalysis AnalyzeTrend(string rawId, DriveHealth current, DateTimeOffset now);
}

/// <summary>
/// Persists drive health readings over time to %LOCALAPPDATA%\RemotePCDiagnostics\drive_health_history.json.
/// Compares current readings against previous visits to detect degrading drives (e.g. newly occurring or increasing
/// uncorrected read/write errors, accelerated wear).
/// </summary>
public sealed class DriveHealthHistoryStore(string? path = null, ILogger? log = null) : IDriveHealthHistoryStore
{
    public const int MaxHistoryPerDrive = 50;
    private readonly object _gate = new();
    private Dictionary<string, List<DriveHealthRecord>>? _cache;

    public static string DefaultPath() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RemotePCDiagnostics", "drive_health_history.json");

    public void Record(IEnumerable<DriveHealth> drives, DateTimeOffset now)
    {
        lock (_gate)
        {
            var data = LoadLocked();
            var modified = false;

            foreach (var d in drives)
            {
                if (string.IsNullOrWhiteSpace(d.RawId)) continue;
                if (!data.TryGetValue(d.RawId, out var list))
                {
                    list = [];
                    data[d.RawId] = list;
                }

                // If recorded very recently (< 1 minute), update the latest instead of creating duplicate points
                if (list.Count > 0 && Math.Abs((now - list[^1].When).TotalMinutes) < 1)
                {
                    list[^1] = ToRecord(d, now);
                }
                else
                {
                    list.Add(ToRecord(d, now));
                    if (list.Count > MaxHistoryPerDrive)
                    {
                        list.RemoveRange(0, list.Count - MaxHistoryPerDrive);
                    }
                }
                modified = true;
            }

            if (modified && path is not null)
            {
                try
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                    File.WriteAllText(path, JsonSerializer.Serialize(data));
                }
                catch (Exception ex)
                {
                    log.Info($"[drive-history] save failed: {ex.Message}");
                }
            }
        }
    }

    public IReadOnlyList<DriveHealthRecord> GetHistory(string rawId)
    {
        lock (_gate)
        {
            var data = LoadLocked();
            return data.TryGetValue(rawId, out var list) ? list.ToList() : [];
        }
    }

    public DriveTrendAnalysis AnalyzeTrend(string rawId, DriveHealth current, DateTimeOffset now)
    {
        IReadOnlyList<DriveHealthRecord> history;
        lock (_gate)
        {
            var data = LoadLocked();
            history = data.TryGetValue(rawId, out var list) ? list.ToList() : [];
        }

        // Compare against earlier visits (ignore readings taken in this current run/minute)
        var prior = history.Where(h => (now - h.When).TotalMinutes >= 1).OrderByDescending(h => h.When).ToList();
        if (prior.Count == 0)
        {
            return new DriveTrendAnalysis(
                HasHistory: false,
                TotalVisits: history.Count > 0 ? history.Count : 1,
                FirstSeen: now,
                PreviousVisit: null,
                ReadErrorDelta: 0,
                WriteErrorDelta: 0,
                WearDelta: 0,
                IsDegrading: false,
                SummaryText: "First recorded health check for this drive");
        }

        var prev = prior[0];
        var first = prior[^1];

        long readDelta = (current.ReadErrors ?? 0) - (prev.ReadErrors ?? 0);
        long writeDelta = (current.WriteErrors ?? 0) - (prev.WriteErrors ?? 0);
        int wearDelta = (current.Wear ?? 0) - (prev.Wear ?? 0);

        // Degradation criteria:
        // 1. Any increase in uncorrected read errors
        // 2. Any increase in uncorrected write errors
        // 3. Significant unexpected wear jump (>= 5%)
        // 4. Windows health degraded from Healthy to Warning/Unhealthy
        bool statusDegraded = prev.Health.Equals("Healthy", StringComparison.OrdinalIgnoreCase) &&
                              (current.Health.Equals("Warning", StringComparison.OrdinalIgnoreCase) ||
                               current.Health.Equals("Unhealthy", StringComparison.OrdinalIgnoreCase));

        bool isDegrading = readDelta > 0 || writeDelta > 0 || wearDelta >= 5 || statusDegraded;

        string summary;
        if (readDelta > 0 && writeDelta > 0)
        {
            summary = $"Degrading: read errors increased by +{readDelta} and write errors by +{writeDelta} since {prev.When:MMM d, yyyy}";
        }
        else if (readDelta > 0)
        {
            summary = $"Degrading: uncorrected read errors increased by +{readDelta} since {prev.When:MMM d, yyyy}";
        }
        else if (writeDelta > 0)
        {
            summary = $"Degrading: uncorrected write errors increased by +{writeDelta} since {prev.When:MMM d, yyyy}";
        }
        else if (statusDegraded)
        {
            summary = $"Degrading: Windows reported status dropped from Healthy to {current.Health} since {prev.When:MMM d, yyyy}";
        }
        else if (wearDelta >= 5)
        {
            summary = $"Wear increased by {wearDelta}% since {prev.When:MMM d, yyyy}";
        }
        else
        {
            int totalVisits = prior.Count + 1;
            summary = $"Stable across {totalVisits} checks since {first.When:MMM d, yyyy}";
        }

        // Build history table for drawer detail
        var detailLines = prior.Take(5).Select(h =>
            $"{h.When:yyyy-MM-dd HH:mm} · Status: {h.Health} · Temp: {(h.TemperatureC is > 0 ? $"{h.TemperatureC}°C" : "n/a")} · Wear: {(h.Wear is not null ? $"{h.Wear}%" : "n/a")} · Read err: {h.ReadErrors ?? 0} · Write err: {h.WriteErrors ?? 0}");
        string detail = string.Join("\n", detailLines);

        return new DriveTrendAnalysis(
            HasHistory: true,
            TotalVisits: prior.Count + 1,
            FirstSeen: first.When,
            PreviousVisit: prev.When,
            ReadErrorDelta: readDelta,
            WriteErrorDelta: writeDelta,
            WearDelta: wearDelta,
            IsDegrading: isDegrading,
            SummaryText: summary,
            HistoryDetail: detail);
    }

    private static DriveHealthRecord ToRecord(DriveHealth d, DateTimeOffset when) =>
        new(when, d.RawId, d.Name, d.Serial, d.ReadErrors, d.WriteErrors, d.Wear, d.TemperatureC, d.PowerOnHours, d.Health);

    private Dictionary<string, List<DriveHealthRecord>> LoadLocked()
    {
        if (_cache is not null) return _cache;
        if (path is not null && File.Exists(path))
        {
            try
            {
                var text = File.ReadAllText(path);
                var loaded = JsonSerializer.Deserialize<Dictionary<string, List<DriveHealthRecord>>>(text);
                if (loaded is not null) return _cache = loaded;
            }
            catch (Exception ex)
            {
                log.Info($"[drive-history] load failed: {ex.Message}");
            }
        }
        return _cache = new Dictionary<string, List<DriveHealthRecord>>(StringComparer.OrdinalIgnoreCase);
    }
}
