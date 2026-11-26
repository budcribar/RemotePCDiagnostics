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
                var key = StableIdentityKey(d);
                if (string.IsNullOrWhiteSpace(key)) continue;

                var list = GetOrCreateDriveHistory(data, key, d.RawId);
                AppendDriveRecord(list, d, now);
                modified = true;
            }

            if (modified && path is not null)
                SaveHistoryLocked(data);
        }
    }

    private static List<DriveHealthRecord> GetOrCreateDriveHistory(
        Dictionary<string, List<DriveHealthRecord>> data, string key, string rawId)
    {
        if (data.TryGetValue(key, out var list))
            return list;

        // Check if existing records were saved under d.RawId
        list = !string.IsNullOrWhiteSpace(rawId) && data.Remove(rawId, out var legacyList) ? legacyList : [];
        data[key] = list;
        return list;
    }

    private static void AppendDriveRecord(List<DriveHealthRecord> list, DriveHealth d, DateTimeOffset now)
    {
        // If recorded very recently (< 1 minute), update the latest if it matches identity, instead of creating duplicate points
        if (list.Count > 0 && MatchesIdentity(list[^1], d) && Math.Abs((now - list[^1].When).TotalMinutes) < 1)
        {
            list[^1] = ToRecord(d, now);
            return;
        }

        list.Add(ToRecord(d, now));
        if (list.Count > MaxHistoryPerDrive)
            list.RemoveRange(0, list.Count - MaxHistoryPerDrive);
    }

    private void SaveHistoryLocked(Dictionary<string, List<DriveHealthRecord>> data)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path!)!);
            File.WriteAllText(path!, JsonSerializer.Serialize(data));
        }
        catch (Exception ex)
        {
            log.Info($"[drive-history] save failed: {ex.Message}");
        }
    }

    public IReadOnlyList<DriveHealthRecord> GetHistory(string rawId)
    {
        lock (_gate)
        {
            var data = LoadLocked();
            if (data.TryGetValue(rawId, out var list))
                return list.ToList();

            var key = StableIdentityKey(rawId, null, null);
            if (data.TryGetValue(key, out var keyList))
                return keyList.ToList();

            return [];
        }
    }

    public DriveTrendAnalysis AnalyzeTrend(string rawId, DriveHealth current, DateTimeOffset now)
    {
        var history = ReadHistoryForDrive(rawId, current);
        // Match a stable device identity before comparing readings:
        // Exclude records from different physical drives (different serial, different identity, or reset power-on hours).
        var matched = history.Where(h => MatchesIdentity(h, current)).ToList();

        // Compare against earlier visits (ignore readings taken in this current run/minute)
        var prior = matched.Where(h => (now - h.When).TotalMinutes >= 1).OrderByDescending(h => h.When).ToList();
        if (prior.Count == 0)
        {
            return new DriveTrendAnalysis(
                HasHistory: false,
                TotalVisits: matched.Count > 0 ? matched.Count : 1,
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
        bool statusDegraded = IsStatusDegraded(prev.Health, current.Health);
        bool isDegrading = readDelta > 0 || writeDelta > 0 || wearDelta >= 5 || statusDegraded;

        var summary = BuildTrendSummary(readDelta, writeDelta, wearDelta, statusDegraded, current.Health, prev.When, first.When, prior.Count + 1);
        var detail = FormatHistoryDetail(prior);

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

    private IReadOnlyList<DriveHealthRecord> ReadHistoryForDrive(string rawId, DriveHealth current)
    {
        lock (_gate)
        {
            var data = LoadLocked();
            var key = StableIdentityKey(current);
            if (data.TryGetValue(key, out var list)) return list.ToList();
            if (data.TryGetValue(rawId, out var rawList)) return rawList.ToList();
            return [];
        }
    }

    private static bool IsStatusDegraded(string previousHealth, string currentHealth) =>
        previousHealth.Equals("Healthy", StringComparison.OrdinalIgnoreCase)
        && (currentHealth.Equals("Warning", StringComparison.OrdinalIgnoreCase)
            || currentHealth.Equals("Unhealthy", StringComparison.OrdinalIgnoreCase));

    private static string BuildTrendSummary(
        long readDelta, long writeDelta, int wearDelta, bool statusDegraded,
        string currentHealth, DateTimeOffset prevWhen, DateTimeOffset firstWhen, int totalVisits)
    {
        if (readDelta > 0 && writeDelta > 0)
            return $"Degrading: read errors increased by +{readDelta} and write errors by +{writeDelta} since {prevWhen:MMM d, yyyy}";
        if (readDelta > 0)
            return $"Degrading: uncorrected read errors increased by +{readDelta} since {prevWhen:MMM d, yyyy}";
        if (writeDelta > 0)
            return $"Degrading: uncorrected write errors increased by +{writeDelta} since {prevWhen:MMM d, yyyy}";
        if (statusDegraded)
            return $"Degrading: Windows reported status dropped from Healthy to {currentHealth} since {prevWhen:MMM d, yyyy}";
        if (wearDelta >= 5)
            return $"Wear increased by {wearDelta}% since {prevWhen:MMM d, yyyy}";
        return $"Stable across {totalVisits} checks since {firstWhen:MMM d, yyyy}";
    }

    private static string FormatHistoryDetail(List<DriveHealthRecord> prior)
    {
        var detailLines = prior.Take(5).Select(h =>
            $"{h.When:yyyy-MM-dd HH:mm} · Status: {h.Health} · Temp: {(h.TemperatureC is > 0 ? $"{h.TemperatureC}°C" : "n/a")} · Wear: {(h.Wear is not null ? $"{h.Wear}%" : "n/a")} · Read err: {h.ReadErrors ?? 0} · Write err: {h.WriteErrors ?? 0}");
        return string.Join("\n", detailLines);
    }

    public static string StableIdentityKey(DriveHealth d) =>
        StableIdentityKey(d.RawId, d.Serial, d.Name, d.UniqueId);

    public static string StableIdentityKey(string? rawId, string? serial, string? name, string? uniqueId = null)
    {
        var s = serial?.Trim();
        if (!string.IsNullOrEmpty(s) && !IsGenericSerial(s))
            return "serial:" + s.ToUpperInvariant();

        var u = uniqueId?.Trim();
        if (!string.IsNullOrEmpty(u))
            return "id:" + u.ToUpperInvariant();

        var r = rawId?.Trim();
        if (!string.IsNullOrEmpty(r))
        {
            if (r.StartsWith("serial:", StringComparison.OrdinalIgnoreCase))
            {
                var ser = r["serial:".Length..].Trim();
                if (!string.IsNullOrEmpty(ser) && !IsGenericSerial(ser))
                    return "serial:" + ser.ToUpperInvariant();
            }
            if (r.StartsWith("id:", StringComparison.OrdinalIgnoreCase))
                return r.ToUpperInvariant();
        }

        var n = (name ?? "").Trim();
        if (!string.IsNullOrEmpty(n))
            return "name:" + n.ToUpperInvariant();

        return !string.IsNullOrEmpty(r) ? r.ToUpperInvariant() : "unknown";
    }

    public static bool IsGenericSerial(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) return true;
        var trimmed = s.Trim();
        return trimmed.Length == 0 ||
               trimmed.All(c => c is '0' or ' ' or '-' or '.' or '_') ||
               trimmed.Equals("None", StringComparison.OrdinalIgnoreCase) ||
               trimmed.Equals("Unknown", StringComparison.OrdinalIgnoreCase) ||
               trimmed.Equals("To be filled by O.E.M.", StringComparison.OrdinalIgnoreCase) ||
               trimmed.Equals("Default string", StringComparison.OrdinalIgnoreCase);
    }

    public static bool MatchesIdentity(DriveHealthRecord h, DriveHealth current)
    {
        // 1. If both have serial numbers, they must match
        bool hHasSerial = !string.IsNullOrWhiteSpace(h.Serial) && !IsGenericSerial(h.Serial);
        bool cHasSerial = !string.IsNullOrWhiteSpace(current.Serial) && !IsGenericSerial(current.Serial);

        if (hHasSerial && cHasSerial)
        {
            if (!string.Equals(h.Serial.Trim(), current.Serial.Trim(), StringComparison.OrdinalIgnoreCase))
                return false;
        }
        else if (hHasSerial != cHasSerial)
        {
            // One has a serial and the other does not; cannot safely assume they are the same physical drive
            return false;
        }

        // 2. If name/model is available on both, verify it matches
        if (!string.IsNullOrWhiteSpace(h.Name) && !string.IsNullOrWhiteSpace(current.Name))
        {
            if (!string.Equals(h.Name.Trim(), current.Name.Trim(), StringComparison.OrdinalIgnoreCase))
                return false;
        }

        // 3. Power-on-hours reset check:
        // A single physical drive's power-on hours monotonically increases over time.
        // If a past record had significant hours and current has substantially fewer, this indicates a replaced drive.
        if (h.PowerOnHours is > 50 && current.PowerOnHours is not null && current.PowerOnHours.Value < h.PowerOnHours.Value - 24)
        {
            return false;
        }

        return true;
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
