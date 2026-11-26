using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RemotePCDiagnostics.Core.Benchmarks;

/// <summary>Supported developer build languages (hidden entirely when their toolchain is absent).</summary>
public enum DeveloperLanguage
{
    CSharp,
    Rust,
    Go,
    TypeScript,
    Python,
    Cpp,
}

/// <summary>Coarse CPU buckets for baseline comparisons (shared with browser performance benchmarks).</summary>
public enum DeveloperCpuClass
{
    Unknown,
    MobileLowPower,
    MobileMainstream,
    Desktop,
}

/// <summary>Result band against a calibrated CPU-class baseline (requires at least 3 reference machines).</summary>
public enum DeveloperBand
{
    NoBaseline,
    Pass,
    Warning,
    Fail,
}

/// <summary>One installed developer toolchain found by read-only detection.</summary>
public sealed record DetectedToolchain(
    DeveloperLanguage Language,
    string DisplayName,
    string ExecutablePath,
    string Version,
    int? MajorVersion = null,
    string? SecondaryExecutable = null);

/// <summary>One calibrated reference baseline cell (class + language + pin + toolchain major).</summary>
public sealed record DeveloperBaselineRow(
    DeveloperCpuClass CpuClass,
    DeveloperLanguage Language,
    string PinId,
    int ToolchainMajor,
    IReadOnlyList<string> ReferenceCpuNames,
    IReadOnlyList<int> ReferenceCoreCounts,
    double ColdMedianSeconds,
    double WarmMedianSeconds,
    int SampleCount,
    DateOnly MeasuredDate);

/// <summary>Versioned shipped baseline catalog. Old pins stay in the file so stored results remain readable.</summary>
public sealed record DeveloperBaselineCatalog(int SchemaVersion, IReadOnlyList<DeveloperBaselineRow> Rows)
{
    public const int CurrentSchemaVersion = 1;
    public const int MinReferenceMachines = 3;
    public const double PassMaxMultiplier = 1.25;
    public const double WarningMaxMultiplier = 2.0;

    public static readonly DeveloperBaselineCatalog Empty = new(CurrentSchemaVersion, []);

    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() },
    };

    public string ToJson() => JsonSerializer.Serialize(this, Json);

    public static DeveloperBaselineCatalog FromJson(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return Empty;
        try { return JsonSerializer.Deserialize<DeveloperBaselineCatalog>(json, Json) ?? Empty; }
        catch (JsonException) { return Empty; }
    }

    /// <summary>Finds a usable baseline cell (must have at least <see cref="MinReferenceMachines"/> reference machines).</summary>
    public DeveloperBaselineRow? FindUsable(DeveloperCpuClass cpuClass, DeveloperLanguage language, string pinId, int? toolchainMajor)
    {
        if (cpuClass == DeveloperCpuClass.Unknown || toolchainMajor is null) return null;
        return Rows.FirstOrDefault(r =>
            r.CpuClass == cpuClass
            && r.Language == language
            && string.Equals(r.PinId, pinId, StringComparison.OrdinalIgnoreCase)
            && r.ToolchainMajor == toolchainMajor.Value
            && r.SampleCount >= MinReferenceMachines
            && r.WarmMedianSeconds > 0);
    }
}

/// <summary>Scoring, CPU-class bucketing, and condition gating for developer benchmarks.</summary>
public static class DeveloperScoring
{
    public const double MinFreeDiskGb = 10.0;
    public const double MinDevDriveFreeDiskGb = 50.0;
    public const int MinWindows11DevDriveBuild = 22621;
    public const int MinWindows11DevDriveRevision = 2338;

    public const string BusyPcWarning =
        "Developer clean builds saturate the CPU and disk for several minutes. The person at the PC will feel it.";

    /// <summary>
    /// Classifies a CPU into a coarse bucket from its name and physical/logical core count.
    /// The CPU name is also stored on every sample so bucket boundaries can be revised later.
    /// </summary>
    public static DeveloperCpuClass ClassifyCpu(string? cpuName, int coreCount)
    {
        if (string.IsNullOrWhiteSpace(cpuName) && coreCount <= 0) return DeveloperCpuClass.Unknown;
        var name = (cpuName ?? "").Trim();

        // Explicit mobile low-power markers: Intel U / Y / P / N / V / Atom / Celeron / Pentium, AMD U, Qualcomm Snapdragon X
        if (HasMobileLowPowerSuffix(name))
            return DeveloperCpuClass.MobileLowPower;

        // Explicit mobile mainstream / performance markers: Intel H / HK / HX, AMD HS / HX / H
        if (HasMobileMainstreamSuffix(name))
            return DeveloperCpuClass.MobileMainstream;

        // Explicit desktop markers: K / KF / KS / F / T / X / XT / X3D / Threadripper / Xeon / Desktop
        if (HasDesktopMarker(name))
            return DeveloperCpuClass.Desktop;

        // Fallback by core count when model string has no mobile/desktop suffix
        if (coreCount > 0)
            return coreCount <= 8 ? DeveloperCpuClass.MobileLowPower : coreCount <= 16 ? DeveloperCpuClass.MobileMainstream : DeveloperCpuClass.Desktop;

        return DeveloperCpuClass.Unknown;
    }

    private static bool HasMobileLowPowerSuffix(string name)
    {
        if (name.Contains("Celeron", StringComparison.OrdinalIgnoreCase)
            || name.Contains("Pentium", StringComparison.OrdinalIgnoreCase)
            || name.Contains("Atom", StringComparison.OrdinalIgnoreCase)
            || name.Contains("Snapdragon", StringComparison.OrdinalIgnoreCase))
            return true;

        foreach (var token in TokenizeModel(name))
        {
            if (token.Length >= 4 && char.IsAsciiDigit(token[0]) && token[^1] is 'U' or 'Y' or 'V' or 'P')
                return true;
            if (token.Length >= 3 && token[0] == 'N' && token[1..].All(char.IsAsciiDigit))
                return true;
        }
        return false;
    }

    private static bool HasMobileMainstreamSuffix(string name)
    {
        foreach (var token in TokenizeModel(name))
        {
            if (token.Length >= 4 && char.IsAsciiDigit(token[0])
                && (token.EndsWith("HX", StringComparison.Ordinal) || token.EndsWith("HK", StringComparison.Ordinal)
                    || token.EndsWith("HS", StringComparison.Ordinal) || token.EndsWith('H')))
                return true;
        }
        return false;
    }

    private static bool HasDesktopMarker(string name)
    {
        if (name.Contains("Threadripper", StringComparison.OrdinalIgnoreCase)
            || name.Contains("Xeon", StringComparison.OrdinalIgnoreCase))
            return true;

        foreach (var token in TokenizeModel(name))
        {
            if (token.Length >= 4 && char.IsAsciiDigit(token[0])
                && (token.EndsWith("X3D", StringComparison.Ordinal) || token.EndsWith("KF", StringComparison.Ordinal)
                    || token.EndsWith("KS", StringComparison.Ordinal) || token.EndsWith("XT", StringComparison.Ordinal)
                    || token.EndsWith('K') || token.EndsWith('X') || token.EndsWith('F') || token.EndsWith('T')))
                return true;
        }
        return false;
    }

    private static IEnumerable<string> TokenizeModel(string name)
    {
        foreach (var raw in name.Split([' ', '-', '_', ',', '(', ')'], StringSplitOptions.RemoveEmptyEntries))
            yield return raw.ToUpperInvariant();
    }

    /// <summary>Higher is better: <c>100 * (class baseline warm seconds / this PC's warm median seconds)</c>.</summary>
    public static double? ComputeScore(double? warmMedianSeconds, DeveloperBaselineRow? baseline)
    {
        if (warmMedianSeconds is not > 0 || baseline is null || baseline.WarmMedianSeconds <= 0)
            return null;
        return Math.Round(100.0 * (baseline.WarmMedianSeconds / warmMedianSeconds.Value), 1);
    }

    /// <summary>Evaluates the band once a calibrated baseline exists and run conditions are comparable.</summary>
    public static DeveloperBand EvaluateBand(double? warmMedianSeconds, DeveloperBaselineRow? baseline, bool comparable)
    {
        if (!comparable || warmMedianSeconds is not > 0 || baseline is null || baseline.SampleCount < DeveloperBaselineCatalog.MinReferenceMachines || baseline.WarmMedianSeconds <= 0)
            return DeveloperBand.NoBaseline;
        var ratio = warmMedianSeconds.Value / baseline.WarmMedianSeconds;
        if (ratio <= DeveloperBaselineCatalog.PassMaxMultiplier) return DeveloperBand.Pass;
        if (ratio <= DeveloperBaselineCatalog.WarningMaxMultiplier) return DeveloperBand.Warning;
        return DeveloperBand.Fail;
    }

    /// <summary>Geometric mean of per-language scores that ran. One language alone is the overall score.</summary>
    public static double? OverallScore(IEnumerable<double> languageScores)
    {
        var valid = languageScores.Where(s => s > 0 && double.IsFinite(s)).ToList();
        if (valid.Count == 0) return null;
        if (valid.Count == 1) return Math.Round(valid[0], 1);
        var sumLog = valid.Sum(Math.Log);
        return Math.Round(Math.Exp(sumLog / valid.Count), 1);
    }

    /// <summary>Checks whether run conditions allow comparing against a CPU-class baseline.</summary>
    public static (bool Comparable, IReadOnlyList<string> Notes) CheckComparability(bool? onBattery, string? powerPlan, bool? thermallyThrottling)
    {
        var notes = new List<string>();
        if (onBattery == true)
            notes.Add("Ran on battery — a comparable score wants the PC plugged in.");
        if (!string.IsNullOrWhiteSpace(powerPlan) && powerPlan.Contains("Power saver", StringComparison.OrdinalIgnoreCase))
            notes.Add("Power saver plan is active — switch to the Balanced power plan (Battery & power plan check) for a comparable score.");
        if (thermallyThrottling == true)
            notes.Add("CPU thermal throttling was detected during the run — excluded from baseline comparison.");
        return (notes.Count == 0, notes);
    }

    /// <summary>Computes the median of a non-empty list of positive durations.</summary>
    public static double? Median(IReadOnlyList<double> values)
    {
        if (values.Count == 0) return null;
        var sorted = values.OrderBy(x => x).ToList();
        return sorted.Count % 2 == 1
            ? sorted[sorted.Count / 2]
            : (sorted[sorted.Count / 2 - 1] + sorted[sorted.Count / 2]) / 2.0;
    }

    /// <summary>Percent faster: <c>(baseline - candidate) / baseline * 100</c>. Negative means candidate was slower.</summary>
    public static double? PercentFaster(double? baselineSeconds, double? candidateSeconds)
    {
        if (baselineSeconds is not > 0 || candidateSeconds is not > 0) return null;
        return Math.Round(((baselineSeconds.Value - candidateSeconds.Value) / baselineSeconds.Value) * 100.0, 1);
    }

    /// <summary>Parses the major version integer from a toolchain version string (e.g. "10.0.404" -> 10, "rustc 1.84.0" -> 1).</summary>
    public static int? ParseMajorVersion(string? version)
    {
        if (string.IsNullOrWhiteSpace(version)) return null;
        for (var i = 0; i < version.Length; i++)
        {
            if (!char.IsAsciiDigit(version[i])) continue;
            var start = i;
            while (i < version.Length && char.IsAsciiDigit(version[i])) i++;
            if (int.TryParse(version[start..i], NumberStyles.None, CultureInfo.InvariantCulture, out var major))
                return major;
        }
        return null;
    }
}

/// <summary>Outcome of one developer clean-build benchmark run for a single language.</summary>
public sealed record DeveloperBuildResult(
    DeveloperLanguage Language,
    string PinId,
    string PinSha256,
    string? ToolchainVersion,
    int? ToolchainMajor,
    double? RestoreSeconds,
    double? ColdMedianSeconds,
    IReadOnlyList<double> ColdSamples,
    double? WarmMedianSeconds,
    IReadOnlyList<double> WarmSamples,
    double? WarmExcludedMedianSeconds = null,
    IReadOnlyList<double>? WarmExcludedSamples = null,
    bool UsedHyperfine = false,
    bool? DefenderActive = null,
    bool? BuildFolderExcluded = null,
    double? Score = null,
    DeveloperBand Band = DeveloperBand.NoBaseline,
    bool Comparable = true,
    IReadOnlyList<string>? ConditionNotes = null,
    string? Note = null,
    int? ToolExitCode = null)
{
    public bool Succeeded => WarmMedianSeconds is > 0;
    public double? AntivirusCostSeconds => WarmMedianSeconds is > 0 && WarmExcludedMedianSeconds is > 0
        ? Math.Round(WarmMedianSeconds.Value - WarmExcludedMedianSeconds.Value, 2)
        : null;
    public double? AntivirusCostPercent => DeveloperScoring.PercentFaster(WarmMedianSeconds, WarmExcludedMedianSeconds);

    public string? FormatToolchainVersion()
    {
        if (string.IsNullOrWhiteSpace(ToolchainVersion)) return null;
        var label = Language switch
        {
            DeveloperLanguage.CSharp => ".NET SDK",
            DeveloperLanguage.Rust => "Rust",
            DeveloperLanguage.Go => "Go",
            DeveloperLanguage.TypeScript => "TypeScript",
            DeveloperLanguage.Python => "Python",
            DeveloperLanguage.Cpp => "C++",
            _ => Language.ToString(),
        };
        return $"{label} {ToolchainVersion}";
    }

    public string FormatDetail()
    {
        if (!Succeeded) return Note ?? "Could not run";
        var parts = new List<string>();
        if (FormatToolchainVersion() is { } tc)
            parts.Add(tc);
        if (ColdMedianSeconds is { } cold)
            parts.Add(string.Create(CultureInfo.InvariantCulture, $"cold {cold:0.0} s"));
        parts.Add(string.Create(CultureInfo.InvariantCulture, $"warm {WarmMedianSeconds!.Value:0.0} s ({WarmSamples.Count} runs)"));
        if (RestoreSeconds is { } rest)
            parts.Add(string.Create(CultureInfo.InvariantCulture, $"restore {rest:0.0} s"));
        if (AntivirusCostPercent is { } avPct && WarmExcludedMedianSeconds is { } ex)
            parts.Add(string.Create(CultureInfo.InvariantCulture, $"AV excluded {ex:0.0} s ({(avPct >= 0 ? $"{avPct:0.0}% faster" : $"{-avPct:0.0}% slower")})"));
        parts.Add(Band == DeveloperBand.NoBaseline ? "no baseline yet" : $"score {Score:0.0} ({Band})");
        return string.Join(" · ", parts);
    }
}

/// <summary>Pre-check result determining whether the opt-in Dev Drive comparison can be offered.</summary>
public sealed record DevDrivePrecheckResult(
    bool Eligible,
    string? Reason = null,
    string? WindowsBuild = null,
    bool DevDrivePolicyEnabled = false,
    bool AgentReady = false,
    double? FreeSpaceGb = null,
    bool? OnAcPower = null);

/// <summary>Outcome of the opt-in NTFS vs temporary Dev Drive VHDX comparison.</summary>
public sealed record DevDriveComparisonResult(
    bool Succeeded,
    string PinId,
    string PinSha256,
    string Order = "NTFS, then Dev Drive",
    double? NtfsColdMedianSeconds = null,
    double? NtfsWarmMedianSeconds = null,
    double? DevDriveColdMedianSeconds = null,
    double? DevDriveWarmMedianSeconds = null,
    bool? DefenderPerformanceModeActive = null,
    string? Note = null,
    DateTimeOffset? CompletedAtUtc = null,
    double? NtfsExcludedWarmMedianSeconds = null,
    double? DevDriveExcludedWarmMedianSeconds = null)
{
    public double? ColdPercentFaster => DeveloperScoring.PercentFaster(NtfsColdMedianSeconds, DevDriveColdMedianSeconds);
    public double? WarmPercentFaster => DeveloperScoring.PercentFaster(NtfsWarmMedianSeconds, DevDriveWarmMedianSeconds);
    public double? ExcludedWarmPercentFaster => DeveloperScoring.PercentFaster(NtfsWarmMedianSeconds, NtfsExcludedWarmMedianSeconds);
    public double? DevDriveExcludedWarmPercentFaster => DeveloperScoring.PercentFaster(NtfsWarmMedianSeconds, DevDriveExcludedWarmMedianSeconds);

    public string FormatSummary()
    {
        if (!Succeeded) return Note ?? "Dev Drive comparison did not complete.";
        static string FormatDelta(double? pct) => pct is { } p
            ? (p >= 0 ? string.Create(CultureInfo.InvariantCulture, $"{p:0.0}% faster") : string.Create(CultureInfo.InvariantCulture, $"{-p:0.0}% slower"))
            : "n/a";

        var warmDelta = FormatDelta(WarmPercentFaster);
        var coldDelta = FormatDelta(ColdPercentFaster);
        var perf = DefenderPerformanceModeActive switch
        {
            true => "Defender performance mode: active",
            false => "Defender performance mode: inactive",
            null => "Defender performance mode: unknown",
        };
        var warmParts = new List<string>
        {
            string.Create(CultureInfo.InvariantCulture, $"NTFS {NtfsWarmMedianSeconds:0.0} s")
        };
        if (NtfsExcludedWarmMedianSeconds is { } exclWarm)
            warmParts.Add(string.Create(CultureInfo.InvariantCulture, $"NTFS+AV exclusion {exclWarm:0.0} s ({FormatDelta(ExcludedWarmPercentFaster)})"));
        warmParts.Add(string.Create(CultureInfo.InvariantCulture, $"Dev Drive {DevDriveWarmMedianSeconds:0.0} s ({warmDelta})"));
        if (DevDriveExcludedWarmMedianSeconds is { } ddExclWarm)
            warmParts.Add(string.Create(CultureInfo.InvariantCulture, $"Dev Drive+AV exclusion {ddExclWarm:0.0} s ({FormatDelta(DevDriveExcludedWarmPercentFaster)})"));

        return string.Create(CultureInfo.InvariantCulture,
            $"Warm: {string.Join(" vs ", warmParts)}; Cold: NTFS {NtfsColdMedianSeconds:0.0} s vs Dev Drive {DevDriveColdMedianSeconds:0.0} s ({coldDelta}). {perf}.");
    }
}

/// <summary>
/// One anonymous local sample appended to <c>dev-benchmarks.json</c> in the protected state folder.
/// Explicitly contains no computer name, user account, serial number, or local path.
/// </summary>
public sealed record DeveloperBenchmarkSample(
    DeveloperLanguage Workload,
    string PinId,
    string PinSha256,
    string? ToolchainVersion,
    int? ToolchainMajor,
    DeveloperCpuClass CpuClass,
    string? CpuName,
    int CoreCount,
    bool? OnBattery,
    string? PowerPlan,
    bool? DefenderScanning,
    double? ColdMedianSeconds,
    double? WarmMedianSeconds,
    double? WarmExcludedMedianSeconds,
    double? RestoreSeconds,
    int ColdRepeats,
    int WarmRepeats,
    DateTimeOffset RecordedAtUtc);

/// <summary>Persisted list of local developer benchmark samples (separate from <c>benchmarks.json</c>).</summary>
public sealed record DeveloperSampleHistory(int SchemaVersion, IReadOnlyList<DeveloperBenchmarkSample> Samples)
{
    public const int CurrentSchemaVersion = 1;
    public const int MaxStoredSamples = 500;

    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() },
    };

    public string ToJson() => JsonSerializer.Serialize(this, Json);

    public static DeveloperSampleHistory? FromJson(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try { return JsonSerializer.Deserialize<DeveloperSampleHistory>(json, Json); }
        catch (JsonException) { return null; }
    }
}

public interface IDeveloperSampleStore
{
    DeveloperSampleHistory Load();
    void Append(DeveloperBenchmarkSample sample);
}

/// <summary>Stores local developer benchmark samples beside <c>benchmarks.json</c> in the protected state folder.</summary>
public sealed class FileDeveloperSampleStore(string path, ILogger? log = null) : IDeveloperSampleStore
{
    public static string DefaultPath() => ProtectedState.PathFor(ProtectedState.DevBenchmarksFile);

    public DeveloperSampleHistory Load()
    {
        try
        {
            if (!File.Exists(path)) return new(DeveloperSampleHistory.CurrentSchemaVersion, []);
            return DeveloperSampleHistory.FromJson(File.ReadAllText(path)) ?? new(DeveloperSampleHistory.CurrentSchemaVersion, []);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            log.Warn($"Developer benchmark sample read failed: {ex.Message}");
            return new(DeveloperSampleHistory.CurrentSchemaVersion, []);
        }
    }

    public void Append(DeveloperBenchmarkSample sample)
    {
        try
        {
            var current = Load();
            var list = current.Samples.Concat([sample]).TakeLast(DeveloperSampleHistory.MaxStoredSamples).ToList();
            var updated = new DeveloperSampleHistory(DeveloperSampleHistory.CurrentSchemaVersion, list);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            var tmp = path + ".tmp";
            File.WriteAllText(tmp, updated.ToJson());
            File.Move(tmp, path, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            log.Warn($"Developer benchmark sample write failed: {ex.Message}");
        }
    }
}
