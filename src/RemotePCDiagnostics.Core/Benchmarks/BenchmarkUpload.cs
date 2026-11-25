using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Core.Benchmarks;

/// <summary>What the PC is made of, sent with uploaded benchmark results so the shop can compare computers. Unknown parts stay null.</summary>
public sealed record BenchmarkHardware(
    string? Manufacturer = null,
    string? Model = null,
    string? Processor = null,
    int? Cores = null,
    int? LogicalProcessors = null,
    double? MemoryGb = null,
    string? Gpu = null,
    string? OperatingSystem = null);

/// <summary>One benchmark's result in an upload: the median, the runs, and how to rank it (lower or higher is better, weight).</summary>
public sealed record BenchmarkUploadResult(
    string Kind,
    string Title,
    string Unit,
    bool LowerIsBetter,
    double Weight,
    double Value,
    IReadOnlyList<double> Samples,
    string? Detail = null);

public sealed record BenchmarkUploadConditions(
    bool? OnBattery,
    double? CpuTemperatureC,
    string? PowerPlan,
    string? PowerMode = null,
    int? PerformanceLimitPercent = null,
    string? PerformanceLimitPowerSource = null,
    int? AcMaxProcessorStatePercent = null,
    bool? DischargingOnAc = null);

/// <summary>The body of <c>POST /api/benchmarks</c> on the Admin site.</summary>
public sealed record BenchmarkUploadRequest(
    string MachineId,
    string MachineName,
    string AppVersion,
    BenchmarkHardware Hardware,
    string Phase,
    DateTimeOffset MeasuredUtc,
    bool Completed,
    BenchmarkUploadConditions Conditions,
    IReadOnlyList<BenchmarkUploadResult> Results);

public static class BenchmarkUpload
{
    /// <summary>
    /// The weight a benchmark carries when computers are ranked against each other. The before/after weights are kept, and the developer
    /// clean build (weight 0 in a before/after, where it is optional) counts too, since build speed is what a developer PC is bought for.
    /// Inventory counts (start-up apps, services, free space) stay at 0: they are listed, not ranked into the overall score.
    /// </summary>
    public static double CompareWeight(BenchmarkInfo info) =>
        info.Weight > 0 ? info.Weight : Benchmarks.IsDeveloperKind(info.Kind) ? 1.0 : 0.0;

    /// <summary>The run to upload: the after pass when there is one (the PC as it is now), else the before pass.</summary>
    public static BenchmarkRun? LatestRun(BenchmarkRun? before, BenchmarkRun? after) => after ?? before;

    /// <summary>Builds the upload from one finished run; measurements without a value are left out. Null when nothing was measured.</summary>
    public static BenchmarkUploadRequest? Build(BenchmarkRun? run, string machineId, string machineName, BenchmarkHardware hardware, string? appVersion = null)
    {
        if (run is null) return null;
        var results = new List<BenchmarkUploadResult>();
        foreach (var m in run.Measurements)
        {
            if (m.Median is not { } value || !double.IsFinite(value)) continue;
            var info = Benchmarks.Info(m.Kind);
            results.Add(new BenchmarkUploadResult(m.Kind.ToString(), info.Title, info.Unit, info.LowerIsBetter, CompareWeight(info), value,
                m.Samples.Where(double.IsFinite).ToList(), Detail(m)));
        }
        if (results.Count == 0) return null;
        return new BenchmarkUploadRequest(machineId, machineName, appVersion ?? AppBuildInfo.Release, hardware, run.Phase.ToString(), run.TimeUtc,
            run.Completed, new BenchmarkUploadConditions(
                run.Conditions.OnBattery,
                run.Conditions.CpuTemperatureC,
                run.Conditions.PowerPlan,
                run.Conditions.PowerMode,
                run.Conditions.PerformanceLimitPercent,
                run.Conditions.PerformanceLimitPowerSource,
                run.Conditions.AcMaxProcessorStatePercent,
                run.Conditions.DischargingOnAc), results);
    }

    /// <summary>Speedometer names the browser it ran in (scores from different browsers do not compare); other kinds keep their own breakdown.</summary>
    private static string? Detail(BenchmarkMeasurement m)
    {
        if (m.RunIdentity is { } id)
            return $"{id.BrowserName}{(string.IsNullOrWhiteSpace(id.BrowserVersion) ? "" : " " + id.BrowserVersion)} · Speedometer {id.SpeedometerVersion}";
        if (m.DeveloperBuild is { } dev)
            return dev.FormatDetail();
        return m.Detail;
    }
}

/// <summary>
/// Reads the PC's model, processor, memory and graphics card via in-process WMI (standard user, no admin, no PowerShell).
/// Anything it cannot read is left unknown; it never fails the upload.
/// </summary>
public static class HardwareIdentityProbe
{
    internal const string Script =
        "$ErrorActionPreference='SilentlyContinue';" +
        "$cs=Get-CimInstance Win32_ComputerSystem;" +
        "$cpu=@(Get-CimInstance Win32_Processor);" +
        "$gpu=@(Get-CimInstance Win32_VideoController | Where-Object { $_.Name } | ForEach-Object { $_.Name });" +
        "$os=Get-CimInstance Win32_OperatingSystem;" +
        "[pscustomobject]@{" +
        "Manufacturer=$cs.Manufacturer;Model=$cs.Model;Memory=$cs.TotalPhysicalMemory;" +
        "Processor=($cpu | Select-Object -First 1).Name;" +
        "Cores=($cpu | Measure-Object -Property NumberOfCores -Sum).Sum;" +
        "Logical=($cpu | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum;" +
        "Gpu=($gpu -join ', ');Os=(($os.Caption + ' ' + $os.Version).Trim())" +
        "} | ConvertTo-Json -Compress";

    public static async Task<BenchmarkHardware> ReadAsync(SystemCommandRunner commands, CancellationToken ct)
    {
        try
        {
            if (!commands.IsScripted && OperatingSystem.IsWindows())
                return await Task.Run(ReadWindows, ct).ConfigureAwait(false);

            var result = await commands.RunPowerShellAsync(Script, ct).ConfigureAwait(false);
            return result is { ExitCode: 0, TimedOut: false } ? Parse(result.StdOut) : new BenchmarkHardware();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new BenchmarkHardware();
        }
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    internal static BenchmarkHardware ReadWindows()
    {
        string? manufacturer = null, model = null, processor = null, os = null;
        double? memoryBytes = null;
        int cores = 0, logical = 0;
        var gpus = new List<string>();

        static string? Clean(object? v) => v?.ToString()?.Trim() is { Length: > 0 } s ? s : null;

        try
        {
            using var s = new System.Management.ManagementObjectSearcher("SELECT Manufacturer, Model, TotalPhysicalMemory FROM Win32_ComputerSystem");
            using var res = s.Get();
            foreach (System.Management.ManagementObject o in res)
            {
                using (o)
                {
                    manufacturer = Clean(o["Manufacturer"]);
                    model = Clean(o["Model"]);
                    if (o["TotalPhysicalMemory"] is { } mem)
                        memoryBytes = Convert.ToDouble(mem, System.Globalization.CultureInfo.InvariantCulture);
                    break;
                }
            }
        }
        catch { }

        try
        {
            using var s = new System.Management.ManagementObjectSearcher("SELECT Name, NumberOfCores, NumberOfLogicalProcessors FROM Win32_Processor");
            using var res = s.Get();
            foreach (System.Management.ManagementObject o in res)
            {
                using (o)
                {
                    processor ??= Clean(o["Name"]);
                    if (o["NumberOfCores"] is { } c) cores += Convert.ToInt32(c, System.Globalization.CultureInfo.InvariantCulture);
                    if (o["NumberOfLogicalProcessors"] is { } l) logical += Convert.ToInt32(l, System.Globalization.CultureInfo.InvariantCulture);
                }
            }
        }
        catch { }

        try
        {
            using var s = new System.Management.ManagementObjectSearcher("SELECT Name FROM Win32_VideoController");
            using var res = s.Get();
            foreach (System.Management.ManagementObject o in res)
            {
                using (o)
                {
                    if (Clean(o["Name"]) is { } g) gpus.Add(g);
                }
            }
        }
        catch { }

        try
        {
            using var s = new System.Management.ManagementObjectSearcher("SELECT Caption, Version FROM Win32_OperatingSystem");
            using var res = s.Get();
            foreach (System.Management.ManagementObject o in res)
            {
                using (o)
                {
                    var combined = $"{Clean(o["Caption"])} {Clean(o["Version"])}".Trim();
                    if (combined.Length > 0) os = combined;
                    break;
                }
            }
        }
        catch { }

        return new BenchmarkHardware(
            Manufacturer: manufacturer,
            Model: model,
            Processor: processor,
            Cores: cores > 0 ? cores : null,
            LogicalProcessors: logical > 0 ? logical : null,
            MemoryGb: memoryBytes is > 0 and var b ? Math.Round(b / (1024d * 1024 * 1024), 1) : null,
            Gpu: gpus.Count > 0 ? string.Join(", ", gpus) : null,
            OperatingSystem: os);
    }

    /// <summary>Reads the probe's JSON line; a field that is missing, empty or the wrong type stays null.</summary>
    public static BenchmarkHardware Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return new BenchmarkHardware();
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return new BenchmarkHardware();
            var memoryBytes = Number(root, "Memory");
            return new BenchmarkHardware(
                Manufacturer: Text(root, "Manufacturer"),
                Model: Text(root, "Model"),
                Processor: Text(root, "Processor"),
                Cores: Number(root, "Cores") is > 0 and var c ? (int)c : null,
                LogicalProcessors: Number(root, "Logical") is > 0 and var l ? (int)l : null,
                MemoryGb: memoryBytes is > 0 and var b ? Math.Round(b / (1024d * 1024 * 1024), 1) : null,
                Gpu: Text(root, "Gpu"),
                OperatingSystem: Text(root, "Os"));
        }
        catch (JsonException)
        {
            return new BenchmarkHardware();
        }
    }

    private static string? Text(JsonElement root, string name) =>
        root.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String && v.GetString()?.Trim() is { Length: > 0 } s ? s : null;

    private static double? Number(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var v)) return null;
        if (v.ValueKind == JsonValueKind.Number && v.TryGetDouble(out var d)) return d;
        if (v.ValueKind == JsonValueKind.String && double.TryParse(v.GetString(), NumberStyles.Float, CultureInfo.InvariantCulture, out var s)) return s;
        return null;
    }
}

/// <summary>The PC's stable identity for uploads: Windows' own MachineGuid, which a standard user can read and which the Agent also uses.</summary>
public static class MachineIdentity
{
    public static string Read(string machineName, Func<string?>? machineGuid = null)
    {
        var guid = (machineGuid ?? ReadMachineGuid)();
        if (Guid.TryParse(guid, out var id) && id != Guid.Empty) return id.ToString("D");
        return "name-" + (string.IsNullOrWhiteSpace(machineName) ? "unknown" : machineName.Trim().ToLowerInvariant());
    }

    private static string? ReadMachineGuid()
    {
        if (!OperatingSystem.IsWindows()) return null;
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography");
            return key?.GetValue("MachineGuid") as string;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            return null;
        }
    }
}
