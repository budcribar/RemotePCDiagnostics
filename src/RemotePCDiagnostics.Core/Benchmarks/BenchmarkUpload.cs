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
    string? OperatingSystem = null,
    string? SystemSku = null,
    string? SystemFamily = null,
    string? FormFactor = null,
    string? Motherboard = null,
    int? MaxClockMhz = null,
    string? Architecture = null,
    string? MemoryType = null,
    int? MemorySpeedMhz = null,
    string? MemorySlots = null,
    string? Storage = null,
    double? GpuMemoryGb = null,
    string? DisplayResolution = null);

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
    IReadOnlyList<BenchmarkUploadResult> Results,
    string? Goal = null);

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
                run.Conditions.DischargingOnAc), results, BenchmarkGoals.Normalize(run.Goal));
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
        "$bb=Get-CimInstance Win32_BaseBoard | Select-Object -First 1;" +
        "$enc=Get-CimInstance Win32_SystemEnclosure | Select-Object -First 1;" +
        "$cpu=@(Get-CimInstance Win32_Processor);" +
        "$mem=@(Get-CimInstance Win32_PhysicalMemory);" +
        "$disk=@(Get-CimInstance Win32_DiskDrive | Where-Object { $_.MediaType -notmatch 'Removable' -and $_.Size -gt 0 });" +
        "$vc=@(Get-CimInstance Win32_VideoController | Where-Object { $_.Name });" +
        "$os=Get-CimInstance Win32_OperatingSystem;" +
        "[pscustomobject]@{" +
        "Manufacturer=$cs.Manufacturer;Model=$cs.Model;SystemSku=$cs.SystemSKUNumber;SystemFamily=$cs.SystemFamily;Memory=$cs.TotalPhysicalMemory;" +
        "Chassis=($enc.ChassisTypes | Select-Object -First 1);" +
        "Motherboard=(($bb.Manufacturer + ' ' + $bb.Product).Trim());" +
        "Processor=($cpu | Select-Object -First 1).Name;" +
        "Cores=($cpu | Measure-Object -Property NumberOfCores -Sum).Sum;" +
        "Logical=($cpu | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum;" +
        "MaxClockMhz=($cpu | Select-Object -First 1).MaxClockSpeed;" +
        "Arch=($cpu | Select-Object -First 1).Architecture;" +
        "MemType=($mem | Select-Object -First 1).SMBIOSMemoryType;" +
        "MemSpeedMhz=($mem | Where-Object { $_.ConfiguredClockSpeed -gt 0 } | Select-Object -First 1).ConfiguredClockSpeed;" +
        "MemSlots=if($mem.Count -gt 0){ ($mem.Count.ToString() + ' x ' + [math]::Round(($mem[0].Capacity/1GB),0).ToString() + ' GB') } else { $null };" +
        "Storage=(($disk | ForEach-Object { ($_.Model.Trim() + ' (' + [math]::Round($_.Size/1GB,0) + ' GB)') }) -join ', ');" +
        "Gpu=(($vc | ForEach-Object { $_.Name }) -join ', ');" +
        "GpuMemBytes=($vc | Measure-Object -Property AdapterRAM -Maximum).Maximum;" +
        "Display=($vc | Where-Object { $_.CurrentHorizontalResolution -gt 0 } | Select-Object -First 1 | ForEach-Object { $_.CurrentHorizontalResolution.ToString() + 'x' + $_.CurrentVerticalResolution.ToString() + $(if($_.CurrentRefreshRate -gt 0){ ' @ ' + $_.CurrentRefreshRate + ' Hz' }else{ '' }) });" +
        "Os=(($os.Caption + ' ' + $os.Version).Trim())" +
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
        string? manufacturer = null, model = null, systemSku = null, systemFamily = null, formFactor = null, motherboard = null;
        string? processor = null, architecture = null, memoryType = null, memorySlots = null, storage = null, display = null, os = null;
        double? memoryBytes = null, gpuMemBytes = null;
        int cores = 0, logical = 0;
        int? maxClockMhz = null, memorySpeedMhz = null;
        var gpus = new List<string>();

        static string? Clean(object? v) => v?.ToString()?.Trim() is { Length: > 0 } s ? s : null;

        try
        {
            using var s = new System.Management.ManagementObjectSearcher("SELECT Manufacturer, Model, SystemSKUNumber, SystemFamily, TotalPhysicalMemory FROM Win32_ComputerSystem");
            using var res = s.Get();
            using var o = res.OfType<System.Management.ManagementObject>().FirstOrDefault();
            if (o is not null)
            {
                manufacturer = Clean(o["Manufacturer"]);
                model = Clean(o["Model"]);
                systemSku = Clean(o["SystemSKUNumber"]);
                systemFamily = Clean(o["SystemFamily"]);
                if (o["TotalPhysicalMemory"] is { } mem)
                    memoryBytes = Convert.ToDouble(mem, CultureInfo.InvariantCulture);
            }
        }
        catch { }

        try
        {
            using var s = new System.Management.ManagementObjectSearcher("SELECT Manufacturer, Product FROM Win32_BaseBoard");
            using var res = s.Get();
            using var o = res.OfType<System.Management.ManagementObject>().FirstOrDefault();
            if (o is not null)
            {
                var mb = $"{Clean(o["Manufacturer"])} {Clean(o["Product"])}".Trim();
                if (mb.Length > 0) motherboard = mb;
            }
        }
        catch { }

        try
        {
            using var s = new System.Management.ManagementObjectSearcher("SELECT ChassisTypes FROM Win32_SystemEnclosure");
            using var res = s.Get();
            using var o = res.OfType<System.Management.ManagementObject>().FirstOrDefault();
            if (o is not null && o["ChassisTypes"] is ushort[] types && types.Length > 0)
                formFactor = MapChassisType(types[0]);
        }
        catch { }

        try
        {
            using var s = new System.Management.ManagementObjectSearcher("SELECT Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed, Architecture FROM Win32_Processor");
            using var res = s.Get();
            foreach (System.Management.ManagementBaseObject o in res)
            {
                using (o)
                {
                    processor ??= Clean(o["Name"]);
                    if (o["NumberOfCores"] is { } c) cores += Convert.ToInt32(c, CultureInfo.InvariantCulture);
                    if (o["NumberOfLogicalProcessors"] is { } l) logical += Convert.ToInt32(l, CultureInfo.InvariantCulture);
                    if (maxClockMhz is null && o["MaxClockSpeed"] is { } mhz && Convert.ToInt32(mhz, CultureInfo.InvariantCulture) is > 0 and var clk)
                        maxClockMhz = clk;
                    if (architecture is null && o["Architecture"] is { } arch)
                        architecture = MapArchitecture(Convert.ToInt32(arch, CultureInfo.InvariantCulture));
                }
            }
        }
        catch { }

        try
        {
            using var s = new System.Management.ManagementObjectSearcher("SELECT Capacity, Speed, ConfiguredClockSpeed, SMBIOSMemoryType FROM Win32_PhysicalMemory");
            using var res = s.Get();
            var dimms = new List<double>();
            foreach (System.Management.ManagementBaseObject o in res)
            {
                using (o)
                {
                    if (o["Capacity"] is { } cap && Convert.ToDouble(cap, CultureInfo.InvariantCulture) is > 0 and var bytes)
                        dimms.Add(Math.Round(bytes / (1024d * 1024 * 1024), 0));
                    if (memoryType is null && o["SMBIOSMemoryType"] is { } mt)
                        memoryType = MapMemoryType(Convert.ToInt32(mt, CultureInfo.InvariantCulture));
                    var spdObj = o["ConfiguredClockSpeed"] ?? o["Speed"];
                    if (memorySpeedMhz is null && spdObj is { } spd && Convert.ToInt32(spd, CultureInfo.InvariantCulture) is > 0 and var mhz)
                        memorySpeedMhz = mhz;
                }
            }
            if (dimms.Count > 0)
            {
                var distinct = dimms.Distinct().ToList();
                memorySlots = distinct.Count == 1
                    ? $"{dimms.Count} × {distinct[0]:0} GB"
                    : string.Join(" + ", dimms.Select(d => $"{d:0} GB"));
            }
        }
        catch { }

        try
        {
            using var s = new System.Management.ManagementObjectSearcher("SELECT Model, Size, MediaType, InterfaceType FROM Win32_DiskDrive");
            using var res = s.Get();
            var drives = new List<string>();
            foreach (System.Management.ManagementBaseObject o in res)
            {
                using (o)
                {
                    var media = Clean(o["MediaType"]) ?? "";
                    if (media.Contains("Removable", StringComparison.OrdinalIgnoreCase)) continue;
                    var dm = Clean(o["Model"]);
                    var bytes = o["Size"] is { } sz ? Convert.ToDouble(sz, CultureInfo.InvariantCulture) : 0;
                    if (dm is null || bytes <= 0) continue;
                    var gb = Math.Round(bytes / (1000d * 1000 * 1000), 0);
                    var capStr = gb >= 1000 ? $"{gb / 1000.0:0.#} TB" : $"{gb:0} GB";
                    drives.Add($"{dm} ({capStr})");
                }
            }
            if (drives.Count > 0) storage = string.Join(", ", drives);
        }
        catch { }

        try
        {
            using var s = new System.Management.ManagementObjectSearcher("SELECT Name, AdapterRAM, CurrentHorizontalResolution, CurrentVerticalResolution, CurrentRefreshRate FROM Win32_VideoController");
            using var res = s.Get();
            foreach (System.Management.ManagementBaseObject o in res)
            {
                using (o)
                {
                    if (Clean(o["Name"]) is { } g) gpus.Add(g);
                    if (o["AdapterRAM"] is { } ram && Convert.ToDouble(ram, CultureInfo.InvariantCulture) is > 0 and var rb)
                        gpuMemBytes = gpuMemBytes is null ? rb : Math.Max(gpuMemBytes.Value, rb);
                    if (display is null && o["CurrentHorizontalResolution"] is { } hObj && o["CurrentVerticalResolution"] is { } vObj)
                    {
                        var h = Convert.ToInt32(hObj, CultureInfo.InvariantCulture);
                        var v = Convert.ToInt32(vObj, CultureInfo.InvariantCulture);
                        if (h > 0 && v > 0)
                        {
                            var hz = o["CurrentRefreshRate"] is { } rObj ? Convert.ToInt32(rObj, CultureInfo.InvariantCulture) : 0;
                            display = hz > 0 ? $"{h}×{v} @ {hz} Hz" : $"{h}×{v}";
                        }
                    }
                }
            }
        }
        catch { }

        try
        {
            using var s = new System.Management.ManagementObjectSearcher("SELECT Caption, Version FROM Win32_OperatingSystem");
            using var res = s.Get();
            using var o = res.OfType<System.Management.ManagementObject>().FirstOrDefault();
            if (o is not null)
            {
                var combined = $"{Clean(o["Caption"])} {Clean(o["Version"])}".Trim();
                if (combined.Length > 0) os = combined;
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
            OperatingSystem: os,
            SystemSku: systemSku,
            SystemFamily: systemFamily,
            FormFactor: formFactor,
            Motherboard: motherboard,
            MaxClockMhz: maxClockMhz,
            Architecture: architecture,
            MemoryType: memoryType,
            MemorySpeedMhz: memorySpeedMhz,
            MemorySlots: memorySlots,
            Storage: storage,
            GpuMemoryGb: gpuMemBytes is > 0 and var gbVal ? Math.Round(gbVal / (1024d * 1024 * 1024), 1) : null,
            DisplayResolution: display);
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
            var gpuBytes = Number(root, "GpuMemBytes");
            return new BenchmarkHardware(
                Manufacturer: Text(root, "Manufacturer"),
                Model: Text(root, "Model"),
                Processor: Text(root, "Processor"),
                Cores: Number(root, "Cores") is > 0 and var c ? (int)c : null,
                LogicalProcessors: Number(root, "Logical") is > 0 and var l ? (int)l : null,
                MemoryGb: memoryBytes is > 0 and var b ? Math.Round(b / (1024d * 1024 * 1024), 1) : null,
                Gpu: Text(root, "Gpu"),
                OperatingSystem: Text(root, "Os"),
                SystemSku: Text(root, "SystemSku"),
                SystemFamily: Text(root, "SystemFamily"),
                FormFactor: Text(root, "FormFactor") ?? (Number(root, "Chassis") is > 0 and var ch ? MapChassisType((int)ch) : null),
                Motherboard: Text(root, "Motherboard"),
                MaxClockMhz: Number(root, "MaxClockMhz") is > 0 and var clk ? (int)clk : null,
                Architecture: Text(root, "Architecture") ?? (Number(root, "Arch") is >= 0 and var ar ? MapArchitecture((int)ar) : null),
                MemoryType: Text(root, "MemoryType") ?? (Number(root, "MemType") is > 0 and var mt ? MapMemoryType((int)mt) : null),
                MemorySpeedMhz: Number(root, "MemSpeedMhz") is > 0 and var ms ? (int)ms : null,
                MemorySlots: Text(root, "MemSlots"),
                Storage: Text(root, "Storage"),
                GpuMemoryGb: gpuBytes is > 0 and var gbVal ? Math.Round(gbVal / (1024d * 1024 * 1024), 1) : null,
                DisplayResolution: Text(root, "Display"));
        }
        catch (JsonException)
        {
            return new BenchmarkHardware();
        }
    }

    internal static string? MapChassisType(int code) => code switch
    {
        3 or 4 or 5 or 6 or 7 or 15 or 16 => "Desktop",
        8 or 9 or 10 or 14 => "Laptop",
        11 or 30 => "Tablet",
        13 => "All-in-One",
        31 or 32 => "2-in-1",
        35 or 36 => "Mini PC",
        _ => null,
    };

    internal static string? MapArchitecture(int code) => code switch
    {
        0 => "x86",
        5 => "ARM",
        9 => "x64",
        12 => "ARM64",
        _ => null,
    };

    internal static string? MapMemoryType(int smbiosType) => smbiosType switch
    {
        20 => "DDR",
        21 => "DDR2",
        24 => "DDR3",
        26 => "DDR4",
        27 => "LPDDR",
        28 => "LPDDR2",
        29 => "LPDDR3",
        30 => "LPDDR4",
        34 => "DDR5",
        35 => "LPDDR5",
        _ => null,
    };

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
