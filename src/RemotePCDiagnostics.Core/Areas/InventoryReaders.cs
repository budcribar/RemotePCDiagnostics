using System.Globalization;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Core.Areas;

// Where Hardware inventory, Services, Device Manager & drivers and Programs & updates read from. The app registers the WMI readers (WMI
// through the Agent, the registry in the app); the Store edition also has the legacy osquery readers (RemotePCDiagnostics.Legacy) for
// when the Agent isn't connected. See IBatteryPowerSource.

/// <summary>Hardware inventory: computer, processor, memory, drives, graphics, network adapters, BIOS.</summary>
public interface IHardwareInventorySource
{
    Task<HardwareInventory> ReadAsync(IProgress<string>? progress, CancellationToken ct);
    /// <summary>Whether the check can run (the legacy reader needs osqueryi.exe).</summary>
    Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken ct) => Task.FromResult(ModuleAvailability.Available);
}

public interface IServiceSource
{
    /// <summary>The Windows services (not drivers), or null when they couldn't be read.</summary>
    Task<IReadOnlyList<ServiceInfo>?> ReadServicesAsync(CancellationToken ct);
    /// <summary>Whether the check can run (the legacy reader needs osqueryi.exe).</summary>
    Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken ct) => Task.FromResult(ModuleAvailability.Available);
}

public interface IDeviceDriverSource
{
    /// <summary>The devices Device Manager shows with a problem, or null when they couldn't be read.</summary>
    Task<IReadOnlyList<ProblemDevice>?> ReadProblemDevicesAsync(CancellationToken ct);
    /// <summary>The installed hardware drivers, or null when they couldn't be read.</summary>
    Task<IReadOnlyList<DriverEntry>?> ReadDriversAsync(CancellationToken ct);
    /// <summary>Whether the check can run (the legacy reader needs osqueryi.exe).</summary>
    Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken ct) => Task.FromResult(ModuleAvailability.Available);
}

public interface IProgramsSource
{
    /// <summary>The Windows version as osquery's <c>os_version</c> names it (name, display_version, build, version, arch, install_date).</summary>
    Task<WindowsVersionRead> ReadWindowsVersionAsync(CancellationToken ct);
    /// <summary>The installed Windows updates, or null when they couldn't be read.</summary>
    Task<IReadOnlyList<InstalledUpdate>?> ReadUpdatesAsync(CancellationToken ct);
    /// <summary>The installed programs, or null when they couldn't be read.</summary>
    Task<IReadOnlyList<InstalledProgram>?> ReadProgramsAsync(CancellationToken ct);
    /// <summary>Whether the check can run (the legacy reader needs osqueryi.exe).</summary>
    Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken ct) => Task.FromResult(ModuleAvailability.Available);
}

/// <param name="Ok">Whether the version could be read.</param>
/// <param name="Values">The values, by osquery column name; null when Windows didn't report one.</param>
public sealed record WindowsVersionRead(bool Ok, IReadOnlyDictionary<string, string>? Values);

/// <summary>WMI's datetime ("yyyyMMddHHmmss.ffffff+UUU", sometimes with * for unknown parts): its date, or null.</summary>
public static class CimDates
{
    public static DateOnly? Parse(string s) =>
        s.Length >= 8 && DateOnly.TryParseExact(s[..8], "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var d) ? d : null;
}

public sealed class WmiHardwareInventorySource(IWmiSource wmi) : IHardwareInventorySource
{
    public const string Cimv2 = @"root\cimv2";
    public const string ComputerSql = "SELECT Name, DNSHostName, Manufacturer, Model, TotalPhysicalMemory FROM Win32_ComputerSystem";
    public const string ProductSql = "SELECT UUID, Version, IdentifyingNumber FROM Win32_ComputerSystemProduct";
    public const string BoardSql = "SELECT Manufacturer, Product, Version, SerialNumber FROM Win32_BaseBoard";
    public const string CpuSql = "SELECT DeviceID, Name, Manufacturer, ProcessorType, SocketDesignation, NumberOfCores, NumberOfLogicalProcessors, CurrentClockSpeed, MaxClockSpeed, LoadPercentage, AddressWidth, Architecture FROM Win32_Processor";
    public const string MemorySql = "SELECT DeviceLocator, BankLabel, FormFactor, SMBIOSMemoryType, Capacity, Speed, ConfiguredClockSpeed, Manufacturer, PartNumber, SerialNumber FROM Win32_PhysicalMemory";
    public const string DiskSql = "SELECT Index, DeviceID, Name, InterfaceType, Manufacturer, Model, SerialNumber, Description, Size, Partitions FROM Win32_DiskDrive";
    public const string GpuSql = "SELECT Caption, AdapterCompatibility, VideoProcessor, DriverVersion, DriverDate, VideoModeDescription FROM Win32_VideoController";
    public const string NetworkSql = "SELECT NetConnectionID, Name, Description, Manufacturer, AdapterType, PhysicalAdapter, NetEnabled, NetConnectionStatus, Speed FROM Win32_NetworkAdapter";
    public const string BiosSql = "SELECT Manufacturer, SMBIOSBIOSVersion, ReleaseDate, SystemBiosMajorVersion, SystemBiosMinorVersion, SerialNumber FROM Win32_BIOS";
    public const string LogicalDrivesSql = "SELECT DeviceID, DriveType, Size FROM Win32_LogicalDisk";

    public async Task<HardwareInventory> ReadAsync(IProgress<string>? progress, CancellationToken ct)
    {
        async Task<WmiQueryResult> Q(string sql) => await wmi.QueryAsync(Cimv2, sql, ct).ConfigureAwait(false);
        static InventorySection<T> Section<T>(WmiQueryResult q, Func<WmiRow, T> map) =>
            q.Success ? new(q.Query, q.Rows!.Select(map).ToList(), null) : new(q.Query, [], q.Error);

        progress.ReportStep(1, HardwareInventory.SectionCount, "Reading computer details…");
        var cs = await Q(ComputerSql).ConfigureAwait(false);
        var product = await Q(ProductSql).ConfigureAwait(false);
        var board = await Q(BoardSql).ConfigureAwait(false);
        var bios = await Q(BiosSql).ConfigureAwait(false);
        progress.ReportStep(2, HardwareInventory.SectionCount, "Reading processor details…");
        var cpu = await Q(CpuSql).ConfigureAwait(false);
        var system = cs.Success
            ? new InventorySection<SystemInfo>(cs.Query, cs.Rows!.Take(1).Select(r => System(r, product.Rows?.FirstOrDefault(), board.Rows?.FirstOrDefault(),
                bios.Rows?.FirstOrDefault(), cpu.Rows ?? [])).ToList(), null)
            : new InventorySection<SystemInfo>(cs.Query, [], cs.Error);
        var cpus = Section(cpu, Cpu);
        progress.ReportStep(3, HardwareInventory.SectionCount, "Reading memory modules…");
        var memory = Section(await Q(MemorySql).ConfigureAwait(false), Memory);
        progress.ReportStep(4, HardwareInventory.SectionCount, "Reading storage drives…");
        var disks = Section(await Q(DiskSql).ConfigureAwait(false), Disk);
        progress.ReportStep(5, HardwareInventory.SectionCount, "Reading graphics adapters…");
        var gpus = Section(await Q(GpuSql).ConfigureAwait(false), Gpu);
        progress.ReportStep(6, HardwareInventory.SectionCount, "Reading network adapters…");
        var nets = Section(await Q(NetworkSql).ConfigureAwait(false), Network);
        progress.ReportStep(7, HardwareInventory.SectionCount, "Reading BIOS details…");
        var biosSection = Section(bios, Bios);

        // The same stand-ins as the osquery reader, so both show the same thing.
        var s0 = system.Items.FirstOrDefault();
        if (cpus.Success && cpus.Items.Count == 0 && s0 is { CpuBrand.Length: > 0 })
            cpus = cpus with { Items = [HardwareInventory.CpuFromSystemPublic(s0)], FromFallback = true };
        if (memory.Success && !memory.Items.Any(m => m.IsPopulated) && s0?.PhysicalMemoryBytes is > 0)
            memory = memory with { FromFallback = true };
        // Installed memory, as osquery reports it: the modules' total (16 GB), not what Windows can use (15.6 GB).
        if (s0 is not null && memory.Items.Where(m => m.IsPopulated).Sum(m => m.SizeMb ?? 0) is > 0 and var installedMb)
            system = system with { Items = [s0 with { PhysicalMemoryBytes = installedMb * 1024 * 1024 }] };
        if (disks.Success && disks.Items.Count == 1 && disks.Items[0].SizeBytes is not > 0)
        {
            var ld = await Q(LogicalDrivesSql).ConfigureAwait(false);
            // DriveType 3 is a local fixed disk.
            var total = ld.Rows?.Where(r => r.Long("DriveType") == 3).Sum(r => r.Long("Size") ?? 0) ?? 0;
            if (total > 0) disks = disks with { Items = [disks.Items[0] with { SizeBytes = total }], FromFallback = true };
        }
        return new(system, cpus, memory, disks) { Gpus = gpus, NetworkAdapters = nets, Bios = biosSection };
    }

    internal static SystemInfo System(WmiRow cs, WmiRow? product, WmiRow? board, WmiRow? bios, IReadOnlyList<WmiRow> cpus)
    {
        var cpu = cpus.FirstOrDefault();
        var vendor = cs.Str("Manufacturer");
        // Lenovo keeps the marketing model in Win32_ComputerSystemProduct.Version and the machine type in Model; osquery shows the first as
        // the model and the second as the version.
        var lenovo = vendor.StartsWith("LENOVO", StringComparison.OrdinalIgnoreCase) && product?.Str("Version") is { Length: > 0 };
        var model = lenovo ? product!.Str("Version") : cs.Str("Model");
        var version = lenovo ? cs.Str("Model") : product?.Str("Version") ?? "";
        var name = cs.Str("Name");
        return new SystemInfo(
            cs.Str("DNSHostName") is { Length: > 0 } dns ? dns : name, name, product?.Str("UUID") ?? "",
            vendor, model, SystemInfo.Reported(version), bios?.Str("SerialNumber") ?? "",
            board?.Str("Manufacturer") ?? "", board?.Str("Product") ?? "", SystemInfo.Reported(board?.Str("Version") ?? ""), board?.Str("SerialNumber") ?? "",
            cpu?.Str("Name") ?? "", Architecture(cpu?.Long("Architecture")),
            Sum(cpus, "NumberOfCores"), Sum(cpus, "NumberOfLogicalProcessors"), cpus.Count > 0 ? cpus.Count : null,
            cs.Long("TotalPhysicalMemory") is > 0 and var mem ? mem : null);
    }

    private static int? Sum(IReadOnlyList<WmiRow> rows, string name) =>
        rows.Select(r => r.Long(name)).Where(v => v is > 0).Select(v => (int)v!.Value).DefaultIfEmpty(0).Sum() is > 0 and var s ? s : null;

    /// <summary>Win32_Processor.Architecture, in osquery's words.</summary>
    public static string Architecture(long? code) => code switch
    {
        0 => "x86", 1 => "MIPS", 2 => "Alpha", 3 => "PowerPC", 5 => "ARM", 6 => "ia64", 9 => "x86_64", 12 => "ARM64", _ => "",
    };

    internal static CpuInfo Cpu(WmiRow r) => new(
        r.Str("DeviceID"), r.Str("Name"), r.Str("Manufacturer"), r.Str("ProcessorType"), r.Str("SocketDesignation"),
        Int(r, "NumberOfCores"), Int(r, "NumberOfLogicalProcessors"), Int(r, "CurrentClockSpeed"), Int(r, "MaxClockSpeed"),
        Int(r, "LoadPercentage"), r.Str("AddressWidth"));

    internal static MemoryDevice Memory(WmiRow r) => new(
        r.Str("DeviceLocator"), r.Str("BankLabel"), FormFactor(r.Long("FormFactor")), MemoryType(r.Long("SMBIOSMemoryType")),
        MemoryDevice.SaneMb(r.Long("Capacity") is > 0 and var bytes ? bytes / (1024 * 1024) : null), Int(r, "Speed"), Int(r, "ConfiguredClockSpeed"),
        r.Str("Manufacturer"), r.Str("PartNumber"), r.Str("SerialNumber"));

    /// <summary>Win32_PhysicalMemory.FormFactor (CIM codes), in the SMBIOS words osquery shows.</summary>
    public static string FormFactor(long? code) => code switch
    {
        1 => "Other", 2 => "SIP", 3 => "DIP", 4 => "ZIP", 6 => "Proprietary Card", 7 => "SIMM", 8 => "DIMM", 9 => "TSOP",
        11 => "RIMM", 12 => "SODIMM", 13 => "SRIMM", _ => code is null ? "" : "Unknown",
    };

    /// <summary>Win32_PhysicalMemory.SMBIOSMemoryType (the SMBIOS type 17 memory type), in osquery's words.</summary>
    public static string MemoryType(long? code) => code switch
    {
        1 => "Other", 2 => "Unknown", 3 => "DRAM", 4 => "EDRAM", 5 => "VRAM", 6 => "SRAM", 7 => "RAM", 8 => "ROM", 9 => "FLASH",
        10 => "EEPROM", 11 => "FEPROM", 12 => "EPROM", 13 => "CDRAM", 14 => "3DRAM", 15 => "SDRAM", 16 => "SGRAM", 17 => "RDRAM",
        18 => "DDR", 19 => "DDR2", 20 => "DDR2 FB-DIMM", 24 => "DDR3", 25 => "FBD2", 26 => "DDR4", 27 => "LPDDR", 28 => "LPDDR2",
        29 => "LPDDR3", 30 => "LPDDR4", 31 => "Logical non-volatile device", 32 => "HBM", 33 => "HBM2", 34 => "DDR5", 35 => "LPDDR5",
        36 => "HBM3", _ => "",
    };

    internal static DiskInfo Disk(WmiRow r) => new(
        Int(r, "Index"), r.Str("DeviceID"), r.Str("Name"), r.Str("InterfaceType"), r.Str("Manufacturer"), r.Str("Model"),
        r.Str("SerialNumber"), r.Str("Description"), r.Long("Size") is > 0 and var size ? size : null, Int(r, "Partitions"));

    internal static GpuInfo Gpu(WmiRow r) => new(
        r.Str("Caption"), r.Str("AdapterCompatibility"), r.Str("VideoProcessor"), r.Str("DriverVersion"),
        CimDates.Parse(r.Str("DriverDate"))?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) ?? "",
        GpuInfo.FormatVideoMode(r.Str("VideoModeDescription")));

    internal static NetworkAdapterInfo Network(WmiRow r) => new(
        r.Str("NetConnectionID").Length > 0 ? r.Str("NetConnectionID") : r.Str("Name"), r.Str("Description"), r.Str("Manufacturer"),
        r.Str("AdapterType"), r.Bool("PhysicalAdapter"), r.Bool("NetEnabled"),
        r.Long("NetConnectionStatus") is { } status ? NetworkAdapterInfo.ConnectionStatus(status.ToString(CultureInfo.InvariantCulture)) : "",
        // Speed means little on an adapter that isn't connected, and long.MaxValue is WMI's "unknown".
        r.Long("NetConnectionStatus") == 2 && r.Long("Speed") is > 0 and < long.MaxValue and var speed ? speed : null);

    /// <summary>The release date as osquery's platform_info gives it: yyyy-MM-dd.</summary>
    internal static BiosInfo Bios(WmiRow r) => new(
        r.Str("Manufacturer"), r.Str("SMBIOSBIOSVersion"),
        CimDates.Parse(r.Str("ReleaseDate"))?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) ?? "",
        r.Long("SystemBiosMajorVersion") is { } major and < 255 && r.Long("SystemBiosMinorVersion") is { } minor and < 255 ? $"{major}.{minor}" : "");

    private static int? Int(WmiRow r, string name) => r.Long(name) is { } v and >= int.MinValue and <= int.MaxValue ? (int)v : null;
}

public sealed class WmiServiceSource(IWmiSource wmi) : IServiceSource
{
    public const string Sql = "SELECT Name, DisplayName, State, StartMode, StartName, Description FROM Win32_Service";

    public async Task<IReadOnlyList<ServiceInfo>?> ReadServicesAsync(CancellationToken ct)
    {
        var q = await wmi.QueryAsync(WmiHardwareInventorySource.Cimv2, Sql, ct).ConfigureAwait(false);
        return q.Success ? q.Rows!.Select(Service).ToList() : null;
    }

    /// <summary>One Win32_Service, with its state and start mode in the words osquery (and the service control manager) uses.</summary>
    public static ServiceInfo Service(WmiRow r) => new(
        r.Str("Name"), r.Str("DisplayName"), Status(r.Str("State")), StartType(r.Str("StartMode")), r.Str("StartName"), r.Str("Description"));

    public static string Status(string state) => state.ToUpperInvariant() switch
    {
        "RUNNING" => "RUNNING", "STOPPED" => "STOPPED", "PAUSED" => "PAUSED", "START PENDING" => "START_PENDING",
        "STOP PENDING" => "STOP_PENDING", "CONTINUE PENDING" => "CONTINUE_PENDING", "PAUSE PENDING" => "PAUSE_PENDING", _ => state,
    };

    public static string StartType(string mode) => mode.ToUpperInvariant() switch
    {
        "AUTO" => "AUTO_START", "MANUAL" => "DEMAND_START", "DISABLED" => "DISABLED", "BOOT" => "BOOT_START", "SYSTEM" => "SYSTEM_START", _ => mode,
    };
}

public sealed class WmiDeviceDriverSource(IWmiSource wmi) : IDeviceDriverSource
{
    public const string ProblemDevicesSql = "SELECT Name, PNPClass, DeviceID, ConfigManagerErrorCode, Status FROM Win32_PnPEntity WHERE ConfigManagerErrorCode <> 0";
    public const string DriversSql = "SELECT DeviceName, Description, DeviceClass, DriverProviderName, Manufacturer, DriverVersion, DriverDate, IsSigned FROM Win32_PnPSignedDriver";

    public async Task<IReadOnlyList<ProblemDevice>?> ReadProblemDevicesAsync(CancellationToken ct)
    {
        var q = await wmi.QueryAsync(WmiHardwareInventorySource.Cimv2, ProblemDevicesSql, ct).ConfigureAwait(false);
        return q.Success
            ? q.Rows!.Select(r => new ProblemDevice(r.Str("Name").Length > 0 ? r.Str("Name") : "Unknown device", r.Str("PNPClass"), r.Str("DeviceID"),
                (int)(r.Long("ConfigManagerErrorCode") ?? 0), r.Str("Status"))).ToList()
            : null;
    }

    public async Task<IReadOnlyList<DriverEntry>?> ReadDriversAsync(CancellationToken ct)
    {
        var q = await wmi.QueryAsync(WmiHardwareInventorySource.Cimv2, DriversSql, ct).ConfigureAwait(false);
        // As osquery's query (device_name != ''): a name of only spaces counts, as on the WPD volume driver.
        return q.Success ? q.Rows!.Where(r => r.Values.TryGetValue("DeviceName", out var n) && n.ValueKind == System.Text.Json.JsonValueKind.String && n.GetString()!.Length > 0)
            .Select(Driver).ToList() : null;
    }

    public static DriverEntry Driver(WmiRow r) => new(
        r.Str("DeviceName").Length > 0 ? r.Str("DeviceName") : r.Str("Description"),
        r.Str("DeviceClass"),
        r.Str("DriverProviderName").Length > 0 ? r.Str("DriverProviderName") : r.Str("Manufacturer"),
        r.Str("DriverVersion"), CimDates.Parse(r.Str("DriverDate")), r.Bool("IsSigned") != false);
}

/// <param name="packages">The signed-in user's Store apps, added to the Uninstall keys' programs (osquery lists them too).</param>
public sealed class WmiProgramsSource(IWmiSource wmi, IRegistrySource registry, IPackageSource? packages = null) : IProgramsSource
{
    public const string OsSql = "SELECT Caption, Version, BuildNumber, OSArchitecture, InstallDate FROM Win32_OperatingSystem";
    public const string UpdatesSql = "SELECT HotFixID, Description, InstalledOn FROM Win32_QuickFixEngineering";
    public const string CurrentVersionKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    public static readonly string[] UninstallKeys = [@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"];
    public static readonly string[] ProgramValues = ["DisplayName", "DisplayVersion", "Publisher", "InstallDate"];

    public async Task<WindowsVersionRead> ReadWindowsVersionAsync(CancellationToken ct)
    {
        var q = await wmi.QueryAsync(WmiHardwareInventorySource.Cimv2, OsSql, ct).ConfigureAwait(false);
        if (!q.Success) return new(false, null);
        if (q.Rows!.FirstOrDefault() is not { } os) return new(true, null);
        var reg = await registry.ReadAsync(new RegistryRead(RegistryRoot.LocalMachine, CurrentVersionKey, ["DisplayVersion"]), ct).ConfigureAwait(false);
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["name"] = os.Str("Caption"),
            ["version"] = os.Str("Version"),
            ["build"] = os.Str("BuildNumber"),
            ["arch"] = os.Str("OSArchitecture"),
            ["install_date"] = CimDates.Parse(os.Str("InstallDate"))?.ToString("yyyyMMdd", CultureInfo.InvariantCulture) ?? "",
            ["display_version"] = reg.Rows?.FirstOrDefault()?.Str("DisplayVersion") ?? "",
        };
        return new(true, values);
    }

    public async Task<IReadOnlyList<InstalledUpdate>?> ReadUpdatesAsync(CancellationToken ct)
    {
        var q = await wmi.QueryAsync(WmiHardwareInventorySource.Cimv2, UpdatesSql, ct).ConfigureAwait(false);
        return q.Success
            ? q.Rows!.Select(r => new InstalledUpdate(r.Str("HotFixID"), r.Str("Description"), OsqueryDates.Parse(r.Str("InstalledOn")))).ToList()
            : null;
    }

    /// <summary>
    /// The Uninstall keys osquery's <c>programs</c> reads: the machine's (64- and 32-bit) and each signed-in user's. Null only when the machine's
    /// keys can't be read.
    /// </summary>
    public async Task<IReadOnlyList<InstalledProgram>?> ReadProgramsAsync(CancellationToken ct)
    {
        var list = new List<InstalledProgram>();
        foreach (var key in UninstallKeys)
        {
            var r = await registry.ReadAsync(new RegistryRead(RegistryRoot.LocalMachine, key, ProgramValues, SubKeys: true), ct).ConfigureAwait(false);
            if (!r.Success) return null;
            list.AddRange(Programs(r));
        }
        var users = await registry.ReadAsync(new RegistryRead(RegistryRoot.Users, "", [], SubKeys: true), ct).ConfigureAwait(false);
        foreach (var user in users.Rows ?? [])
        {
            var sid = user.Str(RegistryRead.KeyColumn);
            // A user's _Classes hive holds no Uninstall key.
            if (sid.Length == 0 || sid.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase)) continue;
            foreach (var key in UninstallKeys)
            {
                var r = await registry.ReadAsync(new RegistryRead(RegistryRoot.Users, sid + @"\" + key, ProgramValues, SubKeys: true), ct).ConfigureAwait(false);
                list.AddRange(Programs(r));
            }
        }
        if (packages is not null)
        {
            // Without the list (it failed, or this host can't read it), the Uninstall keys' programs are still the answer.
            var apps = await packages.ReadPackagesAsync(ct).ConfigureAwait(false);
            list.AddRange(PackageList.Apps(apps).Select(p => new InstalledProgram(p.Str(PackageList.DisplayName), p.Str(PackageList.Version),
                p.Str(PackageList.Publisher), OsqueryDates.Parse(p.Str(PackageList.InstalledDate)))));
        }
        return list;
    }

    private static IEnumerable<InstalledProgram> Programs(WmiQueryResult r) =>
        (r.Rows ?? []).Where(p => p.Str("DisplayName").Length > 0)
            .Select(p => new InstalledProgram(p.Str("DisplayName"), p.Str("DisplayVersion"), p.Str("Publisher"), OsqueryDates.Parse(p.Str("InstallDate"))));
}
