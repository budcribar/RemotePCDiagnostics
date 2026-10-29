namespace RemotePCDiagnostics.Core.Osquery;

/// <summary>osquery <c>system_info</c> (also holds hardware vendor/model/serial, board, CPU brand and total memory).</summary>
public sealed record SystemInfo(
    string Hostname, string ComputerName, string Uuid,
    string HardwareVendor, string HardwareModel, string HardwareVersion, string HardwareSerial,
    string BoardVendor, string BoardModel, string BoardVersion, string BoardSerial,
    string CpuBrand, string CpuType, int? CpuPhysicalCores, int? CpuLogicalCores, int? CpuSockets,
    long? PhysicalMemoryBytes)
{
    public static SystemInfo FromRow(IReadOnlyDictionary<string, string> r) => new(
        r.Str("hostname"), r.Str("computer_name"), r.Str("uuid"),
        r.Str("hardware_vendor"), r.Str("hardware_model"), r.Str("hardware_version"), r.Str("hardware_serial"),
        r.Str("board_vendor"), r.Str("board_model"), r.Str("board_version"), r.Str("board_serial"),
        r.Str("cpu_brand"), r.Str("cpu_type"), r.Int("cpu_physical_cores"), r.Int("cpu_logical_cores"), r.Int("cpu_sockets"),
        r.Long("physical_memory"));
}

/// <summary>osquery <c>cpu_info</c> (Windows; one row per socket).</summary>
public sealed record CpuInfo(
    string DeviceId, string Model, string Manufacturer, string ProcessorType, string SocketDesignation,
    int? NumberOfCores, int? LogicalProcessors, int? CurrentClockSpeedMhz, int? MaxClockSpeedMhz,
    int? LoadPercentage, string AddressWidth)
{
    public static CpuInfo FromRow(IReadOnlyDictionary<string, string> r) => new(
        r.Str("device_id"), r.Str("model"), r.Str("manufacturer"), r.Str("processor_type"), r.Str("socket_designation"),
        r.Int("number_of_cores"), r.Int("logical_processors"), r.Int("current_clock_speed"), r.Int("max_clock_speed"),
        r.Int("load_percentage"), r.Str("address_width"));
}

/// <summary>osquery <c>memory_devices</c> (SMBIOS; <c>size</c> is in MB).</summary>
public sealed record MemoryDevice(
    string DeviceLocator, string BankLocator, string FormFactor, string MemoryType,
    long? SizeMb, int? MaxSpeedMts, int? ConfiguredClockSpeedMts,
    string Manufacturer, string PartNumber, string SerialNumber)
{
    public bool IsPopulated => SizeMb is > 0;

    public static MemoryDevice FromRow(IReadOnlyDictionary<string, string> r) => new(
        r.Str("device_locator"), r.Str("bank_locator"), r.Str("form_factor"), r.Str("memory_type"),
        r.Long("size"), r.Int("max_speed"), r.Int("configured_clock_speed"),
        r.Str("manufacturer"), r.Str("part_number"), r.Str("serial_number"));
}

/// <summary>osquery <c>disk_info</c> (Windows physical disks; <c>disk_size</c> in bytes).</summary>
public sealed record DiskInfo(
    int? DiskIndex, string Id, string Name, string Type, string Manufacturer, string HardwareModel,
    string Serial, string Description, long? SizeBytes, int? Partitions)
{
    public static DiskInfo FromRow(IReadOnlyDictionary<string, string> r) => new(
        r.Int("disk_index"), r.Str("id"), r.Str("name"), r.Str("type"), r.Str("manufacturer"), r.Str("hardware_model"),
        r.Str("serial"), r.Str("description"), r.Long("disk_size"), r.Int("partitions"));
}

/// <summary>One inventory section: parsed items, or the error that prevented them.</summary>
public sealed record InventorySection<T>(string Sql, IReadOnlyList<T> Items, string? Error)
{
    public bool Success => Error is null;

    public static InventorySection<T> From(OsqueryQueryResult q, Func<IReadOnlyDictionary<string, string>, T> map) =>
        q.Success ? new(q.Sql, q.Rows!.Select(map).ToList(), null) : new(q.Sql, [], q.Error);
}

/// <summary>Aggregate of the hardware inventory queries.</summary>
public sealed record HardwareInventory(
    InventorySection<SystemInfo> System,
    InventorySection<CpuInfo> Cpus,
    InventorySection<MemoryDevice> Memory,
    InventorySection<DiskInfo> Disks)
{
    public const string SystemSql = "SELECT * FROM system_info;";
    public const string CpuSql = "SELECT * FROM cpu_info;";
    public const string MemorySql = "SELECT * FROM memory_devices;";
    public const string DiskSql = "SELECT * FROM disk_info;";

    public int FailedSections => new[] { System.Success, Cpus.Success, Memory.Success, Disks.Success }.Count(ok => !ok);

    public static async Task<HardwareInventory> CollectAsync(OsqueryRunner runner, IProgress<string>? progress = null, CancellationToken ct = default)
    {
        async Task<OsqueryQueryResult> Q(string sql) { progress?.Report(sql); return await runner.RunQueryAsync(sql, ct).ConfigureAwait(false); }
        var sys = InventorySection<SystemInfo>.From(await Q(SystemSql).ConfigureAwait(false), SystemInfo.FromRow);
        var cpu = InventorySection<CpuInfo>.From(await Q(CpuSql).ConfigureAwait(false), CpuInfo.FromRow);
        var mem = InventorySection<MemoryDevice>.From(await Q(MemorySql).ConfigureAwait(false), MemoryDevice.FromRow);
        var disk = InventorySection<DiskInfo>.From(await Q(DiskSql).ConfigureAwait(false), DiskInfo.FromRow);
        return new(sys, cpu, mem, disk);
    }

    public static string FormatBytes(long? bytes)
    {
        if (bytes is not > 0) return "—";
        string[] u = ["B", "KB", "MB", "GB", "TB", "PB"];
        double v = bytes.Value; var i = 0;
        while (v >= 1024 && i < u.Length - 1) { v /= 1024; i++; }
        return $"{v:0.#} {u[i]}";
    }
}
