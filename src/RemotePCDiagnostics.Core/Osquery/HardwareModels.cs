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
/// <remarks>Diagnostics (row count, exit code, stderr, elapsed, stdout head) live in <see cref="Query"/> and the log, never in the UI.
/// <see cref="FromFallback"/> is true when <see cref="Items"/> were derived from another table because this one returned nothing usable.</remarks>
public sealed record InventorySection<T>(string Sql, IReadOnlyList<T> Items, string? Error, OsqueryQueryResult? Query = null, bool FromFallback = false)
{
    public bool Success => Error is null;
    public int RowCount => Query?.RowCount ?? Items.Count;
    public int? ExitCode => Query?.ExitCode;
    public string RawStdErr => Query?.RawStdErr ?? "";
    public string RawStdOutHead => Query?.RawStdOutHead ?? "";
    public long ElapsedMs => Query?.ElapsedMs ?? 0;

    public static InventorySection<T> From(OsqueryQueryResult q, Func<IReadOnlyDictionary<string, string>, T> map) =>
        q.Success ? new(q.Sql, q.Rows!.Select(map).ToList(), null, q) : new(q.Sql, [], q.Error, q);
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
    /// <summary>Fallback for a blank disk_info.disk_size: total of fixed logical volumes (logical_drives.size, bytes).</summary>
    public const string LogicalDrivesSql = "SELECT device_id, type, size FROM logical_drives;";

    /// <summary>True when the machine was found to have no osqueryi (every section failed with not-found).</summary>
    public bool ToolMissing { get; init; }

    public int FailedSections => new[] { System.Success, Cpus.Success, Memory.Success, Disks.Success }.Count(ok => !ok);

    public static async Task<HardwareInventory> CollectAsync(OsqueryRunner runner, IProgress<string>? progress = null, CancellationToken ct = default)
    {
        async Task<OsqueryQueryResult> Q(int step, string msg, string sql) { progress.ReportStep(step, 4, msg); return await runner.RunQueryAsync(sql, ct).ConfigureAwait(false); }
        var sys = InventorySection<SystemInfo>.From(await Q(1, "Reading computer details…", SystemSql).ConfigureAwait(false), SystemInfo.FromRow);
        var cpu = InventorySection<CpuInfo>.From(await Q(2, "Reading processor details…", CpuSql).ConfigureAwait(false), CpuInfo.FromRow);
        var mem = InventorySection<MemoryDevice>.From(await Q(3, "Reading memory modules…", MemorySql).ConfigureAwait(false), MemoryDevice.FromRow);
        var disk = InventorySection<DiskInfo>.From(await Q(4, "Reading storage drives…", DiskSql).ConfigureAwait(false), DiskInfo.FromRow);

        // Fallbacks (shown to the user as normal values).
        var s0 = sys.Items.FirstOrDefault();
        if (cpu.Success && cpu.Items.Count == 0 && s0 is { CpuBrand.Length: > 0 })
            cpu = cpu with { Items = [CpuFromSystem(s0)], FromFallback = true };
        if (mem.Success && !mem.Items.Any(m => m.IsPopulated) && s0?.PhysicalMemoryBytes is > 0)
            mem = mem with { FromFallback = true }; // UI/summary use system_info.physical_memory for the total
        if (disk.Success && disk.Items.Count == 1 && disk.Items[0].SizeBytes is not > 0)
        {
            var ld = await runner.RunQueryAsync(LogicalDrivesSql, ct).ConfigureAwait(false);
            var total = ld.Success ? SumFixedDrives(ld.Rows!) : 0;
            if (total > 0) disk = disk with { Items = [disk.Items[0] with { SizeBytes = total }], FromFallback = true };
        }
        return new(sys, cpu, mem, disk) { ToolMissing = !runner.Exists };
    }

    public static CpuInfo CpuFromSystemPublic(SystemInfo s) => CpuFromSystem(s);
    internal static CpuInfo CpuFromSystem(SystemInfo s) =>
        new("", s.CpuBrand, "", s.CpuType, "", s.CpuPhysicalCores, s.CpuLogicalCores, null, null, null, "");

    /// <summary>Sums logical_drives.size for local fixed volumes (Windows type "Local Disk"/"Fixed"); if no type matches, sums all with a size.</summary>
    public static long SumFixedDrives(IEnumerable<IReadOnlyDictionary<string, string>> rows)
    {
        var list = rows.Select(r => (Type: r.Str("type"), Size: r.Long("size") ?? 0)).Where(x => x.Size > 0).ToList();
        var fixedOnes = list.Where(x => x.Type.Contains("Local", StringComparison.OrdinalIgnoreCase) || x.Type.Contains("Fixed", StringComparison.OrdinalIgnoreCase)).ToList();
        return (fixedOnes.Count > 0 ? fixedOnes : list).Sum(x => x.Size);
    }

    /// <summary>Total installed memory: populated memory_devices, otherwise system_info.physical_memory.</summary>
    public long? TotalMemoryBytes
    {
        get
        {
            var mb = Memory.Items.Where(d => d.IsPopulated).Sum(d => d.SizeMb ?? 0);
            return mb > 0 ? mb * 1024 * 1024 : System.Items.FirstOrDefault()?.PhysicalMemoryBytes;
        }
    }

    public long TotalDiskBytes => Disks.Items.Sum(d => d.SizeBytes ?? 0);

    /// <summary>End-user one-liner for the Dashboard: computer, processor, memory, storage.</summary>
    public string FriendlySummary()
    {
        var parts = new List<string>();
        var sys = System.Items.FirstOrDefault();
        if (sys is not null)
        {
            var model = $"{sys.HardwareVendor} {sys.HardwareModel}".Trim();
            var name = sys.ComputerName.Length > 0 ? sys.ComputerName : sys.Hostname;
            if (name.Length > 0 && model.Length > 0) parts.Add($"{name} ({model})");
            else if (name.Length + model.Length > 0) parts.Add(name.Length > 0 ? name : model);
        }
        var cpu = Cpus.Items.FirstOrDefault()?.Model is { Length: > 0 } m ? m : sys?.CpuBrand ?? "";
        if (cpu.Length > 0) parts.Add(cpu);
        if (TotalMemoryBytes is > 0) parts.Add(FormatBytes(TotalMemoryBytes) + " memory");
        if (Disks.Success && Disks.Items.Count > 0)
            parts.Add(Disks.Items.Count == 1 ? "1 drive" + (TotalDiskBytes > 0 ? $" ({FormatBytes(TotalDiskBytes)})" : "") : $"{Disks.Items.Count} drives");
        return parts.Count > 0 ? string.Join(" · ", parts) : "Hardware details are not available on this PC.";
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
