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
        r.Str("hardware_vendor"), r.Str("hardware_model"), Reported(r.Str("hardware_version")), r.Str("hardware_serial"),
        r.Str("board_vendor"), r.Str("board_model"), Reported(r.Str("board_version")), r.Str("board_serial"),
        r.Str("cpu_brand"), r.Str("cpu_type"), r.Int("cpu_physical_cores"), r.Int("cpu_logical_cores"), r.Int("cpu_sockets"),
        r.Long("physical_memory"));

    /// <summary>
    /// Empty when the firmware left the field unset: osquery reports a missing SMBIOS version as -1, and many boards ship
    /// OEM filler text instead of a value. Anything else is kept as it came.
    /// </summary>
    internal static string Reported(string raw) => Unset.Contains(raw.Trim()) ? "" : raw;

    private static readonly HashSet<string> Unset = new(StringComparer.OrdinalIgnoreCase)
    {
        "-1", "None", "Default string", "To Be Filled By O.E.M.", "System Version", "Not Applicable", "Not Specified",
    };
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

/// <summary>osquery <c>video_info</c> (Windows; one row per display adapter). <c>driver_date</c> is Unix seconds.</summary>
/// <remarks>Only the model, vendor and driver: the PnP device ID is not kept.</remarks>
public sealed record GpuInfo(string Model, string Manufacturer, string Series, string DriverVersion, string DriverDate, string VideoMode)
{
    public static GpuInfo FromRow(IReadOnlyDictionary<string, string> r) => new(
        r.Str("model"), r.Str("manufacturer"), r.Str("series"), r.Str("driver_version"), FormatDriverDate(r.Str("driver_date")), FormatVideoMode(r.Str("video_mode")));

    /// <summary>
    /// Windows describes the mode as "3840 x 2160 x 4294967296 colors", counting colors as 2^bits. Shown as
    /// "3840 x 2160, 32-bit color". Text in any other shape is kept as it came.
    /// </summary>
    internal static string FormatVideoMode(string raw)
    {
        const string suffix = " colors";
        if (!raw.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
            return raw;
        var body = raw[..^suffix.Length];
        var cut = body.LastIndexOf(" x ", StringComparison.Ordinal);
        if (cut <= 0 || !ulong.TryParse(body[(cut + 3)..], out var colors) || colors < 2 || !ulong.IsPow2(colors))
            return raw;
        return $"{body[..cut]}, {System.Numerics.BitOperations.Log2(colors)}-bit color";
    }

    /// <summary>Unix seconds to yyyy-MM-dd; any other text is kept as it came.</summary>
    internal static string FormatDriverDate(string raw) =>
        long.TryParse(raw, out var secs) && secs > 0
            ? DateTimeOffset.FromUnixTimeSeconds(secs).UtcDateTime.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture)
            : raw;
}

/// <summary>osquery <c>interface_details</c>, reduced to what describes the adapter.</summary>
/// <remarks>The MAC address, interface GUID, PnP device ID and IP/DNS/DHCP settings are never read into this record,
/// so neither the page nor the automation export can show them.</remarks>
public sealed record NetworkAdapterInfo(string Name, string Description, string Manufacturer, string Type, bool? Physical, bool? Enabled, string Status, long? SpeedBps)
{
    public static NetworkAdapterInfo FromRow(IReadOnlyDictionary<string, string> r) => new(
        r.Str("connection_id").Length > 0 ? r.Str("connection_id") : r.Str("friendly_name"),
        r.Str("description"), r.Str("manufacturer"), r.Str("type"),
        Bool(r.Str("physical_adapter")), Bool(r.Str("enabled")), ConnectionStatus(r.Str("connection_status")), r.Long("speed"));

    private static bool? Bool(string s) => s switch { "1" or "true" or "True" => true, "0" or "false" or "False" => false, _ => null };

    /// <summary>Win32_NetworkAdapter.NetConnectionStatus code to words (osquery passes the number through).</summary>
    internal static string ConnectionStatus(string code) => code switch
    {
        "0" => "Disconnected", "1" => "Connecting", "2" => "Connected", "3" => "Disconnecting", "4" => "Hardware not present",
        "5" => "Hardware disabled", "6" => "Hardware malfunction", "7" => "Media disconnected", "8" => "Authenticating",
        "9" => "Authentication succeeded", "10" => "Authentication failed", "11" => "Invalid address", "12" => "Credentials required",
        _ => code,
    };
}

/// <summary>osquery <c>platform_info</c>: the BIOS/UEFI firmware vendor, version and release date.</summary>
public sealed record BiosInfo(string Vendor, string Version, string Date, string Revision)
{
    public static BiosInfo FromRow(IReadOnlyDictionary<string, string> r) =>
        new(r.Str("vendor"), r.Str("version"), r.Str("date"), r.Str("revision"));
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

    /// <summary>Like <see cref="From"/>, but a table this platform's osquery doesn't have is an empty section, not a failure:
    /// the part is simply not reported on this PC.</summary>
    public static InventorySection<T> FromOptional(OsqueryQueryResult q, Func<IReadOnlyDictionary<string, string>, T> map) =>
        !q.Success && IsMissingTable(q) ? new(q.Sql, [], null, q) : From(q, map);

    /// <summary>A section that was not collected (an inventory recorded before the section existed).</summary>
    public static InventorySection<T> NotCollected(string sql) => new(sql, [], null);

    private static bool IsMissingTable(OsqueryQueryResult q) =>
        $"{q.Error} {q.RawStdErr}".Contains("no such table", StringComparison.OrdinalIgnoreCase);
}

/// <summary>Aggregate of the hardware inventory queries.</summary>
public sealed record HardwareInventory(
    InventorySection<SystemInfo> System,
    InventorySection<CpuInfo> Cpus,
    InventorySection<MemoryDevice> Memory,
    InventorySection<DiskInfo> Disks)
{
    /// <summary>Display adapters (<c>video_info</c>). Empty when the platform doesn't report them.</summary>
    public InventorySection<GpuInfo> Gpus { get; init; } = InventorySection<GpuInfo>.NotCollected(GpuSql);
    /// <summary>Network adapters (<c>interface_details</c>), without addresses or device identifiers.</summary>
    public InventorySection<NetworkAdapterInfo> NetworkAdapters { get; init; } = InventorySection<NetworkAdapterInfo>.NotCollected(NetworkSql);
    /// <summary>BIOS/UEFI firmware (<c>platform_info</c>).</summary>
    public InventorySection<BiosInfo> Bios { get; init; } = InventorySection<BiosInfo>.NotCollected(BiosSql);

    public const string SystemSql = "SELECT * FROM system_info;";
    public const string CpuSql = "SELECT * FROM cpu_info;";
    public const string MemorySql = "SELECT * FROM memory_devices;";
    public const string DiskSql = "SELECT * FROM disk_info;";
    public const string GpuSql = "SELECT * FROM video_info;";
    public const string NetworkSql = "SELECT * FROM interface_details;";
    public const string BiosSql = "SELECT * FROM platform_info;";
    public const int SectionCount = 7;
    /// <summary>Fallback for a blank disk_info.disk_size: total of fixed logical volumes (logical_drives.size, bytes).</summary>
    public const string LogicalDrivesSql = "SELECT device_id, type, size FROM logical_drives;";

    /// <summary>True when the machine was found to have no osqueryi (every section failed with not-found).</summary>
    public bool ToolMissing { get; init; }

    public int FailedSections => new[] { System.Success, Cpus.Success, Memory.Success, Disks.Success, Gpus.Success, NetworkAdapters.Success, Bios.Success }.Count(ok => !ok);

    /// <summary>Failures among the original four sections (computer, processor, memory, storage).</summary>
    public int CoreFailedSections => new[] { System.Success, Cpus.Success, Memory.Success, Disks.Success }.Count(ok => !ok);

    /// <summary>True when no section could be read at all.</summary>
    public bool AllSectionsFailed => FailedSections == SectionCount;

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

    /// <summary>The adapters that are real hardware: those osquery flags as physical, or every adapter when none carries the flag.</summary>
    public IReadOnlyList<NetworkAdapterInfo> PhysicalNetworkAdapters =>
        NetworkAdapters.Items.Any(a => a.Physical is not null) ? NetworkAdapters.Items.Where(a => a.Physical == true).ToList() : NetworkAdapters.Items;

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
