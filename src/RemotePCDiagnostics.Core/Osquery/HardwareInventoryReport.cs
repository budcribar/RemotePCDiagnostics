using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Core.Osquery;

/// <summary>
/// The hardware inventory as an <see cref="AreaReport"/>, so it has the same machine-readable copy as every other check
/// (area-report-data): one card each for the computer, processor, memory, storage, graphics, network adapters and BIOS,
/// with the rows the page's drawers show. Serial numbers, device identifiers and network addresses are left out: an agent
/// reading the inventory has no use for them, and they identify the customer's hardware.
/// </summary>
public static class HardwareInventoryReport
{
    public static AreaReport Build(HardwareInventory inv, DiagnosticStatus status, string? message)
    {
        var sys = inv.System.Items.FirstOrDefault();
        var cards = new List<AreaCard> { System(inv, sys), Cpu(inv, sys), Memory(inv), Disks(inv), Gpus(inv), Network(inv), Bios(inv) };
        return new(cards, string.IsNullOrWhiteSpace(message) ? "Hardware inventory" : message, status);
    }

    private static string Join(params string?[] parts) => string.Join(" ", parts.Where(p => !string.IsNullOrWhiteSpace(p)));

    private static List<AreaRow> Details(params (string Label, string? Value)[] pairs) =>
        pairs.Where(p => !string.IsNullOrWhiteSpace(p.Value)).Select(p => new AreaRow(AreaLevel.Neutral, [p.Label, p.Value!])).ToList();

    private static AreaCard System(HardwareInventory inv, SystemInfo? sys)
    {
        if (!inv.System.Success) return AreaCard.Failed("system", "Computer", "Couldn't read computer details on this PC.");
        if (sys is null) return new("system", "Computer", AreaLevel.Neutral, "", "", [], [], EmptyText: "Computer details aren't available on this PC.");
        return new("system", "Computer", AreaLevel.Ok, Join(sys.HardwareVendor, sys.HardwareModel), sys.HardwareVersion, ["Detail", "Value"],
            Details(("Manufacturer", sys.HardwareVendor), ("Model", sys.HardwareModel), ("Version", sys.HardwareVersion),
                ("Motherboard", Join(sys.BoardVendor, sys.BoardModel, sys.BoardVersion)),
                ("Installed memory", sys.PhysicalMemoryBytes is > 0 ? HardwareInventory.FormatBytes(sys.PhysicalMemoryBytes) : null)));
    }

    private static AreaCard Cpu(HardwareInventory inv, SystemInfo? sys)
    {
        var cpus = inv.Cpus.Items.Count == 0 && sys is { CpuBrand.Length: > 0 } ? [HardwareInventory.CpuFromSystemPublic(sys)] : inv.Cpus.Items;
        if (cpus.Count == 0)
            return inv.Cpus.Success
                ? new("cpu", "Processor", AreaLevel.Neutral, "", "", [], [], EmptyText: "Processor details aren't available on this PC.")
                : AreaCard.Failed("cpu", "Processor", "Couldn't read processor details on this PC.");
        var first = cpus[0];
        var meta = string.Join(" · ", new[]
        {
            first.NumberOfCores is > 0 ? $"{first.NumberOfCores} cores" : null,
            first.LogicalProcessors is > 0 ? $"{first.LogicalProcessors} threads" : null,
            first.MaxClockSpeedMhz is > 0 ? $"up to {first.MaxClockSpeedMhz / 1000.0:0.0#} GHz" : null,
        }.Where(x => x is not null));
        string[] columns = ["Processor", "Manufacturer", "Socket", "Cores", "Threads", "Maximum speed"];
        var rows = cpus.Select(c => new AreaRow(AreaLevel.Neutral,
            [c.Model, c.Manufacturer, c.SocketDesignation, c.NumberOfCores?.ToString() ?? "", c.LogicalProcessors?.ToString() ?? "",
                c.MaxClockSpeedMhz is > 0 ? $"{c.MaxClockSpeedMhz} MHz" : ""])).ToList();
        return new("cpu", "Processor", AreaLevel.Ok, first.Model.Length > 0 ? first.Model : Join(first.Manufacturer, "processor"), meta, columns, rows);
    }

    private static AreaCard Memory(HardwareInventory inv)
    {
        var total = inv.TotalMemoryBytes is > 0 ? HardwareInventory.FormatBytes(inv.TotalMemoryBytes) : "";
        if (!inv.Memory.Success && total.Length == 0) return AreaCard.Failed("memory", "Memory", "Couldn't read memory details on this PC.");
        if (total.Length == 0) return new("memory", "Memory", AreaLevel.Neutral, "", "", [], [], EmptyText: "Memory details aren't available on this PC.");
        var slots = inv.Memory.Items;
        var used = slots.Where(d => d.IsPopulated).ToList();
        var meta = used.Count > 0 ? $"{used.Count} of {slots.Count} slots in use" + (used[0].MemoryType is { Length: > 0 } t ? $" · {t}" : "") : "Installed memory";
        string[] columns = ["Slot", "Bank", "Size", "Type", "Form factor", "Speed", "Manufacturer", "Part number"];
        var rows = slots.Select(d => new AreaRow(AreaLevel.Neutral,
            [d.DeviceLocator, d.BankLocator, d.SizeMb is > 0 ? HardwareInventory.FormatBytes(d.SizeMb * 1024 * 1024) : "Empty", d.MemoryType, d.FormFactor,
                d.ConfiguredClockSpeedMts is > 0 ? $"{d.ConfiguredClockSpeedMts} MT/s" : "", d.Manufacturer, d.PartNumber])).ToList();

        var totalBytes = inv.TotalMemoryBytes ?? 0;
        const long Gib = 1024L * 1024 * 1024;
        // Installed DIMM sums are exact multiples of 1 GiB; WMI TotalPhysicalMemory fallback can be ~0.2 GiB lower due to hardware reserve.
        var belowEightGb = totalBytes > 0 && totalBytes < (long)(7.5 * Gib);
        var exactlyEightGb = !belowEightGb && totalBytes >= (long)(7.5 * Gib) && totalBytes <= (long)(8.5 * Gib);

        var level = belowEightGb ? AreaLevel.Warning : AreaLevel.Ok;
        var notes = new List<string>();
        if (belowEightGb)
            notes.Add("Less than 8 GB of memory is installed. Upgrading to at least 8 GB (16 GB recommended) will noticeably improve Windows and browsing responsiveness.");
        else if (exactlyEightGb)
            notes.Add("8 GB is the practical minimum for comfortable everyday Windows use; 16 GB+ is recommended for heavier multitasking or local AI.");

        if (IsSinglePopulatedUpgradeableSlot(slots, used))
            notes.Add("Adding a matching module would enable dual-channel memory.");

        return new("memory", "Memory", level, total, meta, columns, rows, Note: notes.Count > 0 ? string.Join(" ", notes) : null);
    }

    internal static bool IsSinglePopulatedUpgradeableSlot(IReadOnlyList<MemoryDevice> slots, IReadOnlyList<MemoryDevice> used)
    {
        if (used.Count != 1 || slots.Count < 2) return false;
        var m = used[0];
        var formFactor = m.FormFactor.Trim();
        var isDimm = string.Equals(formFactor, "DIMM", StringComparison.OrdinalIgnoreCase)
            || string.Equals(formFactor, "SODIMM", StringComparison.OrdinalIgnoreCase);
        if (!isDimm) return false;
        if (m.MemoryType.Contains("LPDDR", StringComparison.OrdinalIgnoreCase)) return false;
        return true;
    }

    private static AreaCard Disks(HardwareInventory inv)
    {
        if (!inv.Disks.Success) return AreaCard.Failed("disks", "Storage", "Couldn't read storage details on this PC.");
        var disks = inv.Disks.Items;
        if (disks.Count == 0) return new("disks", "Storage", AreaLevel.Neutral, "", "", [], [], EmptyText: "Storage details aren't available on this PC.");
        string[] columns = ["Model", "Manufacturer", "Size", "Connection", "Partitions"];
        var rows = disks.Select(d => new AreaRow(AreaLevel.Neutral,
            [d.HardwareModel, d.Manufacturer, d.SizeBytes is > 0 ? HardwareInventory.FormatBytes(d.SizeBytes) : "", d.Type, d.Partitions?.ToString() ?? ""])).ToList();
        return new("disks", "Storage", AreaLevel.Ok, disks.Count == 1 ? "1 drive" : $"{disks.Count} drives",
            string.Join(", ", disks.Select(d => d.HardwareModel).Where(m => m.Length > 0).Take(3)), columns, rows);
    }

    private static AreaCard Gpus(HardwareInventory inv)
    {
        if (!inv.Gpus.Success) return AreaCard.Failed("gpu", "Graphics", "Couldn't read graphics details on this PC.");
        var gpus = inv.Gpus.Items.Where(g => g.Model.Length > 0).ToList();
        if (gpus.Count == 0) return new("gpu", "Graphics", AreaLevel.Neutral, "", "", [], [], EmptyText: "Graphics details aren't available on this PC.");
        string[] columns = ["Model", "Manufacturer", "Driver version", "Driver date", "Display mode"];
        var rows = gpus.Select(g => new AreaRow(AreaLevel.Neutral, [g.Model, g.Manufacturer, g.DriverVersion, g.DriverDate, g.VideoMode])).ToList();
        return new("gpu", "Graphics", AreaLevel.Ok, gpus[0].Model,
            gpus.Count == 1 ? Join(gpus[0].DriverVersion is { Length: > 0 } v ? $"Driver {v}" : null) : $"{gpus.Count} adapters", columns, rows);
    }

    private static AreaCard Network(HardwareInventory inv)
    {
        if (!inv.NetworkAdapters.Success) return AreaCard.Failed("network", "Network adapters", "Couldn't read network adapter details on this PC.");
        var adapters = inv.PhysicalNetworkAdapters.Where(a => a.Description.Length > 0).ToList();
        if (adapters.Count == 0)
            return new("network", "Network adapters", AreaLevel.Neutral, "", "", [], [], EmptyText: "Network adapter details aren't available on this PC.");
        string[] columns = ["Name", "Model", "Manufacturer", "Status", "Speed"];
        var rows = adapters.Select(a => new AreaRow(AreaLevel.Neutral, [a.Name, a.Description, a.Manufacturer, a.Status, FormatSpeed(a.SpeedBps)])).ToList();
        return new("network", "Network adapters", AreaLevel.Ok, adapters.Count == 1 ? "1 adapter" : $"{adapters.Count} adapters",
            string.Join(", ", adapters.Select(a => a.Description).Take(3)), columns, rows);
    }

    private static AreaCard Bios(HardwareInventory inv)
    {
        if (!inv.Bios.Success) return AreaCard.Failed("bios", "BIOS", "Couldn't read BIOS details on this PC.");
        var b = inv.Bios.Items.FirstOrDefault(x => x.Vendor.Length + x.Version.Length > 0);
        if (b is null) return new("bios", "BIOS", AreaLevel.Neutral, "", "", [], [], EmptyText: "BIOS details aren't available on this PC.");
        return new("bios", "BIOS", AreaLevel.Ok, Join(b.Vendor, b.Version), b.Date, ["Detail", "Value"],
            Details(("Vendor", b.Vendor), ("Version", b.Version), ("Release date", b.Date), ("Revision", b.Revision)));
    }

    /// <summary>Link speed in bits per second, as Mbps or Gbps.</summary>
    public static string FormatSpeed(long? bps) => bps switch
    {
        null or <= 0 => "",
        >= 1_000_000_000 => $"{bps / 1_000_000_000.0:0.#} Gbps",
        _ => $"{bps / 1_000_000.0:0.#} Mbps",
    };
}
