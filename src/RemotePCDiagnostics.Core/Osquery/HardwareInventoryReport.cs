using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Core.Osquery;

/// <summary>
/// The hardware inventory as an <see cref="AreaReport"/>, so it has the same machine-readable copy as every other check
/// (area-report-data): one card each for the computer, processor, memory and storage, with the rows the page's drawers show.
/// Serial numbers are left out: an agent reading the inventory has no use for them, and they identify the customer's hardware.
/// </summary>
public static class HardwareInventoryReport
{
    public static AreaReport Build(HardwareInventory inv, DiagnosticStatus status, string? message)
    {
        var sys = inv.System.Items.FirstOrDefault();
        var cards = new List<AreaCard> { System(inv, sys), Cpu(inv, sys), Memory(inv), Disks(inv) };
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
        return new("cpu", "Processor", AreaLevel.Ok, first.Model, meta, columns, rows);
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
        return new("memory", "Memory", AreaLevel.Ok, total, meta, columns, rows);
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
}
