using System.Text.Json;
using RemotePCDiagnostics.Core.DataSources;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>
/// Reads the PC's physical drives and their health from Windows Storage WMI (<c>root\Microsoft\Windows\Storage</c>): MSFT_PhysicalDisk,
/// the reliability counters (which need administrator rights, so the app reads them through the Agent) and MSFT_Partition for drive letters.
/// The same data as <c>Get-PhysicalDisk</c> / <c>Get-StorageReliabilityCounter</c>, without PowerShell. Null means the drives couldn't be read.
/// </summary>
public static class DriveReader
{
    public const string StorageNamespace = @"root\Microsoft\Windows\Storage";
    public const string PartitionSql = "SELECT DiskNumber, DriveLetter FROM MSFT_Partition";
    public const string DiskSql = "SELECT ObjectId, DeviceId, UniqueId, FriendlyName, SerialNumber, MediaType, BusType, HealthStatus, OperationalStatus, Size FROM MSFT_PhysicalDisk";

    /// <summary>
    /// One drive's reliability counters. Windows only hands them out through the disk's link to them: a plain SELECT on
    /// MSFT_StorageReliabilityCounter returns nothing, even as administrator. <paramref name="objectId"/> is the disk's ObjectId,
    /// escaped for a WQL string (backslashes and quotes).
    /// </summary>
    public static string CounterSql(string objectId) =>
        $"ASSOCIATORS OF {{MSFT_PhysicalDisk.ObjectId=\"{objectId.Replace(@"\", @"\\").Replace("\"", "\\\"")}\"}} WHERE AssocClass = MSFT_PhysicalDiskToStorageReliabilityCounter";

    public static async Task<IReadOnlyList<DriveHealth>?> ReadWmiAsync(IWmiSource wmi, CancellationToken ct)
    {
        var disks = await wmi.QueryAsync(StorageNamespace, DiskSql, ct).ConfigureAwait(false);
        if (!disks.Success) return null;
        // Letters are best-effort: without them the drives are still listed.
        var parts = await wmi.QueryAsync(StorageNamespace, PartitionSql, ct).ConfigureAwait(false);
        var letters = new Dictionary<long, SortedSet<char>>();
        foreach (var p in parts.Rows ?? [])
            if (p.Long("DiskNumber") is { } n and >= 0 && Letter(p) is { } l)
                (letters.TryGetValue(n, out var set) ? set : letters[n] = []).Add(l);

        var list = new List<DriveHealth>();
        foreach (var d in disks.Rows!)
        {
            var id = d.Str("DeviceId").Trim();
            var objectId = d.Str("ObjectId");
            WmiRow? counter = null;
            if (objectId.Length > 0)
            {
                var c = await wmi.QueryAsync(StorageNamespace, CounterSql(objectId), ct).ConfigureAwait(false);
                counter = c.Rows is { Count: > 0 } rows ? rows[0] : null;
            }
            var diskLetters = long.TryParse(id, out var num) && letters.TryGetValue(num, out var ls) ? new string([.. ls]) : "";
            list.Add(new DriveHealth(
                Name: d.Str("FriendlyName").Trim(), Serial: d.Str("SerialNumber").Trim(),
                MediaType: MediaType(d.Long("MediaType")), BusType: BusType(d.Long("BusType")), Health: Health(d.Long("HealthStatus")),
                Operational: Operational(d), SizeBytes: d.Long("Size") is > 0 and var size ? size : null,
                TemperatureC: Range(counter?.Long("Temperature"), 1, 150), Wear: Range(counter?.Long("Wear"), 0, 100),
                ReadErrors: NonNegative(counter?.Long("ReadErrorsUncorrected")), WriteErrors: NonNegative(counter?.Long("WriteErrorsUncorrected")),
                PowerOnHours: NonNegative(counter?.Long("PowerOnHours")), Letters: diskLetters, UniqueId: d.Str("UniqueId").Trim()));
        }
        return list;
    }

    /// <summary>A drive letter, as WMI's char16 arrives (a one-letter string, or its code).</summary>
    private static char? Letter(WmiRow p)
    {
        var s = p.Str("DriveLetter");
        var ch = s.Length == 1 ? s[0] : p.Long("DriveLetter") is { } code and > 0 and < 128 ? (char)code : '\0';
        return char.IsAsciiLetter(ch) ? char.ToUpperInvariant(ch) : null;
    }

    private static int? Range(long? v, int min, int max) => DriveHealth.Range(v, min, max);
    private static long? NonNegative(long? v) => DriveHealth.NonNegative(v);

    // The names Get-PhysicalDisk prints for these codes, so both paths read the same.
    public static string MediaType(long? code) => code switch { 3 => "HDD", 4 => "SSD", 5 => "SCM", _ => "Unspecified" };

    public static string BusType(long? code) => code switch
    {
        1 => "SCSI", 2 => "ATAPI", 3 => "ATA", 4 => "1394", 5 => "SSA", 6 => "Fibre Channel", 7 => "USB", 8 => "RAID", 9 => "iSCSI",
        10 => "SAS", 11 => "SATA", 12 => "SD", 13 => "MMC", 15 => "File Backed Virtual", 16 => "Storage Spaces", 17 => "NVMe", _ => "Unknown",
    };

    public static string Health(long? code) => code switch { 0 => "Healthy", 1 => "Warning", 2 => "Unhealthy", _ => "Unknown" };

    private static string Operational(WmiRow d)
    {
        if (!d.Values.TryGetValue("OperationalStatus", out var v)) return "";
        IEnumerable<long?> codes = v.ValueKind switch
        {
            JsonValueKind.Array => v.EnumerateArray().Select(e => e.ValueKind == JsonValueKind.Number && e.TryGetInt64(out var l) ? l : (long?)null),
            JsonValueKind.Number when v.TryGetInt64(out var one) => [one],
            _ => [],
        };
        return string.Join(", ", codes.Where(c => c is not null).Select(c => OperationalName(c!.Value)));
    }

    public static string OperationalName(long code) => code switch
    {
        1 => "Other", 2 => "OK", 3 => "Degraded", 4 => "Stressed", 5 => "Predictive Failure", 6 => "Error", 7 => "Non-Recoverable Error",
        8 => "Starting", 9 => "Stopping", 10 => "Stopped", 11 => "In Service", 12 => "No Contact", 13 => "Lost Communication", 14 => "Aborted",
        15 => "Dormant", 16 => "Supporting Entity in Error", 17 => "Completed", 18 => "Power Mode", 0xD010 => "In Maintenance",
        _ => $"Code {code}",
    };
}
