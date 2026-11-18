using System.Management;
using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Core.Platform;

/// <summary>
/// Queries physical disk drive inventory and reliability counters via WMI root\Microsoft\Windows\Storage.
/// Requires elevated Administrator privileges (MSFT_StorageReliabilityCounter access check).
/// Runs inside RemotePCDiagnostics.Agent to keep RemotePCDiagnostics.Host strictly un-elevated (asInvoker).
/// </summary>
public static class WindowsStorageDriveReader
{
    public static List<DriveHealth> ReadDrives()
    {
        var drives = new List<DriveHealth>();
        if (!OperatingSystem.IsWindows())
            return drives;

        try
        {
            var scope = new ManagementScope(@"\\.\root\Microsoft\Windows\Storage");
            scope.Connect();

            // 1. Query MSFT_Partition to map DiskNumber to DriveLetters
            var diskPartitions = new Dictionary<uint, HashSet<char>>();
            try
            {
                using var partSearcher = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT DiskNumber, DriveLetter FROM MSFT_Partition"));
                using var partCollection = partSearcher.Get();
                foreach (var obj in partCollection)
                {
                    if (obj is not ManagementObject mo) continue;
                    using (mo)
                    {
                        var diskNum = mo["DiskNumber"] is uint u ? u : 0;
                        if (mo["DriveLetter"] is char letter && letter != '\0')
                        {
                            if (!diskPartitions.TryGetValue(diskNum, out var set))
                            {
                                set = new HashSet<char>();
                                diskPartitions[diskNum] = set;
                            }
                            set.Add(char.ToUpperInvariant(letter));
                        }
                    }
                }
            }
            catch
            {
                // Partitions mapping is best-effort
            }

            // 2. Query MSFT_PhysicalDisk
            using var diskSearcher = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT DeviceId, UniqueId, FriendlyName, SerialNumber, MediaType, BusType, HealthStatus, OperationalStatus, Size FROM MSFT_PhysicalDisk"));
            using var diskCollection = diskSearcher.Get();

            foreach (var diskObj in diskCollection)
            {
                if (diskObj is not ManagementObject mo) continue;
                using (mo)
                {
                    var deviceId = mo["DeviceId"]?.ToString() ?? "";
                    var uniqueId = mo["UniqueId"]?.ToString() ?? "";
                    var friendlyName = mo["FriendlyName"]?.ToString() ?? "";
                    var serial = mo["SerialNumber"]?.ToString() ?? "";
                    var mediaTypeRaw = mo["MediaType"] is ushort mt ? mt : 0;
                    var busTypeRaw = mo["BusType"] is ushort bt ? bt : 0;
                    var healthRaw = mo["HealthStatus"] is ushort hs ? hs : 0;
                    var opStatusRaw = mo["OperationalStatus"] as ushort[];
                    var sizeBytes = mo["Size"] is ulong s ? (long?)s : null;

                    var mediaTypeStr = mediaTypeRaw switch
                    {
                        3 => "HDD",
                        4 => "SSD",
                        5 => "SCM",
                        _ => "Unspecified"
                    };

                    var busTypeStr = busTypeRaw switch
                    {
                        7 => "USB",
                        8 => "RAID",
                        9 => "iSCSI",
                        10 => "SAS",
                        11 => "SATA",
                        12 => "SD",
                        13 => "MMC",
                        17 => "NVMe",
                        _ => "Unknown"
                    };

                    var healthStr = healthRaw switch
                    {
                        0 => "Healthy",
                        1 => "Warning",
                        2 => "Unhealthy",
                        _ => "Unknown"
                    };

                    var opStatusStr = opStatusRaw is { Length: > 0 }
                        ? string.Join(", ", opStatusRaw.Select(FormatOpStatus))
                        : "OK";

                    string letters = "";
                    if (uint.TryParse(deviceId, out var diskNumInt) && diskPartitions.TryGetValue(diskNumInt, out var lettersSet))
                    {
                        letters = new string(lettersSet.OrderBy(c => c).ToArray());
                    }

                    // 3. Query MSFT_StorageReliabilityCounter for this PhysicalDisk
                    int? tempC = null;
                    int? wearPercent = null;
                    long? readErrors = null;
                    long? writeErrors = null;
                    long? powerOnHours = null;

                    try
                    {
                        using var relSearcher = new ManagementObjectSearcher(
                            scope,
                            new ObjectQuery($"SELECT Temperature, Wear, ReadErrorsUncorrected, WriteErrorsUncorrected, PowerOnHours FROM MSFT_StorageReliabilityCounter WHERE DeviceId = '{deviceId}'"));
                        using var relCollection = relSearcher.Get();
                        foreach (var relObj in relCollection)
                        {
                            if (relObj is not ManagementObject rmo) continue;
                            using (rmo)
                            {
                                if (rmo["Temperature"] is uint t) tempC = (int)t;
                                else if (rmo["Temperature"] is int ti) tempC = ti;

                                if (rmo["Wear"] is byte w) wearPercent = (int)w;
                                else if (rmo["Wear"] is uint wu) wearPercent = (int)wu;

                                if (rmo["ReadErrorsUncorrected"] is ulong re) readErrors = (long)re;
                                if (rmo["WriteErrorsUncorrected"] is ulong we) writeErrors = (long)we;
                                if (rmo["PowerOnHours"] is ulong poh) powerOnHours = (long)poh;
                            }
                        }
                    }
                    catch
                    {
                        // Storage reliability counters are best-effort
                    }

                    drives.Add(new DriveHealth(
                        Name: friendlyName,
                        Serial: serial,
                        MediaType: mediaTypeStr,
                        BusType: busTypeStr,
                        Health: healthStr,
                        Operational: opStatusStr,
                        SizeBytes: sizeBytes,
                        TemperatureC: tempC,
                        Wear: wearPercent,
                        ReadErrors: readErrors,
                        WriteErrors: writeErrors,
                        PowerOnHours: powerOnHours,
                        Letters: letters,
                        UniqueId: uniqueId));
                }
            }
        }
        catch
        {
            // If MSFT_PhysicalDisk or WMI fails, return whatever was collected
        }

        return drives;
    }

    private static string FormatOpStatus(ushort code) => code switch
    {
        1 => "Other",
        2 => "OK",
        3 => "Degraded",
        4 => "Stressed",
        5 => "Predictive Failure",
        6 => "Error",
        7 => "Non-Recoverable Error",
        8 => "Starting",
        9 => "Stopping",
        10 => "Stopped",
        11 => "In Service",
        12 => "No Contact",
        13 => "Lost Communication",
        14 => "Aborted",
        15 => "Dormant",
        _ => $"Code {code}"
    };
}
