using System.Diagnostics.Eventing.Reader;
using System.Runtime.InteropServices;
using RemotePCDiagnostics.Core.Alerts;
using RemotePCDiagnostics.Core.DataSources;

namespace RemotePCDiagnostics.Agent;

/// <summary>
/// The PC side of the Agent's alerts (<see cref="IAlertReadings"/>): the watched events from the System and Application logs, free space on
/// each fixed drive, memory commit charge and power, each a few system calls. Also compiled into tools/RpcdRecorder, so it uses Core only.
/// </summary>
public sealed class WindowsAlertReadings : IAlertReadings
{
    public Task<WmiQueryResult> ReadAsync(string reading, long afterRecordId, TimeSpan lookBack, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) return Task.FromResult(AlertReadings.Failed(reading, "Only on Windows."));
        try
        {
            var result = reading switch
            {
                AlertReadings.Disks => AlertReadings.Result(reading, Disks().Select(AlertReadings.Row)),
                AlertReadings.Memory => CommitPercent() is { } c ? AlertReadings.Result(reading, [AlertReadings.MemoryRow(c)])
                    : AlertReadings.Failed(reading, "GlobalMemoryStatusEx failed."),
                AlertReadings.Power => Power() is { } p ? AlertReadings.Result(reading, [AlertReadings.Row(p)])
                    : AlertReadings.Failed(reading, "GetSystemPowerStatus failed."),
                _ when Channel(reading) is { } channel => AlertReadings.Result(reading, Events(channel, afterRecordId, lookBack, ct).Select(AlertReadings.Row)),
                _ => AlertReadings.Failed(reading, "Unknown reading."),
            };
            return Task.FromResult(result);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Task.FromResult(AlertReadings.Failed(reading, $"{ex.GetType().Name}: {ex.Message}"));
        }
    }

    private static string? Channel(string reading) => AlertRules.EventIds.Keys.FirstOrDefault(c => reading == AlertReadings.Events(c));

    private static List<AlertEvent> Events(string channel, long afterRecordId, TimeSpan lookBack, CancellationToken ct)
    {
        var list = new List<AlertEvent>();
        var query = new EventLogQuery(channel, PathType.LogName, AlertRules.Query(channel, afterRecordId, lookBack));
        using var reader = new EventLogReader(query);
        for (var record = reader.ReadEvent(); record is not null && list.Count < AlertReadings.MaxEvents; record = reader.ReadEvent())
            using (record)
            {
                ct.ThrowIfCancellationRequested();
                list.Add(ToEvent(channel, record));
            }
        return list;
    }

    /// <summary>What the rules read from an event: its provider, ID, record, time, properties and message.</summary>
    public static AlertEvent ToEvent(string channel, EventRecord record)
    {
        string? message = null;
        try { message = record.FormatDescription(); } catch { }
        var properties = record.Properties.Select(p => p.Value?.ToString() ?? "").ToList();
        return new AlertEvent(channel, record.ProviderName ?? "", record.Id, record.RecordId ?? 0,
            (record.TimeCreated ?? DateTime.UtcNow).ToUniversalTime(), properties, message);
    }

    private static List<DiskReading> Disks()
    {
        var list = new List<DiskReading>();
        foreach (var drive in DriveInfo.GetDrives())
        {
            try
            {
                if (drive.DriveType != DriveType.Fixed || !drive.IsReady) continue;
                list.Add(new DiskReading(drive.Name.TrimEnd('\\'), drive.AvailableFreeSpace / 1e9, drive.TotalSize / 1e9));
            }
            catch { /* a drive that went away between listing and reading */ }
        }
        return list;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORYSTATUSEX
    {
        public uint dwLength, dwMemoryLoad;
        public ulong ullTotalPhys, ullAvailPhys, ullTotalPageFile, ullAvailPageFile, ullTotalVirtual, ullAvailVirtual, ullAvailExtendedVirtual;
    }

    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX m);

    /// <summary>Commit charge as a share of the commit limit (memory plus page file): what event 2004 is about.</summary>
    private static double? CommitPercent()
    {
        var m = new MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>() };
        if (!GlobalMemoryStatusEx(ref m) || m.ullTotalPageFile == 0) return null;
        return (m.ullTotalPageFile - m.ullAvailPageFile) * 100.0 / m.ullTotalPageFile;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_POWER_STATUS { public byte ACLineStatus, BatteryFlag, BatteryLifePercent, SystemStatusFlag; public int BatteryLifeTime, BatteryFullLifeTime; }

    [DllImport("kernel32.dll")] private static extern bool GetSystemPowerStatus(out SYSTEM_POWER_STATUS s);

    private static PowerReading? Power()
    {
        if (!GetSystemPowerStatus(out var s)) return null;
        var hasBattery = s.BatteryFlag != 128 && s.BatteryFlag != 255;
        return new PowerReading(DateTimeOffset.UtcNow, s.ACLineStatus == 0, s.BatteryLifePercent <= 100 ? s.BatteryLifePercent : null, (s.BatteryFlag & 8) != 0, hasBattery);
    }
}
