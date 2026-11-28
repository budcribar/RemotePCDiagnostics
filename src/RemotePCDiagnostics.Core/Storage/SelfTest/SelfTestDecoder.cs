using System.Buffers.Binary;
using System.Globalization;

namespace RemotePCDiagnostics.Core.Storage;

/// <summary>
/// Reads the drive's own self-test pages, as the ATA/ATAPI Command Set (ACS) and NVM Express Base specifications lay them out: the ATA
/// SMART data and self-test log, and the NVMe Device Self-test log. Pure, so recordings and tests decode exactly what a drive sent.
/// </summary>
public static class SelfTestDecoder
{
    public const int AtaPageBytes = 512;
    public const int NvmeLogBytes = 564;
    /// <summary>The log entries shown: ATA keeps 21, NVMe 20.</summary>
    public const int MaxLogEntries = 20;
    /// <summary>NVMe defines the short test as taking at most two minutes and reports no estimate for it.</summary>
    public const int NvmeShortMinutes = 2;

    // ATA SMART READ DATA (ACS-3, table "Device SMART data structure").
    private const int AtaExecStatus = 363, AtaOfflineCapability = 367, AtaShortPoll = 372, AtaExtendedPoll = 373, AtaExtendedPollWord = 375;
    private const int AtaSelfTestSupportedBit = 0x10, AtaOfflineImmediateBit = 0x01;
    // ATA SMART self-test log (log address 06h): 21 descriptors of 24 bytes from byte 2, the newest one's index (1-21) at byte 508.
    private const int AtaLogFirstDescriptor = 2, AtaLogDescriptorBytes = 24, AtaLogDescriptors = 21, AtaLogIndex = 508;
    // NVMe Device Self-test log: current operation, its completion, then 20 results of 28 bytes from byte 4, the newest first.
    private const int NvmeLogFirstResult = 4, NvmeResultBytes = 28;
    public const int NvmeOacsSelfTestBit = 0x10;

    /// <summary>The drive's answer decoded. Unsupported drives (wrong bus, no self-test, unreadable) say why.</summary>
    public static SelfTestDriveState Decode(SelfTestDriveAnswer a)
    {
        var protocol = a.Protocol?.Trim().ToLowerInvariant() switch { "ata" => SelfTestProtocol.Ata, "nvme" => SelfTestProtocol.Nvme, _ => SelfTestProtocol.None };
        var model = (a.Model ?? "").Trim();
        var bus = (a.Bus ?? "").Trim();
        SelfTestDriveState Unsupported(string why, string? readError = null) =>
            new(a.Disk, model, bus, protocol, why, null, null, null, null, [], ReadError: readError);

        if (BusReason(bus) is { } busWhy) return Unsupported(busWhy);
        if (protocol == SelfTestProtocol.None)
            return Unsupported(a.Error is { Length: > 0 } e ? "The drive couldn't be asked for a self-test: " + e : "The drive's controller doesn't pass ATA or NVMe commands through.", a.Error);
        return protocol == SelfTestProtocol.Ata ? DecodeAta(a, model, bus) : DecodeNvme(a, model, bus);
    }

    /// <summary>Why a drive on <paramref name="bus"/> can't run a self-test from Windows, or null when its bus can.</summary>
    public static string? BusReason(string bus) => bus.ToLowerInvariant() switch
    {
        "usb" => "The drive is connected over USB: the USB bridge doesn't pass the drive's self-test commands through. Connect it internally (SATA or M.2) to test it.",
        "raid" => "The drive is behind a RAID controller (or Intel RST in RAID mode), which doesn't pass self-test commands to the drive. Use the RAID vendor's tool.",
        "virtual" or "filebackedvirtual" => "This is a virtual disk (a VHD or a virtual machine's disk), which has no self-test.",
        "spaces" => "This is a Storage Spaces virtual disk. Test the physical drives in the pool instead.",
        "iscsi" or "fibre" or "fibrechannel" => "This is a network or SAN disk; test it from the storage system.",
        "sd" or "mmc" => "SD and eMMC storage has no ATA or NVMe self-test.",
        "1394" or "ssa" => "The drive's bus doesn't pass self-test commands through.",
        "ufs" => "UFS storage has no ATA or NVMe self-test that Windows passes through.",
        _ => null,
    };

    private static SelfTestDriveState DecodeAta(SelfTestDriveAnswer a, string model, string bus)
    {
        var data = Bytes(a.SmartData, AtaPageBytes);
        if (data is null)
            return new(a.Disk, model, bus, SelfTestProtocol.Ata,
                "The drive didn't return its SMART data" + (a.Error is { Length: > 0 } e ? $" ({e})" : "") + ", so its self-test can't be used.",
                null, null, null, null, [], ReadError: a.Error);
        if ((data[AtaOfflineCapability] & AtaSelfTestSupportedBit) == 0 || (data[AtaOfflineCapability] & AtaOfflineImmediateBit) == 0)
            return new(a.Disk, model, bus, SelfTestProtocol.Ata, "The drive says it doesn't support the SMART self-test.", null, null, null, null, []);

        var shortMinutes = data[AtaShortPoll] is var s and > 0 ? s : (int?)null;
        int? extendedMinutes = data[AtaExtendedPoll] == 0xFF
            ? BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(AtaExtendedPollWord, 2)) is var w and > 0 ? w : null
            : data[AtaExtendedPoll] is var x and > 0 ? x : null;
        var exec = data[AtaExecStatus];
        var execOutcome = AtaOutcome(exec >> 4);
        int? percent = execOutcome == SelfTestOutcome.InProgress ? Math.Clamp(100 - (exec & 0x0F) * 10, 0, 100) : null;
        var log = Bytes(a.SelfTestLog, AtaPageBytes) is { } l ? AtaLog(l) : [];
        // The exec status doesn't say which test runs; the newest log entry names it once it ends, and a running test is usually the one
        // this app (or the tool that started it) asked for, so it is reported as unknown kind.
        return new(a.Disk, model, bus, SelfTestProtocol.Ata, null, shortMinutes, extendedMinutes, null, percent, log, execOutcome,
            a.SelfTestLog is null ? a.Error : null);
    }

    private static SelfTestDriveState DecodeNvme(SelfTestDriveAnswer a, string model, string bus)
    {
        if (a.NvmeOacs is not { } oacs)
            return new(a.Disk, model, bus, SelfTestProtocol.Nvme,
                "The drive's identify data couldn't be read" + (a.Error is { Length: > 0 } e ? $" ({e})" : "") + ", so its self-test can't be used.",
                null, null, null, null, [], ReadError: a.Error);
        if ((oacs & NvmeOacsSelfTestBit) == 0)
            return new(a.Disk, model, bus, SelfTestProtocol.Nvme, "The drive says it doesn't support the NVMe Device Self-test.", null, null, null, null, []);

        var page = Bytes(a.SelfTestLog, NvmeLogBytes);
        if (page is null)
            return new(a.Disk, model, bus, SelfTestProtocol.Nvme,
                "Windows didn't return the drive's self-test log" + (a.Error is { Length: > 0 } e2 ? $" ({e2})" : "") + ". Windows 10 version 1903 or later is needed.",
                null, null, null, null, [], ReadError: a.Error);
        var current = (page[0] & 0x0F) switch { 1 => SelfTestKind.Short, 2 => SelfTestKind.Extended, 0 => (SelfTestKind?)null, _ => null };
        var running = (page[0] & 0x0F) != 0;
        int? percent = running ? Math.Clamp(page[1] & 0x7F, 0, 100) : null;
        int? extended = a.NvmeExtendedMinutes is > 0 ? a.NvmeExtendedMinutes : null;
        return new(a.Disk, model, bus, SelfTestProtocol.Nvme, null, NvmeShortMinutes, extended, current, percent, NvmeLog(page),
            running ? SelfTestOutcome.InProgress : null);
    }

    /// <summary>The ATA self-test log's entries, newest first (at most <see cref="MaxLogEntries"/>).</summary>
    public static IReadOnlyList<SelfTestLogEntry> AtaLog(byte[] log)
    {
        if (log.Length < AtaPageBytes) return [];
        var newest = log[AtaLogIndex];
        if (newest is < 1 or > AtaLogDescriptors) return [];
        var entries = new List<SelfTestLogEntry>();
        for (var n = 0; n < AtaLogDescriptors && entries.Count < MaxLogEntries; n++)
        {
            var index = (newest - 1 - n + AtaLogDescriptors) % AtaLogDescriptors;
            var d = log.AsSpan(AtaLogFirstDescriptor + index * AtaLogDescriptorBytes, AtaLogDescriptorBytes);
            if (d.IndexOfAnyExcept((byte)0) < 0) break; // never written: the log hasn't wrapped yet
            var test = d[0];
            var kind = (test & 0x7F) switch { 1 => SelfTestKind.Short, 2 => SelfTestKind.Extended, _ => (SelfTestKind?)null };
            var name = (test & 0x7F) switch
            {
                0 => "Off-line data collection",
                1 => "Short",
                2 => "Extended",
                3 => "Conveyance",
                4 => "Selective",
                _ => "Vendor specific",
            };
            var outcome = AtaOutcome(d[1] >> 4);
            var lba = BinaryPrimitives.ReadUInt32LittleEndian(d.Slice(5, 4)) & 0x0FFFFFFF;
            var failed = outcome is >= SelfTestOutcome.FatalError and <= SelfTestOutcome.FailedHandlingDamage;
            entries.Add(new(kind, name, outcome, (d[1] & 0x0F) * 10, BinaryPrimitives.ReadUInt16LittleEndian(d.Slice(2, 2)),
                failed && lba is not (0 or 0x0FFFFFFF) ? lba : null));
        }
        return entries;
    }

    /// <summary>The NVMe Device Self-test log's results, newest first (empty entries skipped).</summary>
    public static IReadOnlyList<SelfTestLogEntry> NvmeLog(byte[] page)
    {
        if (page.Length < NvmeLogBytes) return [];
        var entries = new List<SelfTestLogEntry>();
        for (var i = 0; i < MaxLogEntries; i++)
        {
            var e = page.AsSpan(NvmeLogFirstResult + i * NvmeResultBytes, NvmeResultBytes);
            var result = e[0] & 0x0F;
            if (result == 0x0F) continue; // entry not used
            var code = e[0] >> 4;
            var kind = code switch { 1 => SelfTestKind.Short, 2 => SelfTestKind.Extended, _ => (SelfTestKind?)null };
            var name = code switch { 1 => "Short", 2 => "Extended", 0x0E => "Vendor specific", _ => $"Code {code:X}h" };
            var valid = e[2];
            ulong? lba = (valid & 0x02) != 0 ? BinaryPrimitives.ReadUInt64LittleEndian(e.Slice(16, 8)) : null;
            string? status = (valid & 0x08) != 0
                ? ((valid & 0x04) != 0 ? $"type {e[24] & 0x07}, " : "") + "code " + e[25].ToString("X2", CultureInfo.InvariantCulture) + "h"
                : null;
            var outcome = NvmeOutcome(result);
            entries.Add(new(kind, name, outcome, 0, (long)Math.Min(BinaryPrimitives.ReadUInt64LittleEndian(e.Slice(4, 8)), long.MaxValue),
                lba, outcome == SelfTestOutcome.FailedSegment && e[1] > 0 ? e[1] : null, status));
        }
        return entries;
    }

    /// <summary>ATA self-test execution status (bits 7:4 of the status byte).</summary>
    public static SelfTestOutcome AtaOutcome(int status) => status switch
    {
        0 => SelfTestOutcome.Passed,
        1 => SelfTestOutcome.AbortedByHost,
        2 => SelfTestOutcome.InterruptedByReset,
        3 => SelfTestOutcome.FatalError,
        4 => SelfTestOutcome.FailedUnknownElement,
        5 => SelfTestOutcome.FailedElectrical,
        6 => SelfTestOutcome.FailedServo,
        7 => SelfTestOutcome.FailedRead,
        8 => SelfTestOutcome.FailedHandlingDamage,
        15 => SelfTestOutcome.InProgress,
        _ => SelfTestOutcome.Unknown,
    };

    /// <summary>NVMe Device Self-test Result (bits 3:0 of the status byte).</summary>
    public static SelfTestOutcome NvmeOutcome(int result) => result switch
    {
        0 => SelfTestOutcome.Passed,
        1 => SelfTestOutcome.AbortedByHost,
        2 => SelfTestOutcome.InterruptedByReset,
        3 or 4 or 8 or 9 => SelfTestOutcome.AbortedOther,
        5 => SelfTestOutcome.FatalError,
        6 => SelfTestOutcome.FailedUnknownElement,
        7 => SelfTestOutcome.FailedSegment,
        _ => SelfTestOutcome.Unknown,
    };

    public static bool IsFailure(SelfTestOutcome o) => o is SelfTestOutcome.FatalError or SelfTestOutcome.FailedUnknownElement
        or SelfTestOutcome.FailedElectrical or SelfTestOutcome.FailedServo or SelfTestOutcome.FailedRead or SelfTestOutcome.FailedHandlingDamage
        or SelfTestOutcome.FailedSegment;

    public static bool IsInterrupted(SelfTestOutcome o) => o is SelfTestOutcome.AbortedByHost or SelfTestOutcome.InterruptedByReset or SelfTestOutcome.AbortedOther;

    /// <summary>The outcome in plain words.</summary>
    public static string Describe(SelfTestOutcome o) => o switch
    {
        SelfTestOutcome.Passed => "Completed without error",
        SelfTestOutcome.InProgress => "In progress",
        SelfTestOutcome.AbortedByHost => "Aborted by an abort command",
        SelfTestOutcome.InterruptedByReset => "Interrupted by a reset or restart",
        SelfTestOutcome.AbortedOther => "Aborted before it finished",
        SelfTestOutcome.FatalError => "Fatal or unknown error",
        SelfTestOutcome.FailedUnknownElement => "Failed (the drive didn't say which part)",
        SelfTestOutcome.FailedElectrical => "Failed: electrical element",
        SelfTestOutcome.FailedServo => "Failed: servo or seek element",
        SelfTestOutcome.FailedRead => "Failed: read element",
        SelfTestOutcome.FailedHandlingDamage => "Failed: handling damage",
        SelfTestOutcome.FailedSegment => "Failed: one or more test segments",
        _ => "Unknown result code",
    };

    /// <summary>The bytes in <paramref name="hex"/> when it holds at least <paramref name="minBytes"/>; otherwise null.</summary>
    public static byte[]? Bytes(string? hex, int minBytes)
    {
        if (string.IsNullOrWhiteSpace(hex) || hex.Length % 2 != 0) return null;
        try
        {
            var bytes = Convert.FromHexString(hex);
            return bytes.Length >= minBytes ? bytes : null;
        }
        catch (FormatException) { return null; }
    }
}
