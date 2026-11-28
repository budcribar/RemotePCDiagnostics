using System.Text.Json;
using System.Text.Json.Serialization;

namespace RemotePCDiagnostics.Core.Storage;

/// <summary>Which of the drive's own self-tests to run. The numbers are what ATA (SMART EXECUTE OFF-LINE IMMEDIATE) and NVMe (Device
/// Self-test, Self-test Code) both use for them.</summary>
public enum SelfTestKind
{
    Short = 1,
    Extended = 2,
}

/// <summary>How the drive is asked for a self-test: ATA SMART (SATA and PATA drives on the PC's own controller) or NVMe Device Self-test.</summary>
public enum SelfTestProtocol
{
    None,
    Ata,
    Nvme,
}

/// <summary>
/// What the Agent read from one physical drive for <see cref="AgentScripts.DriveSelfTest"/> (<c>list</c> and <c>status</c>). The raw
/// pages are kept as the drive sent them (hex), so the app decodes them (<see cref="SelfTestDecoder"/>) and a recording replays the
/// drive's real answers. Nothing here identifies the unit: no serial number is read.
/// </summary>
public sealed record SelfTestDriveAnswer
{
    /// <summary>The disk number (<c>\\.\PhysicalDriveN</c>, the Disk N in Disk Management).</summary>
    [JsonPropertyName("disk")] public int Disk { get; init; }
    [JsonPropertyName("model")] public string Model { get; init; } = "";
    /// <summary>Windows' bus type name for the drive (<c>STORAGE_BUS_TYPE</c>: Nvme, Sata, Ata, Usb, Raid, Sas, Scsi, Virtual, Spaces, Sd, ...).</summary>
    [JsonPropertyName("bus")] public string Bus { get; init; } = "";
    /// <summary>"ata", "nvme", or empty when the drive can't be asked through either.</summary>
    [JsonPropertyName("protocol")] public string Protocol { get; init; } = "";
    /// <summary>ATA: the 512-byte SMART READ DATA page (self-test status, capabilities, polling times).</summary>
    [JsonPropertyName("smartData")] public string? SmartData { get; init; }
    /// <summary>ATA: the 512-byte SMART self-test log (log address 06h). NVMe: the 564-byte Device Self-test log page (06h).</summary>
    [JsonPropertyName("selfTestLog")] public string? SelfTestLog { get; init; }
    /// <summary>NVMe Identify Controller: Optional Admin Command Support (bit 4: Device Self-test).</summary>
    [JsonPropertyName("nvmeOacs")] public int? NvmeOacs { get; init; }
    /// <summary>NVMe Identify Controller: Extended Device Self-test Time (EDSTT), in minutes.</summary>
    [JsonPropertyName("nvmeExtendedMinutes")] public int? NvmeExtendedMinutes { get; init; }
    /// <summary>Why the drive couldn't be read (opened, identified or asked for its pages), or null.</summary>
    [JsonPropertyName("error")] public string? Error { get; init; }
}

/// <summary>The Agent's answer to <c>list</c> or <c>status</c>: the drives it read, and whether it is holding the PC awake for a test.</summary>
public sealed record SelfTestAnswer
{
    [JsonPropertyName("drives")] public List<SelfTestDriveAnswer> Drives { get; init; } = [];
    /// <summary>True while the Agent keeps the PC and its disks awake for a running self-test (<see cref="SelfTestPowerGuard"/>).</summary>
    [JsonPropertyName("keepingAwake")] public bool KeepingAwake { get; init; }

    public static readonly JsonSerializerOptions Json = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNameCaseInsensitive = true,
    };

    public string ToJson() => JsonSerializer.Serialize(this, Json);

    /// <summary>The answer in <paramref name="json"/>, or null when it isn't one.</summary>
    public static SelfTestAnswer? Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try { return JsonSerializer.Deserialize<SelfTestAnswer>(json, Json); }
        catch (JsonException) { return null; }
    }
}

/// <summary>How a self-test ended (or that it is still running), in the words both ATA and NVMe results map to.</summary>
public enum SelfTestOutcome
{
    Passed,
    InProgress,
    /// <summary>Stopped by an abort command (this app's Cancel, or another tool's).</summary>
    AbortedByHost,
    /// <summary>Stopped by a reset (a restart, sleep, or the controller being reset).</summary>
    InterruptedByReset,
    /// <summary>Stopped for another reason (NVMe: namespace removed, format, sanitize, unknown).</summary>
    AbortedOther,
    FatalError,
    FailedUnknownElement,
    FailedElectrical,
    FailedServo,
    FailedRead,
    FailedHandlingDamage,
    /// <summary>NVMe: one or more segments failed (the segment number is given).</summary>
    FailedSegment,
    Unknown,
}

/// <summary>One self-test run from the drive's own log, most recent first.</summary>
/// <param name="Kind">Short or extended; null for another test (conveyance, selective, vendor).</param>
/// <param name="TestName">What the drive says ran ("Short", "Extended", "Conveyance", "Selective", "Vendor specific").</param>
/// <param name="PowerOnHours">The drive's power-on hours when the test ended.</param>
/// <param name="FailingLba">The first failing logical block, when the drive gives one.</param>
/// <param name="Segment">NVMe: the failed segment number (1 to 7), when given.</param>
public sealed record SelfTestLogEntry(SelfTestKind? Kind, string TestName, SelfTestOutcome Outcome, int RemainingPercent, long PowerOnHours,
    ulong? FailingLba, int? Segment = null, string? StatusCode = null);

/// <summary>A drive's self-test state, decoded.</summary>
/// <param name="Unsupported">Why the drive can't run a self-test here (the card says "Not supported" with it), or null.</param>
/// <param name="ShortMinutes">The drive's own estimate for the short test, in minutes (ATA reports it; NVMe defines it as at most 2).</param>
/// <param name="ExtendedMinutes">The drive's own estimate for the extended test, in minutes.</param>
/// <param name="Running">The test running now, or null.</param>
/// <param name="PercentDone">How far the running test is (0 to 100), or null.</param>
/// <param name="ExecOutcome">ATA only: what the SMART data says about the last test (also when the log is unreadable).</param>
public sealed record SelfTestDriveState(
    int Disk, string Model, string Bus, SelfTestProtocol Protocol, string? Unsupported,
    int? ShortMinutes, int? ExtendedMinutes, SelfTestKind? Running, int? PercentDone,
    IReadOnlyList<SelfTestLogEntry> Log, SelfTestOutcome? ExecOutcome = null, string? ReadError = null)
{
    public bool Supported => Unsupported is null;
    public bool IsRunning => Running is not null || ExecOutcome == SelfTestOutcome.InProgress;

    /// <summary>"Disk 1: Samsung SSD 990 PRO 2TB", or "Disk 1" without a model.</summary>
    public string Label => string.IsNullOrWhiteSpace(Model) ? $"Disk {Disk}" : $"Disk {Disk}: {Model}";

    public int? MinutesFor(SelfTestKind kind) => kind == SelfTestKind.Short ? ShortMinutes : ExtendedMinutes;
}
