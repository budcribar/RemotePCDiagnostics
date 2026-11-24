using System.Diagnostics;
using System.Globalization;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>Physical memory: what Windows can use and what's free right now.</summary>
public sealed record MemoryUse(long TotalBytes, long AvailableBytes)
{
    public long UsedBytes => Math.Max(0, TotalBytes - AvailableBytes);
    public int UsedPercent => TotalBytes > 0 ? (int)Math.Round(100.0 * UsedBytes / TotalBytes) : 0;

    /// <summary>Commit charge: memory apps and Windows have reserved, backed by RAM or the page file.</summary>
    public long? CommitUsedBytes { get; init; }
    /// <summary>Commit limit: RAM plus the current page file size.</summary>
    public long? CommitLimitBytes { get; init; }
    /// <summary>RAM installed in the PC (can be more than <see cref="TotalBytes"/>).</summary>
    public long? InstalledBytes { get; init; }
    public long? PagefileUsedBytes { get; init; }
    public long? PagefileSizeBytes { get; init; }

    public bool HasCommit => CommitUsedBytes is >= 0 && CommitLimitBytes is > 0;
    public int CommitPercent => HasCommit ? (int)Math.Round(100.0 * CommitUsedBytes!.Value / CommitLimitBytes!.Value) : 0;
}

/// <param name="Memory">Memory in use and commitments, or null when they couldn't be read.</param>
/// <param name="FastStartup">Whether Windows Fast Startup is on, or null when it isn't reported.</param>
public sealed record MemoryRead(MemoryUse? Memory, bool? FastStartup);

/// <summary>
/// Where Resource hogs & uptime reads from. The app registers <see cref="WmiResourceHogsSource"/> (WMI through the Agent, the Fast Startup
/// setting from the registry in the app); the Store edition also has the legacy osquery + PowerShell reader (RemotePCDiagnostics.Legacy)
/// for when the Agent isn't connected. See <see cref="IBatteryPowerSource"/>.
/// </summary>
public interface IResourceHogsSource
{
    /// <summary>Time since the last full restart (Fast Startup not filled in), or null when it couldn't be read.</summary>
    Task<SystemUptimeInfo?> ReadUptimeAsync(CancellationToken ct);
    /// <summary>The running processes (not the idle and System processes), or null when they couldn't be read.</summary>
    Task<IReadOnlyList<ProcessResourceRow>?> ReadProcessesAsync(CancellationToken ct);
    /// <summary>Memory in use, commit charge, installed RAM, the page file and the Fast Startup setting.</summary>
    Task<MemoryRead> ReadMemoryAsync(CancellationToken ct);
    /// <summary>The PC's logical processors, which CPU % is a share of.</summary>
    Task<int> ReadLogicalProcessorsAsync(CancellationToken ct);
    /// <summary>Whether the check can run (the legacy reader needs osqueryi.exe).</summary>
    Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken ct) => Task.FromResult(ModuleAvailability.Available);
}

/// <summary>
/// The wait between the two process snapshots Resource hogs takes for CPU % and disk rate. <see cref="Instant"/> waits for nothing and
/// counts the window as passed, for replays (the result doesn't depend on how fast the test PC is).
/// </summary>
public class SampleTimer
{
    private static readonly Stopwatch Clock = Stopwatch.StartNew();

    public static SampleTimer Real { get; } = new();

    public static SampleTimer Instant() => new InstantTimer();

    /// <summary>A monotonic time.</summary>
    public virtual TimeSpan Now => Clock.Elapsed;

    public virtual Task DelayAsync(TimeSpan delay, CancellationToken ct) => Task.Delay(delay, ct);

    private sealed class InstantTimer : SampleTimer
    {
        private TimeSpan _now;
        public override TimeSpan Now => _now;
        public override Task DelayAsync(TimeSpan delay, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            _now += delay;
            return Task.CompletedTask;
        }
    }
}

/// <summary>
/// Uptime, processes and memory from WMI (<c>Win32_OperatingSystem</c>, <c>Win32_Process</c>, <c>Win32_PhysicalMemory</c>,
/// <c>Win32_PageFileUsage</c>), which the app reads through the Agent; Fast Startup from the registry, which needs no administrator rights.
/// As the Agent runs as administrator, it sees every process's memory and CPU time, which osquery as a standard user can't for some.
/// </summary>
public sealed class WmiResourceHogsSource(
    IWmiSource wmi,
    IRegistrySource registry,
    Func<long?>? monotonicUptimeSeconds = null) : IResourceHogsSource
{
    public const string Cimv2 = @"root\cimv2";
    public const string UptimeSql = "SELECT LastBootUpTime, LocalDateTime FROM Win32_OperatingSystem";
    public const string MemorySql = "SELECT TotalVisibleMemorySize, FreePhysicalMemory, TotalVirtualMemorySize, FreeVirtualMemory FROM Win32_OperatingSystem";
    public const string InstalledMemorySql = "SELECT Capacity FROM Win32_PhysicalMemory";
    public const string PageFileSql = "SELECT CurrentUsage, AllocatedBaseSize FROM Win32_PageFileUsage";
    public const string ProcessorsSql = "SELECT NumberOfLogicalProcessors FROM Win32_ComputerSystem";
    /// <summary>The same processes as osquery's <c>processes WHERE pid &gt; 4</c>: not the idle process (0) or System (4).</summary>
    public const string ProcessesSql = "SELECT ProcessId, ParentProcessId, Name, CreationDate, WorkingSetSize, PrivatePageCount, UserModeTime, KernelModeTime, ReadTransferCount, WriteTransferCount FROM Win32_Process WHERE ProcessId > 4";

    public static readonly RegistryRead FastStartupRead = new(RegistryRoot.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Session Manager\Power", ["HiberbootEnabled"]);

    private async Task<WmiQueryResult> Q(string sql, CancellationToken ct) => await wmi.QueryAsync(Cimv2, sql, ct).ConfigureAwait(false);

    public async Task<SystemUptimeInfo?> ReadUptimeAsync(CancellationToken ct)
    {
        // On live Windows, Environment.TickCount64 is the monotonic kernel uptime (same as Task Manager and
        // ScheduledMetricsPass) and is immune to RTC/NTP clock jumps (e.g. after a BIOS update) that leave
        // Win32_OperatingSystem.LastBootUpTime hundreds of days in the past. Replays leave this null and use WMI.
        if (monotonicUptimeSeconds?.Invoke() is >= 0 and long tickSeconds)
            return FromSeconds(tickSeconds);

        var os = (await Q(UptimeSql, ct).ConfigureAwait(false)).Rows?.FirstOrDefault();
        if (os is null || CimDateTime.Parse(os.Str("LastBootUpTime")) is not { } boot || CimDateTime.Parse(os.Str("LocalDateTime")) is not { } now)
            return null;
        // osquery's uptime is the tick count, which (like this) keeps counting through sleep and Fast Startup's hibernation.
        var seconds = (long)(now - boot).TotalSeconds;
        return seconds < 0 ? null : FromSeconds(seconds);
    }

    /// <summary>Days, hours and minutes as osquery's <c>uptime</c> table splits them.</summary>
    public static SystemUptimeInfo FromSeconds(long seconds) =>
        new(seconds, (int)(seconds / 86400), (int)(seconds % 86400 / 3600), (int)(seconds % 3600 / 60), null);

    public async Task<IReadOnlyList<ProcessResourceRow>?> ReadProcessesAsync(CancellationToken ct)
    {
        var q = await Q(ProcessesSql, ct).ConfigureAwait(false);
        return q.Success ? q.Rows!.Select(Process).Where(p => p.Pid > 4).ToList() : null;
    }

    /// <summary>
    /// One process, in osquery's units: CPU time in ms (WMI counts 100 ns), the start in Unix seconds. <c>PrivatePageCount</c> is in bytes
    /// despite its name (the private bytes osquery calls <c>total_size</c>).
    /// </summary>
    internal static ProcessResourceRow Process(WmiRow r)
    {
        static long NonNegative(long? v) => v is > 0 ? v.Value : 0;
        var cpuMs = (NonNegative(r.Long("UserModeTime")) + NonNegative(r.Long("KernelModeTime"))) / 10_000;
        var disk = NonNegative(r.Long("ReadTransferCount")) + NonNegative(r.Long("WriteTransferCount"));
        var start = CimDateTime.Parse(r.Str("CreationDate"))?.ToUnixTimeSeconds() ?? 0;
        return new(r.Str("Name"), Int(r.Long("ProcessId")), NonNegative(r.Long("WorkingSetSize")), cpuMs, disk,
            ParentPid: Int(r.Long("ParentProcessId")), StartTime: Math.Max(0, start), PrivateBytes: NonNegative(r.Long("PrivatePageCount")));
    }

    private static int Int(long? v) => v is > 0 and <= int.MaxValue ? (int)v.Value : 0;

    public async Task<MemoryRead> ReadMemoryAsync(CancellationToken ct)
    {
        var fastStartup = await ReadFastStartupAsync(ct).ConfigureAwait(false);
        var os = (await Q(MemorySql, ct).ConfigureAwait(false)).Rows?.FirstOrDefault();
        // Win32_OperatingSystem counts in KB.
        var totalKb = os?.Long("TotalVisibleMemorySize");
        var freeKb = os?.Long("FreePhysicalMemory");
        if (os is null || totalKb is not > 0 || freeKb is not >= 0) return new(null, fastStartup);
        var total = Kb(totalKb.Value);
        var free = Math.Min(Kb(freeKb.Value), total);
        var limit = os.Long("TotalVirtualMemorySize") is > 0 and var l ? Kb(l) : (long?)null;
        var commitFree = os.Long("FreeVirtualMemory") is >= 0 and var f ? Kb(f) : (long?)null;

        var modules = await Q(InstalledMemorySql, ct).ConfigureAwait(false);
        var installed = modules.Rows?.Sum(r => r.Long("Capacity") is > 0 and var c ? c : 0) is > 0 and var inst ? inst : (long?)null;
        // No page file is no rows (0 of 0); a failed read leaves the page file out.
        var pf = await Q(PageFileSql, ct).ConfigureAwait(false);
        long? pfUsed = null, pfSize = null;
        if (pf.Success)
        {
            pfUsed = pf.Rows!.Sum(r => Mb(r.Long("CurrentUsage")));
            pfSize = pf.Rows!.Sum(r => Mb(r.Long("AllocatedBaseSize")));
        }
        return new(new MemoryUse(total, free)
        {
            CommitLimitBytes = limit,
            CommitUsedBytes = limit is { } lim && commitFree is { } cf ? Math.Max(0, lim - cf) : null,
            InstalledBytes = installed,
            PagefileUsedBytes = pfUsed,
            PagefileSizeBytes = pfSize,
        }, fastStartup);
    }

    // Kept within range, so a damaged answer can't overflow into a negative size.
    private static long Kb(long kb) => Math.Clamp(kb, 0, long.MaxValue / 1024) * 1024;
    private static long Mb(long? mb) => mb is > 0 ? Math.Min(mb.Value, long.MaxValue / (1024L * 1024 * 1024)) * 1024 * 1024 : 0;

    private async Task<bool?> ReadFastStartupAsync(CancellationToken ct)
    {
        var row = (await registry.ReadAsync(FastStartupRead, ct).ConfigureAwait(false)).Rows?.FirstOrDefault();
        return row?.Long("HiberbootEnabled") switch { 1 => true, 0 => false, _ => null };
    }

    public async Task<int> ReadLogicalProcessorsAsync(CancellationToken ct) =>
        (await Q(ProcessorsSql, ct).ConfigureAwait(false)).Rows?.FirstOrDefault()?.Long("NumberOfLogicalProcessors") is > 0 and <= 4096 and var n
            ? (int)n : Environment.ProcessorCount;
}

/// <summary>WMI's datetime ("yyyyMMddHHmmss.ffffff+UUU": local time, then the offset from UTC in minutes) as an instant, or null.</summary>
public static class CimDateTime
{
    public static DateTimeOffset? Parse(string s)
    {
        if (s.Length < 25 || s[14] != '.' || s[21] is not ('+' or '-')) return null;
        if (!DateTime.TryParseExact(s[..14], "yyyyMMddHHmmss", CultureInfo.InvariantCulture, DateTimeStyles.None, out var local)) return null;
        if (!int.TryParse(s[15..21], NumberStyles.None, CultureInfo.InvariantCulture, out var micros)) return null;
        if (!int.TryParse(s[22..25], NumberStyles.None, CultureInfo.InvariantCulture, out var minutes) || minutes > 14 * 60) return null;
        var offset = TimeSpan.FromMinutes(s[21] == '-' ? -minutes : minutes);
        return new DateTimeOffset(local.AddTicks(micros * 10L), offset);
    }
}

/// <inheritdoc cref="AgentOrFallbackBatteryPowerSource"/>
public sealed class AgentOrFallbackResourceHogsSource(Session.IElevatedCommandBridge agent, IResourceHogsSource withAgent, IResourceHogsSource fallback) : IResourceHogsSource
{
    private IResourceHogsSource Current => agent.IsConnected ? withAgent : fallback;
    public Task<SystemUptimeInfo?> ReadUptimeAsync(CancellationToken ct) => Current.ReadUptimeAsync(ct);
    public Task<IReadOnlyList<ProcessResourceRow>?> ReadProcessesAsync(CancellationToken ct) => Current.ReadProcessesAsync(ct);
    public Task<MemoryRead> ReadMemoryAsync(CancellationToken ct) => Current.ReadMemoryAsync(ct);
    public Task<int> ReadLogicalProcessorsAsync(CancellationToken ct) => Current.ReadLogicalProcessorsAsync(ct);
    public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken ct) => Current.CheckAvailabilityAsync(ct);
}
