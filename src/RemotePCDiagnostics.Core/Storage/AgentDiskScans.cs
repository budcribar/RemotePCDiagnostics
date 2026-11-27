using System.Runtime.InteropServices;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Storage;

/// <summary>
/// <see cref="AgentScripts.DiskReadScan"/>: start, read or stop the surface scan of one disk. A scan runs in the Agent on its own thread
/// and outlives the pipe call that started it; the app asks for its status about once a second.
/// </summary>
public sealed record DiskReadScanAction(string Verb, int DiskNumber, DiskScanMode Mode, int TimeLimitMinutes) : AgentNativeAction
{
    public const string Start = "start", Status = "status", Stop = "stop";
    public const int MaxDisk = 255;
    public static readonly int MaxTimeLimitMinutes = (int)DiskScanOptions.MaxTimeLimit.TotalMinutes;

    public static bool IsVerb(string? v) => v is Start or Status or Stop;

    /// <summary>The fixed argument list: verb, disk number, then for start the mode and the time limit in minutes (0 for none).</summary>
    public static DiskReadScanAction? Parse(IReadOnlyList<string> args)
    {
        if (args.Count < 2 || !IsVerb(args[0]) || !int.TryParse(args[1], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var disk)
            || disk is < 0 or > MaxDisk)
            return null;
        if (args[0] != Start) return args.Count == 2 ? new(args[0], disk, DiskScanMode.Quick, 0) : null;
        if (args.Count != 4 || args[2] is not ("quick" or "full")
            || !int.TryParse(args[3], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var limit)
            || limit < 0 || limit > MaxTimeLimitMinutes)
            return null;
        return new(Start, disk, args[2] == "full" ? DiskScanMode.Full : DiskScanMode.Quick, limit);
    }

    public static string ModeArg(DiskScanMode mode) => mode == DiskScanMode.Full ? "full" : "quick";
}

/// <summary>
/// The Agent's surface scans, one per disk at most. A scan nobody has asked about for <see cref="AbandonAfter"/> (the app closed or lost
/// the Agent) stops by itself. Finished scans are kept so the last status can still be read.
/// </summary>
public sealed class AgentDiskScans(Func<int, IDiskBlockDevice> open, Func<int, IDiskScanConditions?>? conditions = null,
    Func<IScanClock>? clock = null, Func<DateTime>? now = null)
{
    public static readonly TimeSpan AbandonAfter = TimeSpan.FromMinutes(2);

    private static AgentDiskScans? _windows;
    /// <summary>The PC's scans (raw disks through <see cref="WindowsDiskBlockDevice"/>).</summary>
    public static AgentDiskScans Windows => _windows ??= new(
        n => OperatingSystem.IsWindows() ? WindowsDiskBlockDevice.Open(n) : throw new PlatformNotSupportedException("Reading a raw disk needs Windows."),
        n => OperatingSystem.IsWindows() ? new WindowsDiskScanConditions(n) : null);

    private sealed class Job(DiskSurfaceScanner scanner, CancellationTokenSource cts, DateTime started)
    {
        public DiskSurfaceScanner Scanner { get; } = scanner;
        public CancellationTokenSource Cts { get; } = cts;
        public DateTime LastAsked { get; set; } = started;
        public DiskScanStatus? Final { get; set; }
        public Thread? Thread { get; set; }
    }

    private readonly object _gate = new();
    private readonly Dictionary<int, Job> _jobs = [];
    private DateTime Now() => (now ?? (() => DateTime.UtcNow))();

    public ProcessResult Run(DiskReadScanAction a)
    {
        StopAbandoned();
        return a.Verb switch
        {
            DiskReadScanAction.Start => StartScan(a),
            DiskReadScanAction.Stop => StopScan(a.DiskNumber),
            _ => Status(a.DiskNumber),
        };
    }

    private ProcessResult StartScan(DiskReadScanAction a)
    {
        lock (_gate)
        {
            // One scan per disk: asking again while it runs answers with the running scan.
            if (_jobs.TryGetValue(a.DiskNumber, out var running) && running.Final is null)
            {
                running.LastAsked = Now();
                return Answer(running.Scanner.Snapshot());
            }
        }
        IDiskBlockDevice device;
        try { device = open(a.DiskNumber); }
        catch (Exception ex) { return WindowsAgentNativeOps.Failed(ex.Message); }

        var options = new DiskScanOptions(a.DiskNumber, a.Mode, a.Mode == DiskScanMode.Full && a.TimeLimitMinutes > 0 ? TimeSpan.FromMinutes(a.TimeLimitMinutes) : null);
        var scanner = new DiskSurfaceScanner(device, options, SafeConditions(a.DiskNumber), clock?.Invoke());
        var job = new Job(scanner, new CancellationTokenSource(), Now());
        lock (_gate) _jobs[a.DiskNumber] = job;
        job.Thread = new Thread(() => RunJob(job, device)) { IsBackground = true, Name = $"Surface scan of disk {a.DiskNumber}" };
        job.Thread.Start();
        return Answer(scanner.Snapshot());
    }

    private IDiskScanConditions? SafeConditions(int disk)
    {
        try { return conditions?.Invoke(disk); }
        catch { return null; }
    }

    private static void RunJob(Job job, IDiskBlockDevice device)
    {
        // Keeps the PC from sleeping while this thread scans (cleared when it ends; Windows clears it too if the thread dies).
        var awake = OperatingSystem.IsWindows() && SetThreadExecutionState(EsContinuous | EsSystemRequired) != 0;
        try
        {
            job.Final = job.Scanner.Run(job.Cts.Token);
        }
        catch (Exception ex)
        {
            job.Final = job.Scanner.Snapshot() with { State = DiskScanStatus.Failed, Error = ex.Message };
        }
        finally
        {
            if (awake) SetThreadExecutionState(EsContinuous);
            device.Dispose();
        }
    }

    private ProcessResult Status(int disk)
    {
        lock (_gate)
        {
            if (!_jobs.TryGetValue(disk, out var job)) return WindowsAgentNativeOps.Failed($"No surface scan of disk {disk} has run.");
            job.LastAsked = Now();
            return Answer(job.Final ?? job.Scanner.Snapshot());
        }
    }

    private ProcessResult StopScan(int disk)
    {
        Job? job;
        lock (_gate)
        {
            if (!_jobs.TryGetValue(disk, out job)) return WindowsAgentNativeOps.Failed($"No surface scan of disk {disk} has run.");
        }
        job.Cts.Cancel();
        // The scanner stops between blocks; one block is a second at worst, a bad one with retries a little longer.
        job.Thread?.Join(TimeSpan.FromSeconds(10));
        return Answer(job.Final ?? job.Scanner.Snapshot());
    }

    private void StopAbandoned()
    {
        lock (_gate)
        {
            foreach (var job in _jobs.Values)
                if (job.Final is null && Now() - job.LastAsked > AbandonAfter) job.Cts.Cancel();
        }
    }

    /// <summary>Waits for disk <paramref name="disk"/>'s scan to end (tests).</summary>
    public bool WaitFor(int disk, TimeSpan timeout)
    {
        Job? job;
        lock (_gate) _jobs.TryGetValue(disk, out job);
        return job?.Thread?.Join(timeout) ?? true;
    }

    private static ProcessResult Answer(DiskScanStatus status) => new(0, status.ToJson(), "");

    private const uint EsContinuous = 0x80000000, EsSystemRequired = 0x1;

    [DllImport("kernel32.dll")]
    private static extern uint SetThreadExecutionState(uint flags);
}
