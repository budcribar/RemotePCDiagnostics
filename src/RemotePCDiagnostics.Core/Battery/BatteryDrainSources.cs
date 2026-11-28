using System.Runtime.InteropServices;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Battery;

/// <summary>Where the drain test reads the batteries. Null: the PC has no battery (or WMI couldn't say).</summary>
public interface IBatteryDrainReadings
{
    Task<BatteryDrainReading?> ReadAsync(CancellationToken ct);
}

/// <summary>
/// The batteries from WMI, which record/replay already covers: <c>BatteryStatus</c> (power online, remaining capacity, discharge rate,
/// voltage) and <c>BatteryFullChargedCapacity</c> in root\wmi, and the charge Windows shows from <c>Win32_Battery</c>. Several batteries
/// are added up.
/// </summary>
public sealed class WmiBatteryDrainReadings(IWmiSource wmi) : IBatteryDrainReadings
{
    public const string StatusSql = "SELECT InstanceName, PowerOnline, RemainingCapacity, DischargeRate, Voltage FROM BatteryStatus";
    public const string PercentNamespace = @"root\cimv2";
    public const string PercentSql = "SELECT EstimatedChargeRemaining FROM Win32_Battery";

    public async Task<BatteryDrainReading?> ReadAsync(CancellationToken ct)
    {
        var status = await wmi.QueryAsync(BatteryReader.WmiNamespace, StatusSql, ct).ConfigureAwait(false);
        if (status.Rows is not { Count: > 0 } rows) return null;
        var full = await wmi.QueryAsync(BatteryReader.WmiNamespace, BatteryReader.FullChargeSql, ct).ConfigureAwait(false);
        var pct = await wmi.QueryAsync(PercentNamespace, PercentSql, ct).ConfigureAwait(false);

        long? remaining = Sum(rows.Select(r => BatteryReader.Capacity(r.Long("RemainingCapacity"))));
        long? fullCharge = Sum((full.Rows ?? []).Select(r => BatteryReader.Capacity(r.Long("FullChargedCapacity"))));
        var rates = rows.Select(r => BatteryReader.RateMw(r.Long("DischargeRate"))).ToList();
        int? discharge = rates.All(r => r is null) ? null : rates.Sum(r => r ?? 0);
        var voltage = rows.Select(r => r.Long("Voltage")).FirstOrDefault(v => v is > 0 and < 100_000);
        var shown = (pct.Rows ?? []).Select(r => r.Long("EstimatedChargeRemaining")).Where(v => v is >= 0 and <= 100).ToList();
        int? percent = shown.Count > 0 ? (int)Math.Round(shown.Average(v => v!.Value)) : null;
        var onAc = rows.Any(r => r.Bool("PowerOnline") == true);
        return new BatteryDrainReading(onAc, percent, remaining, fullCharge, onAc ? null : discharge, voltage is { } v ? (int)v : null);
    }

    private static long? Sum(IEnumerable<long?> values)
    {
        long total = 0;
        var any = false;
        foreach (var v in values) if (v is { } x) { total += x; any = true; }
        return any ? total : null;
    }
}

/// <param name="NeedsAgent">No Agent, or one too old for the drain test: the run is Skipped, not failed.</param>
public sealed record BatteryDrainAgentAnswer(BatteryDrainPowerAnswer? Answer, string? Error = null, bool NeedsAgent = false)
{
    public bool Ok => Answer is not null;
}

/// <summary>Where the drain test asks for its power settings and the shutdown: the Agent on the PC, a fake in tests.</summary>
public interface IBatteryDrainAgent
{
    Task<BatteryDrainAgentAnswer> SendAsync(string verb, CancellationToken ct);
}

/// <summary>The Agent's <see cref="AgentScripts.BatteryDrainPower"/> over the admin pipe. The app itself never changes the power plan.</summary>
public sealed class AgentBatteryDrainSource(SystemCommandRunner commands) : IBatteryDrainAgent
{
    public static readonly TimeSpan CallTimeout = TimeSpan.FromSeconds(30);
    public const string TooOldText = "The Agent on this PC is too old for the battery drain test. Update RPCD, then run it again.";

    public async Task<BatteryDrainAgentAnswer> SendAsync(string verb, CancellationToken ct)
    {
        var pr = await commands.RunAgentScriptAsync(AgentScripts.Of(AgentScripts.BatteryDrainPower, verb), CallTimeout, ct).ConfigureAwait(false);
        return Read(pr);
    }

    public static BatteryDrainAgentAnswer Read(ProcessResult? pr)
    {
        if (pr is null) return new(null, "The Agent didn't answer in time.");
        if (SystemCommandRunner.AgentFailure(pr) is { } missing)
            return new(null, missing.StartsWith("Unknown script", StringComparison.Ordinal) ? TooOldText : missing, NeedsAgent: true);
        if (pr.ExitCode != 0)
        {
            var why = pr.StdErr.Trim();
            return why.StartsWith("Unknown script", StringComparison.Ordinal) ? new(null, TooOldText, NeedsAgent: true)
                : new(null, why.Length > 0 ? why : $"The Agent's power settings change failed (exit code {pr.ExitCode}).");
        }
        return BatteryDrainPowerAnswer.Parse(pr.StdOut) is { } a ? new(a) : new(null, "The Agent's answer wasn't a power settings status.");
    }
}

/// <summary>The work the PC does while the battery drains.</summary>
public interface IBatteryDrainLoad
{
    void Start(BatteryDrainMode mode);
    void Stop();
}

/// <summary>
/// The drain test's load, in this process (no administrator needed). Maximum load: one below-normal thread per core running the CPU
/// stress test's deterministic kernel, one of them also sweeping a block of memory (an eighth of it, at most 2 GB), and the screen kept on.
/// Balanced: about a fifth of one core, the PC kept awake but the screen left to the person. Below-normal priority keeps the PC usable.
/// </summary>
public sealed class ThreadBatteryDrainLoad(ILogger? log = null) : IBatteryDrainLoad
{
    public const long MaxMemoryBytes = 2L << 30;

    private readonly object _gate = new();
    private CancellationTokenSource? _stop;
    private readonly List<Thread> _threads = [];

    public void Start(BatteryDrainMode mode)
    {
        lock (_gate)
        {
            if (_stop is not null) return;
            var stop = _stop = new CancellationTokenSource();
            var token = stop.Token;
            // The execution state belongs to the thread that set it, so one thread holds it for the whole run.
            Add(() => KeepAwake(mode == BatteryDrainMode.MaxLoad, token), "Battery drain: keep awake", ThreadPriority.Normal);
            if (mode == BatteryDrainMode.Balanced)
            {
                Add(() => Spin(token, busyMs: 20, idleMs: 80), "Battery drain: light load", ThreadPriority.BelowNormal);
            }
            else
            {
                var cores = Math.Max(1, Environment.ProcessorCount);
                Add(() => SweepMemory(token), "Battery drain: memory", ThreadPriority.BelowNormal);
                for (var i = 1; i < cores; i++) Add(() => Spin(token, busyMs: 1000, idleMs: 0), $"Battery drain: core {i}", ThreadPriority.BelowNormal);
            }
            log.Info($"[battery-drain] Load started: {BatteryDrainReport.ModeArg(mode)}, {_threads.Count} threads.");
        }
    }

    public void Stop()
    {
        List<Thread> threads;
        lock (_gate)
        {
            if (_stop is null) return;
            _stop.Cancel();
            threads = [.. _threads];
            _threads.Clear();
            _stop.Dispose();
            _stop = null;
        }
        foreach (var t in threads) t.Join(TimeSpan.FromSeconds(5));
        log.Info("[battery-drain] Load stopped.");
    }

    private void Add(Action work, string name, ThreadPriority priority)
    {
        var t = new Thread(() => { try { work(); } catch (Exception ex) { log.Warn($"[battery-drain] {name} ended: {ex.Message}"); } })
        { IsBackground = true, Name = name, Priority = priority };
        _threads.Add(t);
        t.Start();
    }

    private static void Spin(CancellationToken token, int busyMs, int idleMs)
    {
        ulong seed = (ulong)Environment.CurrentManagedThreadId;
        var sw = System.Diagnostics.Stopwatch.StartNew();
        while (!token.IsCancellationRequested)
        {
            sw.Restart();
            while (sw.ElapsedMilliseconds < busyMs && !token.IsCancellationRequested)
                seed = Stress.DeterministicCpuWorkload.Instance.Compute(seed, 20_000);
            if (idleMs > 0) token.WaitHandle.WaitOne(idleMs);
        }
    }

    private static void SweepMemory(CancellationToken token)
    {
        var total = GC.GetGCMemoryInfo().TotalAvailableMemoryBytes;
        var bytes = Math.Clamp(total / 8, 64L << 20, MaxMemoryBytes);
        const int chunk = 64 << 20;
        var blocks = new List<byte[]>();
        for (long have = 0; have < bytes && !token.IsCancellationRequested; have += chunk) blocks.Add(GC.AllocateUninitializedArray<byte>(chunk));
        byte value = 0;
        while (!token.IsCancellationRequested)
        {
            value++;
            foreach (var b in blocks)
            {
                if (token.IsCancellationRequested) break;
                Array.Fill(b, value);
            }
        }
    }

    private static void KeepAwake(bool display, CancellationToken token)
    {
        var set = OperatingSystem.IsWindows() && SetThreadExecutionState(EsContinuous | EsSystemRequired | (display ? EsDisplayRequired : 0)) != 0;
        try { token.WaitHandle.WaitOne(); }
        finally { if (set) SetThreadExecutionState(EsContinuous); }
    }

    private const uint EsContinuous = 0x80000000, EsSystemRequired = 0x1, EsDisplayRequired = 0x2;

    [DllImport("kernel32.dll")]
    private static extern uint SetThreadExecutionState(uint flags);
}
