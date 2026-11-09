using System.Diagnostics;
using System.Globalization;
using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Core.Benchmarks;

/// <summary>Idle sample: average processor use and memory paging rate over a quiet period.</summary>
public sealed record IdleSample(double CpuPercent, double PagesPerSec);

/// <summary>One reading of what wanders at idle: memory in use and the background-process count (see <see cref="BackgroundProcessCount"/>).</summary>
public sealed record IdleResourceSample(double? MemoryUsedMb, int? BackgroundProcesses);

/// <summary>Inventory read once per run.</summary>
public sealed record SystemResourceSnapshot(
    double? DiskFreeGb = null,
    int? EnabledStartupApps = null,
    int? AutoVendorServices = null,
    int? ActiveScheduledTasks = null,
    int? InstalledBloatwareApps = null);

/// <summary>Windows-specific measurements (Host implementation; fakes in tests). Methods may throw; the runner records a note.</summary>
public interface IBenchmarkProbes
{
    BenchmarkConditions ReadConditions();
    Task<IdleSample?> SampleIdleAsync(TimeSpan duration, CancellationToken ct);
    /// <summary>Milliseconds until the program's window accepts input (or the console program exits); the program is closed afterwards.</summary>
    Task<double?> StartProgramAsync(BuiltInProgram program, CancellationToken ct);
    /// <summary>Random 4 KB reads per second on the system drive (queue depth 1), using the disk speed test's temporary file.</summary>
    Task<double?> DiskRandomReadIopsAsync(TimeSpan duration, CancellationToken ct);
    /// <summary>Windows' own boot-performance events (Diagnostics-Performance, event 100), newest first.</summary>
    Task<IReadOnlyList<WinEvent>> ReadBootEventsAsync(CancellationToken ct);
    /// <summary>Cheap; called <see cref="BenchmarkSettings.ResourceSamples"/> times per run.</summary>
    Task<IdleResourceSample?> ReadIdleResourcesAsync(CancellationToken ct) => Task.FromResult<IdleResourceSample?>(null);
    Task<SystemResourceSnapshot?> ReadResourceSnapshotAsync(CancellationToken ct) => Task.FromResult<SystemResourceSnapshot?>(null);
}

/// <summary>
/// One recorded Windows start (Diagnostics-Performance event 100): total time until the desktop was ready, split into the main path
/// (power-on to the desktop showing) and post-boot (after sign-in until the desktop goes quiet, which startup apps lengthen).
/// <paramref name="AfterInstall"/>: the first start after Windows installed updates, which is much slower and isn't typical.
/// </summary>
public sealed record BootRecord(DateTimeOffset Time, double BootSeconds, double? MainPathSeconds, double? PostBootSeconds, bool AfterInstall = false)
{
    public const string Channel = "Microsoft-Windows-Diagnostics-Performance/Operational";
    public const string Query = "*[System[(EventID=100)]]";

    public static BootRecord? From(WinEvent e)
    {
        if (e.EventId != 100) return null;
        static double? Ms(WinEvent e, string name) => e.NamedData.TryGetValue(name, out var v) && double.TryParse(v, NumberStyles.Float, CultureInfo.InvariantCulture, out var ms) && ms > 0 ? ms / 1000 : null;
        var afterInstall = e.NamedData.TryGetValue("BootIsRebootAfterInstall", out var ai) && (string.Equals(ai, "true", StringComparison.OrdinalIgnoreCase) || ai == "1");
        return Ms(e, "BootTime") is { } boot ? new(e.Time, boot, Ms(e, "MainPathBootTime"), Ms(e, "BootPostBootTime"), afterInstall) : null;
    }

    /// <summary>"until the desktop 25.1 s + settling after sign-in 22.4 s" (medians), or null when Windows didn't record the split.</summary>
    public static string? Breakdown(IReadOnlyList<BootRecord> boots)
    {
        var main = boots.Select(b => b.MainPathSeconds).OfType<double>().ToList();
        var post = boots.Select(b => b.PostBootSeconds).OfType<double>().ToList();
        if (main.Count == 0 || post.Count == 0) return null;
        static double Med(List<double> v) { var s = v.OrderBy(x => x).ToList(); return s.Count % 2 == 1 ? s[s.Count / 2] : (s[s.Count / 2 - 1] + s[s.Count / 2]) / 2; }
        return string.Create(CultureInfo.InvariantCulture, $"until the desktop {Med(main):0.0} s + settling after sign-in {Med(post):0.0} s");
    }
}

/// <summary>Runs the enabled benchmarks in a fixed order (quiet measurements first) and returns one run.</summary>
public sealed class BenchmarkRunner(IBenchmarkProbes probes, ILogger? log = null, Func<string, CancellationToken, Task>? resolve = null,
    Func<TimeSpan, CancellationToken, Task>? delay = null)
{
    private readonly Func<TimeSpan, CancellationToken, Task> wait = delay ?? new Func<TimeSpan, CancellationToken, Task>(Task.Delay);
    public const int BootsBefore = 3;
    public static readonly string[] LookupDomains =
        ["microsoft.com", "google.com", "amazon.com", "wikipedia.org", "apple.com", "cloudflare.com", "github.com", "bing.com", "yahoo.com", "netflix.com"];
    public static readonly TimeSpan LookupTimeout = TimeSpan.FromSeconds(3);

    private void Log(string m) => log.Info("[benchmark] " + m);

    public async Task<BenchmarkRun> RunAsync(BenchmarkPhase phase, BenchmarkSettings settings, DateTimeOffset? beforeTime, IProgress<string>? progress, CancellationToken ct,
        DateTimeOffset? bootsSince = null)
    {
        var started = DateTimeOffset.UtcNow;
        var list = new List<BenchmarkMeasurement>();
        var completed = true;
        BenchmarkConditions conditions;
        try { conditions = probes.ReadConditions(); } catch (Exception ex) { Log("conditions: " + ex.Message); conditions = new(null, null); }
        Log($"{phase} start: enabled={string.Join(",", settings.Enabled)} runs={settings.Runs} battery={conditions.OnBattery} cpu={conditions.CpuTemperatureC}");

        async Task Step(string text, Func<Task> body)
        {
            ct.ThrowIfCancellationRequested();
            progress?.Report(text);
            await body().ConfigureAwait(false);
        }

        try
        {
            if (settings.IsEnabled(BenchmarkKind.IdleCpu) || settings.IsEnabled(BenchmarkKind.Paging))
                await Step($"Measuring background activity while idle ({settings.IdleSample.TotalSeconds:0} s)…", async () =>
                {
                    IdleSample? idle = null; string? note = null;
                    try { idle = await probes.SampleIdleAsync(settings.IdleSample, ct).ConfigureAwait(false); }
                    catch (Exception ex) when (ex is not OperationCanceledException) { Log("idle: " + ex); note = "couldn't read Windows' performance counters"; }
                    if (settings.IsEnabled(BenchmarkKind.IdleCpu)) list.Add(new(BenchmarkKind.IdleCpu, idle is null ? [] : [idle.CpuPercent], idle is null ? note ?? "not available" : null));
                    if (settings.IsEnabled(BenchmarkKind.Paging)) list.Add(new(BenchmarkKind.Paging, idle is null ? [] : [idle.PagesPerSec], idle is null ? note ?? "not available" : null));
                });

            // Right after the quiet idle sample and before anything this app starts (inventory queries, programs) adds to memory use.
            if (Benchmarks.IdleResourceKinds.Any(settings.IsEnabled))
                await Step($"Measuring memory in use and background processes ({settings.ResourceSampleSeconds:0} s)…", async () =>
                {
                    var (memory, processes, note) = await SampleIdleResourcesAsync(settings, ct).ConfigureAwait(false);
                    if (settings.IsEnabled(BenchmarkKind.MemoryUsedMb)) list.Add(new(BenchmarkKind.MemoryUsedMb, memory, memory.Count == 0 ? note : null));
                    if (settings.IsEnabled(BenchmarkKind.BackgroundProcesses)) list.Add(new(BenchmarkKind.BackgroundProcesses, processes, processes.Count == 0 ? note : null));
                });

            if (Benchmarks.ResourceSnapshotKinds.Any(settings.IsEnabled))
                await Step("Measuring disk space and background inventory…", async () =>
                {
                    SystemResourceSnapshot? snap = null; string? note = null;
                    try { snap = await probes.ReadResourceSnapshotAsync(ct).ConfigureAwait(false); }
                    catch (Exception ex) when (ex is not OperationCanceledException) { Log("resources: " + ex.Message); note = "couldn't read system inventory"; }
                    void AddSnap(BenchmarkKind k, double? val)
                    {
                        if (settings.IsEnabled(k)) list.Add(new(k, val is { } v ? [v] : [], val is null ? note ?? "not available" : null));
                    }
                    AddSnap(BenchmarkKind.DiskFreeGb, snap?.DiskFreeGb);
                    AddSnap(BenchmarkKind.EnabledStartupApps, snap?.EnabledStartupApps);
                    AddSnap(BenchmarkKind.AutoVendorServices, snap?.AutoVendorServices);
                    AddSnap(BenchmarkKind.ActiveScheduledTasks, snap?.ActiveScheduledTasks);
                    AddSnap(BenchmarkKind.InstalledBloatwareApps, snap?.InstalledBloatwareApps);
                });

            if (settings.IsEnabled(BenchmarkKind.BootTime))
                await Step("Reading Windows' start-up times…", async () => list.Add(await BootAsync(phase, beforeTime, bootsSince, ct).ConfigureAwait(false)));

            if (settings.IsEnabled(BenchmarkKind.DnsLookup))
                await Step("Timing website lookups…", async () => list.Add(await DnsAsync(settings.Runs, ct).ConfigureAwait(false)));

            if (settings.IsEnabled(BenchmarkKind.ProgramStart))
                await Step("Timing how fast Windows programs start…", async () => list.Add(await ProgramsAsync(settings.Runs, ct).ConfigureAwait(false)));

            if (settings.IsEnabled(BenchmarkKind.CpuSingle))
                await Step("Measuring processor speed (one core)…", async () =>
                    list.Add(new(BenchmarkKind.CpuSingle, await RepeatAsync(settings.Runs, () => Stress.StressTaskScheduler.Run(() => (double?)CpuScore(1, settings.CpuSingleRun, ct), ct)).ConfigureAwait(false))));

            if (settings.IsEnabled(BenchmarkKind.CpuMulti))
                await Step("Measuring processor speed (all cores)…", async () =>
                    list.Add(new(BenchmarkKind.CpuMulti, await RepeatAsync(settings.Runs, () => Stress.StressTaskScheduler.Run(() => (double?)CpuScore(Environment.ProcessorCount, settings.CpuMultiRun, ct), ct)).ConfigureAwait(false))));

            if (settings.IsEnabled(BenchmarkKind.DiskLatency))
                await Step("Measuring disk response time…", async () =>
                {
                    string? note = null;
                    var samples = await RepeatAsync(settings.Runs, async () =>
                    {
                        try { return await probes.DiskRandomReadIopsAsync(settings.DiskRun, ct).ConfigureAwait(false) is > 0 and var iops ? 1000.0 / iops : null; }
                        catch (Exception ex) when (ex is not OperationCanceledException) { Log("disk: " + ex.Message); note = "the disk test couldn't run"; return null; }
                    }).ConfigureAwait(false);
                    list.Add(new(BenchmarkKind.DiskLatency, samples, samples.Count == 0 ? note ?? "not available" : null));
                });
        }
        catch (OperationCanceledException) { completed = false; Log($"{phase} stopped by user"); }

        var run = new BenchmarkRun(phase, started, conditions, list, completed);
        Log($"{phase} done: " + string.Join(" ", list.Select(m => $"{m.Kind}={m.Median?.ToString("0.###", CultureInfo.InvariantCulture) ?? "n/a"}")));
        return run;
    }

    /// <summary>
    /// Several readings <see cref="BenchmarkSettings.ResourceSampleInterval"/> apart; every reading is kept so the comparison uses
    /// their median and spread. Stops at once if the first reading has nothing (probe not available) instead of waiting for nothing.
    /// </summary>
    private async Task<(List<double> Memory, List<double> Processes, string Note)> SampleIdleResourcesAsync(BenchmarkSettings settings, CancellationToken ct)
    {
        var memory = new List<double>(); var processes = new List<double>();
        var note = "not available";
        for (var i = 0; i < Math.Max(1, settings.ResourceSamples); i++)
        {
            if (i > 0) await wait(settings.ResourceSampleInterval, ct).ConfigureAwait(false);
            IdleResourceSample? r = null;
            try { r = await probes.ReadIdleResourcesAsync(ct).ConfigureAwait(false); }
            catch (Exception ex) when (ex is not OperationCanceledException) { Log("idle resources: " + ex.Message); note = "couldn't read memory use or the process list"; }
            if (r?.MemoryUsedMb is { } mb) memory.Add(mb);
            if (r?.BackgroundProcesses is { } n) processes.Add(n);
            if (i == 0 && memory.Count == 0 && processes.Count == 0) break;
        }
        return (memory, processes, note);
    }

    private static async Task<IReadOnlyList<double>> RepeatAsync(int runs, Func<Task<double?>> once)
    {
        var r = new List<double>();
        for (var i = 0; i < Math.Max(1, runs); i++) if (await once().ConfigureAwait(false) is { } v) r.Add(v);
        return r;
    }

    private async Task<BenchmarkMeasurement> BootAsync(BenchmarkPhase phase, DateTimeOffset? beforeTime, DateTimeOffset? bootsSince, CancellationToken ct)
    {
        IReadOnlyList<WinEvent> events;
        try { events = await probes.ReadBootEventsAsync(ct).ConfigureAwait(false); }
        catch (Exception ex) when (ex is not OperationCanceledException) { Log("boot: " + ex.Message); return new(BenchmarkKind.BootTime, [], "Windows' start-up log couldn't be read (run as administrator)"); }
        var boots = events.Select(BootRecord.From).OfType<BootRecord>().OrderByDescending(b => b.Time).ToList();
        return SelectBoots(phase, boots, beforeTime, bootsSince);
    }

    /// <summary>
    /// Which recorded starts count. The first start after Windows installed updates is never used (it's far slower than usual).
    /// Before, with <paramref name="bootsSince"/> (the service workflow's restart before the baseline): only the start(s) since then, so before and
    /// after are each a start from a restart the app asked for. Before without it: the last <see cref="BootsBefore"/> starts (typical start-up).
    /// After: starts recorded after the "before" run (i.e. after the restart).
    /// </summary>
    public static BenchmarkMeasurement SelectBoots(BenchmarkPhase phase, IReadOnlyList<BootRecord> newestFirst, DateTimeOffset? beforeTime, DateTimeOffset? bootsSince = null)
    {
        var usable = newestFirst.Where(b => !b.AfterInstall).ToList();
        var skippedInstall = newestFirst.Count - usable.Count;
        List<BootRecord> chosen;
        string? empty;
        if (phase == BenchmarkPhase.Before)
        {
            chosen = bootsSince is { } since ? usable.Where(b => b.Time > since).ToList() : usable.Take(BootsBefore).ToList();
            empty = bootsSince is not null
                ? "Windows hasn't recorded the start-up after the restart yet (it does a few minutes after sign-in)"
                : newestFirst.Count == 0 ? "Windows hasn't recorded any start-up times on this PC" : "only start-ups right after Windows updates are recorded, and those aren't typical";
        }
        else
        {
            chosen = usable.Where(b => beforeTime is null || b.Time > beforeTime).ToList();
            empty = newestFirst.Any(b => b.AfterInstall && (beforeTime is null || b.Time > beforeTime))
                ? "the only start-up since the before benchmark was right after Windows installed updates, which isn't comparable; restart once more"
                : "no restart since the before benchmark, or Windows hasn't recorded it yet (it does a few minutes after sign-in)";
        }
        if (chosen.Count == 0) return new(BenchmarkKind.BootTime, [], empty);
        return new(BenchmarkKind.BootTime, chosen.Select(b => b.BootSeconds).ToList(), null, BootRecord.Breakdown(chosen));
    }

    private async Task<BenchmarkMeasurement> ProgramsAsync(int runs, CancellationToken ct)
    {
        // One sample per round = total time to start every program once, so each sample covers the same work.
        var samples = new List<double>();
        string? note = null;
        for (var i = 0; i < Math.Max(1, runs); i++)
        {
            double total = 0; var ok = true;
            foreach (var p in BuiltInPrograms.All)
            {
                double? ms = null;
                try { ms = await probes.StartProgramAsync(p, ct).ConfigureAwait(false); }
                catch (Exception ex) when (ex is not OperationCanceledException) { Log($"start {p.Name}: {ex.Message}"); }
                if (ms is null) { ok = false; note = $"{p.Name} couldn't be started"; break; }
                total += ms.Value;
            }
            if (ok) samples.Add(total / BuiltInPrograms.All.Count);
        }
        return new(BenchmarkKind.ProgramStart, samples, samples.Count == 0 ? note : null);
    }

    private async Task<BenchmarkMeasurement> DnsAsync(int runs, CancellationToken ct)
    {
        var r = resolve ?? (async (name, c) => await System.Net.Dns.GetHostAddressesAsync(name, c).ConfigureAwait(false));
        var samples = new List<double>();
        for (var i = 0; i < Math.Max(1, runs); i++)
        {
            var times = new List<double>();
            foreach (var d in LookupDomains)
            {
                // A random name under each domain is never in any cache, so before and after both measure a real lookup.
                var name = $"rpd-{Guid.NewGuid():N}".Substring(0, 16) + "." + d;
                using var to = CancellationTokenSource.CreateLinkedTokenSource(ct);
                to.CancelAfter(LookupTimeout);
                var sw = Stopwatch.StartNew();
                try { await r(name, to.Token).ConfigureAwait(false); times.Add(sw.Elapsed.TotalMilliseconds); }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested) { /* timed out: not counted */ }
                catch (System.Net.Sockets.SocketException) { times.Add(sw.Elapsed.TotalMilliseconds); } // "no such name" is still a full answer
            }
            if (times.Count >= LookupDomains.Length / 2) samples.Add(new BenchmarkMeasurement(BenchmarkKind.DnsLookup, times).Median!.Value);
        }
        return new(BenchmarkKind.DnsLookup, samples, samples.Count == 0 ? "website lookups didn't get answers (offline?)" : null);
    }

    /// <summary>Fixed integer workload on <paramref name="threads"/> threads for <paramref name="duration"/>; returns work units per second (points).</summary>
    public static double CpuScore(int threads, TimeSpan duration, CancellationToken ct = default)
    {
        threads = Math.Max(1, threads);
        var counts = new long[threads * 8]; // padded: one slot per 64 bytes to avoid false sharing
        var sw = Stopwatch.StartNew();
        var workers = Enumerable.Range(0, threads).Select(t => new Thread(() =>
        {
            ulong x = 0x9E3779B97F4A7C15UL ^ (ulong)(t + 1);
            long units = 0;
            do // at least one unit per thread, so a very short run never scores 0
            {
                for (var i = 0; i < 20_000; i++) { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x *= 0x2545F4914F6CDD1DUL; }
                units++;
            }
            while (sw.Elapsed < duration && !ct.IsCancellationRequested);
            counts[t * 8] = units + (long)(x & 0); // keep x alive
        }) { IsBackground = true, Priority = ThreadPriority.BelowNormal }).ToList();
        workers.ForEach(w => w.Start());
        workers.ForEach(w => w.Join());
        ct.ThrowIfCancellationRequested();
        var secs = Math.Max(sw.Elapsed.TotalSeconds, 1e-3);
        return Enumerable.Range(0, threads).Sum(t => counts[t * 8]) / secs / 100; // scaled to readable "points"
    }
}
