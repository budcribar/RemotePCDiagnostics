using System.Diagnostics;

namespace RemotePCDiagnostics.Core.Npu;

/// <summary>
/// Detects NPUs, checks driver health, and runs a short matrix-multiply (or queue round-trip) on each one with a watchdog. Fully automatic.
/// One instance per NPU (keyed on its PnP hardware id); a PC without an NPU doesn't show the test. Each NPU gets the whole time budget.
/// </summary>
public sealed class NpuTestModule(INpuIo io, ILogger? log = null) : OnDemandModuleBase(log), INpuTestModule, IInstanceSummary
{
    public const string ModuleName = ModuleSlugs.NpuTest;
    public static readonly TimeSpan DefaultDuration = NpuTestLimits.DefaultDuration;
    public static readonly TimeSpan MaxDuration = TimeSpan.FromSeconds(60);
    public static readonly TimeSpan[] DurationChoices = [TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(60)];
    public static readonly TimeSpan WatchdogGrace = NpuTestLimits.WatchdogGrace;
    /// <summary>Square matrix size (256×256 floats = 256 KB per matrix).</summary>
    public const int MatrixSize = 256;
    public const int MaxMatrixSize = NpuTestLimits.MaxMatrixSize;
    public const int MaxIterations = 100_000;
    /// <summary>Largest allowed |device − CPU| per element (float32, K=256, inputs in [-1,1]).</summary>
    public const double MaxAbsError = 1e-2;
    /// <summary>Device slower than the single-thread CPU reference by more than this = Warning.</summary>
    public const double SlowFactor = 20;

    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.NpuTest;
    public override string DisplayName => "NPU (AI accelerator) test";
    protected override string CancelledMessage => "The NPU test was cancelled.";
    public NpuTestSettings Settings { get; } = new();

    /// <summary>Longest the one-time presence check may take before the NPU test is treated as absent (hidden).</summary>
    public static readonly TimeSpan DetectionTimeout = TimeSpan.FromSeconds(20);
    private Task<bool>? _detect;
    private volatile bool _present;

    public bool IsPresent => _present;

    /// <summary>One cached detection on a background thread. Exceptions, an empty list or a timeout = no NPU (the test stays hidden).</summary>
    public Task<bool> DetectPresenceAsync(CancellationToken ct = default)
    {
        lock (Gate) _detect ??= DetectCoreAsync();
        return ct.CanBeCanceled ? _detect.WaitAsync(ct) : _detect;
    }

    private async Task<bool> DetectCoreAsync()
    {
        try
        {
            var list = await Task.Run(() => io.ListDevices()).WaitAsync(DetectionTimeout).ConfigureAwait(false);
            _present = list is { Count: > 0 };
            Log($"{Name}: presence check found {list?.Count ?? 0} NPU(s){(_present ? "" : "; test hidden")}");
        }
        catch (Exception ex) { _present = false; LogWarn($"{Name}: presence check failed, test hidden: {ex.Message}"); }
        return _present;
    }

    public static ModuleInstance InstanceOf(NpuDevice d) => new(InstanceKeys.From(d.HardwareId is { Length: > 0 } hw ? hw + "|" + d.Id : d.Id), d.Name, d.Id);

    /// <summary>Lists NPUs (bounded by <see cref="DetectionTimeout"/>); runs nothing on them.</summary>
    public async Task<ModuleDetection> DetectAsync(CancellationToken ct = default)
    {
        IReadOnlyList<NpuDevice> list;
        try { list = await Task.Run(() => io.ListDevices(), ct).WaitAsync(DetectionTimeout, ct).ConfigureAwait(false) ?? []; }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            _present = false;
            LogWarn($"{Name}: detection failed, test hidden: {ex.Message}");
            return ModuleDetection.NotApplicable("Couldn't look for an NPU");
        }
        _present = list.Count > 0;
        Log($"{Name}: found {list.Count} NPU(s){(_present ? "" : "; test hidden")}");
        return list.Count == 0 ? ModuleDetection.NotApplicable("This PC has no NPU (AI accelerator), or Windows has no driver for it")
            : ModuleDetection.For(list.Select(InstanceOf));
    }

    /// <summary>Tests one NPU with the whole time budget.</summary>
    public Task<DiagnosticResult> RefreshAsync(ModuleInstance instance, IProgress<string>? progress, CancellationToken cancellationToken = default) =>
        RunGuardedAsync(async ct =>
        {
            try
            {
                var budget = ClampDuration(Settings.Duration);
                var device = (await Task.Run(Devices, ct).ConfigureAwait(false)).FirstOrDefault(d => d.Id == instance.Details);
                if (device is null) return CouldNotRun.Result(Name, $"{instance.Label} is no longer connected.");
                var (a, b) = Inputs(MatrixSize);
                float[] reference = [];
                var cpu = await Stress.StressTaskScheduler.Run(() => CpuBaseline(a, b, MatrixSize, out reference), ct).ConfigureAwait(false);
                progress?.Report($"Testing {device.Name}…");
                var report = await TestDeviceAsync(io, device, a, b, reference, cpu, budget, WatchdogGrace, ct, Logger).ConfigureAwait(false);
                Log($"{Name}: {device.Name}: {report.Verdict} {report.Message}");
                return ToResult(new NpuTestReport([report], MatrixSize, budget, report.Verdict, null));
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                LogError($"{Name}: {ex}");
                return new DiagnosticResult(Name, DiagnosticStatus.Error, "The NPU test couldn't finish on this PC. Please try again.", DateTimeOffset.Now);
            }
        }, cancellationToken);

    /// <summary>One report listing every NPU's latest result, for the page.</summary>
    public object? Combine(IReadOnlyList<DiagnosticResult> instanceResults)
    {
        var reports = instanceResults.Select(r => r.Payload).OfType<NpuTestReport>().ToList();
        if (reports.Count == 0) return null;
        var devices = reports.SelectMany(r => r.Devices).ToList();
        return new NpuTestReport(devices, MatrixSize, reports.Max(r => r.Budget), Worst(devices.Select(d => d.Verdict)), reports.Select(r => r.Notice).FirstOrDefault(n => n is not null));
    }

    public IReadOnlyList<NpuDevice> Devices()
    {
        try { return io.ListDevices(); }
        catch (Exception ex) { LogWarn($"{Name}: device list failed: {ex.Message}"); return []; }
    }

    public static TimeSpan ClampDuration(TimeSpan d) => d <= TimeSpan.Zero ? DefaultDuration : d > MaxDuration ? MaxDuration : d;

    protected override async Task<DiagnosticResult> RunCoreAsync(IProgress<string>? progress, CancellationToken ct)
    {
        try { return await RunAllDevicesAsync(progress, ct).ConfigureAwait(false); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            LogError($"{Name}: {ex}");
            return new DiagnosticResult(Name, DiagnosticStatus.Error, "The NPU test couldn't finish on this PC. Please try again.", DateTimeOffset.Now);
        }
    }

    private async Task<DiagnosticResult> RunAllDevicesAsync(IProgress<string>? progress, CancellationToken ct)

    {
        progress?.Report("Looking for an NPU…");
        var devices = await Task.Run(Devices, ct).ConfigureAwait(false);
        var budget = ClampDuration(Settings.Duration);
        if (devices.Count == 0)
        {
            Log($"{Name}: no NPU found");
            return ToResult(new NpuTestReport([], MatrixSize, budget, NpuVerdict.NoNpu, "This PC has no NPU (AI accelerator), or Windows has no driver for it."));
        }
        var (a, b) = Inputs(MatrixSize);
        float[] reference = [];
        var cpu = await Stress.StressTaskScheduler.Run(() => CpuBaseline(a, b, MatrixSize, out reference), ct).ConfigureAwait(false);
        var per = budget / devices.Count;
        var reports = new List<NpuDeviceReport>();
        foreach (var d in devices)
        {
            ct.ThrowIfCancellationRequested();
            progress?.Report($"Testing {d.Name}…");
            reports.Add(await TestDeviceAsync(io, d, a, b, reference, cpu, per, WatchdogGrace, ct, Logger).ConfigureAwait(false));
        }
        var rep = new NpuTestReport(reports, MatrixSize, budget, Worst(reports.Select(r => r.Verdict)), null);
        Log($"{Name}: {rep.Overall}; " + string.Join("; ", reports.Select(r => $"{r.Device.Name}: {r.Verdict} {r.Message}")));
        return ToResult(rep);
    }

    /// <summary>Driver check, watchdog-bounded workload, then the decision table. Public for tests.</summary>
    public static async Task<NpuDeviceReport> TestDeviceAsync(INpuIo io, NpuDevice d, float[] a, float[] b, float[] reference, double cpuMs,
        TimeSpan budget, TimeSpan grace, CancellationToken ct, ILogger? log = null)
    {
        if (!d.DriverHealthy)
            return Report(d, NpuVerdict.DriverProblem, null, cpuMs, null, null);
        if (!d.HasAdapter)
            return Report(d, NpuVerdict.NoAdapter, null, cpuMs, null, null);
        var n = (int)Math.Sqrt(a.Length);
        var req = new NpuWorkloadRequest(n, a, b, budget, MaxIterations);
        // The driver call runs on its own task; if it hangs we stop waiting (abandon it) and report, so the app never freezes.
        var work = Stress.StressTaskScheduler.Run(() => io.RunWorkloadAsync(d, req, ct), CancellationToken.None);
        NpuWorkloadResult res;
        try { res = await work.WaitAsync(budget + grace, ct).ConfigureAwait(false); }
        catch (TimeoutException)
        {
            _ = work.ContinueWith(t => _ = t.Exception, TaskScheduler.Default); // observe a late fault
            log.Warn($"NpuTest: {d.Name} timed out after {budget + grace}");
            return Report(d, NpuVerdict.TimedOut, null, cpuMs, null, null);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            log.Error($"NpuTest: {d.Name} workload failed: {ex}");
            return Report(d, NpuVerdict.WorkloadFailed, null, cpuMs, null, ex.Message);
        }
        double? err = res.Output is null ? null : MaxError(res.Output, reference);
        return Report(d, Decide(res, err, cpuMs), res, cpuMs, err, res.Note);
    }

    /// <summary>Decision table for a workload that returned (driver/no-adapter/timeout/exception are handled before).</summary>
    public static NpuVerdict Decide(NpuWorkloadResult res, double? maxAbsError, double cpuAverageMs)
    {
        if (res.Kind == NpuWorkloadKind.None || res.Iterations <= 0) return NpuVerdict.WorkloadFailed;
        if (res.Kind == NpuWorkloadKind.MatMulComputeShader)
        {
            if (maxAbsError is null || double.IsNaN(maxAbsError.Value) || maxAbsError > MaxAbsError) return NpuVerdict.Mismatch;
            if (cpuAverageMs > 0 && res.AverageMs / cpuAverageMs > SlowFactor) return NpuVerdict.Slow;
            return NpuVerdict.Pass;
        }
        return NpuVerdict.SmokeOnly;
    }

    public static DiagnosticStatus StatusOf(NpuVerdict v) => v switch
    {
        NpuVerdict.Pass => DiagnosticStatus.Ok,
        NpuVerdict.NoNpu or NpuVerdict.Slow or NpuVerdict.SmokeOnly => DiagnosticStatus.Warning,
        _ => DiagnosticStatus.Error,
    };

    /// <summary>Worst verdict across devices (errors beat warnings beat pass).</summary>
    public static NpuVerdict Worst(IEnumerable<NpuVerdict> vs)
    {
        var list = vs.ToList();
        if (list.Count == 0) return NpuVerdict.NoNpu;
        return list.OrderByDescending(v => StatusOf(v) switch { DiagnosticStatus.Error => 3, DiagnosticStatus.Warning => 2, _ => 1 })
            .ThenBy(v => (int)v).First();
    }

    private static NpuDeviceReport Report(NpuDevice d, NpuVerdict v, NpuWorkloadResult? res, double cpuMs, double? err, string? detail)
    {
        double? gflops = res is { Kind: NpuWorkloadKind.MatMulComputeShader, AverageMs: > 0 } ? 2.0 * MatrixSizeOf(res) / (res.AverageMs * 1e6) : null;
        double? slow = res is { Kind: NpuWorkloadKind.MatMulComputeShader, AverageMs: > 0 } && cpuMs > 0 ? res.AverageMs / cpuMs : null;
        var msg = v switch
        {
            NpuVerdict.DriverProblem => $"Driver problem: {(d.ProblemCode is { } c and not 0 ? NpuDetection.ProblemText(c) : $"status {d.Status}")}. Reinstall or update the NPU driver.",
            NpuVerdict.NoAdapter => "Windows lists the NPU, but its compute driver isn't loaded (no DirectX adapter). Install the vendor's NPU driver.",
            NpuVerdict.TimedOut => "The NPU didn't finish its workload in time (driver hang?). The test stopped waiting.",
            NpuVerdict.WorkloadFailed => $"The workload failed on the NPU{(detail is { Length: > 0 } ? ": " + detail : ".")}",
            NpuVerdict.Mismatch => $"The NPU returned wrong results (max error {err:0.####} vs CPU, limit {MaxAbsError}).",
            NpuVerdict.Slow => $"The NPU works but is {slow:0}× slower than the CPU reference ({RemotePCDiagnostics.Core.History.MeasurementFormat.Significant(res!.AverageMs, System.Globalization.CultureInfo.InvariantCulture)} ms vs {RemotePCDiagnostics.Core.History.MeasurementFormat.Significant(cpuMs, System.Globalization.CultureInfo.InvariantCulture)} ms).",
            NpuVerdict.SmokeOnly => $"Driver healthy; the NPU accepted and completed {res!.Iterations} work submissions (avg {RemotePCDiagnostics.Core.History.MeasurementFormat.Significant(res.AverageMs, System.Globalization.CultureInfo.InvariantCulture)} ms). This NPU only runs ML operators (no compute shaders), so the math wasn't checked.",
            NpuVerdict.Pass => $"Passed: {res!.Iterations} matrix multiplies, results match the CPU, {gflops:0.0} GFLOPS ({RemotePCDiagnostics.Core.History.MeasurementFormat.Significant(res.AverageMs, System.Globalization.CultureInfo.InvariantCulture)} ms each).",
            _ => "No NPU found.",
        };
        return new NpuDeviceReport(d, v, msg, res?.Kind ?? NpuWorkloadKind.None, res?.FirstRunMs, res?.AverageMs, res?.Iterations ?? 0, gflops, cpuMs, slow, err,
            res?.AdapterDescription, detail);
    }

    private static double MatrixSizeOf(NpuWorkloadResult r) { var n = r.Output is null ? MatrixSize : Math.Sqrt(r.Output.Length); return n * n * n; }

    public DiagnosticResult ToResult(NpuTestReport r)
    {
        var msg = r.Overall switch
        {
            NpuVerdict.NoNpu => "Skipped: No NPU found.",
            _ when r.Devices.Count == 1 => r.Devices[0].Message,
            _ => $"{r.Devices.Count(d => d.Verdict == NpuVerdict.Pass)} of {r.Devices.Count} NPUs passed. " + r.Devices.First(d => d.Verdict == r.Overall).Message,
        };
        return new DiagnosticResult<NpuTestReport>(Name, StatusOf(r.Overall), msg, DateTimeOffset.Now, r);
    }

    /// <summary>Deterministic inputs in [-1, 1].</summary>
    public static (float[] A, float[] B) Inputs(int n, int seed = 12345)
    {
        n = Math.Clamp(n, 1, MaxMatrixSize);
        var rnd = new Random(seed);
        var a = new float[n * n]; var b = new float[n * n];
        for (var i = 0; i < a.Length; i++) { a[i] = (float)(rnd.NextDouble() * 2 - 1); b[i] = (float)(rnd.NextDouble() * 2 - 1); }
        return (a, b);
    }

    /// <summary>Row-major C = A·B on the CPU (single thread, float accumulate like the shader).</summary>
    public static float[] CpuMatMul(float[] a, float[] b, int n)
    {
        var c = new float[n * n];
        for (var i = 0; i < n; i++)
            for (var k = 0; k < n; k++)
            {
                var aik = a[i * n + k];
                for (var j = 0; j < n; j++) c[i * n + j] += aik * b[k * n + j];
            }
        return c;
    }

    /// <summary>Average ms of a CPU matmul (3 runs, best), and the reference result.</summary>
    public static double CpuBaseline(float[] a, float[] b, int n, out float[] reference)
    {
        reference = CpuMatMul(a, b, n);
        var best = double.MaxValue;
        for (var i = 0; i < 3; i++) { var sw = Stopwatch.StartNew(); CpuMatMul(a, b, n); best = Math.Min(best, sw.Elapsed.TotalMilliseconds); }
        return best;
    }

    public static double MaxError(float[] got, float[] expected)
    {
        if (got.Length != expected.Length) return double.PositiveInfinity;
        double m = 0;
        for (var i = 0; i < got.Length; i++)
        {
            var e = Math.Abs((double)got[i] - expected[i]);
            if (double.IsNaN(e)) return double.NaN;
            if (e > m) m = e;
        }
        return m;
    }
}
