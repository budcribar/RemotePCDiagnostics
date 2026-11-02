using System.Diagnostics;

namespace RemotePCDiagnostics.Core.Npu;

public enum NpuVerdict { NoNpu, DriverProblem, NoAdapter, WorkloadFailed, TimedOut, Mismatch, Slow, SmokeOnly, Pass }

/// <summary>Per-device outcome. <paramref name="MaxAbsError"/> is vs the CPU reference (null = no numeric check).</summary>
public sealed record NpuDeviceReport(NpuDevice Device, NpuVerdict Verdict, string Message, NpuWorkloadKind Kind, double? FirstRunMs, double? AverageMs,
    int Iterations, double? Gflops, double? CpuAverageMs, double? SlowdownVsCpu, double? MaxAbsError, string? Adapter, string? Note);

public sealed record NpuTestReport(IReadOnlyList<NpuDeviceReport> Devices, int MatrixSize, TimeSpan Budget, NpuVerdict Overall, string? Notice);

/// <summary>Settings chosen on the page.</summary>
public sealed class NpuTestSettings
{
    public TimeSpan Duration { get; set; } = NpuTestModule.DefaultDuration;
}

/// <summary>NPU test: on-demand, own page, not in Run All and not part of the stress run (like the security audit and the audio tests).</summary>
public interface INpuTestModule : IDiagnosticModule
{
    NpuTestSettings Settings { get; }
    IReadOnlyList<NpuDevice> Devices();
    void Cancel();
}

/// <summary>Detects NPUs, checks driver health, and runs a short matrix-multiply (or queue round-trip) on each one with a watchdog. Fully automatic.</summary>
public sealed class NpuTestModule(INpuIo io, Action<string>? log = null) : INpuTestModule
{
    public const string ModuleName = "NpuTest";
    public static readonly TimeSpan DefaultDuration = TimeSpan.FromSeconds(10);
    public static readonly TimeSpan MaxDuration = TimeSpan.FromSeconds(60);
    public static readonly TimeSpan[] DurationChoices = [TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(60)];
    /// <summary>Extra time on top of the budget for device creation, first run and readback before the watchdog gives up.</summary>
    public static readonly TimeSpan WatchdogGrace = TimeSpan.FromSeconds(15);
    /// <summary>Square matrix size (256×256 floats = 256 KB per matrix).</summary>
    public const int MatrixSize = 256;
    public const int MaxMatrixSize = 512;
    public const int MaxIterations = 100_000;
    /// <summary>Largest allowed |device − CPU| per element (float32, K=256, inputs in [-1,1]).</summary>
    public const double MaxAbsError = 1e-2;
    /// <summary>Device slower than the single-thread CPU reference by more than this = Warning.</summary>
    public const double SlowFactor = 20;

    private readonly object _gate = new();
    private CancellationTokenSource? _runCts;

    public string Name => ModuleName;
    public string DisplayName => "NPU (AI accelerator) test";
    public bool IncludeInRunAll => false;
    public NpuTestSettings Settings { get; } = new();
    public event EventHandler<DiagnosticResult>? Updated { add { } remove { } } // no unsolicited updates

    private void Log(string s) { try { log?.Invoke(s); } catch { } }

    public IReadOnlyList<NpuDevice> Devices()
    {
        try { return io.ListDevices(); }
        catch (Exception ex) { Log($"{Name}: device list failed: {ex.Message}"); return []; }
    }

    public void Cancel() { lock (_gate) { try { _runCts?.Cancel(); } catch (ObjectDisposedException) { } } }

    public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken cancellationToken = default) => Task.FromResult(ModuleAvailability.Available);

    public static TimeSpan ClampDuration(TimeSpan d) => d <= TimeSpan.Zero ? DefaultDuration : d > MaxDuration ? MaxDuration : d;

    public async Task<DiagnosticResult> RefreshAsync(IProgress<string>? progress, CancellationToken cancellationToken = default)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        lock (_gate) _runCts = cts;
        try { return await RunCoreAsync(progress, cts.Token).ConfigureAwait(false); }
        catch (OperationCanceledException) when (cts.IsCancellationRequested)
        {
            return new DiagnosticResult(Name, DiagnosticStatus.Warning, "The NPU test was cancelled.", DateTimeOffset.Now) { Cancelled = true };
        }
        catch (Exception ex)
        {
            Log($"{Name}: {ex}");
            return new DiagnosticResult(Name, DiagnosticStatus.Error, "The NPU test couldn't finish on this PC. Please try again.", DateTimeOffset.Now);
        }
        finally { lock (_gate) _runCts = null; }
    }

    private async Task<DiagnosticResult> RunCoreAsync(IProgress<string>? progress, CancellationToken ct)
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
        var cpu = CpuBaseline(a, b, MatrixSize, out var reference);
        var per = budget / devices.Count;
        var reports = new List<NpuDeviceReport>();
        foreach (var d in devices)
        {
            ct.ThrowIfCancellationRequested();
            progress?.Report($"Testing {d.Name}…");
            reports.Add(await TestDeviceAsync(io, d, a, b, reference, cpu, per, WatchdogGrace, ct, Log).ConfigureAwait(false));
        }
        var rep = new NpuTestReport(reports, MatrixSize, budget, Worst(reports.Select(r => r.Verdict)), null);
        Log($"{Name}: {rep.Overall}; " + string.Join("; ", reports.Select(r => $"{r.Device.Name}: {r.Verdict} {r.Message}")));
        return ToResult(rep);
    }

    /// <summary>Driver check, watchdog-bounded workload, then the decision table. Public for tests.</summary>
    public static async Task<NpuDeviceReport> TestDeviceAsync(INpuIo io, NpuDevice d, float[] a, float[] b, float[] reference, double cpuMs,
        TimeSpan budget, TimeSpan grace, CancellationToken ct, Action<string>? log = null)
    {
        if (!d.DriverHealthy)
            return Report(d, NpuVerdict.DriverProblem, null, cpuMs, null, null);
        if (!d.HasAdapter)
            return Report(d, NpuVerdict.NoAdapter, null, cpuMs, null, null);
        var n = (int)Math.Sqrt(a.Length);
        var req = new NpuWorkloadRequest(n, a, b, budget, MaxIterations);
        // The driver call runs on its own task; if it hangs we stop waiting (abandon it) and report, so the app never freezes.
        var work = Task.Run(() => io.RunWorkloadAsync(d, req, ct), CancellationToken.None);
        NpuWorkloadResult res;
        try { res = await work.WaitAsync(budget + grace, ct).ConfigureAwait(false); }
        catch (TimeoutException)
        {
            _ = work.ContinueWith(t => _ = t.Exception, TaskScheduler.Default); // observe a late fault
            log?.Invoke($"NpuTest: {d.Name} timed out after {budget + grace}");
            return Report(d, NpuVerdict.TimedOut, null, cpuMs, null, null);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            log?.Invoke($"NpuTest: {d.Name} workload failed: {ex}");
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
            NpuVerdict.Slow => $"The NPU works but is {slow:0}× slower than the CPU reference ({res!.AverageMs:0.###} ms vs {cpuMs:0.###} ms).",
            NpuVerdict.SmokeOnly => $"Driver healthy; the NPU accepted and completed {res!.Iterations} work submissions (avg {res.AverageMs:0.###} ms). This NPU only runs ML operators (no compute shaders), so the math wasn't checked.",
            NpuVerdict.Pass => $"Passed: {res!.Iterations} matrix multiplies, results match the CPU, {gflops:0.0} GFLOPS ({res.AverageMs:0.###} ms each).",
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
