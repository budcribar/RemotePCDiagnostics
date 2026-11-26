using System.Diagnostics;
using Microsoft.ML.OnnxRuntime;
using Microsoft.Windows.AI.MachineLearning;
using RemotePCDiagnostics.Core.Npu;

namespace RemotePCDiagnostics.Host;

/// <summary>
/// Runs the NPU matrix-multiply workload through Windows ML (ONNX Runtime + Windows-managed NPU Execution Providers):
/// Qualcomm Hexagon (<c>QNNExecutionProvider</c>), AMD Ryzen AI (<c>VitisAIExecutionProvider</c>), and
/// Intel AI Boost (<c>OpenVINOExecutionProvider</c>). Strictly pins execution to <see cref="OrtHardwareDeviceType.NPU"/>
/// with CPU fallback disabled so the workload is guaranteed to execute on the NPU.
/// </summary>
internal static class WindowsMlNpuRunner
{
    private static readonly SemaphoreSlim InitGate = new(1, 1);
    private static bool _catalogRegistered;

    public static NpuWorkloadResult? TryRunMatMul(
        NpuDevice device,
        NpuWorkloadRequest req,
        int n,
        Action<string> log,
        Action<string> logWarn,
        CancellationToken ct)
    {
        if (!OperatingSystem.IsWindowsVersionAtLeast(10, 0, 26100))
            return null;

        try
        {
            EnsureCatalogRegistered(log, logWarn, ct);

            var env = OrtEnv.Instance();
            var epDevices = env.GetEpDevices();
            var npuDevices = epDevices
                .Where(d => d.HardwareDevice.Type == OrtHardwareDeviceType.NPU)
                .ToList();

            log($"NpuTest/WinML: {epDevices.Count} EP device(s) total, {npuDevices.Count} NPU device(s): " +
                string.Join(", ", npuDevices.Select(d => $"{d.EpName} ({d.HardwareDevice.Vendor})")));

            if (npuDevices.Count == 0)
                return null;

            var selected = SelectDeviceForVendor(npuDevices, device.Vendor);
            var modelBytes = OnnxMatMulBuilder.BuildFloat32MatMul(n);

            using var sessionOptions = new SessionOptions();
            sessionOptions.AddSessionConfigEntry("session.disable_cpu_ep_fallback", "1");
            sessionOptions.AppendExecutionProvider(env, [selected], new Dictionary<string, string>());

            using var session = new InferenceSession(modelBytes, sessionOptions);
            long[] shape = [n, n];
            using var ortA = OrtValue.CreateTensorValueFromMemory(req.A, shape);
            using var ortB = OrtValue.CreateTensorValueFromMemory(req.B, shape);
            var inputs = new Dictionary<string, OrtValue>(2)
            {
                ["A"] = ortA,
                ["B"] = ortB,
            };
            using var runOptions = new RunOptions();

            var deadline = Stopwatch.StartNew();
            var firstSw = Stopwatch.StartNew();
            float[] output;
            using (var firstResults = session.Run(runOptions, inputs, session.OutputNames))
            {
                firstSw.Stop();
                var tensor = firstResults[0].GetTensorDataAsSpan<float>();
                if (tensor.Length != n * n)
                    throw new NpuDeviceException($"Windows ML returned {tensor.Length} floats instead of {n * n}.");
                output = tensor.ToArray();
            }

            double firstMs = firstSw.Elapsed.TotalMilliseconds;
            int iterations = 1;
            var loopSw = Stopwatch.StartNew();
            while (iterations < req.MaxIterations && deadline.Elapsed < req.Budget)
            {
                ct.ThrowIfCancellationRequested();
                using var results = session.Run(runOptions, inputs, session.OutputNames);
                iterations++;
            }
            loopSw.Stop();

            double avgMs = iterations == 1
                ? firstMs
                : (firstMs + loopSw.Elapsed.TotalMilliseconds) / iterations;

            var adapterLabel = string.IsNullOrWhiteSpace(selected.HardwareDevice.Vendor)
                ? $"Windows ML · {selected.EpName}"
                : $"Windows ML · {selected.EpName} ({selected.HardwareDevice.Vendor})";

            log($"NpuTest/WinML: {selected.EpName} completed {iterations} runs (first {firstMs:0.0} ms, avg {avgMs:0.0} ms)");
            return new NpuWorkloadResult(
                NpuWorkloadKind.MatMulComputeShader,
                output,
                firstMs,
                avgMs,
                iterations,
                adapterLabel,
                Note: $"Windows ML ({selected.EpName})");
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            logWarn($"NpuTest/WinML: unavailable or failed ({ex.GetType().Name}: {ex.Message})");
            return null;
        }
    }

    private static OrtEpDevice SelectDeviceForVendor(List<OrtEpDevice> npuDevices, string vendor)
    {
        var preferredEp = vendor switch
        {
            "Qualcomm" => "QNNExecutionProvider",
            "AMD" => "VitisAIExecutionProvider",
            "Intel" => "OpenVINOExecutionProvider",
            _ => null,
        };
        if (preferredEp is not null)
        {
            var match = npuDevices.FirstOrDefault(d => string.Equals(d.EpName, preferredEp, StringComparison.OrdinalIgnoreCase));
            if (match is not null) return match;
        }
        return npuDevices[0];
    }

    private static void EnsureCatalogRegistered(Action<string> log, Action<string> logWarn, CancellationToken ct)
    {
        if (_catalogRegistered) return;
        InitGate.Wait(ct);
        try
        {
            if (_catalogRegistered) return;
            var catalog = ExecutionProviderCatalog.GetDefault();
            try
            {
                // Downloads & registers certified Windows ML execution providers (QNN, VitisAI, OpenVINO) on Windows 11 24H2+.
                var ensureTask = catalog.EnsureAndRegisterCertifiedAsync().AsTask(ct);
                if (!ensureTask.Wait(TimeSpan.FromSeconds(60), ct))
                    logWarn("NpuTest/WinML: EnsureAndRegisterCertifiedAsync timed out after 60s; trying already-installed providers.");
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logWarn($"NpuTest/WinML: EnsureAndRegisterCertifiedAsync failed ({ex.Message}); trying RegisterCertifiedAsync.");
                try { catalog.RegisterCertifiedAsync().AsTask(ct).Wait(TimeSpan.FromSeconds(15), ct); }
                catch (Exception ex2) when (ex2 is not OperationCanceledException)
                {
                    logWarn($"NpuTest/WinML: RegisterCertifiedAsync failed ({ex2.Message}).");
                }
            }
            _catalogRegistered = true;
            log("NpuTest/WinML: ExecutionProviderCatalog initialized.");
        }
        finally
        {
            InitGate.Release();
        }
    }
}
