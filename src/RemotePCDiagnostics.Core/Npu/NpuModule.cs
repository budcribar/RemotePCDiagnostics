using System.Diagnostics;

namespace RemotePCDiagnostics.Core.Npu;

public enum NpuVerdict { NoNpu, DriverProblem, NoAdapter, WorkloadFailed, TimedOut, Mismatch, Slow, SmokeOnly, Pass }

/// <summary>Per-device outcome. <paramref name="MaxAbsError"/> is vs the CPU reference (null = no numeric check).</summary>
public sealed record NpuDeviceReport(NpuDevice Device, NpuVerdict Verdict, string Message, NpuWorkloadKind Kind, double? FirstRunMs, double? AverageMs,
    int Iterations, double? Gflops, double? CpuAverageMs, double? SlowdownVsCpu, double? MaxAbsError, string? Adapter, string? Note);

public sealed record NpuTestReport(IReadOnlyList<NpuDeviceReport> Devices, int MatrixSize, TimeSpan Budget, NpuVerdict Overall, string? Notice);

/// <summary>The NPU test's limits that the app's NPU adapter (WindowsNpuIo) also applies.</summary>
public static class NpuTestLimits
{
    public static readonly TimeSpan DefaultDuration = TimeSpan.FromSeconds(10);
    /// <summary>Extra time on top of the budget for device creation, first run and readback before the watchdog gives up.</summary>
    public static readonly TimeSpan WatchdogGrace = TimeSpan.FromSeconds(15);
    public const int MaxMatrixSize = 512;
}

/// <summary>Settings chosen on the page.</summary>
public sealed class NpuTestSettings
{
    public TimeSpan Duration { get; set; } = NpuTestLimits.DefaultDuration;
}

/// <summary>NPU test: on-demand, own page, not in Run All and not part of the stress run (like the security audit and the audio tests).</summary>
public interface INpuTestModule : IPerDeviceModule
{
    NpuTestSettings Settings { get; }
    IReadOnlyList<NpuDevice> Devices();
    void Cancel();
}
