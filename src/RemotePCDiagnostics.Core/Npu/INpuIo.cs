namespace RemotePCDiagnostics.Core.Npu;

/// <summary>Where a device entry came from.</summary>
public enum NpuSource { PnP, DXCore, Both }

/// <summary>What the D3D12 driver behind the NPU can do (DXCore attributes). Generic = ML/metacommands only (no shaders), Core = compute shaders.</summary>
public enum NpuComputeLevel { Unknown, None, GenericMl, CoreCompute }

/// <param name="Id">PnP instance id, or "dxcore:&lt;LUID&gt;" for a DXCore-only entry.</param>
/// <param name="ProblemCode">Windows ConfigManagerErrorCode (0 = working, null = unknown).</param>
/// <param name="AdapterLuid">DXCore adapter LUID (null = no DXCore adapter matched, e.g. driver not loaded).</param>
public sealed record NpuDevice(string Id, string Name, string Vendor, string? DriverVersion, string? Status, int? ProblemCode,
    NpuSource Source, string? HardwareId = null, long? AdapterLuid = null, NpuComputeLevel Compute = NpuComputeLevel.Unknown)
{
    public bool HasAdapter => AdapterLuid is not null;
    public bool DriverHealthy => ProblemCode is null or 0 && !string.Equals(Status, "Error", StringComparison.OrdinalIgnoreCase)
        && !string.Equals(Status, "Degraded", StringComparison.OrdinalIgnoreCase);
}

/// <summary>Raw PnP row (Win32_PnPEntity), parsed by <see cref="NpuDetection"/>.</summary>
public sealed record PnpRow(string? DeviceId, string? Name, string? PnpClass, string? ClassGuid, string? Manufacturer, string? Status,
    int? ConfigManagerErrorCode, string? DriverVersion, string[]? HardwareIds);

/// <summary>Raw DXCore adapter (compute-only / ML adapter), parsed by <see cref="NpuDetection"/>.</summary>
public sealed record DxCoreAdapterRow(long Luid, string Description, uint VendorId, uint DeviceId, ulong DriverVersion,
    bool IsNpuHardwareType, bool SupportsGraphics, bool SupportsCoreCompute, bool SupportsGenericMl, bool IsHardware);

/// <param name="MatrixSize">Square matrix size N (A·B, N×N floats); capped by <see cref="NpuTestModule.MaxMatrixSize"/>.</param>
/// <param name="A">Row-major N×N input.</param>
/// <param name="Budget">Time to keep repeating the workload (after the first, checked, run).</param>
/// <param name="MaxIterations">Hard cap on repeats.</param>
public sealed record NpuWorkloadRequest(int MatrixSize, float[] A, float[] B, TimeSpan Budget, int MaxIterations);

/// <summary>Kind of work that actually ran on the device.</summary>
public enum NpuWorkloadKind { None, MatMulComputeShader, QueueRoundTrip }

/// <param name="Output">Result of the first run (N×N), null when the device can only do a queue round-trip (no numeric check possible).</param>
/// <param name="FirstRunMs">Time of the first run including upload/readback.</param>
/// <param name="AverageMs">Average per repeat (dispatch + wait).</param>
/// <param name="AdapterDescription">Adapter the work was submitted to (as reported by the driver).</param>
public sealed record NpuWorkloadResult(NpuWorkloadKind Kind, float[]? Output, double FirstRunMs, double AverageMs, int Iterations,
    string? AdapterDescription, string? Note = null);

/// <summary>Device creation or the workload failed (driver error, device removed, TDR).</summary>
public sealed class NpuDeviceException(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>NPU access (Host: WMI/PnP + DXCore + Direct3D 12). Implementations never show OS dialogs, never use the network, and honour cancellation.</summary>
public interface INpuIo
{
    IReadOnlyList<NpuDevice> ListDevices();
    /// <summary>Runs a small bounded workload on the device's DXCore adapter. Throws <see cref="NpuDeviceException"/> on driver failure.</summary>
    Task<NpuWorkloadResult> RunWorkloadAsync(NpuDevice device, NpuWorkloadRequest request, CancellationToken ct);
}

/// <summary>No NPU (CI, non-Windows): the test reports "No NPU found".</summary>
public sealed class NullNpuIo : INpuIo
{
    public IReadOnlyList<NpuDevice> ListDevices() => [];
    public Task<NpuWorkloadResult> RunWorkloadAsync(NpuDevice device, NpuWorkloadRequest request, CancellationToken ct) => throw new NpuDeviceException("No NPU.");
}
