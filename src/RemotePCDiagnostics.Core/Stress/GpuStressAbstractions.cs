namespace RemotePCDiagnostics.Core.Stress;

public enum GpuAdapterKind { Hardware, Software }

/// <summary>The graphics adapter a test runs on. Software = Microsoft Basic Render Driver (WARP): never a GPU pass.</summary>
/// <param name="Id">Stable identity for per-GPU results: PCI vendor, device, subsystem and revision ids (plus "#2" for a second identical
/// card), never the adapter LUID, which changes each boot. Null when the factory can't tell adapters apart.</param>
public sealed record GpuAdapterInfo(string Name, GpuAdapterKind Kind, long DedicatedMemoryBytes = 0, uint VendorId = 0, string? Id = null)
{
    public static string PciId(uint vendor, uint device, uint subSys, uint revision) =>
        $"PCI\\VEN_{vendor:X4}&DEV_{device:X4}&SUBSYS_{subSys:X8}&REV_{revision:X2}";

    /// <summary>Gives each adapter its <see cref="Id"/> from <paramref name="pciId"/>, numbering identical cards in enumeration order.</summary>
    public static IReadOnlyList<GpuAdapterInfo> WithIds(IEnumerable<(GpuAdapterInfo Info, string PciId)> adapters)
    {
        var seen = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        return adapters.Select(a =>
        {
            var n = seen[a.PciId] = seen.GetValueOrDefault(a.PciId) + 1;
            return a.Info with { Id = n == 1 ? a.PciId : $"{a.PciId}#{n}" };
        }).ToList();
    }

    /// <summary>Microsoft's software rasterizer (WARP / Basic Render Driver) reports vendor 0x1414.</summary>
    public const uint MicrosoftVendorId = 0x1414;
    public bool IsSoftware => Kind == GpuAdapterKind.Software || VendorId == MicrosoftVendorId;
}

/// <summary>One finished compute dispatch: one value per thread, plus how long the GPU took (dispatch + readback).</summary>
public sealed record GpuBatchResult(uint[] Output, TimeSpan GpuTime);

/// <summary>An open GPU compute device that runs the deterministic stress kernel (<see cref="GpuStressKernel"/>).</summary>
public interface IGpuComputeDevice : IDisposable
{
    GpuAdapterInfo Adapter { get; }
    /// <summary>Number of threads (output values) per dispatch.</summary>
    int ThreadCount { get; }
    /// <summary>Runs one dispatch and waits for its result. Throws <see cref="GpuDeviceLostException"/> if the driver reset or the device was removed.</summary>
    GpuBatchResult RunBatch(uint seed, uint iterations);
}

public enum GpuOpenStatus { Opened, NoGpu, SoftwareOnly, Failed }

public sealed record GpuOpenResult(GpuOpenStatus Status, IGpuComputeDevice? Device = null, string? Detail = null)
{
    public static GpuOpenResult Ok(IGpuComputeDevice d) => new(GpuOpenStatus.Opened, d);
}

public interface IGpuDeviceFactory
{
    /// <summary>Opens the first usable hardware adapter. Never opens a software adapter as a GPU.</summary>
    GpuOpenResult Open();

    /// <summary>The hardware adapters (no software ones), each with its <see cref="GpuAdapterInfo.Id"/>. Opens nothing. Empty when the
    /// factory can't list them: the GPU test then runs once, on the first adapter.</summary>
    IReadOnlyList<GpuAdapterInfo> ListAdapters() => [];

    /// <summary>Opens the adapter with this <see cref="GpuAdapterInfo.Id"/>; <see cref="GpuOpenStatus.NoGpu"/> when it is gone.</summary>
    GpuOpenResult Open(string adapterId) => Open();
}

/// <summary>The GPU stopped responding: Windows reset the driver (TDR) or the device was removed/hung.</summary>
public sealed class GpuDeviceLostException(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>
/// The compute kernel, as HLSL (run by the GPU) and as its exact C# twin (the CPU reference). Integer-only
/// (xorshift + FNV multiply + rotate, all mod 2^32) so a healthy GPU must match the CPU bit for bit;
/// floating point is avoided because drivers may legally fuse or flush denormals.
/// </summary>
public static class GpuStressKernel
{
    public const int GroupSize = 256;

    public const string Hlsl = """
        cbuffer Params : register(b0) { uint g_seed; uint g_iterations; uint g_pad0; uint g_pad1; };
        RWStructuredBuffer<uint> g_out : register(u0);
        [numthreads(256, 1, 1)]
        void main(uint3 id : SV_DispatchThreadID)
        {
            uint x = (g_seed ^ (id.x * 0x9E3779B9u)) | 1u;
            uint acc = 0x811C9DC5u;
            for (uint i = 0; i < g_iterations; i++)
            {
                x ^= x << 13; x ^= x >> 17; x ^= x << 5;
                acc = (acc ^ x) * 0x01000193u;
                acc = (acc << 7) | (acc >> 25);
                acc += x >> 3;
            }
            g_out[id.x] = acc ^ x;
        }
        """;

    public static uint Reference(uint seed, uint index, uint iterations)
    {
        unchecked
        {
            uint x = (seed ^ (index * 0x9E3779B9u)) | 1u;
            uint acc = 0x811C9DC5u;
            for (uint i = 0; i < iterations; i++)
            {
                x ^= x << 13; x ^= x >> 17; x ^= x << 5;
                acc = (acc ^ x) * 0x01000193u;
                acc = (acc << 7) | (acc >> 25);
                acc += x >> 3;
            }
            return acc ^ x;
        }
    }
}
