namespace RemotePCDiagnostics.Core.GpuMemory;

/// <summary>
/// The graphics chips and their memory, for the video memory test. The app's is Direct3D 11 (Host); record and replay wrap it
/// (<see cref="Recording.RecordingGpuMemorySource"/>), and tests use a simulated chip with injected faults.
/// </summary>
public interface IGpuMemorySource
{
    /// <summary>The hardware adapters (never the Microsoft Basic Render Driver), with their memory budgets. Opens nothing.</summary>
    IReadOnlyList<GpuMemoryAdapter> ListAdapters();

    /// <summary>Opens the adapter with this <see cref="GpuMemoryAdapter.Id"/>. Throws when it is gone or can't be opened.</summary>
    IGpuMemoryDevice Open(string adapterId);
}

/// <summary>
/// An open graphics chip holding the test's blocks of video memory. Each call runs one compute dispatch on one block and waits for it.
/// Disposing frees every block. Throws <see cref="Stress.GpuDeviceLostException"/> when Windows reset the driver or removed the device.
/// </summary>
public interface IGpuMemoryDevice : IDisposable
{
    GpuMemoryAdapter Adapter { get; }

    /// <summary>Allocates one more block. False when the chip has no memory left for it (that is not a fault).</summary>
    bool TryAllocateBlock(long bytes);

    /// <summary>The blocks allocated so far, in bytes each.</summary>
    IReadOnlyList<long> Blocks { get; }

    /// <summary>Runs <paramref name="op"/> with <paramref name="pattern"/> over block <paramref name="block"/>. <paramref name="baseWord"/> is the
    /// block's first word counted over all blocks (the address the patterns use); <paramref name="inverted"/> complements the pattern.</summary>
    GpuBlockResult Run(int block, GpuMemoryOp op, GpuMemoryPattern pattern, uint seed, bool inverted, uint baseWord);
}

/// <summary>No graphics chips (the source on a build or test with no Direct3D).</summary>
public sealed class NoGpuMemorySource : IGpuMemorySource
{
    public IReadOnlyList<GpuMemoryAdapter> ListAdapters() => [];
    public IGpuMemoryDevice Open(string adapterId) => throw new InvalidOperationException("No graphics adapters on this build.");
}
