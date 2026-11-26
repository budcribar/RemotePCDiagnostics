using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace RemotePCDiagnostics.Core.Stress;

/// <summary>
/// One logical processor: <paramref name="Index"/> is its number as Task Manager shows it ("CPU 5"), <paramref name="Group"/> and
/// <paramref name="Number"/> address it for affinity, <paramref name="Core"/> is the physical core it belongs to (two logical processors
/// share a core with Hyper-Threading/SMT), and <paramref name="EfficiencyClass"/> is 0 for efficiency cores on a hybrid CPU (higher is faster;
/// every core is 0 on a CPU that isn't hybrid).
/// </summary>
public sealed record LogicalProcessor(int Index, ushort Group, byte Number, int Core, byte EfficiencyClass);

/// <summary>Pins the calling thread to one logical processor, so a result measured on that thread belongs to that processor.</summary>
public interface ICpuPinning
{
    /// <summary>Every logical processor the threads can be pinned to, in <see cref="LogicalProcessor.Index"/> order; empty when pinning isn't possible.</summary>
    IReadOnlyList<LogicalProcessor> Processors { get; }

    /// <summary>Pins the calling thread to <paramref name="processor"/> until the result is disposed (which restores the thread's old affinity).
    /// Null when Windows refused, for example when the app is limited to some processors.</summary>
    IDisposable? Pin(LogicalProcessor processor);
}

/// <summary>Windows: reads the processor layout once and pins with SetThreadGroupAffinity. Elsewhere: no processors, no pinning.</summary>
public sealed class WindowsCpuPinning : ICpuPinning
{
    public static readonly WindowsCpuPinning Instance = new();

    private readonly Lazy<IReadOnlyList<LogicalProcessor>> _processors = new(ReadProcessors);
    public IReadOnlyList<LogicalProcessor> Processors => _processors.Value;

    public IDisposable? Pin(LogicalProcessor processor)
    {
        if (!OperatingSystem.IsWindows()) return null;
        var want = new GroupAffinity { Mask = (UIntPtr)(1UL << processor.Number), Group = processor.Group };
        var thread = GetCurrentThread();
        return SetThreadGroupAffinity(thread, ref want, out var previous) ? new Restore(previous) : null;
    }

    private sealed class Restore(GroupAffinity previous) : IDisposable
    {
        private int _done;
        public void Dispose()
        {
            if (Interlocked.Exchange(ref _done, 1) != 0) return;
            var p = previous;
            SetThreadGroupAffinity(GetCurrentThread(), ref p, out _);
        }
    }

    private static IReadOnlyList<LogicalProcessor> ReadProcessors()
    {
        if (!OperatingSystem.IsWindows()) return [];
        try
        {
            uint length = 0;
            GetLogicalProcessorInformationEx(RelationProcessorCore, null, ref length);
            if (length == 0) return [];
            var buffer = new byte[length];
            if (!GetLogicalProcessorInformationEx(RelationProcessorCore, buffer, ref length)) return [];
            return ParseProcessorCores(buffer.AsSpan(0, (int)length));
        }
        catch (Exception ex) when (ex is EntryPointNotFoundException or DllNotFoundException) { return []; }
    }

    /// <summary>
    /// Parses the RelationProcessorCore records of GetLogicalProcessorInformationEx: each is
    /// { DWORD Relationship; DWORD Size; BYTE Flags; BYTE EfficiencyClass; BYTE Reserved[20]; WORD GroupCount; GROUP_AFFINITY GroupMask[GroupCount] }
    /// with GROUP_AFFINITY = { KAFFINITY Mask (8 bytes on 64-bit); WORD Group; WORD Reserved[3] } starting at offset 32.
    /// </summary>
    internal static IReadOnlyList<LogicalProcessor> ParseProcessorCores(ReadOnlySpan<byte> buffer)
    {
        var found = new List<(ushort Group, byte Number, int Core, byte Efficiency)>();
        int offset = 0, core = 0;
        while (offset + 32 <= buffer.Length)
        {
            var record = buffer[offset..];
            var relationship = BinaryPrimitives.ReadUInt32LittleEndian(record);
            var size = (int)BinaryPrimitives.ReadUInt32LittleEndian(record[4..]);
            if (size <= 0 || size > record.Length) break;
            if (relationship == RelationProcessorCore)
            {
                var efficiency = record[9];
                var groupCount = BinaryPrimitives.ReadUInt16LittleEndian(record[30..]);
                for (int g = 0; g < groupCount && 32 + (g + 1) * 16 <= size; g++)
                {
                    var affinity = record[(32 + g * 16)..];
                    var mask = BinaryPrimitives.ReadUInt64LittleEndian(affinity);
                    var group = BinaryPrimitives.ReadUInt16LittleEndian(affinity[8..]);
                    for (byte bit = 0; bit < 64; bit++)
                        if ((mask & (1UL << bit)) != 0) found.Add((group, bit, core, efficiency));
                }
                core++;
            }
            offset += size;
        }
        return found.OrderBy(p => p.Group).ThenBy(p => p.Number)
            .Select((p, i) => new LogicalProcessor(i, p.Group, p.Number, p.Core, p.Efficiency)).ToList();
    }

    private const int RelationProcessorCore = 0;

    [StructLayout(LayoutKind.Sequential)]
    private struct GroupAffinity
    {
        public UIntPtr Mask;
        public ushort Group;
        public ushort Reserved0, Reserved1, Reserved2;
    }

    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern IntPtr GetCurrentThread();

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetThreadGroupAffinity(IntPtr thread, ref GroupAffinity affinity, out GroupAffinity previous);

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetLogicalProcessorInformationEx(int relationship, byte[]? buffer, ref uint length);
}
