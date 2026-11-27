using System.Text.Json.Serialization;

namespace RemotePCDiagnostics.Core.GpuMemory;

/// <summary>Quick (about 1.5 minutes per graphics chip) or Extended (about 10 minutes per graphics chip, with moving inversions).</summary>
[JsonConverter(typeof(JsonStringEnumConverter<GpuMemoryMode>))]
public enum GpuMemoryMode { Quick, Extended }

/// <summary>What one pattern writes into each 32-bit word (see <see cref="GpuMemoryKernel.Expected"/>).</summary>
[JsonConverter(typeof(JsonStringEnumConverter<GpuMemoryPattern>))]
public enum GpuMemoryPattern
{
    /// <summary>One bit set, moving one place per word (finds bits stuck at 0 and shorted neighbours).</summary>
    WalkingOnes,
    /// <summary>One bit clear, moving one place per word (finds bits stuck at 1).</summary>
    WalkingZeros,
    /// <summary>Each word holds its own address (finds address lines that alias two locations).</summary>
    OwnAddress,
    /// <summary>A hash of the address and a seed (finds data-dependent faults).</summary>
    Random,
    /// <summary>The same 32-bit value in every word (the moving inversions' backgrounds).</summary>
    Solid,
}

/// <summary>One dispatch over one block: write the pattern, check it, or check it and then write its complement (a moving inversion).</summary>
public enum GpuMemoryOp { Write, Verify, VerifyThenInvert }

/// <summary>
/// One graphics adapter as the memory test sees it. <see cref="DedicatedBytes"/> is the adapter's own video memory (DXGI);
/// <see cref="BudgetBytes"/> and <see cref="UsageBytes"/> are what Windows lets this app use right now and what is already used (DXGI 1.4,
/// local segment: on an integrated GPU that is the shared system memory). Null when Windows doesn't say.
/// </summary>
public sealed record GpuMemoryAdapter(
    string Id, string Name, uint VendorId, long DedicatedBytes, long SharedBytes, bool Integrated, long? BudgetBytes = null, long? UsageBytes = null)
{
    public long? FreeBytes => BudgetBytes is > 0 and var b ? Math.Max(0, b - (UsageBytes ?? 0)) : null;
}

/// <summary>A word that didn't hold what was written. <see cref="ByteOffset"/> counts from the start of all the memory the test allocated.</summary>
public sealed record GpuMemoryError(long ByteOffset, uint Expected, uint Actual, GpuMemoryPattern Pattern, int Pass)
{
    /// <summary>The bits that came back wrong.</summary>
    public uint FlippedBits => Expected ^ Actual;
}

/// <summary>What one dispatch found: how many words were wrong (all of them, counted on the GPU) and the first few, with their word index in the block.</summary>
public sealed record GpuBlockResult(long Errors, IReadOnlyList<GpuWordError> First)
{
    public static readonly GpuBlockResult Clean = new(0, []);
}

/// <summary>One wrong word in a block, as the GPU reported it.</summary>
public sealed record GpuWordError(uint Word, uint Expected, uint Actual);

/// <summary>How one graphics chip's test ended.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<GpuMemoryOutcome>))]
public enum GpuMemoryOutcome { Passed, ErrorsFound, DriverReset, Hung, Overheated, Cancelled, CouldNotRun, NotSupported }

/// <summary>One graphics chip's result: what was tested, how often, and what went wrong.</summary>
public sealed record GpuMemoryAdapterResult(
    GpuMemoryAdapter Adapter, GpuMemoryOutcome Outcome, GpuMemoryMode Mode, long MemoryBytes, long PlannedBytes, long TestedBytes, int Blocks,
    int Passes, long Errors, IReadOnlyList<GpuMemoryError> FirstErrors, uint FlippedBits, double? MaxTemperatureC, double? StartTemperatureC,
    TimeSpan Ran, string? Reason = null)
{
    /// <summary>The share of the chip's memory that was tested (0..1).</summary>
    public double TestedFraction => MemoryBytes <= 0 ? 0 : Math.Clamp((double)TestedBytes / MemoryBytes, 0, 1);
    public long TestedMb => TestedBytes / GpuMemoryPlan.MB;
}

/// <summary>Live progress of one chip's test.</summary>
public sealed record GpuMemoryProgress(string Adapter, int AdapterIndex, int AdapterCount, TimeSpan Elapsed, TimeSpan Duration, int Pass, long TestedBytes, long Errors, double? TemperatureC)
{
    public double Fraction => Duration <= TimeSpan.Zero ? 1 : Math.Clamp(Elapsed / Duration, 0, 1);
}

/// <summary>Timing and limits of the test. The defaults are the product; tests shrink them.</summary>
public sealed record GpuMemoryOptions
{
    public GpuMemoryMode Mode { get; init; } = GpuMemoryMode.Quick;
    /// <summary>How long each chip is tested; null = <see cref="DefaultDuration"/>. Whole passes only: a pass that is going finishes.</summary>
    public TimeSpan? Duration { get; init; }
    /// <summary>One block (one D3D11 buffer). Well under D3D11's smallest per-resource limit (128 MB).</summary>
    public long BlockBytes { get; init; } = 64 * GpuMemoryPlan.MB;
    /// <summary>A single dispatch that hasn't come back after this long means the GPU hung (Windows normally resets it after 2 s).</summary>
    public TimeSpan OpWatchdog { get; init; } = TimeSpan.FromSeconds(30);
    public TimeSpan SensorInterval { get; init; } = TimeSpan.FromSeconds(2);
    /// <summary>Wrong words kept with their offsets (all are counted).</summary>
    public int MaxRecordedErrors { get; init; } = 16;

    public TimeSpan EffectiveDuration => Duration ?? DefaultDuration(Mode);
    public static TimeSpan DefaultDuration(GpuMemoryMode mode) => mode == GpuMemoryMode.Extended ? TimeSpan.FromMinutes(10) : TimeSpan.FromSeconds(90);
}

/// <summary>How much of a chip's memory to test.</summary>
public static class GpuMemoryPlan
{
    public const long MB = 1024 * 1024;
    /// <summary>The share of free memory the test takes (the desktop and other apps keep the rest).</summary>
    public const double FreeShare = 0.8;
    /// <summary>Below this share of the chip's memory tested, the result is a Warning: too little was covered to clear it.</summary>
    public const double WarnBelowFraction = 0.25;
    /// <summary>An integrated GPU's "video memory" is system memory: test at most this much of it.</summary>
    public const long IntegratedCap = 2048 * MB;
    /// <summary>Smaller than this is not worth testing (the desktop needs the memory).</summary>
    public const long MinBytes = 64 * MB;

    /// <summary>The memory the verdict is measured against: the dedicated memory of a discrete GPU, the capped shared budget of an integrated one.</summary>
    public static long MemoryBytes(GpuMemoryAdapter a) => a.Integrated
        ? Math.Min(IntegratedCap, a.BudgetBytes is > 0 and var b ? b : (a.SharedBytes > 0 ? a.SharedBytes : IntegratedCap))
        : a.DedicatedBytes;

    /// <summary>Bytes to allocate: 80 % of what is free (capped for integrated GPUs), whole blocks only, never more than the chip's memory.</summary>
    public static long Target(GpuMemoryAdapter a, long blockBytes)
    {
        var memory = MemoryBytes(a);
        // Without a budget from Windows, assume a busy desktop is using a third of it.
        var free = a.FreeBytes ?? memory * 2 / 3;
        var target = (long)(Math.Min(free, memory) * FreeShare);
        if (a.Integrated) target = Math.Min(target, IntegratedCap);
        if (target < MinBytes) return 0;
        return Math.Max(blockBytes, target / blockBytes * blockBytes);
    }
}

/// <summary>One step of a pass: write a pattern into every block, then check every block. A moving inversion checks and complements upwards,
/// checks and complements back downwards, then checks once more.</summary>
public sealed record GpuMemoryStep(GpuMemoryPattern Pattern, uint Seed, bool MovingInversion = false)
{
    public string Label => MovingInversion ? $"Moving inversions ({PatternName(Pattern)})" : PatternName(Pattern);

    public static string PatternName(GpuMemoryPattern p) => p switch
    {
        GpuMemoryPattern.WalkingOnes => "Walking ones",
        GpuMemoryPattern.WalkingZeros => "Walking zeros",
        GpuMemoryPattern.OwnAddress => "Address in address",
        GpuMemoryPattern.Random => "Random",
        _ => "Solid",
    };

    /// <summary>The steps of pass <paramref name="pass"/> (0-based). Each pass moves the walking bit and changes the random seed, so
    /// repeated passes don't write the same values.</summary>
    public static IReadOnlyList<GpuMemoryStep> ForPass(GpuMemoryMode mode, int pass)
    {
        var p = (uint)pass;
        var seed = unchecked(0x2545F491u * (p + 1));
        var steps = new List<GpuMemoryStep>
        {
            new(GpuMemoryPattern.WalkingOnes, p),
            new(GpuMemoryPattern.WalkingZeros, p),
            new(GpuMemoryPattern.OwnAddress, p % 2 == 0 ? 0u : 0xFFFFFFFFu),
            new(GpuMemoryPattern.Random, seed),
        };
        if (mode == GpuMemoryMode.Extended)
        {
            uint[] backgrounds = [0x00000000u, 0x55555555u, 0x33333333u, 0x0F0F0F0Fu, 0x00FF00FFu];
            steps.Add(new(GpuMemoryPattern.Solid, backgrounds[pass % backgrounds.Length], MovingInversion: true));
            steps.Add(new(GpuMemoryPattern.Random, ~seed, MovingInversion: true));
        }
        return steps;
    }
}

/// <summary>
/// The compute kernel, as HLSL (run on the GPU) and as the same function in C# (the reference the tests and the CPU side use). One
/// dispatch covers one block: each thread walks the block with a grid stride. A check counts every wrong word on the GPU and records the
/// first few, so only a few hundred bytes come back per block rather than the block itself.
/// </summary>
public static class GpuMemoryKernel
{
    public const int GroupSize = 256;
    /// <summary>Thread groups per dispatch (a grid stride loop covers the rest of the block).</summary>
    public const int MaxGroups = 4096;
    /// <summary>Wrong words the GPU records per dispatch (it counts all of them).</summary>
    public const int MaxRecords = 16;
    /// <summary>Length of the error buffer in uints: the count, then (word, expected, actual) per record.</summary>
    public const int ErrorBufferLength = 1 + MaxRecords * 3;

    public const uint FlagVerify = 1, FlagInverted = 2, FlagThenInvert = 4;

    public const string Hlsl = """
        cbuffer Params : register(b0) { uint g_pattern; uint g_seed; uint g_flags; uint g_base; uint g_words; uint g_stride; uint g_pad0; uint g_pad1; };
        RWStructuredBuffer<uint> g_mem : register(u0);
        RWStructuredBuffer<uint> g_err : register(u1);
        uint Hash(uint x) { x ^= x >> 16; x *= 0x7FEB352Du; x ^= x >> 15; x *= 0x846CA68Bu; x ^= x >> 16; return x; }
        uint Expected(uint pattern, uint word, uint seed)
        {
            if (pattern == 0) return 1u << ((word + seed) & 31u);
            if (pattern == 1) return ~(1u << ((word + seed) & 31u));
            if (pattern == 2) return (word << 2) ^ seed;
            if (pattern == 3) return Hash(word ^ (seed * 0x9E3779B9u));
            return seed;
        }
        [numthreads(256, 1, 1)]
        void main(uint3 id : SV_DispatchThreadID)
        {
            for (uint i = id.x; i < g_words; i += g_stride)
            {
                uint e = Expected(g_pattern, g_base + i, g_seed);
                if (g_flags & 2u) e = ~e;
                if (g_flags & 1u)
                {
                    uint a = g_mem[i];
                    if (a != e)
                    {
                        uint n;
                        InterlockedAdd(g_err[0], 1u, n);
                        if (n < 16u) { g_err[1 + n * 3] = i; g_err[2 + n * 3] = e; g_err[3 + n * 3] = a; }
                    }
                    if (g_flags & 4u) g_mem[i] = ~e;
                }
                else
                {
                    g_mem[i] = e;
                }
            }
        }
        """;

    public static uint Hash(uint x)
    {
        unchecked
        {
            x ^= x >> 16; x *= 0x7FEB352Du; x ^= x >> 15; x *= 0x846CA68Bu; x ^= x >> 16;
            return x;
        }
    }

    /// <summary>The value word <paramref name="word"/> (counted over all blocks) holds for this pattern and seed, before any inversion.</summary>
    public static uint Expected(GpuMemoryPattern pattern, uint word, uint seed) => unchecked(pattern switch
    {
        GpuMemoryPattern.WalkingOnes => 1u << (int)((word + seed) & 31u),
        GpuMemoryPattern.WalkingZeros => ~(1u << (int)((word + seed) & 31u)),
        GpuMemoryPattern.OwnAddress => (word << 2) ^ seed,
        GpuMemoryPattern.Random => Hash(word ^ (seed * 0x9E3779B9u)),
        _ => seed,
    });

    public static uint Flags(GpuMemoryOp op, bool inverted) =>
        (op == GpuMemoryOp.Write ? 0 : FlagVerify) | (inverted ? FlagInverted : 0) | (op == GpuMemoryOp.VerifyThenInvert ? FlagThenInvert : 0);

    /// <summary>Thread groups and the grid stride for a block of <paramref name="words"/> words.</summary>
    public static (uint Groups, uint Stride) Dispatch(long words)
    {
        var groups = (uint)Math.Clamp((words + GroupSize - 1) / GroupSize, 1, MaxGroups);
        return (groups, groups * GroupSize);
    }

    /// <summary>Reads the error buffer the kernel wrote.</summary>
    public static GpuBlockResult Decode(ReadOnlySpan<uint> err)
    {
        if (err.Length == 0 || err[0] == 0) return GpuBlockResult.Clean;
        var n = (int)Math.Min(err[0], MaxRecords);
        var first = new List<GpuWordError>(n);
        for (var i = 0; i < n && 3 + i * 3 < err.Length; i++) first.Add(new(err[1 + i * 3], err[2 + i * 3], err[3 + i * 3]));
        return new(err[0], first);
    }
}
