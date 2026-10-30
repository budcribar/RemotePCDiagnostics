using System.Globalization;

namespace RemotePCDiagnostics.Core.Stress;

public enum MemoryPattern { Zeros, Ones, Alternating10, Alternating01, WalkingOnes }

/// <summary>Test patterns written to and read back from memory, 64 bits at a time.</summary>
public static class MemoryPatterns
{
    public static readonly MemoryPattern[] All = [MemoryPattern.Zeros, MemoryPattern.Ones, MemoryPattern.Alternating10, MemoryPattern.Alternating01, MemoryPattern.WalkingOnes];

    /// <summary>Expected value of word <paramref name="index"/> for a pattern (walking ones shifts a single 1 bit through each word).</summary>
    public static ulong Expected(MemoryPattern p, long index) => p switch
    {
        MemoryPattern.Zeros => 0UL,
        MemoryPattern.Ones => ulong.MaxValue,
        MemoryPattern.Alternating10 => 0xAAAAAAAAAAAAAAAAUL,
        MemoryPattern.Alternating01 => 0x5555555555555555UL,
        _ => 1UL << (int)(index & 63),
    };

    /// <summary>Fills <paramref name="words"/>; <paramref name="baseIndex"/> is the global word index of words[0].</summary>
    public static void Fill(Span<ulong> words, MemoryPattern p, long baseIndex)
    {
        if (p != MemoryPattern.WalkingOnes) { words.Fill(Expected(p, 0)); return; }
        for (int i = 0; i < words.Length; i++) words[i] = 1UL << (int)((baseIndex + i) & 63);
    }

    /// <summary>Counts words that don't match; calls <paramref name="onBad"/> for each (global word index, expected, actual).</summary>
    public static long Verify(ReadOnlySpan<ulong> words, MemoryPattern p, long baseIndex, Action<long, ulong, ulong>? onBad = null)
    {
        long bad = 0;
        if (p != MemoryPattern.WalkingOnes)
        {
            var e = Expected(p, 0);
            int i = words.IndexOfAnyExcept(e);
            while (i >= 0)
            {
                bad++; onBad?.Invoke(baseIndex + i, e, words[i]);
                var rest = words[(i + 1)..].IndexOfAnyExcept(e);
                i = rest < 0 ? -1 : i + 1 + rest;
            }
            return bad;
        }
        for (int i = 0; i < words.Length; i++)
        {
            var e = 1UL << (int)((baseIndex + i) & 63);
            if (words[i] != e) { bad++; onBad?.Invoke(baseIndex + i, e, words[i]); }
        }
        return bad;
    }
}

/// <summary>How much memory to test.</summary>
public enum MemoryTestMode { Quick, Full }

public static class MemorySizing
{
    public const long MB = 1024L * 1024, GB = 1024 * MB;
    public const long ChunkBytes = 64 * MB;
    public const long MinTestBytes = 64 * MB;
    public const double QuickFraction = 0.10, FullFraction = 0.80;
    public const long QuickCap = 2 * GB;
    public const long QuickReserve = 1 * GB, FullReserve = 2 * GB;

    /// <summary>
    /// Quick: min(10% of available, 2 GB). Full: up to 80% of available. Both always leave the reserve
    /// (1 GB quick, 2 GB full) of available memory untouched. Rounded down to whole 64 MB chunks; null when too little is free.
    /// </summary>
    public static long? Plan(long availableBytes, MemoryTestMode mode)
    {
        long size = mode == MemoryTestMode.Quick
            ? Math.Min(Math.Min((long)(availableBytes * QuickFraction), QuickCap), availableBytes - QuickReserve)
            : Math.Min((long)(availableBytes * FullFraction), availableBytes - FullReserve);
        size -= size % ChunkBytes;
        return size >= MinTestBytes ? size : null;
    }
}

/// <summary>Line protocol between the app and the memory test helper process (stdout, one message per line).</summary>
public abstract record MemTestMessage
{
    public const string Prefix = "MT ";

    public sealed record Allocated(long Bytes) : MemTestMessage;
    /// <summary>Pass = completed full pattern passes so far; Fraction = progress through the current pass.</summary>
    public sealed record Progress(int Pass, string Pattern, double Fraction, long Errors) : MemTestMessage;
    public sealed record BadWord(long Offset, ulong Expected, ulong Actual) : MemTestMessage;
    public sealed record Done(long Bytes, int Passes, long Errors) : MemTestMessage;
    public sealed record Fail(string Reason) : MemTestMessage;

    private static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

    public string Format() => this switch
    {
        Allocated a => $"{Prefix}ALLOC {a.Bytes.ToString(Inv)}",
        Progress p => $"{Prefix}PROGRESS {p.Pass.ToString(Inv)} {p.Pattern} {p.Fraction.ToString("0.####", Inv)} {p.Errors.ToString(Inv)}",
        BadWord b => $"{Prefix}BAD {b.Offset.ToString(Inv)} {b.Expected:X16} {b.Actual:X16}",
        Done d => $"{Prefix}DONE {d.Bytes.ToString(Inv)} {d.Passes.ToString(Inv)} {d.Errors.ToString(Inv)}",
        Fail f => $"{Prefix}FAIL {f.Reason.ReplaceLineEndings(" ")}",
        _ => throw new InvalidOperationException(),
    };

    /// <summary>Parses one line; null for anything that isn't a well-formed protocol message (ignored, logged by the caller).</summary>
    public static MemTestMessage? Parse(string? line)
    {
        if (line is null || !line.StartsWith(Prefix, StringComparison.Ordinal)) return null;
        var parts = line[Prefix.Length..].Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0) return null;
        try
        {
            return parts[0] switch
            {
                "ALLOC" when parts.Length == 2 => new Allocated(long.Parse(parts[1], Inv)),
                "PROGRESS" when parts.Length == 5 => new Progress(int.Parse(parts[1], Inv), parts[2], double.Parse(parts[3], Inv), long.Parse(parts[4], Inv)),
                "BAD" when parts.Length == 4 => new BadWord(long.Parse(parts[1], Inv), ulong.Parse(parts[2], NumberStyles.HexNumber, Inv), ulong.Parse(parts[3], NumberStyles.HexNumber, Inv)),
                "DONE" when parts.Length == 4 => new Done(long.Parse(parts[1], Inv), int.Parse(parts[2], Inv), long.Parse(parts[3], Inv)),
                "FAIL" => new Fail(string.Join(' ', parts.Skip(1))),
                _ => null,
            };
        }
        catch (FormatException) { return null; }
        catch (OverflowException) { return null; }
    }
}
