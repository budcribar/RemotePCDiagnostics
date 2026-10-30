using System.Runtime.InteropServices;

namespace RemotePCDiagnostics.Core.Stress;

/// <summary>A block of memory under test.</summary>
public interface IMemoryBlock : IDisposable
{
    Span<ulong> Words { get; }
}

public sealed class ArrayMemoryBlock(long words) : IMemoryBlock
{
    private readonly ulong[] _a = new ulong[words];
    public Span<ulong> Words => _a;
    public void Dispose() { }
}

/// <summary>Native (non-GC) memory, committed by touching every page.</summary>
public sealed unsafe class NativeMemoryBlock : IMemoryBlock
{
    private void* _p;
    private readonly int _words;
    public NativeMemoryBlock(long bytes)
    {
        _words = checked((int)(bytes / sizeof(ulong)));
        _p = NativeMemory.AlignedAlloc((nuint)bytes, 4096);
        try { new Span<ulong>(_p, _words).Clear(); }
        catch { NativeMemory.AlignedFree(_p); _p = null; throw; }
    }
    ~NativeMemoryBlock() => Free();
    public Span<ulong> Words => new(_p, _words);
    public void Dispose() { Free(); GC.SuppressFinalize(this); }
    private void Free() { if (_p != null) { NativeMemory.AlignedFree(_p); _p = null; } }
}

/// <summary>
/// Runs pattern passes over memory blocks until the deadline or cancellation: for each pattern, fill every block,
/// then read every block back and verify. Used by the helper process; testable with array blocks.
/// </summary>
public sealed class MemorySweep(IReadOnlyList<IMemoryBlock> blocks, Func<bool> shouldStop, Action<MemTestMessage> emit)
{
    /// <summary>Test hook: runs after a pattern is written and before it is verified.</summary>
    public Action<MemoryPattern>? AfterFill { get; init; }
    public int MaxBadReports { get; init; } = 20;
    public int ProgressEveryBlocks { get; init; } = 1;

    public MemTestMessage.Done Run()
    {
        long totalWords = blocks.Sum(b => (long)b.Words.Length), errors = 0, reported = 0;
        int passes = 0, steps = blocks.Count * 2, patternsDone = 0;
        while (!shouldStop())
        {
            foreach (var p in MemoryPatterns.All)
            {
                long baseIdx = 0;
                for (int i = 0; i < blocks.Count; i++)
                {
                    if (shouldStop()) goto done;
                    MemoryPatterns.Fill(blocks[i].Words, p, baseIdx);
                    baseIdx += blocks[i].Words.Length;
                    Report(p, i + 1);
                }
                AfterFill?.Invoke(p);
                baseIdx = 0;
                for (int i = 0; i < blocks.Count; i++)
                {
                    if (shouldStop()) goto done;
                    errors += MemoryPatterns.Verify(blocks[i].Words, p, baseIdx, (idx, e, a) =>
                    {
                        if (reported++ < MaxBadReports) emit(new MemTestMessage.BadWord(idx * sizeof(ulong), e, a));
                    });
                    baseIdx += blocks[i].Words.Length;
                    Report(p, blocks.Count + i + 1);
                }
                patternsDone++;
            }
            passes++;
        }
    done:
        // Whole passes, or 1 if at least one complete pattern was checked (short time limits).
        var done = new MemTestMessage.Done(totalWords * sizeof(ulong), passes > 0 ? passes : patternsDone > 0 ? 1 : 0, errors);
        emit(done);
        return done;

        void Report(MemoryPattern p, int step)
        {
            if (step % ProgressEveryBlocks == 0 || step == steps)
                emit(new MemTestMessage.Progress(passes, p.ToString(), (double)(patternsDone % MemoryPatterns.All.Length * steps + step) / (steps * MemoryPatterns.All.Length), errors));
        }
    }
}
