namespace RemotePCDiagnostics.Core.Optimizations;

/// <summary>
/// Remembers the last storage cleanup scan for a few minutes. The scan sizes large folders file by file (NuGet packages,
/// %TEMP%, browser caches), so it runs only when asked for and repeat views reuse the result.
/// </summary>
public sealed class StorageCleanupCache(Func<CancellationToken, Task<IReadOnlyList<StorageCleanupItem>>> scan, TimeSpan? ttl = null, Func<DateTimeOffset>? clock = null)
{
    public static readonly TimeSpan DefaultTtl = TimeSpan.FromMinutes(5);
    private readonly SemaphoreSlim _gate = new(1, 1);
    private (DateTimeOffset At, IReadOnlyList<StorageCleanupItem> Items)? _last;

    private DateTimeOffset Now => clock?.Invoke() ?? DateTimeOffset.UtcNow;

    /// <param name="refresh">Scan again even if the last result is recent (e.g. right after a cleanup ran).</param>
    public async Task<IReadOnlyList<StorageCleanupItem>> GetAsync(bool refresh = false, CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (!refresh && _last is { } l && Now - l.At < (ttl ?? DefaultTtl)) return l.Items;
            var items = await scan(ct).ConfigureAwait(false);
            _last = (Now, items);
            return items;
        }
        finally { _gate.Release(); }
    }

    /// <summary>Forget the last result (call after deleting anything the scan measures).</summary>
    public void Invalidate()
    {
        _gate.Wait();
        try { _last = null; } finally { _gate.Release(); }
    }
}
