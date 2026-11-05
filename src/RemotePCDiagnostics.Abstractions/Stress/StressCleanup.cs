namespace RemotePCDiagnostics.Core.Stress;

/// <summary>
/// Things a running stress test has acquired and must give back (stop worker threads, kill a helper process, delete a temp file,
/// release a device). The test registers each one as soon as it has it; the test runner calls <see cref="RunAsync"/> when the test
/// finishes, is stopped, errors, or hangs and is abandoned. Runs the actions newest first, each at most once, and never throws,
/// so calling it again (or after the test's own cleanup already ran) does nothing.
/// </summary>
public sealed class StressCleanup(ILogger? log = null)
{
    private readonly object _gate = new();
    private readonly List<(string Name, Func<Task> Action)> _items = [];

    public void Register(string name, Action action) => Register(name, () => { action(); return Task.CompletedTask; });

    public void Register(string name, Func<Task> action)
    {
        lock (_gate) _items.Add((name, action));
    }

    /// <summary>Number of cleanup actions still waiting to run.</summary>
    public int Pending { get { lock (_gate) return _items.Count; } }

    public async Task RunAsync()
    {
        while (true)
        {
            (string Name, Func<Task> Action) item;
            lock (_gate)
            {
                if (_items.Count == 0) return;
                item = _items[^1];
                _items.RemoveAt(_items.Count - 1);
            }
            try { await item.Action().ConfigureAwait(false); }
            catch (Exception ex) { log.Warn($"Stress cleanup: {item.Name} failed: {ex.Message}"); }
        }
    }
}
