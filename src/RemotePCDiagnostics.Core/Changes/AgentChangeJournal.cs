using System.Text.Json;
using RemotePCDiagnostics.Core.Logging;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Changes;

/// <summary>
/// The undo journal for the app, which isn't elevated and so can't open the state folder (only administrators can). The Agent reads
/// it, records each change the app makes and takes off the ones it undid. While the Agent isn't connected, changes are kept here and
/// sent once it connects; then the saved journal is read again.
/// </summary>
/// <remarks>
/// <paramref name="fallbackPath"/> is the journal file itself, used only while the Agent isn't connected and this process can open it:
/// an app the restart-resume task started with administrator rights. A standard-user app can't, and leaves it alone.
/// </remarks>
public sealed class AgentChangeJournal : IChangeJournal, IDisposable
{
    private readonly IElevatedCommandBridge _agent;
    private readonly IElevationContext? _connection;
    private readonly string? _fallbackPath;
    private readonly ILogger? _log;
    private readonly object _gate = new();
    private readonly SemaphoreSlim _sync = new(1, 1);
    private List<ChangeRecord> _items = [];
    /// <summary>Records and removals the Agent hasn't saved yet, oldest first.</summary>
    private readonly List<(ChangeRecord? Add, Guid? Remove)> _unsent = [];
    private bool _loaded, _fromFile, _wasConnected;
    /// <summary>Counts this app's records and removals, so a read that crossed one is done again instead of dropping it.</summary>
    private int _version;

    public AgentChangeJournal(IElevatedCommandBridge agent, IElevationContext? connection = null, string? fallbackPath = null, ILogger? log = null)
        : this(agent, connection, fallbackPath, log, syncNow: true) { }

    private AgentChangeJournal(IElevatedCommandBridge agent, IElevationContext? connection, string? fallbackPath, ILogger? log, bool syncNow)
    {
        _agent = agent;
        _connection = connection;
        _fallbackPath = fallbackPath;
        _log = log;
        if (_connection is not null) _connection.Changed += OnConnectionChanged;
        _wasConnected = agent.IsConnected;
        if (!_wasConnected) TryLoadFile();
        else if (syncNow) _ = Task.Run(() => SyncAsync());
    }

    public event Action? Changed;

    private System.Collections.Immutable.ImmutableArray<ChangeRecord> _allSnapshot = [];

    public bool IsLoaded { get { lock (_gate) return _loaded; } }

    public IReadOnlyList<ChangeRecord> All { get { lock (_gate) return _allSnapshot; } }

    /// <summary>Unsaved records and removals waiting for the Agent (tests and logs).</summary>
    public int UnsentCount { get { lock (_gate) return _unsent.Count; } }

    /// <summary>The journal read through <paramref name="agent"/>, or null when the Agent couldn't read it (not connected, or too old).</summary>
    public static async Task<AgentChangeJournal?> LoadAsync(IElevatedCommandBridge agent, ILogger? log = null, CancellationToken ct = default)
    {
        if (!agent.IsConnected) return null;
        var journal = new AgentChangeJournal(agent, null, null, log, syncNow: false);
        await journal.SyncAsync(ct).ConfigureAwait(false);
        return journal.IsLoaded ? journal : null;
    }

    public void Add(ChangeRecord r)
    {
        lock (_gate)
        {
            // Only the oldest "before" matters for a target (as in the file journal): undo returns to the state before this app touched it.
            if (_items.Any(x => x.Kind == r.Kind && string.Equals(x.Target, r.Target, StringComparison.OrdinalIgnoreCase))) return;
            _items.Add(r);
            _allSnapshot = [.. _items];
            _version++;
        }
        Save((r, null));
        Raise();
    }

    public void Remove(Guid id)
    {
        lock (_gate) { _items.RemoveAll(x => x.Id == id); _allSnapshot = [.. _items]; _version++; }
        Save((null, id));
        Raise();
    }

    public void RemoveLatest(ChangeKind kind, string target)
    {
        ChangeRecord? latest;
        lock (_gate) latest = _items.LastOrDefault(x => x.Kind == kind && string.Equals(x.Target, target, StringComparison.OrdinalIgnoreCase));
        if (latest is not null) Remove(latest.Id);
    }

    /// <summary>Sends what's waiting, then reads the saved journal again. Runs whenever the Agent connects.</summary>
    public async Task SyncAsync(CancellationToken ct = default)
    {
        await _sync.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            while (true)
            {
                (ChangeRecord? Add, Guid? Remove) next;
                lock (_gate) { if (_unsent.Count == 0) break; next = _unsent[0]; }
                if (!await SendAsync(next, ct).ConfigureAwait(false)) return; // tried again on the next connect
                lock (_gate) _unsent.RemoveAt(0);
            }
            for (var attempt = 0; attempt < 3; attempt++)
            {
                int before;
                lock (_gate) before = _version;
                var saved = await _agent.ReadChangeJournalAsync(ct).ConfigureAwait(false);
                if (saved is null) return;
                lock (_gate)
                {
                    if (_version != before) continue; // a record or removal crossed this read: read again
                    _items = [.. saved];
                    _allSnapshot = [.. _items];
                    _loaded = true;
                    _fromFile = false;
                }
                Raise();
                return;
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.Warn($"[undo] Reading the undo journal through the Agent failed: {ex.Message}"); }
        finally { _sync.Release(); }
    }

    private void Save((ChangeRecord? Add, Guid? Remove) op)
    {
        if (_agent.IsConnected)
        {
            bool sent;
            try { sent = Task.Run(() => SendAsync(op)).GetAwaiter().GetResult(); }
            catch (Exception ex) when (ex is not OperationCanceledException) { _log.Warn($"[undo] The Agent didn't save the undo journal: {ex.Message}"); sent = false; }
            if (sent) return;
        }
        bool fromFile;
        lock (_gate) fromFile = _fromFile;
        if (fromFile && TryWriteFile()) return;
        lock (_gate) _unsent.Add(op);
        _log.Warn(op.Add is { } a
            ? $"[undo] {a.Kind} '{a.Target}' is kept for now; it's saved in the undo journal once the Agent connects."
            : $"[undo] Change {op.Remove} was undone but is still in the saved journal; it's taken off once the Agent connects.");
    }

    private Task<bool> SendAsync((ChangeRecord? Add, Guid? Remove) op, CancellationToken ct = default) =>
        op.Add is { } add ? _agent.AddJournalChangeAsync(add, ct) : _agent.RemoveJournalChangeAsync(op.Remove!.Value, ct);

    private void OnConnectionChanged()
    {
        var now = _agent.IsConnected;
        var connectedNow = now && !_wasConnected;
        _wasConnected = now;
        if (connectedNow) _ = Task.Run(() => SyncAsync());
    }

    private void TryLoadFile()
    {
        if (string.IsNullOrEmpty(_fallbackPath)) return;
        try
        {
            var loaded = File.Exists(_fallbackPath)
                ? JsonSerializer.Deserialize<List<ChangeRecord>>(File.ReadAllText(_fallbackPath), FileChangeJournal.Json) ?? []
                : Directory.Exists(Path.GetDirectoryName(_fallbackPath)) && CanWriteNextTo(_fallbackPath) ? [] : null;
            if (loaded is null) return;
            lock (_gate) { _items = loaded; _allSnapshot = [.. _items]; _loaded = true; _fromFile = true; }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException) { /* a standard-user app: wait for the Agent */ }
    }

    private bool TryWriteFile()
    {
        try
        {
            string json;
            lock (_gate) json = JsonSerializer.Serialize(_items, FileChangeJournal.Json);
            var tmp = _fallbackPath + ".tmp";
            File.WriteAllText(tmp, json);
            File.Move(tmp, _fallbackPath!, overwrite: true);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            lock (_gate) _fromFile = false;
            _log.Warn($"[undo] Saving the undo journal failed: {ex.Message}");
            return false;
        }
    }

    /// <summary>Whether this process may create files in the (existing) state folder, without leaving anything behind.</summary>
    private static bool CanWriteNextTo(string path)
    {
        var probe = Path.Combine(Path.GetDirectoryName(path)!, $".probe-{Guid.NewGuid():N}");
        try { File.WriteAllText(probe, ""); File.Delete(probe); return true; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return false; }
    }

    private void Raise() { try { Changed?.Invoke(); } catch { } }

    public void Dispose()
    {
        if (_connection is not null) _connection.Changed -= OnConnectionChanged;
    }
}
