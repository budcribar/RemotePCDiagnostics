using RemotePCDiagnostics.Core.Logging;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Changes;

/// <summary>
/// The undo journal as the Agent reads it, for an app that isn't elevated and so can't open the state folder itself. It holds the
/// records the Agent returned; taking an undone record off goes to the Agent too. It's for undoing only: recording new changes
/// isn't supported.
/// </summary>
public sealed class AgentChangeJournal : IChangeJournal
{
    private readonly IElevatedCommandBridge _agent;
    private readonly ILogger? _log;
    private readonly object _gate = new();
    private readonly List<ChangeRecord> _items;

    private AgentChangeJournal(IElevatedCommandBridge agent, IReadOnlyList<ChangeRecord> items, ILogger? log)
    {
        _agent = agent;
        _items = [.. items];
        _log = log;
    }

    public event Action? Changed;

    /// <summary>The journal read through <paramref name="agent"/>, or null when the Agent couldn't read it (not connected, or too old).</summary>
    public static async Task<AgentChangeJournal?> LoadAsync(IElevatedCommandBridge agent, ILogger? log = null, CancellationToken ct = default)
    {
        if (!agent.IsConnected) return null;
        var items = await agent.ReadChangeJournalAsync(ct).ConfigureAwait(false);
        return items is null ? null : new AgentChangeJournal(agent, items, log);
    }

    public IReadOnlyList<ChangeRecord> All { get { lock (_gate) return _items.ToList(); } }

    public void Add(ChangeRecord r) => throw new NotSupportedException("Changes are recorded by the app, not through the Agent's undo journal.");

    /// <summary>Takes the record off here and asks the Agent to take it off the file. When the Agent can't, it stays in the file for a later undo.</summary>
    public void Remove(Guid id)
    {
        lock (_gate) _items.RemoveAll(x => x.Id == id);
        bool removed;
        try { removed = Task.Run(() => _agent.RemoveJournalChangeAsync(id)).GetAwaiter().GetResult(); }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.Warn($"[undo] The Agent couldn't take {id} off the journal: {ex.Message}"); removed = false; }
        if (!removed) _log.Warn($"[undo] Change {id} was undone but is still in the journal; a later undo will try it again.");
        try { Changed?.Invoke(); } catch { }
    }

    public void RemoveLatest(ChangeKind kind, string target)
    {
        ChangeRecord? latest;
        lock (_gate) latest = _items.LastOrDefault(x => x.Kind == kind && string.Equals(x.Target, target, StringComparison.OrdinalIgnoreCase));
        if (latest is not null) Remove(latest.Id);
    }
}
