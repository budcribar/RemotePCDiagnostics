using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Logging;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Memory;

/// <summary>Before/after wording shown on a card after an action.</summary>
public static class MemoryFeedback
{
    public const long MeasurableBytes = 50L << 20;

    public static long Freed(MemoryReading before, MemoryReading after) => after.AvailableBytes - before.AvailableBytes;

    public static string Describe(MemoryReading? before, MemoryReading? after, bool deferred)
    {
        if (deferred) return "Takes effect next launch or after a restart; no change measured yet.";
        if (before is null || after is null) return "Couldn't measure memory before and after.";
        var delta = Freed(before, after);
        var range = $"Available RAM {MemoryText.Gb(before.AvailableBytes)} → {MemoryText.Gb(after.AvailableBytes)} GB (used {before.UsedPercent}% → {after.UsedPercent}%).";
        if (delta >= MeasurableBytes) return $"Freed about {MemoryText.Size(delta)}. {range}";
        if (delta <= -MeasurableBytes) return $"No memory freed: other apps used {MemoryText.Size(-delta)} more meanwhile. {range}";
        return $"No measurable change. {range}";
    }

    /// <summary>Whether an action's effect should show right away (closing/stopping) or only later (settings).</summary>
    public static bool IsDeferred(MemoryActionType t) => t is MemoryActionType.DisableStartup or MemoryActionType.EnableBrowserMemorySaver
        or MemoryActionType.SetServiceManual or MemoryActionType.SetServiceDisabled or MemoryActionType.OpenSettings;
}

public sealed record ActionOutcome(bool Success, string Message);

/// <summary>Host-side probes and actions (Windows implementation in the Host; fakes in tests). Methods may throw.</summary>
public interface IMemorySystem
{
    MemoryReading ReadMemory();
    Task<MemorySnapshot> CaptureAsync(IReadOnlyList<ServiceInfo> services, CancellationToken ct);
    /// <summary>Asks every window of the app to close (like clicking X). Never kills.</summary>
    Task<ActionOutcome> CloseAppAsync(string processName, CancellationToken ct);
    /// <summary>Ends the app's processes. Only called after a graceful close failed and the user clicked Force close.</summary>
    Task<ActionOutcome> ForceCloseAppAsync(string processName, CancellationToken ct);
    Task<ActionOutcome> RunCommandAsync(string fileName, IReadOnlyList<string> args, CancellationToken ct);
    /// <summary>HKCU StartupApproved\Run raw value (null = not present).</summary>
    byte[]? GetStartupApproved(string name);
    /// <summary>Writes (or deletes when null) the HKCU StartupApproved\Run value.</summary>
    void SetStartupApproved(string name, byte[]? value);
    bool IsBrowserRunning(BrowserKind kind);
    string? ReadBrowserLocalState(BrowserKind kind);
    void WriteBrowserLocalState(BrowserKind kind, string json);
    void OpenUri(string uri);
    /// <summary>"Automatic", "AutomaticDelayed", "Manual" or "Disabled".</summary>
    string GetServiceStartType(string name);
    void SetServiceStartType(string name, string startType);
}

public sealed record UndoEntry(string Id, string Label, MemoryActionType Type, string Target, string? Previous, byte[]? PreviousBytes = null);

public sealed record SuggestionResult(string SuggestionId, bool Success, string Message, DateTime When, bool CanForceClose = false);

/// <summary>
/// Scans, shows and applies memory suggestions. Every change runs only from an explicit click; each is logged to the Event Log (1400)
/// with the actor (Local/Remote technician) and, where possible, can be undone.
/// </summary>
public sealed class MemorySuggestionService(IMemorySystem sys, ServicesModule? services = null, ServiceActionService? serviceActions = null,
    ISessionContext? session = null, Action<LogLevel, string>? events = null, Action<string>? log = null, TimeSpan? settle = null, Func<DateTime>? now = null)
{
    public static readonly string[] StartTypes = ["Automatic", "AutomaticDelayed", "Manual", "Disabled"];
    private readonly TimeSpan _settle = settle ?? TimeSpan.FromSeconds(2.5);
    private readonly object _gate = new();
    private readonly Dictionary<string, SuggestionResult> _results = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<UndoEntry> _undo = [];
    private readonly List<SuggestionResult> _recent = [];

    public event Action? Changed;
    public MemorySnapshot? Snapshot { get; private set; }
    public IReadOnlyList<MemorySuggestion> Suggestions { get; private set; } = [];
    public bool Scanning { get; private set; }
    public string? Busy { get; private set; }
    public string? ScanError { get; private set; }
    public long TotalFreedBytes { get; private set; }
    public IReadOnlyList<UndoEntry> Undos { get { lock (_gate) return _undo.ToList(); } }
    public IReadOnlyList<SuggestionResult> Recent { get { lock (_gate) return _recent.ToList(); } }
    public SuggestionResult? ResultFor(string id) { lock (_gate) return _results.GetValueOrDefault(id); }
    public UndoEntry? UndoFor(string id) { lock (_gate) return _undo.LastOrDefault(u => u.Id == id); }

    private string Actor => ServiceActor.From(session);
    private void Log(string m) => log?.Invoke("[memory] " + m);
    private void Raise() { try { Changed?.Invoke(); } catch (Exception ex) { Log("Changed handler failed: " + ex.Message); } }

    public async Task ScanAsync(CancellationToken ct = default)
    {
        if (Scanning) return;
        Scanning = true; ScanError = null; Raise();
        try
        {
            var svcList = services?.Latest.Values.ToList() ?? [];
            Snapshot = await sys.CaptureAsync(svcList, ct).ConfigureAwait(false);
            Suggestions = MemorySuggestionEngine.Build(Snapshot);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log("Scan failed: " + ex);
            ScanError = "Couldn't read what's using memory on this PC.";
        }
        finally { Scanning = false; Raise(); }
    }

    private MemoryReading? SafeRead() { try { return sys.ReadMemory(); } catch (Exception ex) { Log("ReadMemory failed: " + ex.Message); return null; } }

    /// <summary>Runs one action of one suggestion (explicit UI click only), measures memory before/after, logs 1400, rescans.</summary>
    public async Task<SuggestionResult> ApplyAsync(MemorySuggestion s, MemoryAction a, CancellationToken ct = default)
    {
        if (!s.Actions.Contains(a) && a.Type != MemoryActionType.ForceCloseApp) return Record(s.Id, new(false, "That action isn't available."), a, null);
        if (Busy is not null) return new(s.Id, false, "Another change is still running.", DateTime.Now);
        Busy = s.Id; Raise();
        try
        {
            var before = SafeRead();
            ActionOutcome outcome;
            try { outcome = await PerformAsync(s, a, ct).ConfigureAwait(false); }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Log($"{a.Type} '{a.Target}' failed: {ex}");
                outcome = new(false, "Windows didn't allow that change.");
            }
            string text = outcome.Message;
            if (outcome.Success && a.Type != MemoryActionType.OpenSettings)
            {
                var deferred = MemoryFeedback.IsDeferred(a.Type);
                MemoryReading? after = null;
                if (!deferred) { await Task.Delay(_settle, ct).ConfigureAwait(false); after = SafeRead(); }
                text += " " + MemoryFeedback.Describe(before, after, deferred);
                if (!deferred && before is not null && after is not null)
                    lock (_gate) TotalFreedBytes += Math.Max(0, MemoryFeedback.Freed(before, after));
            }
            var canForce = !outcome.Success && a.Type == MemoryActionType.CloseApp;
            var r = Record(s.Id, outcome with { Message = text }, a, null, canForce);
            if (a.Type != MemoryActionType.OpenSettings) await ScanAsync(ct).ConfigureAwait(false);
            return r;
        }
        finally { Busy = null; Raise(); }
    }

    public async Task<SuggestionResult> UndoAsync(UndoEntry u, CancellationToken ct = default)
    {
        lock (_gate) if (!_undo.Contains(u)) return new(u.Id, false, "Nothing to undo.", DateTime.Now);
        ActionOutcome outcome;
        try
        {
            switch (u.Type)
            {
                case MemoryActionType.DisableStartup:
                    sys.SetStartupApproved(u.Target, u.PreviousBytes);
                    outcome = new(true, $"{u.Label} will start with Windows again.");
                    break;
                case MemoryActionType.EnableBrowserMemorySaver:
                    var kind = Enum.Parse<BrowserKind>(u.Target);
                    if (sys.IsBrowserRunning(kind)) { outcome = new(false, $"Close {BrowserPrefs.Label(kind)} first, then undo."); break; }
                    sys.WriteBrowserLocalState(kind, u.Previous!);
                    outcome = new(true, $"{BrowserPrefs.FeatureName(kind)} setting restored for {BrowserPrefs.Label(kind)}.");
                    break;
                case MemoryActionType.SetServiceManual or MemoryActionType.SetServiceDisabled:
                    if (!StartTypes.Contains(u.Previous)) { outcome = new(false, "The original setting wasn't recorded."); break; }
                    sys.SetServiceStartType(u.Target, u.Previous!);
                    outcome = new(true, $"{u.Label} start-up setting restored to {u.Previous}.");
                    break;
                default:
                    outcome = new(false, "This change can't be undone from here.");
                    break;
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log($"Undo {u.Type} '{u.Target}' failed: {ex}");
            outcome = new(false, "Windows didn't allow undoing that change.");
        }
        if (outcome.Success) lock (_gate) _undo.Remove(u);
        Event(outcome.Success ? LogLevel.Information : LogLevel.Warning, $"Memory suggestion undone\r\nActor: {Actor}\r\nAction: {u.Type}\r\nTarget: {u.Target}\r\nResult: {(outcome.Success ? "Success" : "Failed")}\r\nMessage: {outcome.Message}");
        var r = new SuggestionResult(u.Id, outcome.Success, (outcome.Success ? "Undone: " : "") + outcome.Message, DateTime.Now);
        lock (_gate) { _results[u.Id] = r; _recent.Insert(0, r); }
        await ScanAsync(ct).ConfigureAwait(false);
        return r;
    }

    private SuggestionResult Record(string id, ActionOutcome o, MemoryAction a, UndoEntry? _, bool canForce = false)
    {
        var r = new SuggestionResult(id, o.Success, (o.Success ? "Done: " : "") + o.Message, DateTime.Now, canForce);
        lock (_gate)
        {
            _results[id] = r;
            _recent.Insert(0, r);
            if (_recent.Count > 20) _recent.RemoveAt(_recent.Count - 1);
        }
        Event(o.Success ? LogLevel.Information : LogLevel.Warning,
            $"Memory suggestion applied\r\nActor: {Actor}\r\nSuggestion: {id}\r\nAction: {a.Type}\r\nTarget: {a.Target}\r\nResult: {(o.Success ? "Success" : "Failed")}\r\nMessage: {r.Message}");
        return r;
    }

    private void Event(LogLevel l, string text) { try { events?.Invoke(l, text); } catch (Exception ex) { Log("Event write failed: " + ex.Message); } }

    private void AddUndo(UndoEntry u) { lock (_gate) { _undo.RemoveAll(x => x.Id == u.Id && x.Type == u.Type); _undo.Add(u); } }

    private async Task<ActionOutcome> PerformAsync(MemorySuggestion s, MemoryAction a, CancellationToken ct)
    {
        Log($"{Actor} clicked {a.Type} '{a.Target}' on suggestion '{s.Id}'");
        switch (a.Type)
        {
            case MemoryActionType.CloseApp or MemoryActionType.ForceCloseApp:
                if (ProtectedProcesses.IsProtected(a.Target)) return new(false, $"{MemoryText.FriendlyAppName(a.Target)} is part of Windows or this app and can't be closed from here.");
                if (Snapshot?.App(a.Target) is { IsService: true }) return new(false, "That's a background service, not an app.");
                return a.Type == MemoryActionType.CloseApp ? await sys.CloseAppAsync(a.Target, ct).ConfigureAwait(false) : await sys.ForceCloseAppAsync(a.Target, ct).ConfigureAwait(false);

            case MemoryActionType.ShutdownBuildServers:
                var cmd = MemoryCommandAllowlist.BuildServerShutdown;
                if (!MemoryCommandAllowlist.IsAllowed(cmd.FileName, cmd.Arguments)) return new(false, "Not allowed.");
                return await sys.RunCommandAsync(cmd.FileName, cmd.Arguments, ct).ConfigureAwait(false);

            case MemoryActionType.DisableStartup:
                if (Snapshot?.Startup?.FirstOrDefault(e => e.Name == a.Target) is not { } entry) return new(false, "That startup app is no longer listed.");
                var prev = sys.GetStartupApproved(entry.Name);
                sys.SetStartupApproved(entry.Name, StartupParsing.DisabledValue((now ?? (() => DateTime.UtcNow))()));
                AddUndo(new(s.Id, MemoryText.FriendlyAppName(entry.ExeName), a.Type, entry.Name, null, prev));
                return new(true, $"{MemoryText.FriendlyAppName(entry.ExeName)} won't start with Windows (your account only).");

            case MemoryActionType.EnableBrowserMemorySaver:
                var kind = Enum.Parse<BrowserKind>(a.Target);
                if (sys.IsBrowserRunning(kind)) return new(false, $"{BrowserPrefs.Label(kind)} is open. Use its settings page instead, or close it and try again.");
                var json = sys.ReadBrowserLocalState(kind);
                var updated = BrowserPrefs.EnableMemorySaver(json, kind);
                if (updated is null) return new(false, $"Couldn't find the {BrowserPrefs.FeatureName(kind)} setting; use {BrowserPrefs.Label(kind)}'s settings page.");
                sys.WriteBrowserLocalState(kind, updated);
                AddUndo(new(s.Id, BrowserPrefs.Label(kind), a.Type, a.Target, json));
                return new(true, $"{BrowserPrefs.FeatureName(kind)} turned on for {BrowserPrefs.Label(kind)}.");

            case MemoryActionType.OpenSettings:
                if (!MemoryCommandAllowlist.IsAllowedSettingsUri(a.Target)) return new(false, "Not allowed.");
                sys.OpenUri(a.Target);
                return new(true, "Opened the settings page on this PC.");

            case MemoryActionType.StopService or MemoryActionType.SetServiceManual or MemoryActionType.SetServiceDisabled:
                var info = Snapshot?.Services?.FirstOrDefault(x => x.Info.Name.Equals(a.Target, StringComparison.OrdinalIgnoreCase))?.Info;
                if (info is null) return new(false, "That service is no longer listed.");
                if (ServiceProtection.IsProtected(info.Name) || ServiceProtection.IsSelfComponent(info.Name) || MemorySuggestionEngine.CandidateFor(info) is null)
                    return new(false, $"{info.Label} is protected and can't be changed from here.");
                if (a.Type == MemoryActionType.StopService)
                {
                    if (serviceActions is null) return new(false, "Service control isn't available.");
                    var r = await serviceActions.ExecuteAsync(info, ServiceAction.Stop, ct).ConfigureAwait(false);
                    return new(r.Success, r.Success ? $"{info.Label} stopped until the next restart." : r.Message);
                }
                var target = a.Type == MemoryActionType.SetServiceManual ? "Manual" : "Disabled";
                var original = sys.GetServiceStartType(info.Name);
                sys.SetServiceStartType(info.Name, target);
                AddUndo(new(s.Id, info.Label, a.Type, info.Name, original));
                return new(true, $"{info.Label} set to {target} (was {original}).");
        }
        return new(false, "Unknown action.");
    }
}
