using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Changes;
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
        or MemoryActionType.SetServiceManual or MemoryActionType.SetServiceDisabled or MemoryActionType.OpenSettings
        or MemoryActionType.RestartPc or MemoryActionType.DisableFastStartup or MemoryActionType.DisableTransparency or MemoryActionType.AutoManagePageFile
        or MemoryActionType.AddDefenderExclusions or MemoryActionType.DisableWidgets or MemoryActionType.DisableSearchHighlights
        or MemoryActionType.ReduceHibernateFile or MemoryActionType.SkipOfficeStartScreen or MemoryActionType.BlockBrowserExtension;
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
    /// <summary>HKCU transparency effects (Settings > Personalization > Colors); null = not set (Windows default: on).</summary>
    bool? GetTransparency() => null;
    void SetTransparency(bool on) => throw new NotSupportedException();
    /// <summary>Switches the page file to "managed by Windows" (admin; effective after restart).</summary>
    Task<ActionOutcome> EnableAutoPageFileAsync(CancellationToken ct) => Task.FromResult(new ActionOutcome(false, "Not supported on this PC."));
    /// <summary>Current custom page file settings (opaque, for undo), or null when Windows manages it / unknown.</summary>
    Task<string?> ReadPageFileSettingsAsync(CancellationToken ct) => Task.FromResult<string?>(null);
    /// <summary>Puts back custom page file settings saved by <see cref="ReadPageFileSettingsAsync"/> (admin; after restart).</summary>
    Task<ActionOutcome> RestorePageFileAsync(string settings, CancellationToken ct) => Task.FromResult(new ActionOutcome(false, "Not supported on this PC."));
    /// <summary>Removable caches and leftovers with their measured size. Expensive (sizes big folders), so it isn't part of
    /// <see cref="CaptureAsync"/>; the Host caches the result for a few minutes unless <paramref name="refresh"/> is set.</summary>
    /// <summary>Current hibernation file state (registry + hiberfil.sys size); null = couldn't read.</summary>
    HibernateInfo? ReadHibernate() => null;
    /// <summary>Runs powercfg /h /type reduced (or full) with administrator rights.</summary>
    Task<ActionOutcome> SetHibernateTypeAsync(bool reduced, CancellationToken ct) => Task.FromResult(new ActionOutcome(false, "Not supported on this PC."));
    Task<IReadOnlyList<StorageCleanupItem>> ScanStorageCleanupsAsync(bool refresh, CancellationToken ct) => Task.FromResult<IReadOnlyList<StorageCleanupItem>>([]);
    /// <summary>Runs a Defender PowerShell script built by <see cref="DefenderProbe"/> (admin). Output = its stdout.</summary>
    Task<(bool Ok, string? Output)> RunDefenderScriptAsync(string script, CancellationToken ct) => Task.FromResult<(bool, string?)>((false, null));
    /// <summary>A DWORD on <see cref="RegistryAllowlist"/> (null = absent). Throws for a value that exists but isn't a DWORD.</summary>
    int? ReadDword(RegistrySetting setting) => null;
    /// <summary>Writes a DWORD on <see cref="RegistryAllowlist"/> (HKLM needs admin). Refuses anything else.</summary>
    void WriteDword(RegistrySetting setting, int value) => throw new NotSupportedException();
    /// <summary>Deletes a value on <see cref="RegistryAllowlist"/> (no error when it's already absent).</summary>
    void DeleteDword(RegistrySetting setting) => throw new NotSupportedException();
    /// <summary>#22: the values under the browser's HKLM ExtensionInstallBlocklist policy key (empty = key absent; null = couldn't read).</summary>
    IReadOnlyList<BlocklistEntry>? ReadExtensionBlocklist(BrowserKind browser) => null;
    /// <summary>Adds one REG_SZ entry (admin). Refuses IDs not on <see cref="BrowserExtensions.Allowlist"/> and names that already exist.</summary>
    void AddExtensionBlock(BrowserKind browser, string valueName, string extensionId) => throw new NotSupportedException();
    /// <summary>Deletes one entry, only when it still holds <paramref name="extensionId"/> (admin). Refuses IDs not on the allowlist.</summary>
    void RemoveExtensionBlock(BrowserKind browser, string valueName, string extensionId) => throw new NotSupportedException();
}

public sealed record UndoEntry(string Id, string Label, MemoryActionType Type, string Target, string? Previous, byte[]? PreviousBytes = null);

public sealed record SuggestionResult(string SuggestionId, bool Success, string Message, DateTime When, bool CanForceClose = false);

/// <summary>
/// Scans, shows and applies memory suggestions. Every change runs only from an explicit click; each is logged to the Event Log (1400)
/// with the actor (Local/Remote technician) and, where possible, can be undone.
/// </summary>
public sealed class MemorySuggestionService(IMemorySystem sys, ServicesModule? services = null, ServiceActionService? serviceActions = null,
    ISessionContext? session = null, Action<LogLevel, string>? events = null, Action<string>? log = null, TimeSpan? settle = null, Func<DateTime>? now = null,
    RemediationService? remediation = null, IChangeJournal? journal = null)
{
    private void Journal(ChangeKind kind, string target, string? previous, string label, bool restart = false)
    {
        try { journal?.Add(ChangeRecord.New(kind, target, previous, label, Actor, restart)); } catch (Exception ex) { Log("journal: " + ex.Message); }
    }

    private static ChangeKind? JournalKind(MemoryActionType t) => t switch
    {
        MemoryActionType.DisableStartup => ChangeKind.StartupApp, MemoryActionType.EnableBrowserMemorySaver => ChangeKind.BrowserSettings,
        MemoryActionType.SetServiceManual or MemoryActionType.SetServiceDisabled => ChangeKind.ServiceStartType,
        MemoryActionType.DisableTransparency => ChangeKind.Transparency, MemoryActionType.ReduceHibernateFile => ChangeKind.HiberFileType, _ => null,
    };
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

    public string Actor => ServiceActor.From(session);
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
                case MemoryActionType.AddDefenderExclusions:
                    var (df, dp) = DefenderProbe.Decode(u.Previous);
                    var (ok, _) = await sys.RunDefenderScriptAsync(DefenderProbe.RemoveScript(df, dp), ct).ConfigureAwait(false);
                    if (ok)
                        foreach (var t in df.Select(f => "path|" + f).Concat(dp.Select(x => "process|" + x)))
                            try { journal?.RemoveLatest(ChangeKind.DefenderExclusion, t); } catch { }
                    outcome = ok ? new(true, "Defender scans those folders and build tools again.") : new(false, "Windows didn't allow removing the exclusions.");
                    break;
                case MemoryActionType.DisableWidgets or MemoryActionType.DisableSearchHighlights:
                    outcome = UndoRegistry(u);
                    break;
                case MemoryActionType.SkipOfficeStartScreen:
                    outcome = UndoRegistry(u, $"The start screen is back in {u.Target}. Takes effect the next time each app opens.");
                    break;
                case MemoryActionType.BlockBrowserExtension:
                    var (extOk, extMessage) = BrowserExtensions.RemoveBlock(sys, u.Target, u.Previous);
                    if (extOk) try { journal?.RemoveLatest(ChangeKind.ExtensionBlock, u.Target); } catch { }
                    outcome = new(extOk, extMessage);
                    break;
                case MemoryActionType.ReduceHibernateFile:
                    var full = await sys.SetHibernateTypeAsync(false, ct).ConfigureAwait(false);
                    outcome = full.Success ? new(true, "The hibernation file is full size again; Hibernate is back in the power menu.") : full;
                    break;
                case MemoryActionType.DisableTransparency:
                    sys.SetTransparency(u.Previous != "0");
                    outcome = new(true, u.Previous != "0" ? "Transparency effects turned back on." : "Transparency effects left off (they were off before).");
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
        if (outcome.Success)
        {
            lock (_gate) _undo.Remove(u);
            if (JournalKind(u.Type) is { } jk) try { journal?.RemoveLatest(jk, u.Target); } catch { }
        }
        Event(outcome.Success ? LogLevel.Information : LogLevel.Warning, $"Memory suggestion undone\r\nActor: {Actor}\r\nAction: {u.Type}\r\nTarget: {u.Target}\r\nResult: {(outcome.Success ? "Success" : "Failed")}\r\nMessage: {outcome.Message}");
        var r = new SuggestionResult(u.Id, outcome.Success, (outcome.Success ? "Undone: " : "") + outcome.Message, DateTime.Now);
        lock (_gate) { _results[u.Id] = r; _recent.Insert(0, r); }
        await ScanAsync(ct).ConfigureAwait(false);
        return r;
    }

    /// <summary>Adds only the missing exclusions, confirms them by reading back, journals each one for Undo all.</summary>
    private async Task<ActionOutcome> AddDefenderExclusionsAsync(MemorySuggestion s, CancellationToken ct)
    {
        if (Snapshot?.Defender is not { HasWork: true } d) return new(false, "Nothing left to exclude.");
        var (ok, output) = await sys.RunDefenderScriptAsync(DefenderProbe.AddScript(d.MissingFolders, d.MissingProcesses), ct).ConfigureAwait(false);
        if (!ok) return new(false, "Windows didn't allow adding Defender exclusions (administrator rights needed, or your organization manages Defender).");
        var (folders, procs) = DefenderProbe.Confirmed(output, d.MissingFolders, d.MissingProcesses);
        foreach (var f in folders) Journal(ChangeKind.DefenderExclusion, "path|" + f, null, $"Defender no longer scans {f}");
        foreach (var p in procs) Journal(ChangeKind.DefenderExclusion, "process|" + p, null, $"Defender no longer scans files opened by {Path.GetFileName(p)} ({p})");
        if (folders.Count + procs.Count > 0) AddUndo(new(s.Id, "Defender exclusions", MemoryActionType.AddDefenderExclusions, "", DefenderProbe.Encode(folders, procs)));
        var missed = d.MissingFolders.Count + d.MissingProcesses.Count - folders.Count - procs.Count;
        if (folders.Count + procs.Count == 0) return new(false, "Defender didn't keep the exclusions; your organization's policy probably controls them.");
        return new(true, $"Defender no longer scans {MemoryText.Plural(folders.Count, "folder", "folders")} and {MemoryText.Plural(procs.Count, "build tool", "build tools")}."
            + (missed > 0 ? $" {missed} weren't kept (organization policy)." : "") + " Builds speed up from the next one.");
    }

    /// <summary>Result of one allowlisted DWORD write. <see cref="Changed"/> = written (and journaled); false when it was already that value.</summary>
    private sealed record DwordWrite(bool Ok, bool Changed, string Target, string? Previous);

    /// <summary>
    /// Sets an allowlisted DWORD, reads it back, and journals the old value (null = absent) only when the new value stuck.
    /// Never throws: access denied, UCPD or an organization policy is reported as not Ok, with nothing journaled.
    /// </summary>
    private DwordWrite SetDword(RegistrySetting setting, int value, Func<string, string> label, bool restart = true)
    {
        if (RegistryAllowlist.Find(setting.Target) is not { } r) return new(false, false, setting.Target, null);
        try
        {
            var before = sys.ReadDword(r);
            if (before == value) return new(true, false, r.Target, RegistryAllowlist.Encode(before));
            sys.WriteDword(r, value);
            if (sys.ReadDword(r) != value) { Log($"{r.Target} = {value} didn't stick"); return new(false, false, r.Target, null); }
            var previous = RegistryAllowlist.Encode(before);
            Journal(ChangeKind.RegistryValue, r.Target, previous, label(RegistryAllowlist.Describe(before)), restart);
            return new(true, true, r.Target, previous);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log($"{r.Target} = {value} failed: {ex.Message}");
            return new(false, false, r.Target, null);
        }
    }

    private const string PolicyRefused = "(administrator rights needed, or your organization manages this setting). Nothing was changed.";

    /// <summary>#16: the Widgets machine policy (HKCU TaskbarDa is blocked by UCPD, so it's never written), then ends the Widgets processes.</summary>
    /// <summary>powercfg /h /type reduced, then reads it back. Journals "full" so Undo all can put the full file back.</summary>
    private async Task<ActionOutcome> ReduceHibernateFileAsync(MemorySuggestion s, CancellationToken ct)
    {
        if (Snapshot?.Hibernate is not { OfferReduce: true } before) return new(false, "The hibernation file is already reduced or turned off.");
        var r = await sys.SetHibernateTypeAsync(true, ct).ConfigureAwait(false);
        if (!r.Success) return r;
        var after = sys.ReadHibernate();
        if (after?.Reduced == false) return new(false, "Windows didn't shrink the hibernation file; nothing was changed.");
        AddUndo(new(s.Id, "Hibernation file", MemoryActionType.ReduceHibernateFile, "", "full"));
        Journal(ChangeKind.HiberFileType, "", "full", "Hibernation file (hiberfil.sys) shrunk to the Fast Startup size (was full size)");
        var freed = before.FileBytes is { } b && after?.FileBytes is { } a && b > a ? $" Freed {MemoryText.Size(b - a)} on the system drive." : "";
        return new(true, "hiberfil.sys now holds only what Fast Startup needs." + freed + " Fast Startup still works; Hibernate is no longer in the power menu.");
    }

    private async Task<ActionOutcome> DisableWidgetsAsync(MemorySuggestion s, CancellationToken ct)
    {
        var w = SetDword(RegistryAllowlist.WidgetsPolicy, 0, was => $"Widgets turned off for everyone on this PC (policy was {was})");
        if (!w.Ok) return new(false, "Windows didn't keep the Widgets policy " + PolicyRefused);
        if (w.Changed) AddUndo(new(s.Id, "Widgets", MemoryActionType.DisableWidgets, "", RegistryUndo.Encode([new RegistryUndo.Item(w.Target, w.Previous)])));
        var ended = 0;
        foreach (var name in WindowsFeeds.WidgetProcesses)
        {
            if (Snapshot?.App(name) is null) continue;
            try { if ((await sys.ForceCloseAppAsync(name, ct).ConfigureAwait(false)).Success) ended++; }
            catch (Exception ex) when (ex is not OperationCanceledException) { Log($"End {name}: {ex.Message}"); }
        }
        return new(true, "Widgets turned off for everyone on this PC" + (ended > 0 ? " and its background processes ended" : "") + ". Takes full effect after a restart.");
    }

    /// <summary>#17: the Search highlights policy (must stick), plus this account's Settings toggle (best effort). Never DisableSearchBoxSuggestions.</summary>
    private ActionOutcome DisableSearchHighlights(MemorySuggestion s)
    {
        var policy = SetDword(RegistryAllowlist.SearchHighlightsPolicy, 0, was => $"Search highlights turned off for everyone on this PC (policy was {was})");
        if (!policy.Ok) return new(false, "Windows didn't keep the Search highlights policy " + PolicyRefused);
        var toggle = SetDword(RegistryAllowlist.SearchHighlightsToggle, 0, was => $"Search highlights setting turned off for this account (was {was})");
        var changed = new[] { policy, toggle }.Where(x => x.Changed).Select(x => new RegistryUndo.Item(x.Target, x.Previous)).ToList();
        if (changed.Count > 0) AddUndo(new(s.Id, "Search highlights", MemoryActionType.DisableSearchHighlights, "", RegistryUndo.Encode(changed)));
        return new(true, "Search highlights turned off" + (toggle.Ok ? "" : " (this account's Settings toggle couldn't be changed; the policy still applies)") + ". Takes full effect after a restart.");
    }

    /// <summary>
    /// #23: DisableBootToOfficeStart = 1 for each installed Office 16 app whose start screen is still on (HKCU: the account this app runs as).
    /// Each value that reads back is journaled with its old value; one that doesn't stick is left out (nothing journaled for it).
    /// </summary>
    private ActionOutcome SkipOfficeStartScreen(MemorySuggestion s)
    {
        IReadOnlyList<OfficeStartApp> apps = Snapshot is { } snap ? OfficeStartScreen.StillOn(snap) : [];
        if (apps.Count == 0) return new(false, "The Office start screen is already off.");
        var done = new List<string>();
        var failed = new List<string>();
        var changed = new List<RegistryUndo.Item>();
        foreach (var app in apps)
        {
            if (OfficeStartScreen.Setting(app.App) is not { } setting) continue;
            var w = SetDword(setting, 1, was => $"{app.App} start screen turned off for this account (was {was})", restart: false);
            if (!w.Ok) { failed.Add(app.App); continue; }
            done.Add(app.App);
            if (w.Changed) changed.Add(new(w.Target, w.Previous));
        }
        if (done.Count == 0) return new(false, $"Windows didn't keep the start screen setting for {OfficeStartScreen.Join(failed)} (your organization may manage Office settings). Nothing was changed.");
        if (changed.Count > 0) AddUndo(new(s.Id, "Office start screen", MemoryActionType.SkipOfficeStartScreen, OfficeStartScreen.Join(done), RegistryUndo.Encode(changed)));
        return new(true, $"{OfficeStartScreen.Join(done)} will open straight to a blank document (this account)."
            + (failed.Count > 0 ? $" {OfficeStartScreen.Join(failed)} couldn't be changed (your organization may manage Office settings)." : "")
            + " Takes effect the next time each app opens.");
    }

    /// <summary>
    /// #22: adds one allowlisted extension ID to the browser's machine blocklist as the next numbered entry, reads it back, and
    /// journals the value name it added. Nothing else in the list is touched; nothing is journaled when it doesn't stick.
    /// </summary>
    private ActionOutcome BlockBrowserExtension(MemoryAction a)
    {
        if (!BrowserExtensions.TryParseTarget(a.Target, out var browser, out var id) || BrowserExtensions.Known(browser, id) is not { } known)
            return new(false, "That extension isn't one this app may block.");
        var label = BrowserPrefs.Label(browser);
        try
        {
            if (sys.ReadExtensionBlocklist(browser) is not { } list) return new(false, $"Couldn't read {label}'s extension blocklist; nothing was changed.");
            if (BrowserExtensions.IsBlocked(list, id)) return new(true, $"{known.Name} is already blocked in {label}.");
            if (BrowserExtensions.NextName(list) is not { } name)
                return new(false, $"{label}'s extension blocklist isn't numbered 1, 2, 3… (your organization may manage it), so it was left as is.");
            sys.AddExtensionBlock(browser, name, id);
            var after = sys.ReadExtensionBlocklist(browser);
            if (after?.FirstOrDefault(e => e.Name == name)?.Data?.Trim().Equals(id, StringComparison.OrdinalIgnoreCase) != true)
            {
                Log($"{label} blocklist {name} = {id} didn't stick");
                // Best effort: the name was free before, and the Host deletes it only if it holds this ID.
                try { sys.RemoveExtensionBlock(browser, name, id); } catch (Exception ex) when (ex is not OperationCanceledException) { Log("cleanup: " + ex.Message); }
                return new(false, $"Windows didn't keep {known.Name} on {label}'s blocklist " + PolicyRefused);
            }
            var target = BrowserExtensions.Target(browser, id);
            Journal(ChangeKind.ExtensionBlock, target, name, $"{known.Name} turned off in {label} for everyone on this PC (blocklist entry {name} added; was not blocked)");
            AddUndo(new(BrowserExtensions.SuggestionId(browser, id), $"{known.Name} ({label})", MemoryActionType.BlockBrowserExtension, target, name));
            return new(true, $"{known.Name} is turned off in {label} for everyone on this PC and can't be turned back on or reinstalled until you undo this. {label} now shows \"Managed by your organization\".");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log($"Block {a.Target} failed: {ex.Message}");
            return new(false, $"Windows didn't allow blocking {known.Name} in {label} " + PolicyRefused);
        }
    }

    /// <summary>Per-item undo: restores every value this click changed (allowlisted only) and drops their journal records.</summary>
    private ActionOutcome UndoRegistry(UndoEntry u, string? done = null)
    {
        var items = RegistryUndo.Decode(u.Previous);
        if (items.Count == 0) return new(false, "The original setting wasn't recorded.");
        var failed = new List<string>();
        foreach (var item in items)
        {
            bool ok;
            try { ok = RegistryAllowlist.Restore(sys, item.Target, item.Previous).Ok; }
            catch (Exception ex) when (ex is not OperationCanceledException) { Log($"Undo {item.Target}: {ex.Message}"); ok = false; }
            if (ok) { try { journal?.RemoveLatest(ChangeKind.RegistryValue, item.Target); } catch { } }
            else failed.Add(item.Target);
        }
        return failed.Count == 0
            ? new(true, done ?? $"{u.Label} turned back on. Takes full effect after a restart.")
            : new(false, $"Windows didn't allow turning {u.Label} back on (administrator rights needed).");
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
                Journal(ChangeKind.StartupApp, entry.Name, prev is null ? null : Convert.ToBase64String(prev), $"{MemoryText.FriendlyAppName(entry.ExeName)} won't start with Windows");
                return new(true, $"{MemoryText.FriendlyAppName(entry.ExeName)} won't start with Windows (your account only).");

            case MemoryActionType.EnableBrowserMemorySaver:
                var kind = Enum.Parse<BrowserKind>(a.Target);
                if (sys.IsBrowserRunning(kind)) return new(false, $"{BrowserPrefs.Label(kind)} is open. Use its settings page instead, or close it and try again.");
                var json = sys.ReadBrowserLocalState(kind);
                var updated = BrowserPrefs.EnableMemorySaver(json, kind);
                if (updated is null) return new(false, $"Couldn't find the {BrowserPrefs.FeatureName(kind)} setting; use {BrowserPrefs.Label(kind)}'s settings page.");
                sys.WriteBrowserLocalState(kind, updated);
                AddUndo(new(s.Id, BrowserPrefs.Label(kind), a.Type, a.Target, json));
                Journal(ChangeKind.BrowserSettings, a.Target, json, $"{BrowserPrefs.FeatureName(kind)} turned on in {BrowserPrefs.Label(kind)}");
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
                    if (MemorySuggestionEngine.IsVisualStudioCollector(info.Name))
                        return new(false, "Only changing the startup type to Manual is offered for the Visual Studio diagnostics collector.");
                    if (serviceActions is null) return new(false, "Service control isn't available.");
                    var r = await serviceActions.ExecuteAsync(info, ServiceAction.Stop, ct).ConfigureAwait(false);
                    if (r.Success) Journal(ChangeKind.ServiceRunning, info.Name, "Running", $"{info.Label} stopped");
                    return new(r.Success, r.Success ? $"{info.Label} stopped until the next restart." : r.Message);
                }
                var target = a.Type == MemoryActionType.SetServiceManual ? "Manual" : "Disabled";
                var original = sys.GetServiceStartType(info.Name);
                sys.SetServiceStartType(info.Name, target);
                AddUndo(new(s.Id, info.Label, a.Type, info.Name, original));
                Journal(ChangeKind.ServiceStartType, info.Name, original, $"{info.Label} set to {target}");
                return new(true, $"{info.Label} set to {target} (was {original}).");

            case MemoryActionType.RestartPc or MemoryActionType.DisableFastStartup:
                // Same audited path as the Remediation buttons (restart also registers auto-resume after sign-in).
                if (remediation is null) return new(false, "Restarting isn't available from here.");
                var kindR = a.Type == MemoryActionType.RestartPc ? RemediationKind.ScheduleCleanRestart : RemediationKind.DisableFastStartup;
                var rr = await remediation.ExecuteAsync(new AreaAction(kindR, a.Label), ct).ConfigureAwait(false);
                return new(rr.Success, rr.Message);

            case MemoryActionType.DisableTransparency:
                var before = sys.GetTransparency();
                if (before == false) return new(true, "Transparency effects are already off.");
                sys.SetTransparency(false);
                AddUndo(new(s.Id, "Transparency effects", a.Type, "", before == false ? "0" : "1"));
                Journal(ChangeKind.Transparency, "", before == false ? "0" : "1", "Transparency effects turned off");
                return new(true, "Transparency effects turned off (this account).");

            case MemoryActionType.AddDefenderExclusions:
                return await AddDefenderExclusionsAsync(s, ct).ConfigureAwait(false);

            case MemoryActionType.DisableWidgets:
                return await DisableWidgetsAsync(s, ct).ConfigureAwait(false);

            case MemoryActionType.ReduceHibernateFile:
                return await ReduceHibernateFileAsync(s, ct).ConfigureAwait(false);

            case MemoryActionType.DisableSearchHighlights:
                return DisableSearchHighlights(s);

            case MemoryActionType.SkipOfficeStartScreen:
                return SkipOfficeStartScreen(s);

            case MemoryActionType.BlockBrowserExtension:
                return BlockBrowserExtension(a);

            case MemoryActionType.AutoManagePageFile:
                var pageFileBefore = await sys.ReadPageFileSettingsAsync(ct).ConfigureAwait(false);
                var pf = await sys.EnableAutoPageFileAsync(ct).ConfigureAwait(false);
                if (pf.Success && pageFileBefore is not null) Journal(ChangeKind.PageFile, "", pageFileBefore, "Page file managed by Windows", restart: true);
                return pf;
        }
        return new(false, "Unknown action.");
    }
}
