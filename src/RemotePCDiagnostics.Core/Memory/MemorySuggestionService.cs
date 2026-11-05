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

    /// <summary>
    /// The result already says when it takes effect ("Takes effect after the next restart.", "Takes full effect the next time you sign in."),
    /// so the generic deferred line from <see cref="Describe"/> would only repeat it.
    /// </summary>
    public static bool SaysWhen(string? message) =>
        message is not null && System.Text.RegularExpressions.Regex.IsMatch(message, @"\btakes (full )?effect\b", System.Text.RegularExpressions.RegexOptions.IgnoreCase);

    /// <summary>Whether an action's effect should show right away (closing/stopping) or only later (settings).</summary>
    public static bool IsDeferred(MemoryActionType t) => t is MemoryActionType.DisableStartup or MemoryActionType.EnableBrowserMemorySaver
        or MemoryActionType.SetServiceManual or MemoryActionType.SetServiceDisabled or MemoryActionType.OpenSettings
        or MemoryActionType.RestartPc or MemoryActionType.DisableFastStartup or MemoryActionType.DisableTransparency or MemoryActionType.AutoManagePageFile
        or MemoryActionType.AddDefenderExclusions or MemoryActionType.DisableWidgets or MemoryActionType.DisableSearchHighlights
        or MemoryActionType.ReduceHibernateFile or MemoryActionType.SkipOfficeStartScreen or MemoryActionType.SetPdfDefaultPrinter or MemoryActionType.DisableOfficeOptionalExperiences or MemoryActionType.BlockBrowserExtension
        or MemoryActionType.RemoveApp or MemoryActionType.RemoveXboxApps or MemoryActionType.StopSilentAppInstalls or MemoryActionType.RemoveNarratorAddons; // disk space / later installs, not memory
}

/// <param name="Skipped">Nothing was attempted on purpose (e.g. the app whose cache it is was open); the workflow lists it as skipped.</param>
public sealed record ActionOutcome(bool Success, string Message, bool Skipped = false);

/// <summary>
/// Host-side probes and actions (Windows implementation in the Host; fakes in tests). Methods may throw. It is the sum of the role
/// interfaces below, each registered on its own, so a consumer can take only the part it uses.
/// </summary>
public interface IMemorySystem : IMemoryProbe, IAppControl, IServiceConfig, IBrowserSettings, IRegistryTweaks, IPowerConfig, IStorageCleanupSystem, IDefenderConfig, IAppManagementSystem
{
}

/// <summary>Memory and process readings: free memory, the snapshot the suggestions are built from, running processes.</summary>
public interface IMemoryProbe
{
    MemoryReading ReadMemory();
    Task<MemorySnapshot> CaptureAsync(IReadOnlyList<ServiceInfo> services, CancellationToken ct);
    Task<MemorySnapshot> CaptureAsync(IReadOnlyList<ServiceInfo> services, IProgress<string>? progress, CancellationToken ct) => CaptureAsync(services, ct);
    /// <summary>Names (without .exe) of the processes running right now, for a last check just before acting; null = not available.</summary>
    IReadOnlyList<string>? RunningProcessNames() => null;
}

/// <summary>Closing apps, starting tools, opening links, and the startup-apps switch.</summary>
public interface IAppControl
{
    /// <summary>Asks every window of the app to close (like clicking X). Never kills.</summary>
    Task<ActionOutcome> CloseAppAsync(string processName, CancellationToken ct);
    /// <summary>Ends the app's processes. Only called after a graceful close failed and the user clicked Force close.</summary>
    Task<ActionOutcome> ForceCloseAppAsync(string processName, CancellationToken ct);
    Task<ActionOutcome> RunCommandAsync(string fileName, IReadOnlyList<string> args, CancellationToken ct);
    /// <summary>HKCU StartupApproved\Run raw value (null = not present).</summary>
    byte[]? GetStartupApproved(string name);
    /// <summary>Writes (or deletes when null) the HKCU StartupApproved\Run value.</summary>
    void SetStartupApproved(string name, byte[]? value);
    void OpenUri(string uri);
}

/// <summary>Windows services' start types and delayed-start values, and allowlisted scheduled tasks.</summary>
public interface IServiceConfig
{
    /// <summary>"Automatic", "AutomaticDelayed", "Manual" or "Disabled".</summary>
    string GetServiceStartType(string name);
    void SetServiceStartType(string name, string startType);
    /// <summary>A DWORD under HKLM\SYSTEM\CurrentControlSet\Services\&lt;service&gt; (only <see cref="ServiceDelayedStart.ValueName"/>).
    /// (true, null) = absent; (false, _) = couldn't read.</summary>
    (bool Known, int? Value) ReadServiceValue(string service, string name) => (false, null);
    /// <summary>Writes that DWORD back, or deletes it when <paramref name="value"/> is null (admin; protected services refused).</summary>
    void RestoreServiceValue(string service, string name, int? value) => throw new NotSupportedException();
    /// <summary>State of an allowlisted scheduled task ("Ready", "Disabled", …, or <see cref="ScheduledTaskAllowlist.Missing"/>); null = couldn't read.</summary>
    Task<string?> GetScheduledTaskStateAsync(string path, CancellationToken ct) => Task.FromResult<string?>(null);
    /// <summary>Enables or disables an allowlisted scheduled task (admin) and returns its state read back (null = couldn't read).</summary>
    Task<string?> SetScheduledTaskEnabledAsync(string path, bool enabled, CancellationToken ct) => Task.FromResult<string?>(null);
}

/// <summary>Browser Local State files, extension blocklist policies and background browser processes.</summary>
public interface IBrowserSettings
{
    bool IsBrowserRunning(BrowserKind kind);
    string? ReadBrowserLocalState(BrowserKind kind);
    void WriteBrowserLocalState(BrowserKind kind, string json);
    /// <summary>#22: the values under the browser's HKLM ExtensionInstallBlocklist policy key (empty = key absent; null = couldn't read).</summary>
    IReadOnlyList<BlocklistEntry>? ReadExtensionBlocklist(BrowserKind browser) => null;
    /// <summary>Adds one REG_SZ entry (admin). Refuses IDs not on <see cref="BrowserExtensions.Allowlist"/> and names that already exist.</summary>
    void AddExtensionBlock(BrowserKind browser, string valueName, string extensionId) => throw new NotSupportedException();
    /// <summary>Deletes one entry, only when it still holds <paramref name="extensionId"/> (admin). Refuses IDs not on the allowlist.</summary>
    void RemoveExtensionBlock(BrowserKind browser, string valueName, string extensionId) => throw new NotSupportedException();
    /// <summary>
    /// #19: ends the browser's processes in this Windows session, only when none of them has a window (it's only running in the background).
    /// Never closes a window: fails instead. Success = none of its processes is left in this session.
    /// </summary>
    Task<ActionOutcome> EndBrowserBackgroundAsync(BrowserKind kind, CancellationToken ct) => Task.FromResult(new ActionOutcome(false, "Not supported on this PC."));
}

/// <summary>Allowlisted registry values (Windows settings the suggestions change), transparency and the default printer.</summary>
public interface IRegistryTweaks
{
    /// <summary>HKCU transparency effects (Settings > Personalization > Colors); null = not set (Windows default: on).</summary>
    bool? GetTransparency() => null;
    void SetTransparency(bool on) => throw new NotSupportedException();
    /// <summary>A DWORD on <see cref="RegistryAllowlist"/> (null = absent). Throws for a value that exists but isn't a DWORD.</summary>
    int? ReadDword(RegistrySetting setting) => null;
    /// <summary>Writes a DWORD on <see cref="RegistryAllowlist"/> (HKLM needs admin). Refuses anything else.</summary>
    void WriteDword(RegistrySetting setting, int value) => throw new NotSupportedException();
    /// <summary>Deletes a value on <see cref="RegistryAllowlist"/> (no error when it's already absent).</summary>
    void DeleteDword(RegistrySetting setting) => throw new NotSupportedException();
    /// <summary>The registry key exists (64-bit view). Used before a write to record which keys it creates (<see cref="RegistryKeyCleanup"/>).</summary>
    bool RegistryKeyExists(RegistryRoot root, string key) => true;
    /// <summary>
    /// Deletes the key only if it has no values and no subkeys, and only keys <see cref="RegistryKeyCleanup.IsCleanupKey"/> allows.
    /// True = deleted or already absent; false = kept (not empty, or not allowed). May throw (access denied).
    /// </summary>
    bool DeleteRegistryKeyIfEmpty(RegistryRoot root, string key) => false;
    /// <summary>#24: this account's default printer, its port, LegacyDefaultPrinterMode and whether Print to PDF exists (registry only); null = couldn't read.</summary>
    DefaultPrinterInfo? ReadDefaultPrinter() => null;
    /// <summary>The printer is installed (local printer or \\server\printer connection). Only names that pass <see cref="DefaultPrinter.IsSafeName"/>.</summary>
    bool PrinterExists(string name) => false;
    /// <summary>Makes an installed printer this account's default (winspool SetDefaultPrinter).</summary>
    ActionOutcome SetDefaultPrinter(string name) => new(false, "Not supported on this PC.");
}

/// <summary>Page file and hibernation file settings.</summary>
public interface IPowerConfig
{
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
    /// <summary><see cref="Hibernation.TrackedValues"/> under HKLM\SYSTEM\CurrentControlSet\Control\Power (a null value = absent); null = couldn't read.</summary>
    IReadOnlyDictionary<string, int?>? ReadHibernateValues() => null;
    /// <summary>Deletes one of <see cref="Hibernation.TrackedValues"/> (admin). Refuses any other name.</summary>
    void DeleteHibernateValue(string name) => throw new NotSupportedException();
}

/// <summary>Scanning and deleting removable caches and leftovers.</summary>
public interface IStorageCleanupSystem
{
    Task<IReadOnlyList<StorageCleanupItem>> ScanStorageCleanupsAsync(bool refresh, CancellationToken ct) => Task.FromResult<IReadOnlyList<StorageCleanupItem>>([]);
    Task<IReadOnlyList<StorageCleanupItem>> ScanStorageCleanupsAsync(bool refresh, IProgress<string>? progress, CancellationToken ct) => ScanStorageCleanupsAsync(refresh, ct);
    /// <summary>
    /// Deletes one <see cref="Storage.StorageCleanupCatalog"/> category: re-evaluates its rule on disk, deletes only inside its allowlisted folders,
    /// skips it entirely while its app is open. Permanent.
    /// </summary>
    Task<Storage.StorageCleanResult> CleanStorageAsync(string id, CancellationToken ct) => Task.FromResult(Storage.StorageCleanResult.NotRun(id, "Not supported on this PC."));
}

/// <summary>Microsoft Defender settings (exclusions).</summary>
public interface IDefenderConfig
{
    /// <summary>Runs a Defender PowerShell script built by <see cref="DefenderProbe"/> (admin). Output = its stdout.</summary>
    Task<(bool Ok, string? Output)> RunDefenderScriptAsync(string script, CancellationToken ct) => Task.FromResult<(bool, string?)>((false, null));
}

/// <summary>Removing and reinstalling allowlisted apps (Store packages, vendor uninstallers, winget).</summary>
public interface IAppManagementSystem
{
    /// <summary>#3/#8/#10: allowlisted Store packages, Uninstall entries, settings and scheduled tasks present on this PC (registry reads; sizes cached). Null = couldn't read.</summary>
    AppRemovalInfo? ReadRemovableApps() => null;
    /// <summary>Removes allowlisted packages for all users plus their provisioned copies (admin), then reads back. Returns the family names still present; null = couldn't run.</summary>
    Task<IReadOnlyList<string>?> RemoveAppxPackagesAsync(IReadOnlyList<RemovableAppx> apps, CancellationToken ct) => Task.FromResult<IReadOnlyList<string>?>(null);
    /// <summary>Runs a validated vendor uninstaller (<see cref="AppRemoval.IsAllowedCommand"/>) and waits for it to finish (admin).</summary>
    Task<ActionOutcome> RunUninstallerAsync(UninstallCommand command, CancellationToken ct) => Task.FromResult(new ActionOutcome(false, "Not supported on this PC."));
    /// <summary>
    /// Runs a validated <see cref="StoreReinstall"/> winget command (<see cref="StoreReinstall.IsAllowedCommand"/>) as the signed-in user, not
    /// elevated and never as SYSTEM, and waits up to <see cref="StoreReinstall.Timeout"/>.
    /// </summary>
    Task<WingetResult> RunWingetAsync(WingetCommand command, CancellationToken ct) => Task.FromResult(WingetResult.NotStarted("Not supported on this PC."));
    /// <summary>The allowlisted package (exact name + publisher id) is installed for the signed-in account (Get-AppxPackage); null = couldn't tell.</summary>
    Task<bool?> IsStorePackageInstalledAsync(RemovableAppx app, CancellationToken ct) => Task.FromResult<bool?>(null);
}

/// <param name="CreatedKey">Topmost registry key the change created (<see cref="ChangeRecord.CreatedKey"/>), removed again on undo while empty.</param>
/// <param name="PreviousExtra">Side-effect values recorded before the change (<see cref="ChangeRecord.PreviousExtra"/>).</param>
public sealed record UndoEntry(string Id, string Label, MemoryActionType Type, string Target, string? Previous, byte[]? PreviousBytes = null,
    string? CreatedKey = null, string? PreviousExtra = null);

public sealed record SuggestionResult(string SuggestionId, bool Success, string Message, DateTime When, bool CanForceClose = false, bool Skipped = false);

/// <summary>
/// Scans, shows and applies memory suggestions. Every change runs only from an explicit click; each is logged to the Event Log (1400)
/// with the actor (Local/Remote technician) and, where possible, can be undone.
/// </summary>
public sealed partial class MemorySuggestionService(IMemorySystem sys, ServicesModule? services = null, ServiceActionService? serviceActions = null,
    ISessionContext? session = null, Action<LogLevel, string>? events = null, Action<string>? log = null, TimeSpan? settle = null, Func<DateTime>? now = null,
    RemediationService? remediation = null, IChangeJournal? journal = null)
{
    private void Journal(ChangeKind kind, string target, string? previous, string label, bool restart = false, string? createdKey = null, string? extra = null)
    {
        try { journal?.Add(ChangeRecord.New(kind, target, previous, label, Actor, restart, createdKey, extra)); } catch (Exception ex) { Log("journal: " + ex.Message); }
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
    public CheckProgress? ScanProgress { get; private set; }
    public string? Busy { get; private set; }
    public string? ScanError { get; private set; }
    public long TotalFreedBytes { get; private set; }
    /// <summary>Last storage scan (<see cref="ScanStorageAsync"/>); not part of the memory scan because it sizes big folders.</summary>
    public IReadOnlyList<StorageCleanupItem> StorageItems { get; private set; } = [];
    /// <summary>One "Delete" suggestion per storage cleanup category found (kept apart from the memory suggestions).</summary>
    public IReadOnlyList<MemorySuggestion> StorageSuggestions { get; private set; } = [];
    public bool ScanningStorage { get; private set; }
    public CheckProgress? StorageScanProgress { get; private set; }
    public bool StorageScanned { get; private set; }
    public string? StorageError { get; private set; }
    /// <summary>Disk space freed by storage cleanups this session.</summary>
    public long StorageFreedBytes { get; private set; }
    private readonly SemaphoreSlim _storageGate = new(1, 1);
    public IReadOnlyList<UndoEntry> Undos { get { lock (_gate) return _undo.ToList(); } }
    public IReadOnlyList<SuggestionResult> Recent { get { lock (_gate) return _recent.ToList(); } }
    public SuggestionResult? ResultFor(string id) { lock (_gate) return _results.GetValueOrDefault(id); }
    public UndoEntry? UndoFor(string id) { lock (_gate) return _undo.LastOrDefault(u => u.Id == id); }

    public string Actor => ServiceActor.From(session);
    private void Log(string m) => log?.Invoke("[memory] " + m);
    private void Raise() { try { Changed?.Invoke(); } catch (Exception ex) { Log("Changed handler failed: " + ex.Message); } }

    public async Task ScanAsync(CancellationToken ct = default, IProgress<string>? progress = null)
    {
        if (Scanning) return;
        Scanning = true; ScanError = null; Raise();
        try
        {
            var svcList = services?.Latest.Values.ToList() ?? [];
            var tracked = CheckProgressExtensions.Create(cp => { ScanProgress = cp; Raise(); }, progress);
            tracked.ReportStep(1, 5, "Reading memory and running processes…");
            Snapshot = await sys.CaptureAsync(svcList, tracked, ct).ConfigureAwait(false);
            PruneStaleServiceRunningEntries(Snapshot, svcList);
            Suggestions = MemorySuggestionEngine.Build(Snapshot);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log("Scan failed: " + ex);
            ScanError = "Couldn't read what's using memory on this PC.";
        }
        finally { Scanning = false; ScanProgress = null; Raise(); }
    }

    private void PruneStaleServiceRunningEntries(MemorySnapshot snap, IReadOnlyList<ServiceInfo> svcList)
    {
        if (journal is null) return;
        try
        {
            foreach (var c in journal.All.Where(c => c.Kind == ChangeKind.ServiceRunning && c.Previous == "Running"))
            {
                var runningInSnap = snap.Services?.Any(s => string.Equals(s.Info.Name, c.Target, StringComparison.OrdinalIgnoreCase) && s.Info.IsRunning) == true;
                var runningInList = svcList.Any(s => string.Equals(s.Name, c.Target, StringComparison.OrdinalIgnoreCase) && s.IsRunning);
                var beforeBoot = snap.Uptime is { } up && DateTimeOffset.UtcNow - up > c.TimeUtc.AddMinutes(1);
                if (runningInSnap || runningInList || beforeBoot)
                    journal.Remove(c.Id);
            }
        }
        catch (Exception ex) { Log("journal prune: " + ex.Message); }
    }

    /// <summary>Measures the storage cleanups (cached by the Host for a few minutes unless <paramref name="refresh"/>). Never throws.</summary>
    public async Task ScanStorageAsync(bool refresh = false, CancellationToken ct = default, IProgress<string>? progress = null)
    {
        await _storageGate.WaitAsync(ct).ConfigureAwait(false);
        ScanningStorage = true; StorageError = null; Raise();
        try
        {
            var tracked = CheckProgressExtensions.Create(cp => { StorageScanProgress = cp; Raise(); }, progress);
            tracked.ReportStep(1, Storage.StorageCleanupCatalog.All.Count + 3, "Measuring caches and leftovers…");
            SetStorage(await sys.ScanStorageCleanupsAsync(refresh, tracked, ct).ConfigureAwait(false));
            StorageScanned = true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log("Storage scan failed: " + ex);
            StorageError = "Couldn't measure the caches and leftovers on this PC.";
        }
        finally { ScanningStorage = false; StorageScanProgress = null; _storageGate.Release(); Raise(); }
    }

    private void SetStorage(IReadOnlyList<StorageCleanupItem> items)
    {
        StorageItems = items;
        StorageSuggestions = Storage.StorageCleanupCatalog.Suggestions(items);
    }

    /// <summary>
    /// Runs one storage cleanup category by id (never a path). Journals one permanent (NotUndoable) record with what was deleted and how much
    /// space it freed, only when something really was deleted.
    /// </summary>
    private async Task<ActionOutcome> CleanStorageAsync(MemoryAction a, CancellationToken ct)
    {
        if (Storage.StorageCleanupCatalog.Find(a.Target) is not { } c) return new(false, "That cleanup isn't one this app may run.");
        var r = await sys.CleanStorageAsync(c.Id, ct).ConfigureAwait(false);
        if (!r.Ran) return new(false, r.Message, Skipped: r.RunningApps is { Count: > 0 });
        if (r.FilesRemoved > 0)
        {
            var size = Storage.StorageCleanupEngine.SizeText(r.BytesFreed);
            Journal(ChangeKind.NotUndoable, $"{c.Id}:{Guid.NewGuid():N}", null,
                $"{c.Title}: {MemoryText.Plural((int)Math.Min(r.FilesRemoved, int.MaxValue), "file")} deleted, {size} freed (can't be undone)");
            lock (_gate) StorageFreedBytes += r.BytesFreed;
        }
        SetStorage(StorageItems.Where(i => i.Id != c.Id).ToList()); // what's left is in use or newer than the rule allows
        return new(r.FilesRemoved > 0 || r.FilesSkipped == 0, r.Message);
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
            if (outcome.Success && a.Type is not (MemoryActionType.OpenSettings or MemoryActionType.CleanStorage)) // disk, not memory
            {
                var deferred = MemoryFeedback.IsDeferred(a.Type);
                MemoryReading? after = null;
                if (!deferred) { await Task.Delay(_settle, ct).ConfigureAwait(false); after = SafeRead(); }
                if (!(deferred && MemoryFeedback.SaysWhen(text))) text += " " + MemoryFeedback.Describe(before, after, deferred);
                if (!deferred && before is not null && after is not null)
                    lock (_gate) TotalFreedBytes += Math.Max(0, MemoryFeedback.Freed(before, after));
            }
            var canForce = !outcome.Success && a.Type == MemoryActionType.CloseApp;
            var r = Record(s.Id, outcome with { Message = text }, a, null, canForce);
            if (a.Type is not (MemoryActionType.OpenSettings or MemoryActionType.CleanStorage)) await ScanAsync(ct).ConfigureAwait(false);
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
                    ServiceDelayedStart.Restore(sys, u.Target, u.PreviousExtra, Log);
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
                case MemoryActionType.SetPdfDefaultPrinter:
                    outcome = UndoPdfDefaultPrinter(u);
                    break;
                case MemoryActionType.DisableOfficeOptionalExperiences:
                    outcome = UndoRegistry(u, "Office's optional online extras are back for this account. Takes effect the next time each Office app opens.");
                    break;
                case MemoryActionType.BlockBrowserExtension:
                    var (extOk, extMessage) = BrowserExtensions.RemoveBlock(sys, u.Target, u.Previous, u.CreatedKey, Log);
                    if (extOk) try { journal?.RemoveLatest(ChangeKind.ExtensionBlock, u.Target); } catch { }
                    outcome = new(extOk, extMessage);
                    break;
                case MemoryActionType.StopBrowserBackground:
                    outcome = await UndoBrowserBackgroundAsync(u, ct).ConfigureAwait(false);
                    break;
                case MemoryActionType.ReduceHibernateFile:
                    var full = await sys.SetHibernateTypeAsync(false, ct).ConfigureAwait(false);
                    if (full.Success) Hibernation.RemoveAddedValues(sys, u.PreviousExtra, Log);
                    outcome = full.Success ? new(true, "The hibernation file is full size again; Hibernate is back in the power menu.") : full;
                    break;
                case MemoryActionType.StopSilentAppInstalls:
                    outcome = UndoRegistry(u, "Windows may install promoted apps and show suggestions again.");
                    break;
                case MemoryActionType.RemoveApp or MemoryActionType.RemoveXboxApps or MemoryActionType.RemoveNarratorAddons:
                    outcome = await UndoAppRemovalAsync(u, ct).ConfigureAwait(false);
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
        return new(true, $"Defender no longer scans {DefenderProbe.Describe(folders.Count, procs.Count)}."
            + (missed > 0 ? $" {missed} weren't kept (organization policy)." : "") + " Builds speed up from the next one.");
    }

    /// <summary>
    /// #14: Claude / Codex VM service to Manual. Only from Automatic; read back, and journaled (with the old start type) only when Manual stuck.
    /// </summary>
    private ActionOutcome SetAiVmServiceManual(MemorySuggestion s, MemoryAction a, ServiceInfo info, string original, string? delayed)
    {
        if (a.Type != MemoryActionType.SetServiceManual) return new(false, "Only \"start only when needed\" (Manual) is offered for this service.");
        if (original is not ("Automatic" or "AutomaticDelayed")) return new(true, $"{info.Label} already starts only when needed ({original}).");
        sys.SetServiceStartType(info.Name, "Manual");
        string after;
        try { after = sys.GetServiceStartType(info.Name); }
        catch (Exception ex) when (ex is not OperationCanceledException) { Log($"Read back {info.Name}: {ex.Message}"); after = "unknown"; }
        if (after != "Manual") return new(false, $"Windows didn't keep {info.Label} on Manual (it's {after}). Nothing was changed.");
        AddUndo(new(s.Id, info.Label, a.Type, info.Name, original, PreviousExtra: delayed));
        Journal(ChangeKind.ServiceStartType, info.Name, original, $"{ServiceLabel(info.Label, "Manual", original)}; starts only when {AiVmServices.AppName(info.Name)} needs it", extra: delayed);
        return new(true, $"{info.Label} now starts only when {AiVmServices.AppName(info.Name)} needs it (was {original}). Takes effect after the next restart.");
    }

    /// <summary>
    /// #14: wsl --shutdown (allowlisted path and argument only). Re-checks just before running that Linux still looks idle, since the
    /// card may be minutes old. Nothing is journaled: there's nothing to undo (Linux starts again when it's used).
    /// </summary>
    private async Task<ActionOutcome> ShutdownWslAsync(CancellationToken ct)
    {
        if (Snapshot is not { } snap || WslShutdown.IdleVm(snap) is null) return new(false, "WSL isn't running, or Linux is in use now.");
        IReadOnlyList<string>? names = null;
        try { names = sys.RunningProcessNames(); } catch (Exception ex) when (ex is not OperationCanceledException) { Log("process list: " + ex.Message); }
        var busy = (names ?? []).Where(WslShutdown.IsBusyName).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (busy.Count > 0) return new(false, $"Linux is in use now ({string.Join(", ", busy)}), so WSL was left running.");
        var cmd = MemoryCommandAllowlist.WslShutdown;
        if (!MemoryCommandAllowlist.IsAllowed(cmd.FileName, cmd.Arguments)) return new(false, "Not allowed.");
        return await sys.RunCommandAsync(cmd.FileName, cmd.Arguments, ct).ConfigureAwait(false);
    }

    /// <summary>Result of one allowlisted DWORD write. <see cref="Changed"/> = written (and journaled); false when it was already that value.
    /// <see cref="CreatedKey"/> = the topmost key the write created (journaled, so undo deletes it again while empty).</summary>
    private sealed record DwordWrite(bool Ok, bool Changed, string Target, string? Previous, string? CreatedKey = null)
    {
        public RegistryUndo.Item Item => new(Target, Previous, CreatedKey);
    }

    /// <summary>Journal label for a service start-type change: "SysMain set to Manual (was Automatic)".</summary>
    public static string ServiceLabel(string label, string target, string original) => $"{label} set to {target} (was {original})";

    /// <summary>
    /// Sets an allowlisted DWORD, reads it back, and journals the old value (null = absent) only when the new value stuck.
    /// Never throws: access denied, UCPD or an organization policy is reported as not Ok, with nothing journaled.
    /// </summary>
    private DwordWrite SetDword(RegistrySetting setting, int value, Func<string, string> label, bool restart = true)
    {
        if (RegistryAllowlist.Find(setting.Target) is not { } r) return new(false, false, setting.Target, null);
        string? created = null;
        try
        {
            var before = sys.ReadDword(r);
            if (before == value) return new(true, false, r.Target, RegistryAllowlist.Encode(before));
            created = RegistryKeyCleanup.TopmostMissing(sys, r.Root, r.Key, Log);
            sys.WriteDword(r, value);
            if (sys.ReadDword(r) != value)
            {
                Log($"{r.Target} = {value} didn't stick");
                RegistryKeyCleanup.Remove(sys, r.Root, r.Key, created, Log);
                return new(false, false, r.Target, null);
            }
            var previous = RegistryAllowlist.Encode(before);
            Journal(ChangeKind.RegistryValue, r.Target, previous, label(RegistryAllowlist.Describe(before)), restart, created);
            return new(true, true, r.Target, previous, created);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log($"{r.Target} = {value} failed: {ex.Message}");
            // The Host already tries this when SetValue fails; again here for keys created before a later failure. Never throws.
            RegistryKeyCleanup.Remove(sys, r.Root, r.Key, created, Log);
            return new(false, false, r.Target, null);
        }
    }

    private const string PolicyRefused = "(administrator rights needed, or your organization manages this setting). Nothing was changed.";

    /// <summary>#16: the Widgets machine policy (HKCU TaskbarDa is blocked by UCPD, so it's never written), then ends the Widgets processes.</summary>
    /// <summary>powercfg /h /type reduced, then reads it back. Journals "full" so Undo all can put the full file back.</summary>
    private async Task<ActionOutcome> ReduceHibernateFileAsync(MemorySuggestion s, CancellationToken ct)
    {
        if (Snapshot?.Hibernate is not { OfferReduce: true } before) return new(false, "The hibernation file is already reduced or turned off.");
        var values = Hibernation.RecordValues(sys, Log); // HiberFileType / HibernateEnabled: undo removes the ones powercfg adds
        var r = await sys.SetHibernateTypeAsync(true, ct).ConfigureAwait(false);
        if (!r.Success) return r;
        var after = sys.ReadHibernate();
        if (after?.Reduced == false) return new(false, "Windows didn't shrink the hibernation file; nothing was changed.");
        AddUndo(new(s.Id, "Hibernation file", MemoryActionType.ReduceHibernateFile, "", "full", PreviousExtra: values));
        Journal(ChangeKind.HiberFileType, "", "full", "Hibernation file (hiberfil.sys) shrunk to the Fast Startup size (was full size)", extra: values);
        var freed = before.FileBytes is { } b && after?.FileBytes is { } a && b > a ? $" Freed {MemoryText.Size(b - a)} on the system drive." : "";
        return new(true, "hiberfil.sys now holds only what Fast Startup needs." + freed + " Fast Startup still works; Hibernate is no longer in the power menu.");
    }

    private async Task<ActionOutcome> DisableWidgetsAsync(MemorySuggestion s, CancellationToken ct)
    {
        if (Snapshot?.Feeds is { WidgetsPolicyBlocked: true })
            return new(false, "This version of Windows blocks the Widgets policy (User Choice Protection), so nothing was changed. Hide Widgets from Settings > Personalization > Taskbar instead.");
        var w = SetDword(RegistryAllowlist.WidgetsPolicy, 0, was => $"Widgets turned off for everyone on this PC (policy was {was})");
        if (!w.Ok) return new(false, "Windows didn't keep the Widgets policy " + PolicyRefused);
        if (w.Changed) AddUndo(new(s.Id, "Widgets", MemoryActionType.DisableWidgets, "", RegistryUndo.Encode([w.Item])));
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
        var changed = new[] { policy, toggle }.Where(x => x.Changed).Select(x => x.Item).ToList();
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
            if (w.Changed) changed.Add(w.Item);
        }
        if (done.Count == 0) return new(false, $"Windows didn't keep the start screen setting for {OfficeStartScreen.Join(failed)} (your organization may manage Office settings). Nothing was changed.");
        if (changed.Count > 0) AddUndo(new(s.Id, "Office start screen", MemoryActionType.SkipOfficeStartScreen, OfficeStartScreen.Join(done), RegistryUndo.Encode(changed)));
        return new(true, $"{OfficeStartScreen.Join(done)} will open straight to a blank document (this account)."
            + (failed.Count > 0 ? $" {OfficeStartScreen.Join(failed)} couldn't be changed (your organization may manage Office settings)." : "")
            + " Takes effect the next time each app opens.");
    }

    /// <summary>
    /// #24: LegacyDefaultPrinterMode = 1 (so Windows stops switching the default), then Microsoft Print to PDF as this account's default,
    /// read back. Journals the old mode (RegistryValue) and the old printer's name (DefaultPrinter). If the printer doesn't change,
    /// the mode is put back and nothing is journaled.
    /// </summary>
    private ActionOutcome SetPdfDefaultPrinter(MemorySuggestion s)
    {
        var live = sys.ReadDefaultPrinter();
        if (live is not { Offer: true } || !DefaultPrinter.IsSafeName(live.CurrentName))
            return new(false, live is { HasPrintToPdf: false } ? $"{DefaultPrinter.PdfPrinter} isn't installed on this PC." : "The default printer isn't a network printer any more; nothing was changed.");
        var old = live.CurrentName!;
        var mode = SetDword(RegistryAllowlist.LegacyDefaultPrinterMode, 1,
            was => $"\"Let Windows manage my default printer\" turned off for this account (LegacyDefaultPrinterMode was {was})", restart: false);
        if (!mode.Ok) return new(false, "Windows didn't keep the default printer setting (your organization may manage printers). Nothing was changed.");
        ActionOutcome set;
        try { set = sys.SetDefaultPrinter(DefaultPrinter.PdfPrinter); }
        catch (Exception ex) when (ex is not OperationCanceledException) { Log("SetDefaultPrinter: " + ex.Message); set = new(false, "Windows didn't allow changing the default printer."); }
        string? now = null;
        if (set.Success) try { now = sys.ReadDefaultPrinter()?.CurrentName; } catch (Exception ex) when (ex is not OperationCanceledException) { Log("default printer read back: " + ex.Message); }
        if (!set.Success || !DefaultPrinter.IsPdf(now))
        {
            if (mode.Changed)
            {
                try { if (RegistryAllowlist.Restore(sys, mode.Target, mode.Previous, mode.CreatedKey, Log).Ok) journal?.RemoveLatest(ChangeKind.RegistryValue, mode.Target); }
                catch (Exception ex) when (ex is not OperationCanceledException) { Log("LegacyDefaultPrinterMode rollback: " + ex.Message); }
            }
            return new(false, $"Windows didn't make {DefaultPrinter.PdfPrinter} the default printer (your organization may manage printers). Nothing was changed.");
        }
        Journal(ChangeKind.DefaultPrinter, DefaultPrinter.JournalTarget, old, $"Default printer for this account set to {DefaultPrinter.PdfPrinter} (was \"{old}\")");
        AddUndo(new(s.Id, "Default printer", MemoryActionType.SetPdfDefaultPrinter, old,
            RegistryUndo.Encode(mode.Changed ? new List<RegistryUndo.Item> { mode.Item } : new List<RegistryUndo.Item>())));
        return new(true, $"{DefaultPrinter.PdfPrinter} is now the default printer for this account (was \"{old}\"). When you print, pick \"{old}\" in the print dialog."
            + " Word and Excel no longer wait for the network printer when they open.");
    }

    /// <summary>Per-item undo for #24: the old default printer (if still installed), then the old LegacyDefaultPrinterMode.</summary>
    private ActionOutcome UndoPdfDefaultPrinter(UndoEntry u)
    {
        (bool Ok, string Message) printer;
        try { printer = DefaultPrinter.Restore(sys, DefaultPrinter.JournalTarget, u.Target); }
        catch (Exception ex) when (ex is not OperationCanceledException) { Log("Undo default printer: " + ex.Message); printer = (false, "Windows didn't allow changing the default printer back."); }
        if (printer.Ok) try { journal?.RemoveLatest(ChangeKind.DefaultPrinter, DefaultPrinter.JournalTarget); } catch { }
        var modeOk = true;
        foreach (var item in RegistryUndo.Decode(u.Previous))
        {
            bool ok;
            try { ok = RegistryAllowlist.Restore(sys, item.Target, item.Previous, item.CreatedKey, Log).Ok; }
            catch (Exception ex) when (ex is not OperationCanceledException) { Log($"Undo {item.Target}: {ex.Message}"); ok = false; }
            if (ok) { try { journal?.RemoveLatest(ChangeKind.RegistryValue, item.Target); } catch { } }
            else modeOk = false;
        }
        if (!printer.Ok) return new(false, printer.Message + (modeOk ? "" : " The \"Let Windows manage my default printer\" setting couldn't be put back either."));
        return modeOk
            ? new(true, printer.Message + " The \"Let Windows manage my default printer\" setting is back as it was.")
            : new(false, printer.Message + " But the \"Let Windows manage my default printer\" setting couldn't be put back.");
    }

    /// <summary>
    /// #18: ControllerConnectedServicesEnabled = 2 (the Office policy "Allow the use of additional optional connected experiences in Office"
    /// set to disabled) for this account. Read back and journaled with its old value; nothing is journaled when it doesn't stick.
    /// </summary>
    private ActionOutcome DisableOfficeOptionalExperiences(MemorySuggestion s)
    {
        if (Snapshot is { } snap && !OfficePrivacy.Offer(snap)) return new(false, "Office's optional online extras are already off or managed by your organization.");
        var w = SetDword(OfficePrivacy.Setting, OfficePrivacy.Disabled, was => $"Office optional connected experiences turned off for this account (policy was {was})", restart: false);
        if (!w.Ok) return new(false, "Windows didn't keep the Office setting (administrator rights needed, or your organization manages Office settings). Nothing was changed.");
        if (w.Changed) AddUndo(new(s.Id, "Office optional online extras", MemoryActionType.DisableOfficeOptionalExperiences, "", RegistryUndo.Encode([w.Item])));
        return new(true, "Office's optional online extras are off for this account (online pictures, Smart Lookup, Outlook weather, the Office Store for add-ins). OneDrive, SharePoint and co-authoring keep working. Takes effect the next time each Office app opens.");
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
            var created = RegistryKeyCleanup.TopmostMissing(sys, RegistryRoot.LocalMachine, BrowserExtensions.BlocklistKey(browser), Log);
            sys.AddExtensionBlock(browser, name, id);
            var after = sys.ReadExtensionBlocklist(browser);
            if (after?.FirstOrDefault(e => e.Name == name)?.Data?.Trim().Equals(id, StringComparison.OrdinalIgnoreCase) != true)
            {
                Log($"{label} blocklist {name} = {id} didn't stick");
                // Best effort: the name was free before, and the Host deletes it only if it holds this ID.
                try { sys.RemoveExtensionBlock(browser, name, id); } catch (Exception ex) when (ex is not OperationCanceledException) { Log("cleanup: " + ex.Message); }
                RegistryKeyCleanup.Remove(sys, RegistryRoot.LocalMachine, BrowserExtensions.BlocklistKey(browser), created, Log);
                return new(false, $"Windows didn't keep {known.Name} on {label}'s blocklist " + PolicyRefused);
            }
            var target = BrowserExtensions.Target(browser, id);
            Journal(ChangeKind.ExtensionBlock, target, name, $"{known.Name} turned off in {label} for everyone on this PC (blocklist entry {name} added; was not blocked)", createdKey: created);
            AddUndo(new(BrowserExtensions.SuggestionId(browser, id), $"{known.Name} ({label})", MemoryActionType.BlockBrowserExtension, target, name, CreatedKey: created));
            return new(true, $"{known.Name} is turned off in {label} for everyone on this PC and can't be turned back on or reinstalled until you undo this. {label} now shows \"Managed by your organization\".");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log($"Block {a.Target} failed: {ex.Message}");
            return new(false, $"Windows didn't allow blocking {known.Name} in {label} " + PolicyRefused);
        }
    }

    /// <summary>
    /// #19: for the non-default browser only. Ends its windowless background processes (never a window), then turns off
    /// background_mode.enabled in its Local State (read back), then for Edge sets the Startup Boost policy (read back).
    /// Each value that sticks is journaled with its old value; if a browser window is open, nothing is changed.
    /// </summary>
    private async Task<ActionOutcome> StopBrowserBackgroundAsync(MemorySuggestion s, MemoryAction a, CancellationToken ct)
    {
        if (!Enum.TryParse<BrowserKind>(a.Target, out var kind) || Snapshot is not { } snap || BrowserBackground.Secondary(snap) != kind
            || BrowserBackground.For(snap, kind) is not { } info)
            return new(false, "That browser is your default browser now (or couldn't be checked), so it was left as is.");
        var name = BrowserPrefs.Label(kind);
        var doPref = BrowserBackground.BackgroundModeOn(info);
        var doBoost = BrowserBackground.StartupBoostChangeable(info);
        if (!doPref && !doBoost) return new(false, $"{name} is already set not to run in the background.");

        var ended = false;
        if (sys.IsBrowserRunning(kind))
        {
            var end = await sys.EndBrowserBackgroundAsync(kind, ct).ConfigureAwait(false);
            ended = end.Success && !sys.IsBrowserRunning(kind);
            if (!ended && doPref) return new(false, $"{name} is open (or couldn't be closed in the background). Close its windows and try again. Nothing was changed.");
        }

        string? prefPrevious = null;
        var prefChanged = false;
        if (doPref)
        {
            var json = sys.ReadBrowserLocalState(kind);
            if (!BrowserBackground.TryReadBackgroundMode(json, out var before) || BrowserBackground.SetBackgroundMode(json, false) is not { } updated)
                return new(false, $"Couldn't read {name}'s settings file. Nothing was changed.");
            if (before != false)
            {
                sys.WriteBrowserLocalState(kind, updated);
                if (!BrowserBackground.TryReadBackgroundMode(sys.ReadBrowserLocalState(kind), out var after) || after != false)
                {
                    Log($"{kind} background_mode.enabled = false didn't stick");
                    return new(false, $"{name} didn't keep the setting. Nothing was changed.");
                }
                prefPrevious = BrowserBackground.Encode(before);
                prefChanged = true;
                Journal(ChangeKind.BrowserLocalStateValue, BrowserBackground.Target(kind), prefPrevious,
                    $"{name} no longer runs background apps when it's closed (\"Continue running background apps\" {BrowserBackground.Describe(before)})");
            }
        }

        var registry = new List<RegistryUndo.Item>();
        var boostFailed = false;
        if (doBoost)
        {
            var w = SetDword(BrowserBackground.StartupBoostSetting, 0, was => $"Microsoft Edge Startup Boost turned off for everyone on this PC (policy was {was})", restart: false);
            if (!w.Ok) boostFailed = true;
            else if (w.Changed) registry.Add(w.Item);
        }

        if (!prefChanged && registry.Count == 0)
            return boostFailed
                ? new(false, "Windows didn't keep the Startup Boost policy " + PolicyRefused)
                : new(false, $"{name} is already set not to run in the background.");
        AddUndo(new(s.Id, name, MemoryActionType.StopBrowserBackground, kind.ToString(), BrowserBackground.EncodeUndo(new(prefChanged, prefPrevious, registry))));
        var parts = new List<string>();
        if (prefChanged) parts.Add("background apps off");
        if (registry.Count > 0) parts.Add("Startup Boost off for everyone on this PC (Edge will say \"managed by your organization\")");
        return new(true, $"{name} won't run in the background: {string.Join("; ", parts)}."
            + (ended ? $" Its background processes were ended." : "")
            + (boostFailed ? " Startup Boost couldn't be turned off (administrator rights needed, or your organization manages Edge)." : "")
            + " Takes full effect the next time you sign in.");
    }

    /// <summary>#19 per-item undo: puts back the Local State value and the Startup Boost policy this click changed, and drops their journal records.</summary>
    private async Task<ActionOutcome> UndoBrowserBackgroundAsync(UndoEntry u, CancellationToken ct)
    {
        if (!Enum.TryParse<BrowserKind>(u.Target, out var kind) || BrowserBackground.DecodeUndo(u.Previous) is not { } undo)
            return new(false, "The original setting wasn't recorded.");
        var name = BrowserPrefs.Label(kind);
        var failed = new List<string>();
        foreach (var item in undo.Registry ?? [])
        {
            bool ok;
            try { ok = RegistryAllowlist.Restore(sys, item.Target, item.Previous, item.CreatedKey, Log).Ok; }
            catch (Exception ex) when (ex is not OperationCanceledException) { Log($"Undo {item.Target}: {ex.Message}"); ok = false; }
            if (ok) { try { journal?.RemoveLatest(ChangeKind.RegistryValue, item.Target); } catch { } }
            else failed.Add("Startup Boost");
        }
        if (undo.LocalStateChanged)
        {
            var target = BrowserBackground.Target(kind);
            var (ok, message) = await BrowserBackground.RestoreAsync(sys, target, undo.LocalStatePrevious, ct).ConfigureAwait(false);
            if (ok) { try { journal?.RemoveLatest(ChangeKind.BrowserLocalStateValue, target); } catch { } }
            else return new(false, message + (failed.Count > 0 ? " Startup Boost couldn't be turned back on either (administrator rights needed)." : ""));
        }
        return failed.Count == 0
            ? new(true, $"{name} may run in the background again" + (undo.Registry?.Count > 0 ? " (Startup Boost policy removed; Edge is no longer \"managed\")" : "") + ". Takes full effect the next time you sign in.")
            : new(false, "Windows didn't allow turning Startup Boost back on (administrator rights needed).");
    }

    /// <summary>Per-item undo: restores every value this click changed (allowlisted only) and drops their journal records.</summary>
    private ActionOutcome UndoRegistry(UndoEntry u, string? done = null)
    {
        var items = RegistryUndo.Decode(u.Previous);
        if (items.Count == 0) return new(false, "The original setting wasn't recorded.");
        var failed = new List<string>();
        foreach (var item in Enumerable.Reverse(items)) // last written first: the first write is the one that created any keys
        {
            bool ok;
            try { ok = RegistryAllowlist.Restore(sys, item.Target, item.Previous, item.CreatedKey, Log).Ok; }
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
        var r = new SuggestionResult(id, o.Success, (o.Success && !o.Skipped ? "Done: " : "") + o.Message, DateTime.Now, canForce, o.Skipped);
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

            case MemoryActionType.ShutdownWsl:
                return await ShutdownWslAsync(ct).ConfigureAwait(false);

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
                var delayed = ServiceDelayedStart.Record(sys, info.Name, Log); // undo puts DelayedAutostart back exactly (absent stays absent)
                if (AiVmServices.Is(info.Name)) return SetAiVmServiceManual(s, a, info, original, delayed);
                sys.SetServiceStartType(info.Name, target);
                AddUndo(new(s.Id, info.Label, a.Type, info.Name, original, PreviousExtra: delayed));
                Journal(ChangeKind.ServiceStartType, info.Name, original, ServiceLabel(info.Label, target, original), extra: delayed);
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

            case MemoryActionType.SetPdfDefaultPrinter:
                return SetPdfDefaultPrinter(s);

            case MemoryActionType.DisableOfficeOptionalExperiences:
                return DisableOfficeOptionalExperiences(s);

            case MemoryActionType.BlockBrowserExtension:
                return BlockBrowserExtension(a);

            case MemoryActionType.StopBrowserBackground:
                return await StopBrowserBackgroundAsync(s, a, ct).ConfigureAwait(false);

            case MemoryActionType.RemoveApp:
                return await RemoveAppAsync(s, a, ct).ConfigureAwait(false);

            case MemoryActionType.RemoveXboxApps:
                return await RemoveXboxAppsAsync(s, ct).ConfigureAwait(false);

            case MemoryActionType.RemoveNarratorAddons:
                return await RemoveNarratorAddonsAsync(s, ct).ConfigureAwait(false);

            case MemoryActionType.StopSilentAppInstalls:
                return StopSilentAppInstalls(s);

            case MemoryActionType.CleanStorage:
                return await CleanStorageAsync(a, ct).ConfigureAwait(false);

            case MemoryActionType.AutoManagePageFile:
                var pageFileBefore = await sys.ReadPageFileSettingsAsync(ct).ConfigureAwait(false);
                var pf = await sys.EnableAutoPageFileAsync(ct).ConfigureAwait(false);
                if (pf.Success && pageFileBefore is not null) Journal(ChangeKind.PageFile, "", pageFileBefore, "Page file managed by Windows", restart: true);
                return pf;
        }
        return new(false, "Unknown action.");
    }
}
