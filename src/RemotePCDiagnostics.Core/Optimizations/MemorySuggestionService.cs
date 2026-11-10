using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Logging;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Optimizations;

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
/// with the actor (Local/Remote user) and, where possible, can be undone.
/// </summary>
public sealed class MemorySuggestionService(IMemorySystem sys, ServicesModule? services = null, ServiceActionService? serviceActions = null,
    ISessionContext? session = null, Action<LogLevel, string>? events = null, ILogger? log = null, TimeSpan? settle = null, Func<DateTime>? now = null,
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

    // One class per suggestion family; each acts only through the shared context (the state stays here).
    private SuggestionContext? _ctx;
    private SuggestionContext Ctx => _ctx ??= new(sys, journal, () => Snapshot, () => Actor, AddUndo, log, serviceActions, remediation, now ?? (() => DateTime.UtcNow));
    private AppRemovalSuggestions? _apps;
    private AppRemovalSuggestions Apps => _apps ??= new(Ctx);
    private BrowserSuggestions? _browser;
    private BrowserSuggestions Browser => _browser ??= new(Ctx);
    private DefenderSuggestions? _defender;
    private DefenderSuggestions Defender => _defender ??= new(Ctx);
    private OfficeSuggestions? _office;
    private OfficeSuggestions Office => _office ??= new(Ctx);
    private PowerSuggestions? _power;
    private PowerSuggestions Power => _power ??= new(Ctx);
    private ServiceSuggestions? _serviceFamily;
    private ServiceSuggestions ServiceFamily => _serviceFamily ??= new(Ctx);
    private WindowsShellSuggestions? _shell;
    private WindowsShellSuggestions Shell => _shell ??= new(Ctx);
    private StartupAppSuggestions? _startupApps;
    private StartupAppSuggestions StartupApps => _startupApps ??= new(Ctx);
    private void Log(string m) => log.Info("[memory] " + m);
    private void LogWarn(string m) => log.Warn("[memory] " + m);
    private void LogError(string m) => log.Error("[memory] " + m);
    private void Raise() { try { Changed?.Invoke(); } catch (Exception ex) { LogWarn("Changed handler failed: " + ex.Message); } }

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
            LogWarn("Scan failed: " + ex);
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
            LogWarn("Storage scan failed: " + ex);
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

    private MemoryReading? SafeRead() { try { return sys.ReadMemory(); } catch (Exception ex) { LogWarn("ReadMemory failed: " + ex.Message); return null; } }

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
                LogError($"{a.Type} '{a.Target}' failed: {ex}");
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
            outcome = u.Type switch
            {
                MemoryActionType.DisableStartup => StartupApps.UndoStartup(u),
                MemoryActionType.EnableBrowserMemorySaver => Browser.UndoMemorySaver(u),
                MemoryActionType.SetServiceManual or MemoryActionType.SetServiceDisabled => ServiceFamily.UndoStartType(u),
                MemoryActionType.AddDefenderExclusions => await Defender.UndoExclusionsAsync(u, ct).ConfigureAwait(false),
                MemoryActionType.DisableWidgets or MemoryActionType.DisableSearchHighlights => Ctx.UndoRegistry(u),
                MemoryActionType.SkipOfficeStartScreen => Ctx.UndoRegistry(u, $"The start screen is back in {u.Target}. Takes effect the next time each app opens."),
                MemoryActionType.SetPdfDefaultPrinter => Office.UndoPdfDefaultPrinter(u),
                MemoryActionType.DisableOfficeOptionalExperiences => Ctx.UndoRegistry(u, "Office's optional online extras are back for this account. Takes effect the next time each Office app opens."),
                MemoryActionType.BlockBrowserExtension => Browser.UndoExtensionBlock(u),
                MemoryActionType.StopBrowserBackground => await Browser.UndoBrowserBackgroundAsync(u, ct).ConfigureAwait(false),
                MemoryActionType.ReduceHibernateFile => await Power.UndoHibernateAsync(u, ct).ConfigureAwait(false),
                MemoryActionType.StopSilentAppInstalls => Ctx.UndoRegistry(u, "Windows may install promoted apps and show suggestions again."),
                MemoryActionType.RemoveApp or MemoryActionType.RemoveXboxApps or MemoryActionType.RemoveNarratorAddons => await Apps.UndoAppRemovalAsync(u, ct).ConfigureAwait(false),
                MemoryActionType.DisableTransparency => Shell.UndoTransparency(u),
                _ => new(false, "This change can't be undone from here."),
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            LogError($"Undo {u.Type} '{u.Target}' failed: {ex}");
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

    /// <summary>Journal label for a service start-type change: "SysMain set to Manual (was Automatic)".</summary>
    public static string ServiceLabel(string label, string target, string original) => $"{label} set to {target} (was {original})";

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

    private void Event(LogLevel l, string text) { try { events?.Invoke(l, text); } catch (Exception ex) { LogWarn("Event write failed: " + ex.Message); } }

    private void AddUndo(UndoEntry u) { lock (_gate) { _undo.RemoveAll(x => x.Id == u.Id && x.Type == u.Type); _undo.Add(u); } }

    /// <summary>Hands one clicked action to its suggestion family.</summary>
    private async Task<ActionOutcome> PerformAsync(MemorySuggestion s, MemoryAction a, CancellationToken ct)
    {
        Log($"{Actor} clicked {a.Type} '{a.Target}' on suggestion '{s.Id}'");
        return a.Type switch
        {
            MemoryActionType.CloseApp or MemoryActionType.ForceCloseApp => await StartupApps.CloseAppAsync(a, ct).ConfigureAwait(false),
            MemoryActionType.ShutdownBuildServers => await StartupApps.ShutdownBuildServersAsync(ct).ConfigureAwait(false),
            MemoryActionType.DisableStartup => StartupApps.DisableStartup(s, a),
            MemoryActionType.ShutdownWsl => await ServiceFamily.ShutdownWslAsync(ct).ConfigureAwait(false),
            MemoryActionType.StopService or MemoryActionType.SetServiceManual or MemoryActionType.SetServiceDisabled => await ServiceFamily.ChangeServiceAsync(s, a, ct).ConfigureAwait(false),
            MemoryActionType.EnableBrowserMemorySaver => Browser.EnableMemorySaver(s, a),
            MemoryActionType.BlockBrowserExtension => Browser.BlockBrowserExtension(a),
            MemoryActionType.StopBrowserBackground => await Browser.StopBrowserBackgroundAsync(s, a, ct).ConfigureAwait(false),
            MemoryActionType.OpenSettings => OpenSettings(a),
            MemoryActionType.RestartPc or MemoryActionType.DisableFastStartup => await Power.RestartOrFastStartupAsync(a, ct).ConfigureAwait(false),
            MemoryActionType.ReduceHibernateFile => await Power.ReduceHibernateFileAsync(s, ct).ConfigureAwait(false),
            MemoryActionType.AutoManagePageFile => await Power.AutoManagePageFileAsync(ct).ConfigureAwait(false),
            MemoryActionType.DisableTransparency => Shell.DisableTransparency(s, a),
            MemoryActionType.DisableWidgets => await Shell.DisableWidgetsAsync(s, ct).ConfigureAwait(false),
            MemoryActionType.DisableSearchHighlights => Shell.DisableSearchHighlights(s),
            MemoryActionType.AddDefenderExclusions => await Defender.AddDefenderExclusionsAsync(s, ct).ConfigureAwait(false),
            MemoryActionType.SkipOfficeStartScreen => Office.SkipOfficeStartScreen(s),
            MemoryActionType.SetPdfDefaultPrinter => Office.SetPdfDefaultPrinter(s),
            MemoryActionType.DisableOfficeOptionalExperiences => Office.DisableOfficeOptionalExperiences(s),
            MemoryActionType.RemoveApp => await Apps.RemoveAppAsync(s, a, ct).ConfigureAwait(false),
            MemoryActionType.RemoveXboxApps => await Apps.RemoveXboxAppsAsync(s, ct).ConfigureAwait(false),
            MemoryActionType.RemoveNarratorAddons => await Apps.RemoveNarratorAddonsAsync(s, ct).ConfigureAwait(false),
            MemoryActionType.StopSilentAppInstalls => Apps.StopSilentAppInstalls(s),
            MemoryActionType.CleanStorage => await CleanStorageAsync(a, ct).ConfigureAwait(false),
            _ => new(false, "Unknown action."),
        };
    }

    private ActionOutcome OpenSettings(MemoryAction a)
    {
        if (!MemoryCommandAllowlist.IsAllowedSettingsUri(a.Target)) return new(false, "Not allowed.");
        sys.OpenUri(a.Target);
        return new(true, "Opened the settings page on this PC.");
    }
}
