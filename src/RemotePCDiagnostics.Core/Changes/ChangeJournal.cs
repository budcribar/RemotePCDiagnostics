using System.Text.Json;
using System.Text.Json.Serialization;

namespace RemotePCDiagnostics.Core.Changes;

/// <summary>Kinds of reversible changes. Each record keeps what was there before, so "Undo all" can put it back.</summary>
public enum ChangeKind
{
    StartupApp,          // Target = Run-key name; Previous = StartupApproved bytes (base64) or null (value absent)
    ServiceStartType,    // Target = service name; Previous = "Automatic" | "AutomaticDelayed" | "Manual" | "Disabled"
    ServiceRunning,      // Target = service name; Previous = "Running" | "Stopped"
    BrowserSettings,     // Target = BrowserKind; Previous = the browser's Local State JSON
    Transparency,        // Previous = "1" | "0"
    FastStartup,         // Previous = HiberbootEnabled value ("1")
    PowerPlan,           // Previous = scheme GUID
    SystemProxy,         // Previous = ProxyEnable value ("1")
    AdapterDns,          // Target = adapter alias; Previous = "" (automatic/DHCP) or "1.1.1.1,8.8.8.8"
    PageFile,            // Previous = base64 JSON of the custom page file settings
    TempFiles,           // Previous = "files:bytes" removed by the cleanup; permanent; undo reports it as skipped
    DefenderExclusion,   // Target = "path|C:\src\app" or "process|C:\...\MSBuild.exe"; added by this app, undo removes it
    HiberFileType,       // Previous = "full": hiberfil.sys was shrunk with powercfg /h /type reduced; undo runs /type full
    RegistryValue,       // Target = "HKLM\SOFTWARE\Policies\Microsoft\Dsh|AllowNewsAndInterests" (must be on RegistryAllowlist); Previous = old DWORD or null (absent: undo deletes it)
    NotUndoable,         // A permanent change (installed updates, removed apps); "Undo all" reports it as skipped, then forgets it
    ExtensionBlock,      // Target = "Chrome|<extension id>" (must be on BrowserExtensions.Allowlist); Previous = the blocklist value name this app added ("3"); undo deletes only that value
}

/// <param name="Label">Friendly, e.g. "Spotify won't start with Windows".</param>
/// <param name="NeedsRestart">Undo fully applies only after a restart (Fast Startup, page file).</param>
public sealed record ChangeRecord(Guid Id, DateTimeOffset TimeUtc, ChangeKind Kind, string Target, string? Previous, string Label, string Actor, bool NeedsRestart = false)
{
    public static ChangeRecord New(ChangeKind kind, string target, string? previous, string label, string actor, bool needsRestart = false) =>
        new(Guid.NewGuid(), DateTimeOffset.UtcNow, kind, target, previous, label, actor, needsRestart);
}

/// <summary>Changes made by this app that can be reverted, kept across restarts.</summary>
public interface IChangeJournal
{
    IReadOnlyList<ChangeRecord> All { get; }
    void Add(ChangeRecord r);
    void Remove(Guid id);
    /// <summary>Removes the newest record of this kind and target (after a per-item undo elsewhere in the app).</summary>
    void RemoveLatest(ChangeKind kind, string target);
    event Action? Changed;
}

/// <summary>In-memory journal (tests, or when no file can be written).</summary>
public class MemoryChangeJournal : IChangeJournal
{
    protected readonly object Gate = new();
    protected readonly List<ChangeRecord> Items = [];
    public event Action? Changed;
    public IReadOnlyList<ChangeRecord> All { get { lock (Gate) return Items.ToList(); } }

    public void Add(ChangeRecord r)
    {
        lock (Gate)
        {
            // Only the oldest "before" matters for a target: undoing must return to the state before this app touched it.
            if (Items.Any(x => x.Kind == r.Kind && string.Equals(x.Target, r.Target, StringComparison.OrdinalIgnoreCase))) return;
            Items.Add(r);
            Persist();
        }
        Raise();
    }

    public void Remove(Guid id) { lock (Gate) { Items.RemoveAll(x => x.Id == id); Persist(); } Raise(); }

    public void RemoveLatest(ChangeKind kind, string target)
    {
        lock (Gate)
        {
            var i = Items.FindLastIndex(x => x.Kind == kind && string.Equals(x.Target, target, StringComparison.OrdinalIgnoreCase));
            if (i < 0) return;
            Items.RemoveAt(i);
            Persist();
        }
        Raise();
    }

    protected virtual void Persist() { }
    private void Raise() { try { Changed?.Invoke(); } catch { } }
}

/// <summary>Journal saved as JSON in %LOCALAPPDATA%\RemotePCDiagnostics\changes.json (survives restarts).</summary>
public sealed class FileChangeJournal : MemoryChangeJournal
{
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };
    private readonly string _path;
    private readonly Action<string>? _log;

    public static string DefaultPath() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RemotePCDiagnostics", "changes.json");

    public FileChangeJournal(string path, Action<string>? log = null)
    {
        _path = path; _log = log;
        try
        {
            if (File.Exists(path) && JsonSerializer.Deserialize<List<ChangeRecord>>(File.ReadAllText(path), Json) is { } loaded) Items.AddRange(loaded);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException) { log?.Invoke($"Change journal read failed: {ex.Message}"); }
    }

    protected override void Persist()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            var tmp = _path + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(Items, Json));
            File.Move(tmp, _path, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { _log?.Invoke($"Change journal write failed: {ex.Message}"); }
    }
}
