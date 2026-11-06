using System.Text.Json;
using System.Text.Json.Serialization;

namespace RemotePCDiagnostics.Core.Preferences;

/// <summary>
/// Choices the people using this app make on this PC, kept between runs (%LOCALAPPDATA%\RemotePCDiagnostics\preferences.json).
/// Shared by the local window and a remote technician, like the rest of the app's state. Null = never chosen (use the default).
/// </summary>
public sealed record UserPreferences
{
    /// <summary>"dark", "light" or "system".</summary>
    public string? Theme { get; init; }

    /// <summary>Service workflow: fixes the technician ticked or unticked by hand (fix id → ticked). Applied the next time the checks run.</summary>
    public Dictionary<string, bool> WorkflowFixChoices { get; init; } = new(StringComparer.Ordinal);

    /// <summary>Service workflow review: fix areas left open.</summary>
    public List<string> WorkflowOpenAreas { get; init; } = [];

    /// <summary>Checks &amp; tests: group collapsed states, stress test length and the ticked checks/tests.</summary>
    public bool? ChecksCollapsed { get; init; }
    public bool? StressCollapsed { get; init; }
    public string? StressMode { get; init; }
    /// <summary>The ticked checks and tests, by module id.</summary>
    public List<Guid>? SelectedModuleIds { get; init; }
    /// <summary>Before module ids: the ticked modules by name. Only read to convert it to <see cref="SelectedModuleIds"/> (see
    /// <see cref="FilePreferencesStore.Load"/>); never written. Remove with the format 3 migration.</summary>
    public List<string>? SelectedModules { get; init; }

    /// <summary>Most remembered fix choices; the oldest are dropped first (fix ids from long-gone apps shouldn't pile up).</summary>
    public const int MaxFixChoices = 500;
}

public interface IPreferencesStore
{
    UserPreferences Load();
    void Save(UserPreferences p);
}

public sealed class MemoryPreferencesStore : IPreferencesStore
{
    private UserPreferences _p = new();
    public UserPreferences Load() => _p;
    public void Save(UserPreferences p) => _p = p;
}

/// <summary>JSON file; a missing or unreadable file means "no preferences yet" (never an error the user sees).</summary>
public sealed class FilePreferencesStore(string path, ILogger? log = null) : IPreferencesStore
{
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull };

    public static string DefaultPath() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RemotePCDiagnostics", "preferences.json");

    public UserPreferences Load()
    {
        try
        {
            if (!File.Exists(path)) return new();
            var p = JsonSerializer.Deserialize<UserPreferences>(File.ReadAllText(path), Json) ?? new();
            // One-time conversion: selections saved by name before module ids.
            if (p.SelectedModules is { } names)
                p = p with { SelectedModuleIds = p.SelectedModuleIds ?? names.Select(ModuleIds.FromSlug).OfType<Guid>().Distinct().ToList(), SelectedModules = null };
            return p with { WorkflowFixChoices = new(p.WorkflowFixChoices ?? new(), StringComparer.Ordinal), WorkflowOpenAreas = p.WorkflowOpenAreas ?? [] };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            log.Warn("[prefs] couldn't read preferences: " + ex.Message);
            return new();
        }
    }

    public void Save(UserPreferences p)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            var tmp = path + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(p, Json));
            File.Move(tmp, path, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { log.Warn("[prefs] couldn't save preferences: " + ex.Message); }
    }
}

/// <summary>The app's preferences: read once, updated and saved on every change.</summary>
public sealed class PreferencesService(IPreferencesStore store)
{
    private readonly object _gate = new();
    private UserPreferences _current = store.Load();

    public event Action? Changed;

    public UserPreferences Current { get { lock (_gate) return _current; } }

    public void Update(Func<UserPreferences, UserPreferences> change)
    {
        lock (_gate)
        {
            _current = change(_current);
            store.Save(_current);
        }
        try { Changed?.Invoke(); } catch { }
    }

    /// <summary>Remembers the technician's tick for these fixes (newest last; the oldest beyond the cap are dropped).</summary>
    public void RememberFixChoices(IEnumerable<(string Id, bool On)> choices)
    {
        Update(p =>
        {
            var d = new Dictionary<string, bool>(p.WorkflowFixChoices, StringComparer.Ordinal);
            foreach (var (id, on) in choices) { d.Remove(id); d[id] = on; } // re-inserted, so usually the newest are last
            var keep = d.Skip(Math.Max(0, d.Count - UserPreferences.MaxFixChoices)).ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal);
            return p with { WorkflowFixChoices = keep };
        });
    }

    public void ForgetFixChoices(IEnumerable<string> ids) =>
        Update(p => p with { WorkflowFixChoices = p.WorkflowFixChoices.Where(x => !ids.Contains(x.Key)).ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal) });

    /// <summary>Ticked or not for a fix: the technician's earlier choice if there is one, otherwise the fix's default.</summary>
    public bool IsTicked(string fixId, bool defaultOn) => Current.WorkflowFixChoices.TryGetValue(fixId, out var on) ? on : defaultOn;
}
