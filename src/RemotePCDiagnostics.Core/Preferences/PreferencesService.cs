using System.Text.Json;
using System.Text.Json.Serialization;

namespace RemotePCDiagnostics.Core.Preferences;

/// <summary>
/// Choices the people using this app make on this PC, kept between runs (%LOCALAPPDATA%\RemotePCDiagnostics\preferences.json).
/// Shared by the local window and a remote user, like the rest of the app's state. Null = never chosen (use the default).
/// </summary>
public sealed record UserPreferences
{
    /// <summary>"dark", "light" or "system".</summary>
    public string? Theme { get; init; }

    /// <summary>Service workflow: fixes the remote user ticked or unticked by hand (fix id → ticked). Applied the next time the checks run.</summary>
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

    /// <summary>White-label shop or refurbisher branding applied to client service reports and 1-page buyer Hardware QA certificates.</summary>
    public Workflow.ShopBranding? Branding { get; init; }

    /// <summary>Preferred shop relay server URL (e.g. <c>https://relay.example.com</c>) for remote sessions and hosted QR certificate publishing.</summary>
    public string? RelayServerUrl { get; init; }

    /// <summary>Normalized shop tenant slug (e.g. <c>acme-pc</c>) for remote technician sessions and branding lookup.</summary>
    public string? ShopGroupSlug { get; init; }

    /// <summary>Shop API key (<c>rpd_live_...</c>) used exclusively as a Bearer header when publishing hosted reports/certificates; never embedded in HTML.</summary>
    public string? ShopApiKey { get; init; }

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

    /// <summary>Remembers the remote user's tick for these fixes (newest last; the oldest beyond the cap are dropped).</summary>
    public void RememberFixChoices(IEnumerable<(string Id, bool On)> choices)
    {
        var updates = new List<(string Id, bool On)>();
        var updatedIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var (id, on) in choices)
        {
            if (updatedIds.Add(id)) updates.Add((id, on));
            else
            {
                updates.RemoveAll(x => string.Equals(x.Id, id, StringComparison.Ordinal));
                updates.Add((id, on));
            }
        }
        Update(p =>
        {
            var ordered = new List<(string Id, bool On)>(p.WorkflowFixChoices.Count + updates.Count);
            foreach (var kv in p.WorkflowFixChoices)
                if (!updatedIds.Contains(kv.Key)) ordered.Add((kv.Key, kv.Value));
            ordered.AddRange(updates);
            var skip = Math.Max(0, ordered.Count - UserPreferences.MaxFixChoices);
            var keep = new Dictionary<string, bool>(Math.Min(ordered.Count, UserPreferences.MaxFixChoices), StringComparer.Ordinal);
            for (var i = skip; i < ordered.Count; i++) keep[ordered[i].Id] = ordered[i].On;
            return p with { WorkflowFixChoices = keep };
        });
    }

    public void ForgetFixChoices(IEnumerable<string> ids) =>
        Update(p => p with { WorkflowFixChoices = p.WorkflowFixChoices.Where(x => !ids.Contains(x.Key)).ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal) });

    /// <summary>Ticked or not for a fix: the remote user's earlier choice if there is one, otherwise the fix's default.</summary>
    public bool IsTicked(string fixId, bool defaultOn) => Current.WorkflowFixChoices.TryGetValue(fixId, out var on) ? on : defaultOn;
}
