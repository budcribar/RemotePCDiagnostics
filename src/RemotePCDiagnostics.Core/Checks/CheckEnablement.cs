using System.Text.Json;
using System.Text.Json.Serialization;

namespace RemotePCDiagnostics.Core.Checks;

/// <summary>
/// One diagnostic check a technician can turn on or off. <see cref="Id"/> is the check id <c>list_checks</c> returns (the module slug).
/// A check the PC cannot run stays in the report with <see cref="Available"/> false and is not given a checkbox.
/// </summary>
public sealed record CheckChoice(string Id, string Title, string Category, bool Available, bool Enabled, string? Reason = null);

/// <summary>
/// Which diagnostic checks run on this PC. Saved the same way benchmark settings are: one file in the protected state folder, read and
/// written through the Agent, so the local window and a remote session share it and it survives a restart.
/// The file stores the ids that are turned off. A check that is not listed is enabled, including one added after the file was saved.
/// </summary>
public sealed record CheckSettings
{
    public const int CurrentSchemaVersion = 1;
    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    /// <summary>Check ids turned off. Empty means every diagnostic check is enabled.</summary>
    public IReadOnlyList<string> Disabled { get; init; } = [];

    /// <summary>Preferred display order of check ids (Dashboard cards and Checks list). Empty uses catalog order.</summary>
    public IReadOnlyList<string> Order { get; init; } = [];

    public bool IsEnabled(string checkId) =>
        !Disabled.Any(id => string.Equals(id, checkId, StringComparison.OrdinalIgnoreCase));

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };

    public string ToJson() => JsonSerializer.Serialize(
        this with { Disabled = CheckEnableRules.Normalize(Disabled), Order = CheckEnableRules.NormalizeOrder(Order) }, Json);

    public static CheckSettings? FromJson(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try
        {
            var state = JsonSerializer.Deserialize<CheckSettings>(json, Json);
            if (state is null) return null;
            if (!json.Contains("\"SchemaVersion\"", StringComparison.Ordinal))
                state = state with { SchemaVersion = 1 };
            return state with
            {
                SchemaVersion = CheckSettings.CurrentSchemaVersion,
                Disabled = CheckEnableRules.Normalize(state.Disabled),
                Order = CheckEnableRules.NormalizeOrder(state.Order),
            };
        }
        catch (JsonException) { return null; }
    }
}

public interface ICheckSettingsStore
{
    CheckSettings? Load();
    void Save(CheckSettings settings);
}

/// <summary>JSON file in the protected state folder (%ProgramData%\RemotePCDiagnostics\state; see <see cref="ProtectedState"/>).</summary>
public sealed class FileCheckSettingsStore(string path, ILogger? log = null) : ICheckSettingsStore
{
    public static string DefaultPath() => ProtectedState.PathFor(ProtectedState.CheckSettingsFile);

    public CheckSettings? Load()
    {
        try { return File.Exists(path) ? CheckSettings.FromJson(File.ReadAllText(path)) : null; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { log.Warn($"Check settings read failed: {ex.Message}"); return null; }
    }

    public void Save(CheckSettings settings)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            var tmp = path + ".tmp";
            File.WriteAllText(tmp, settings.ToJson());
            File.Move(tmp, path, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { log.Warn($"Check settings write failed: {ex.Message}"); }
    }
}

/// <summary>Which diagnostic checks are saved as enabled, and which this PC can turn on.</summary>
public static class CheckEnableRules
{
    /// <summary>Shown when a check is hidden because this PC lacks the hardware it measures.</summary>
    public const string UnavailableReason = "This PC doesn't have the hardware this check needs.";

    /// <summary>The reason stored on a result when a turned-off check is asked to run. History and the Checks row show it as Skipped.</summary>
    public const string TurnedOffReason = "this check is turned off";

    /// <summary>The checkbox test id for one check. The id is the check id, the same string <c>list_checks</c> returns.</summary>
    public static string Control(string checkId) => "check-enable-" + checkId;

    public static List<string> Normalize(IEnumerable<string>? ids)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (ids is not null)
            foreach (var id in ids)
                if (!string.IsNullOrWhiteSpace(id)) set.Add(id.Trim());
        return set.OrderBy(id => id, StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>Deduplicates and trims check ids while preserving their explicit display order.</summary>
    public static List<string> NormalizeOrder(IEnumerable<string>? ids)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var list = new List<string>();
        if (ids is not null)
        {
            foreach (var id in ids)
            {
                var trimmed = id?.Trim();
                if (!string.IsNullOrWhiteSpace(trimmed) && seen.Add(trimmed))
                    list.Add(trimmed);
            }
        }
        return list;
    }

    /// <summary>Orders <paramref name="items"/> according to <paramref name="order"/>; unlisted items retain their original relative order at the end.</summary>
    public static List<T> ApplyOrder<T>(IEnumerable<T> items, Func<T, string> getId, IReadOnlyList<string>? order)
    {
        var list = items.ToList();
        if (order is null || order.Count == 0 || list.Count <= 1) return list;
        var rank = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < order.Count; i++)
            rank.TryAdd(order[i], i);
        return list
            .Select((item, idx) => (item, r: rank.TryGetValue(getId(item), out var pos) ? pos : int.MaxValue, idx))
            .OrderBy(x => x.r).ThenBy(x => x.idx)
            .Select(x => x.item)
            .ToList();
    }

    /// <summary>Moves <paramref name="fromId"/> to the position of <paramref name="toId"/> across the combined ordered list.</summary>
    public static IReadOnlyList<string> Reorder(IReadOnlyList<string> currentOrder, IEnumerable<string> allIds, string fromId, string toId)
    {
        if (string.IsNullOrWhiteSpace(fromId) || string.IsNullOrWhiteSpace(toId) || string.Equals(fromId, toId, StringComparison.OrdinalIgnoreCase))
            return NormalizeOrder(currentOrder);
        var combined = ApplyOrder(NormalizeOrder(allIds), id => id, currentOrder);
        var fromIdx = combined.FindIndex(id => string.Equals(id, fromId, StringComparison.OrdinalIgnoreCase));
        var toIdx = combined.FindIndex(id => string.Equals(id, toId, StringComparison.OrdinalIgnoreCase));
        if (fromIdx < 0 || toIdx < 0 || fromIdx == toIdx) return combined;
        var moved = combined[fromIdx];
        combined.RemoveAt(fromIdx);
        combined.Insert(toIdx, moved);
        return combined;
    }

    /// <summary>The disabled list after turning <paramref name="checkId"/> on or off. Turning an unavailable check on leaves the list as it was.</summary>
    public static IReadOnlyList<string> WithEnabled(CheckSettings settings, string checkId, bool on, bool available)
    {
        if (string.IsNullOrWhiteSpace(checkId) || (on && !available)) return settings.Disabled;
        var set = new HashSet<string>(settings.Disabled, StringComparer.OrdinalIgnoreCase);
        if (on) set.Remove(checkId);
        else set.Add(checkId.Trim());
        return Normalize(set);
    }

    /// <summary>The disabled list after turning every available check on or off. Checks that are hidden are left as they were.</summary>
    public static IReadOnlyList<string> WithAll(CheckSettings settings, IEnumerable<string> availableIds, bool on)
    {
        var available = new HashSet<string>(availableIds.Where(id => !string.IsNullOrWhiteSpace(id)).Select(id => id.Trim()), StringComparer.OrdinalIgnoreCase);
        var set = new HashSet<string>(settings.Disabled, StringComparer.OrdinalIgnoreCase);
        if (on) set.RemoveWhere(available.Contains);
        else foreach (var id in available) set.Add(id);
        return Normalize(set);
    }

    /// <summary>A result recorded instead of running a check that is turned off. Warning plus a skip gate: the row says Skipped, not failed.</summary>
    public static DiagnosticResult SkippedResult(string checkId, Guid moduleId) =>
        ModuleOrdering.GateResult(checkId, new DependencyGate(GateKind.Skipped, TurnedOffReason, moduleId));

    public static bool IsTurnedOff(DiagnosticResult result) =>
        result.Payload is DependencyGate { Kind: GateKind.Skipped, Reason: TurnedOffReason };

    /// <summary>
    /// Every diagnostic check (the ones <c>list_checks</c> lists: Run all checks), in catalog order, including ones hidden because the
    /// hardware is missing. A check whose hardware detection has not finished yet is left out, the same way the page hides it until it knows.
    /// </summary>
    public static IReadOnlyList<CheckChoice> Choices(DiagnosticsService diagnostics, CheckSettings settings)
    {
        var list = new List<CheckChoice>();
        foreach (var descriptor in diagnostics.Catalog.All)
        {
            var module = diagnostics.Catalog.ModuleFor(descriptor.Id);
            if (module is null || !module.IncludeInRunAll) continue;
            if (diagnostics.Catalog.StateOf(module.Id) == ModuleState.Disabled) continue;
            if (!TryAvailability(diagnostics, module, out var available, out var reason)) continue;
            list.Add(new CheckChoice(
                module.Name, module.DisplayName, ModuleGroups.DisplayName(descriptor.Group),
                available, settings.IsEnabled(module.Name), available ? null : reason));
        }
        return list;
    }

    /// <summary>False when the check should be left out of the report (hardware detection is still running).</summary>
    private static bool TryAvailability(DiagnosticsService diagnostics, IDiagnosticModule module, out bool available, out string? reason)
    {
        available = true;
        reason = null;
        if (module is IHardwareGatedModule gated)
        {
            if (gated.IsPresent) return true;
            if (diagnostics.IsDetectingHardware) return false;
            available = false;
            reason = UnavailableReason;
            return true;
        }
        if (module is IDetectableModule)
        {
            var detection = diagnostics.DetectionOf(module.Id);
            if (detection is null) return false;
            if (detection.Applies) return true;
            available = false;
            reason = string.IsNullOrWhiteSpace(detection.NotApplicableReason) ? UnavailableReason : detection.NotApplicableReason;
            return true;
        }
        return diagnostics.Catalog.StateOf(module.Id) == ModuleState.Available;
    }
}

/// <summary>The saved enablement for this PC. A missing file means every diagnostic check is enabled.</summary>
public sealed class CheckSettingsService
{
    private readonly ICheckSettingsStore _store;
    private readonly object _gate = new();
    private CheckSettings _state;

    public CheckSettingsService(ICheckSettingsStore store)
    {
        _store = store;
        _state = store.Load() ?? new CheckSettings();
    }

    public event Action? Changed;

    public CheckSettings Settings { get { lock (_gate) return _state; } }

    public bool IsEnabled(string checkId) => Settings.IsEnabled(checkId);

    /// <summary>
    /// Reads the saved file again: the app reads it through the Agent, which may connect after the service was made. Does nothing when
    /// nothing could be read. True when it read the file.
    /// </summary>
    public bool Reload()
    {
        var saved = _store.Load();
        if (saved is null) return false;
        lock (_gate) _state = saved;
        Raise();
        return true;
    }

    public void SetEnabled(string checkId, bool on, bool available) => SetEnabled(checkId, on, available, persistToHost: true);

    public void SetEnabled(string checkId, bool on, bool available, bool persistToHost) =>
        Save(Settings with { Disabled = CheckEnableRules.WithEnabled(Settings, checkId, on, available) }, persistToHost);

    public void SetAll(IEnumerable<string> availableIds, bool on) => SetAll(availableIds, on, persistToHost: true);

    public void SetAll(IEnumerable<string> availableIds, bool on, bool persistToHost) =>
        Save(Settings with { Disabled = CheckEnableRules.WithAll(Settings, availableIds, on) }, persistToHost);

    public void SetOrder(IEnumerable<string> orderedIds, bool persistToHost = true) =>
        Save(Settings with { Order = CheckEnableRules.NormalizeOrder(orderedIds) }, persistToHost);

    public void Reorder(string fromId, string toId, IEnumerable<string> allIds, bool persistToHost = true) =>
        Save(Settings with { Order = CheckEnableRules.Reorder(Settings.Order, allIds, fromId, toId) }, persistToHost);

    /// <summary>Applies a remote technician's saved preferences to this session without overwriting the customer PC's host settings file.</summary>
    public void ApplyRemotePrefs(CheckSettings prefs) => Save(prefs, persistToHost: false);

    private void Save(CheckSettings settings, bool persistToHost = true)
    {
        CheckSettings saved;
        lock (_gate)
            _state = saved = settings with
            {
                SchemaVersion = CheckSettings.CurrentSchemaVersion,
                Disabled = CheckEnableRules.Normalize(settings.Disabled),
                Order = CheckEnableRules.NormalizeOrder(settings.Order),
            };
        if (persistToHost) _store.Save(saved);
        Raise();
    }

    private void Raise() { try { Changed?.Invoke(); } catch { } }
}
