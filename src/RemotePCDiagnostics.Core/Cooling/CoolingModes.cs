using System.Text.Json;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Cooling;

/// <summary>One mode a thermal setting can take: its id as the setting stores it, and the name people know it by.</summary>
public sealed record CoolingModeOption(string Id, string Name);

/// <summary>
/// One switchable thermal setting: Windows' power mode (<see cref="CoolingModes.WindowsKind"/>) or the PC maker's thermal profile
/// (<see cref="CoolingModes.MakerKind"/>). <see cref="Options"/> is empty, with <see cref="Note"/> saying why, when it can't be switched here.
/// </summary>
public sealed record CoolingModeGroup(string Kind, string Title, string? Current, IReadOnlyList<CoolingModeOption> Options, string? Note = null)
{
    public string NameOf(string? id) => id is null ? "unknown" : Options.FirstOrDefault(o => string.Equals(o.Id, id, StringComparison.OrdinalIgnoreCase))?.Name ?? id;
}

/// <summary>The Agent's answer to a <see cref="AgentScripts.CoolingModes"/> request: the settings as they are now (after a set, read back).</summary>
/// <param name="SetError">After a set: why the setting refused the change, or null when it took it.</param>
/// <param name="Restored">After restore: true when every setting is back as it was before the test.</param>
public sealed record CoolingModesAnswer(IReadOnlyList<CoolingModeGroup> Groups, string? SetError = null, bool? Restored = null)
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public CoolingModeGroup? Group(string kind) => Groups.FirstOrDefault(g => g.Kind == kind);

    public string ToJson() => JsonSerializer.Serialize(this, Json);

    public static CoolingModesAnswer? Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try { return JsonSerializer.Deserialize<CoolingModesAnswer>(json.Trim(), Json) is { Groups: not null } a ? a : null; }
        catch (JsonException) { return null; }
    }
}

/// <param name="NoAgent">No Agent (the Store edition on its own, or an Agent too old to know the request): that part is Skipped, not failed.</param>
public sealed record CoolingModesReply(CoolingModesAnswer? Answer, string? Error, bool NoAgent = false)
{
    public bool Ok => Answer is not null;
    public const string TooOldText = "The Agent on this PC is too old to switch thermal modes. Update RPCD, then run the test again.";

    public static CoolingModesReply Failed(string why, bool noAgent = false) => new(null, why, noAgent);

    public static CoolingModesReply Read(ProcessResult? r, bool hasAdminRights)
    {
        if (r is null) return Failed("The Agent didn't answer.");
        if (Areas.SystemCommandRunner.AgentFailure(r) is { } missing && !hasAdminRights)
            return Failed(missing.Trim().Length > 0 ? missing.Trim() : "The Agent isn't connected.", noAgent: true);
        var err = r.StdErr.Trim();
        if (err.StartsWith("Unknown script", StringComparison.Ordinal)) return Failed(TooOldText, noAgent: true);
        if (r.TimedOut) return Failed("The Agent didn't answer in time.");
        if (r.ExitCode != 0) return Failed(err.Length > 0 ? err : $"The Agent answered with exit code {r.ExitCode}.");
        return CoolingModesAnswer.Parse(r.StdOut) is { } a ? new(a, null) : Failed("The Agent's answer couldn't be read.");
    }
}

/// <summary><see cref="AgentScripts.CoolingModes"/>: <c>list</c>; <c>set windows|maker VALUE</c>; <c>restore</c>.</summary>
public sealed record CoolingModesAction(string Verb, string? Kind = null, string? Value = null) : AgentNativeAction
{
    public const string List = "list", Set = "set", Restore = "restore";
    public const int MaxValueLength = 64;

    /// <summary>The request in <paramref name="a"/>, or null when it isn't exactly one this app sends.</summary>
    public static CoolingModesAction? Parse(IReadOnlyList<string> a)
    {
        if (a.Count == 1 && a[0] is List or Restore) return new(a[0]);
        if (a.Count != 3 || a[0] != Set || a[1] is not (CoolingModes.WindowsKind or CoolingModes.MakerKind)) return null;
        var v = a[2];
        if (string.IsNullOrWhiteSpace(v) || v.Length > MaxValueLength || v.Any(char.IsControl)) return null;
        // Windows' power mode is one of its three overlay GUIDs; a maker value is checked against the list the setting itself gives.
        if (a[1] == CoolingModes.WindowsKind && !WindowsPowerMode.IsKnown(v)) return null;
        return new(Set, a[1], v);
    }

    public IReadOnlyList<string> Args() => Verb == Set ? [Verb, Kind!, Value!] : [Verb];
}

/// <summary>A thermal setting the Agent can read and switch, behind an interface so the journal and restore can be tested.</summary>
public interface IThermalModeSetting
{
    /// <summary><see cref="CoolingModes.WindowsKind"/> or <see cref="CoolingModes.MakerKind"/>.</summary>
    string Kind { get; }
    /// <summary>The setting now; null when this PC doesn't have it at all.</summary>
    CoolingModeGroup? Read();
    /// <summary>Sets <paramref name="id"/> (one of the setting's own options). Null when it took the change, else why not.</summary>
    string? Set(string id);
}

/// <summary>What the Agent changed, written before the first change so a crash or restart still puts it back.</summary>
public sealed record CoolingModesJournal(Dictionary<string, string> Originals, DateTimeOffset Since);

public static class CoolingModes
{
    public const string WindowsKind = "windows", MakerKind = "maker";
    public const string JournalFile = "cooling-modes.json";
}

/// <summary>
/// The Agent's side of <see cref="AgentScripts.CoolingModes"/>. Before the first switch it journals every setting's current mode
/// (<see cref="ProtectedState"/>); restore sets each one back and removes the journal, and the Agent restores at start when one is left.
/// A set is only to a mode the setting itself lists.
/// </summary>
/// <param name="settle">How long a set may take to show when read back (firmware and maker services can apply it a moment later);
/// the setting is read again every <see cref="SettleStep"/> until it shows or this runs out. Null is 2 seconds.</param>
public sealed class AgentCoolingModes(IReadOnlyList<IThermalModeSetting> settings, string journalPath, ILogger? log = null, TimeSpan? settle = null)
{
    public static readonly TimeSpan SettleStep = TimeSpan.FromMilliseconds(250);
    private readonly TimeSpan _settle = settle ?? TimeSpan.FromSeconds(2);
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private static readonly object Gate = new();

    public ProcessResult Run(CoolingModesAction action)
    {
        lock (Gate)
        {
            try
            {
                switch (action.Verb)
                {
                    case CoolingModesAction.List:
                        return Answer(new(ReadAll()));
                    case CoolingModesAction.Set:
                        return SetOne(action.Kind!, action.Value!);
                    case CoolingModesAction.Restore:
                        var ok = RestoreAll();
                        return Answer(new(ReadAll(), Restored: ok));
                    default:
                        return new(1, "", "That isn't a thermal mode request.");
                }
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                log.Warn($"[cooling] {string.Join(' ', action.Args())} failed: {ex}");
                return new(1, "", "The thermal mode couldn't be read or changed: " + ex.Message.Trim());
            }
        }
    }

    /// <summary>At the Agent's start: puts back modes a cooling test changed before a crash or restart. Never throws.</summary>
    public void RecoverAtStart()
    {
        try
        {
            lock (Gate)
            {
                if (!File.Exists(journalPath)) return;
                log.Info("[cooling] A cooling test's thermal modes were still changed at start; putting them back.");
                RestoreAll();
            }
        }
        catch (Exception ex) { log.Warn($"[cooling] Couldn't restore the thermal modes at start: {ex.Message}"); }
    }

    private List<CoolingModeGroup> ReadAll()
    {
        var groups = new List<CoolingModeGroup>();
        foreach (var s in settings)
        {
            try { if (s.Read() is { } g) groups.Add(g); }
            catch (Exception ex) when (ex is not OutOfMemoryException) { log.Warn($"[cooling] reading {s.Kind} failed: {ex.Message}"); }
        }
        return groups;
    }

    private ProcessResult SetOne(string kind, string id)
    {
        var setting = settings.FirstOrDefault(s => s.Kind == kind);
        if (setting?.Read() is not { } now) return new(1, "", "This PC has no such thermal setting.");
        var option = now.Options.FirstOrDefault(o => string.Equals(o.Id, id, StringComparison.OrdinalIgnoreCase));
        if (option is null) return new(1, "", $"\"{id}\" isn't a mode this setting lists.");
        if (!Journal()) return new(1, "", "The current thermal modes couldn't be saved first, so nothing was changed.");
        var why = string.Equals(now.Current, option.Id, StringComparison.OrdinalIgnoreCase) ? null : setting.Set(option.Id);
        if (why is null) WaitToShow(setting, option.Id);
        log.Info($"[cooling] set {kind} to {option.Name} ({option.Id}): {why ?? "done"}");
        return Answer(new(ReadAll(), SetError: why));
    }

    /// <summary>Reads <paramref name="setting"/> again until it shows <paramref name="id"/> or the settle time runs out.</summary>
    private void WaitToShow(IThermalModeSetting setting, string id)
    {
        for (var waited = TimeSpan.Zero; waited < _settle; waited += SettleStep)
        {
            string? current;
            try { current = setting.Read()?.Current; }
            catch (Exception ex) when (ex is not OutOfMemoryException) { return; }
            if (string.Equals(current, id, StringComparison.OrdinalIgnoreCase)) return;
            Thread.Sleep(SettleStep);
        }
    }

    /// <summary>Writes the journal once (the first switch of a run); true when it exists afterwards.</summary>
    private bool Journal()
    {
        if (File.Exists(journalPath)) return true;
        var originals = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var g in ReadAll())
            if (g.Options.Count > 0 && g.Current is { } c) originals[g.Kind] = c;
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(journalPath)!);
            File.WriteAllText(journalPath, JsonSerializer.Serialize(new CoolingModesJournal(originals, DateTimeOffset.Now), Json));
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            log.Warn($"[cooling] Couldn't journal the thermal modes: {ex.Message}");
            return false;
        }
    }

    private bool RestoreAll()
    {
        if (!File.Exists(journalPath)) return true;
        CoolingModesJournal? journal;
        try { journal = JsonSerializer.Deserialize<CoolingModesJournal>(File.ReadAllText(journalPath), Json); }
        catch (JsonException ex) { log.Warn($"[cooling] The journal couldn't be read: {ex.Message}"); TryDelete(); return true; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { log.Warn($"[cooling] The journal couldn't be read: {ex.Message}"); return false; }
        if (journal is null) { TryDelete(); return true; }
        var failed = 0;
        foreach (var (kind, original) in journal.Originals)
        {
            var setting = settings.FirstOrDefault(s => s.Kind == kind);
            if (setting is null) continue;
            string? why;
            try { why = string.Equals(setting.Read()?.Current, original, StringComparison.OrdinalIgnoreCase) ? null : setting.Set(original); }
            catch (Exception ex) when (ex is not OutOfMemoryException) { why = ex.Message; }
            if (why is not null) { failed++; log.Warn($"[cooling] Couldn't put {kind} back to {original}: {why}"); }
        }
        // Kept when something didn't go back, so the next restore (or the next start of the Agent) tries again.
        if (failed == 0) TryDelete();
        else return false;
        log.Info($"[cooling] Thermal modes restored ({journal.Originals.Count}).");
        return true;
    }

    private void TryDelete()
    {
        try { File.Delete(journalPath); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { log.Warn($"[cooling] Couldn't remove {journalPath}: {ex.Message}"); }
    }

    private static ProcessResult Answer(CoolingModesAnswer a) => new(0, a.ToJson(), "");
}
