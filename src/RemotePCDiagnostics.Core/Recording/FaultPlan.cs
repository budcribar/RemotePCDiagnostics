using System.Text.Json;
using System.Text.Json.Serialization;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Core.Recording;

/// <summary>
/// One fault to inject: which answers it breaks (<see cref="Source"/> and <see cref="Match"/>) and how (<see cref="Fault"/>, one of
/// <see cref="Faults"/>). Used by the fault-injection UI tests (docs/fault-injection.md) to break a replayed PC's answers while the real
/// pages run on them.
/// </summary>
public sealed record FaultRule
{
    /// <summary>wmi, registry, packages, antivirus, audio, display, devicesensors, process, file, or * for any.</summary>
    public string Source { get; init; } = "*";
    /// <summary>Text the answer's <see cref="RecordingReplay.Key"/> contains (case ignored), or * for any.</summary>
    public string Match { get; init; } = "*";
    public string Fault { get; init; } = "";
    /// <summary>For delay and timeout: how long to wait first.</summary>
    public int? Ms { get; init; }
    /// <summary>For error: the message (otherwise a generic WMI failure).</summary>
    public string? Message { get; init; }
    /// <summary>For value: the row (default 0), the property and the value it gets (absent = the property is removed).</summary>
    public int? Row { get; init; }
    public string? Property { get; init; }
    public JsonElement? Value { get; init; }
    /// <summary>For drop-after: how many WMI answers the Agent gives before it drops.</summary>
    public int? After { get; init; }
    /// <summary>Break only the first matching answer (for retry tests).</summary>
    public bool Once { get; init; }

    public bool Applies(string source, string key) =>
        (Source == "*" || string.Equals(Source, source, StringComparison.OrdinalIgnoreCase)) &&
        (Match == "*" || key.Contains(Match, StringComparison.OrdinalIgnoreCase));

    public override string ToString() => $"{Source} {Match}: {Fault}";
}

/// <summary>The faults a <see cref="FaultRule"/> can inject. Whole-answer errors use the wording Windows gives (<see cref="SystemWmiSource"/>).</summary>
public static class Faults
{
    // A failed answer.
    public const string Error = "error", AccessDenied = "access-denied", MissingClass = "missing-class", MissingNamespace = "missing-namespace",
        InvalidQuery = "invalid-query", ProviderFailure = "provider-failure", Quota = "quota";
    // An answer that isn't what was expected.
    public const string Empty = "empty", Garbage = "garbage", CutOff = "cut-off", ExitCode = "exit-code", Value = "value";
    // Timing: answers late, never answers until cancelled, or fails after a wait as WMI does when it times out.
    public const string Delay = "delay", Hang = "hang", Timeout = "timeout";
    // The Agent (which reads all WMI): never connected, or drops after some answers.
    public const string Disconnected = "disconnected", DropAfter = "drop-after";

    /// <summary>Every whole-answer fault, for the fault matrix.</summary>
    public static readonly IReadOnlyList<string> WholeAnswer = [AccessDenied, MissingClass, MissingNamespace, InvalidQuery, ProviderFailure, Timeout, Empty, Garbage, CutOff];

    public const string GarbageText = "@@ garbage ##";
    public const string TimedOutText = "The query timed out after 30s.";

    /// <summary>The error text for a failed-answer fault, as <see cref="SystemWmiSource"/> words a real ManagementException; null for other
    /// faults. <paramref name="recorded"/>: the errors the recorded PC really gave (<see cref="ErrorProbes"/>), used first.</summary>
    public static string? ErrorText(FaultRule rule, IReadOnlyDictionary<string, string>? recorded = null) => rule.Fault switch
    {
        _ when rule.Message is null && recorded is not null && recorded.TryGetValue(rule.Fault, out var real) => real,
        Error => rule.Message ?? "Failed (0x80041001): Generic failure",
        AccessDenied => "AccessDenied (0x80041003): Access denied",
        MissingClass => "InvalidClass (0x80041010): Invalid class",
        MissingNamespace => "InvalidNamespace (0x8004100E): Invalid namespace",
        InvalidQuery => "InvalidQuery (0x80041017): Invalid query",
        ProviderFailure => "ProviderLoadFailure (0x80041013): Provider load failure",
        Quota => "QuotaViolation (0x8004106C): Quota violation",
        Timeout => TimedOutText,
        Disconnected or DropAfter => AgentWmiSource.NotConnected,
        _ => null,
    };
}

/// <summary>
/// The faults in force. Thread safe: the UI tests change it while the replay host runs. <see cref="Hits"/> lists each fault injected, so a
/// test can tell a fault that never applied (its check didn't ask that question) from one the page handled.
/// </summary>
public sealed class FaultPlan
{
    private readonly object _gate = new();
    private List<FaultRule> _rules = [];
    private readonly HashSet<FaultRule> _spent = [];
    private readonly List<string> _hits = [];
    private readonly List<string> _questions = [];
    private int _wmiAnswers;

    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = true,
    };

    public FaultPlan(IEnumerable<FaultRule>? rules = null) { if (rules is not null) Set(rules); }

    /// <summary>The errors the replayed PC really gave (<see cref="ErrorProbes"/>), used instead of the standard wording when present.</summary>
    public IReadOnlyDictionary<string, string> RecordedErrors { get; private set; } = new Dictionary<string, string>();

    public void UseRecordedErrors(MachineRecording recording) => RecordedErrors = ErrorProbes.From(recording);

    /// <summary>The error text this rule answers with (null: the rule doesn't fail the answer).</summary>
    public string? ErrorFor(FaultRule rule) => Faults.ErrorText(rule, RecordedErrors);

    public IReadOnlyList<FaultRule> Rules { get { lock (_gate) return [.. _rules]; } }
    public IReadOnlyList<string> Hits { get { lock (_gate) return [.. _hits]; } }

    /// <summary>Every question asked through the plan, in order, faulted or not (<see cref="RecordingReplay.Key"/>), from the
    /// <paramref name="since"/>th on: a test notes the count before running one check, then reads which questions that check asked.</summary>
    public IReadOnlyList<string> Questions(int since = 0) { lock (_gate) return [.. _questions.Skip(since)]; }

    public int QuestionCount { get { lock (_gate) return _questions.Count; } }

    /// <summary>Replaces the rules, and starts the Agent's answer count and the hit list again.</summary>
    public void Set(IEnumerable<FaultRule> rules)
    {
        lock (_gate)
        {
            _rules = [.. rules];
            _spent.Clear();
            _hits.Clear();
            _wmiAnswers = 0;
        }
    }

    public void Clear() => Set([]);

    /// <summary>Reads <c>{ "rules": [ ... ] }</c> or a bare array of rules.</summary>
    public static IReadOnlyList<FaultRule> Parse(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var array = doc.RootElement.ValueKind == JsonValueKind.Object && doc.RootElement.TryGetProperty("rules", out var r) ? r : doc.RootElement;
        return array.Deserialize<List<FaultRule>>(Json) ?? [];
    }

    /// <summary>The rule that breaks this answer, or null. A <see cref="FaultRule.Once"/> rule is spent by its first answer.</summary>
    public FaultRule? For(string source, string key)
    {
        lock (_gate)
        {
            _questions.Add(key);
            if (source == RecordedCall.WmiKind)
            {
                _wmiAnswers++;
                foreach (var rule in _rules)
                    if (rule.Fault == Faults.Disconnected || (rule.Fault == Faults.DropAfter && _wmiAnswers > (rule.After ?? 0)))
                        return Hit(rule, key);
            }
            foreach (var rule in _rules)
            {
                if (rule.Fault is Faults.Disconnected or Faults.DropAfter || _spent.Contains(rule) || !rule.Applies(source, key)) continue;
                if (rule.Once) _spent.Add(rule);
                return Hit(rule, key);
            }
            return null;
        }
    }

    private FaultRule Hit(FaultRule rule, string key)
    {
        _hits.Add($"{rule.Fault}: {key.Replace('\n', ' ')}");
        return rule;
    }

    /// <summary>Waits as the timing faults say. Hang waits until <paramref name="ct"/> is cancelled (then throws, as a cancelled read does).</summary>
    public static async Task WaitAsync(FaultRule rule, CancellationToken ct)
    {
        switch (rule.Fault)
        {
            case Faults.Delay: await Task.Delay(rule.Ms ?? 3000, ct).ConfigureAwait(false); break;
            case Faults.Timeout: await Task.Delay(rule.Ms ?? 3000, ct).ConfigureAwait(false); break;
            case Faults.Hang: await Task.Delay(System.Threading.Timeout.Infinite, ct).ConfigureAwait(false); break;
        }
    }

    /// <summary>A WMI-shaped answer (WMI, the registry, the package list) with the fault applied.</summary>
    public static WmiQueryResult Apply(FaultRule rule, WmiQueryResult answer, string? error = null)
    {
        error ??= Faults.ErrorText(rule);
        if (error is not null) return WmiQueryResult.Failed(answer.Namespace, answer.Query, error);
        var rows = answer.Rows;
        if (rows is null) return answer;
        return rule.Fault switch
        {
            Faults.Empty => answer with { Rows = [] },
            Faults.CutOff => answer with { Rows = [.. rows.Take(rows.Count / 2)] },
            Faults.Garbage => answer with
            {
                Rows = [.. rows.Select(r => new WmiRow(r.Values.ToDictionary(v => v.Key, _ => JsonSerializer.SerializeToElement(Faults.GarbageText))))],
            },
            Faults.Value when rule.Property is { } property && (rule.Row ?? 0) < rows.Count => answer with
            {
                Rows = [.. rows.Select((r, i) => i == (rule.Row ?? 0) ? WithValue(r, property, rule.Value) : r)],
            },
            _ => answer,
        };
    }

    private static WmiRow WithValue(WmiRow row, string property, JsonElement? value)
    {
        var values = new Dictionary<string, JsonElement>(row.Values, StringComparer.OrdinalIgnoreCase);
        if (value is { } v) values[property] = v; else values.Remove(property);
        return new(values);
    }

    /// <summary>A program's output with the fault applied.</summary>
    public static ProcessResult Apply(FaultRule rule, ProcessResult answer) => rule.Fault switch
    {
        Faults.Timeout => answer with { TimedOut = true, StdOut = "" },
        Faults.ExitCode or Faults.AccessDenied => new(1, "", "Access is denied."),
        _ when Faults.ErrorText(rule) is { } error => new(1, "", error),
        Faults.Empty => answer with { StdOut = "" },
        Faults.Garbage => answer with { StdOut = Faults.GarbageText + "\n\u0000\u0007" },
        Faults.CutOff => answer with { StdOut = answer.StdOut[..(answer.StdOut.Length / 2)] },
        _ => answer,
    };

    /// <summary>A report file's text with the fault applied (null: the file couldn't be read).</summary>
    public static string? Apply(FaultRule rule, string? text) => rule.Fault switch
    {
        _ when Faults.ErrorText(rule) is not null => null,
        Faults.Empty => "",
        Faults.Garbage => Faults.GarbageText,
        Faults.CutOff => text?[..(text.Length / 2)],
        _ => text,
    };
}
