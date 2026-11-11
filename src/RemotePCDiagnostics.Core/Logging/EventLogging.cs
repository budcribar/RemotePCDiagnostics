using System.Collections;
using System.Collections.Concurrent;
using System.Globalization;
using System.Reflection;
using System.Text;
using RemotePCDiagnostics.Core.Security;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Sensors;

namespace RemotePCDiagnostics.Core.Logging;

public enum LogLevel { Information, Warning, Error }

/// <summary>Stable Windows Event Log IDs per category (see README "Windows Event Log").</summary>
public static class LogEventIds
{
    public const int AppStart = 1000, AppExit = 1001;
    /// <summary>Written while the app's events move to its own log, to see which log Windows puts them in.</summary>
    public const int LogMoveProbe = 1002;
    public const int TestResult = 1100, SuiteStarted = 1110, SuiteFinished = 1111;
    public const int FanDiagnostic = 1200;
    public const int SensorDriver = 1300;
    public const int MemorySuggestion = 1400;
    public const int Benchmark = 1500;
    public const int Undo = 1600;
    public const int Workflow = 1700;
    /// <summary>A module plugin loaded, or was found and disabled (with the reason).</summary>
    public const int ModulePlugin = 1800;
    public const int Error = 1900;
    /// <summary>A warning-level line from the app log that no specific category claimed.</summary>
    public const int AppWarning = 1910;
}

/// <summary>Extra fields written into each 1100 event (test display name, machine, app version).</summary>
/// <param name="ModuleId">The module's permanent id for a slug (the catalog's); defaults to <see cref="History.HistoryIds.For"/>.</param>
public sealed record ResultEventContext(Func<string, string>? DisplayName, Func<string>? Machine, string? AppVersion, Func<string, Guid>? ModuleId = null);

public sealed record LogEntry(int EventId, LogLevel Level, string Message);

/// <summary>Structured log destination (Host: Windows Event Log). Implementations must be cheap, thread-safe and never throw.</summary>
public interface ILogSink
{
    void Write(LogEntry entry);
}

public static class LogText
{
    /// <summary>Event Log message limit is 31,839 chars; keep a margin.</summary>
    public const int MaxMessageLength = 31000;
    public const string TruncatedSuffix = "… [truncated]";

    public static string Truncate(string? s) => s is null ? "" :
        s.Length <= MaxMessageLength ? s : s[..(MaxMessageLength - TruncatedSuffix.Length)] + TruncatedSuffix;

    /// <summary>Which existing App.Log lines also go to the event log (null = file only).</summary>
    public static LogEntry? Route(string message)
    {
        if (string.IsNullOrEmpty(message)) return null;
        if (message.StartsWith("Fan diagnostic", StringComparison.Ordinal))
            return new(LogEventIds.FanDiagnostic, message.Contains("failed", StringComparison.OrdinalIgnoreCase) || message.Contains("error", StringComparison.OrdinalIgnoreCase) || message.Contains("backing off", StringComparison.Ordinal) ? LogLevel.Warning : LogLevel.Information, message);
        if (message.StartsWith("CPU sensor driver", StringComparison.Ordinal) || message.StartsWith("LibreHardwareMonitor: no usable CPU temperature", StringComparison.Ordinal))
            return new(LogEventIds.SensorDriver, LogLevel.Information, message);
        if (message.StartsWith("LibreHardwareMonitor open failed", StringComparison.Ordinal))
            return new(LogEventIds.SensorDriver, LogLevel.Error, message);
        if (message.StartsWith("Stress suite (", StringComparison.Ordinal))
            return new(message.Contains(" started", StringComparison.Ordinal) ? LogEventIds.SuiteStarted : LogEventIds.SuiteFinished, LogLevel.Information, message);
        if (message.StartsWith("Unhandled:", StringComparison.Ordinal) || message.StartsWith("Fatal:", StringComparison.Ordinal))
            return new(LogEventIds.Error, LogLevel.Error, message);
        return null;
    }
}

/// <summary>
/// Writes one event per finished diagnostic (every module, every run path) by watching <see cref="ResultStore"/>.
/// Skips NotRun/Running, repeated store updates of the same result, and throttles the live sensor page (refreshes every 5 s)
/// to one event per 10 minutes unless its status changes. A failing sink never affects a run.
/// </summary>
public sealed class ResultEventLogger
{
    public static readonly TimeSpan SensorsThrottle = TimeSpan.FromMinutes(10);
    public const int MaxAuditItems = 25;
    private readonly ILogSink _sink;
    private readonly Func<string, string?>? _suiteLabel;
    private readonly ConcurrentDictionary<string, DateTimeOffset> _started = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, (DateTimeOffset Stamp, DiagnosticStatus Status, string Message)> _last = new(StringComparer.OrdinalIgnoreCase);

    private readonly Action<DiagnosticResult, TimeSpan?, string?>? _recorded;

    /// <param name="recorded">Called once per logged result (after dedup/throttle), e.g. to append to the history store.</param>
    private readonly ResultEventContext? _ctx;

    public ResultEventLogger(ResultStore store, ILogSink sink, Func<string, string?>? suiteLabel = null, Action<DiagnosticResult, TimeSpan?, string?>? recorded = null, ResultEventContext? context = null)
    {
        _sink = sink; _suiteLabel = suiteLabel; _recorded = recorded; _ctx = context;
        store.Changed += (_, r) => OnChanged(r);
        store.InstanceChanged += (_, r) => OnChanged(r);
    }

    public void OnChanged(DiagnosticResult r)
    {
        try
        {
            if (r.Status == DiagnosticStatus.NotRun) return;
            var key = r.InstanceKey is { } ik ? r.ModuleName + "#" + ik : r.ModuleName;
            if (r.Status == DiagnosticStatus.Running) { _started[key] = r.Timestamp; return; }
            if (r.Payload is InstanceResults) { _started.TryRemove(key, out _); return; } // each instance was logged on its own
            if (_last.TryGetValue(key, out var x))
            {
                if (x.Stamp == r.Timestamp && x.Status == r.Status && x.Message == r.Message) return; // same result stored again
                if (r.ModuleName == LibreHardwareMonitorModule.ModuleName && x.Status == r.Status && r.Timestamp - x.Stamp < SensorsThrottle) return;
            }
            _last[key] = (r.Timestamp, r.Status, r.Message);
            TimeSpan? duration = _started.TryRemove(key, out var s) && r.Timestamp >= s ? r.Timestamp - s : null;
            string? label = null;
            try { label = _suiteLabel?.Invoke(r.ModuleName); } catch { }
            try { _sink.Write(new LogEntry(LogEventIds.TestResult, LevelFor(r), LogText.Truncate(Format(r, duration, label, _ctx)))); } catch { }
            try { _recorded?.Invoke(r, duration, label); } catch { }
        }
        catch { /* logging must never affect diagnostics */ }
    }

    public static bool IsCancelled(DiagnosticResult r) => r.Cancelled || r.Payload is IRunEnd { RunEnd: RunEnd.Cancelled };

    public static string Outcome(DiagnosticResult r) => r.Payload is DependencyGate gate ? gate.Outcome
        : r.Payload is ModuleAvailability or IRunEnd { RunEnd: RunEnd.CouldNotRun } ? CouldNotRun.OutcomeText
        : IsCancelled(r) ? "Cancelled"
        : r.Status switch { DiagnosticStatus.Ok => "OK", DiagnosticStatus.Warning => "Warning", DiagnosticStatus.Error => "Critical", _ => r.Status.ToString() };

    public static LogLevel LevelFor(DiagnosticResult r) => Outcome(r) switch
    {
        "Critical" => LogLevel.Error,
        "Warning" or "Cancelled" or CouldNotRun.OutcomeText or "Skipped" or "Blocked" => LogLevel.Warning,
        _ => LogLevel.Information,
    };

    /// <summary>Message format version written in "Format:" (parsed back by <see cref="History.HistoryEventParser"/>).</summary>
    public const int FormatVersion = 3;

    /// <summary>Stable "Key: value" lines (one per line), then "Measurements:" ("  Name=value") and human "Details:". Format 3 adds
    /// "Module id:" (the permanent id History groups and matches on); "Test:" stays in English only for people reading Event Viewer.</summary>
    public static string Format(DiagnosticResult r, TimeSpan? duration, string? suiteLabel = null, ResultEventContext? ctx = null)
    {
        static string One(string? s) => (s ?? "").Replace("\r", " ").Replace("\n", " ").Trim();
        var sb = new StringBuilder();
        sb.Append("Test result: ").Append(r.ModuleName).AppendLine();
        var id = Guid.Empty;
        try { id = ctx?.ModuleId?.Invoke(r.ModuleName) ?? Guid.Empty; } catch { }
        if (id == Guid.Empty) id = History.HistoryIds.For(r.ModuleName);
        sb.Append("Module id: ").Append(id.ToString("D")).AppendLine();
        if (r.InstanceKey is { Length: > 0 } instanceKey)
        {
            sb.Append("Instance id: ").Append(One(instanceKey)).AppendLine();
            if (!string.IsNullOrWhiteSpace(r.InstanceLabel)) sb.Append("Instance: ").Append(One(r.InstanceLabel)).AppendLine();
        }
        if (ctx?.DisplayName is { } dn) { string? t = null; try { t = dn(r.ModuleName); } catch { } if (!string.IsNullOrEmpty(t)) sb.Append("Test: ").Append(One(t)).AppendLine(); }
        sb.Append("Outcome: ").Append(Outcome(r)).AppendLine();
        sb.Append("Summary: ").Append(One(r.Message)).AppendLine();
        if (duration is { } d) sb.Append("Duration: ").Append(d.TotalSeconds.ToString("0.0", CultureInfo.InvariantCulture)).AppendLine(" s");
        if (suiteLabel is not null) sb.Append("Stress suite: ").Append(suiteLabel).AppendLine();
        sb.Append("Finished: ").Append(r.Timestamp.ToString("O", CultureInfo.InvariantCulture)).AppendLine();
        if (ctx?.Machine is { } mf) { string? m = null; try { m = mf(); } catch { } if (!string.IsNullOrEmpty(m)) sb.Append("Machine: ").Append(One(m)).AppendLine(); }
        if (!string.IsNullOrEmpty(ctx?.AppVersion)) sb.Append("App version: ").Append(ctx!.AppVersion).AppendLine();
        sb.Append("Format: ").Append(FormatVersion).AppendLine();
        var ms = Measurements(r.Payload);
        if (ms.Count > 0)
        {
            sb.AppendLine("Measurements:");
            foreach (var (n, v) in ms) sb.Append("  ").Append(n).Append('=').AppendLine(One(v));
        }
        var details = Details(r.Payload);
        if (details.Length > 0) sb.Append("Details:").AppendLine().Append(details);
        return sb.ToString().TrimEnd();
    }

    /// <summary>Key measurements only: numbers/bools/enums/durations from the payload (no free text, so no serials,
    /// paths or tokens), plus special cases for sensors and the security audit (failed/warning item IDs and titles only).</summary>
    public static string Details(object? payload)
    {
        var sb = new StringBuilder();
        switch (payload)
        {
            case null: break;
            case AreaReport: break; // Card observations are recorded once, under Measurements.
            case Exception ex: sb.Append("  Error: ").Append(ex.GetType().Name).Append(": ").AppendLine(ex.Message); break;
            case ModuleAvailability a: sb.Append("  Unavailable: ").AppendLine(a.Reason); break;
            case SecurityAuditReport sec:
                sb.AppendLine($"  Failed={sec.Failed} Warnings={sec.Warnings} Passed={sec.Passed} NotChecked={sec.NotChecked}");
                var bad = sec.Shown.Where(f => f.Outcome is AuditOutcome.Failed or AuditOutcome.Warning).ToList();
                foreach (var f in bad.Take(MaxAuditItems)) sb.AppendLine($"  {f.OutcomeText}: {f.Id} {f.Name}");
                if (bad.Count > MaxAuditItems) sb.AppendLine($"  … and {bad.Count - MaxAuditItems} more");
                break;
            case SensorReport rep:
                foreach (var g in rep.Groups.Where(g => g.Readings.Count > 0))
                    sb.AppendLine($"  {g.Title}: " + string.Join("; ", g.Readings.Select(e => $"{e.Reading.FriendlyName}={e.Reading.Value?.ToString("0", CultureInfo.InvariantCulture)} {e.Reading.Unit}{(e.Reading.Max is { } mx ? $" (max {mx.ToString("0", CultureInfo.InvariantCulture)})" : "")}").Take(12)));
                break;
            default: AppendScalars(sb, payload); break;
        }
        return sb.ToString();
    }

    private static void AppendScalars(StringBuilder sb, object payload)
    {
        foreach (var (name, value) in Measurements(payload)) sb.Append("  ").Append(name).Append(": ").AppendLine(value);
    }

    /// <summary>Key numeric measurements of a payload (name, invariant text). Same data as event 1100; no free text.</summary>
    public static IReadOnlyList<(string Name, string Value)> Measurements(object? payload)
    {
        var list = new List<(string, string)>();
        switch (payload)
        {
            case null or Exception or ModuleAvailability: return list;
            case AreaReport area:
                foreach (var card in area.Cards.Take(MaxAuditItems))
                {
                    var value = card.ErrorText ?? (string.IsNullOrWhiteSpace(card.Headline) ? card.EmptyText : card.Headline);
                    if (!string.IsNullOrWhiteSpace(value))
                        list.Add((card.Title, value + (string.IsNullOrWhiteSpace(card.Meta) ? "" : " · " + card.Meta)));
                }
                return list;
            case SecurityAuditReport sec:
                list.Add(("Failed", sec.Failed.ToString(CultureInfo.InvariantCulture))); list.Add(("Warnings", sec.Warnings.ToString(CultureInfo.InvariantCulture)));
                list.Add(("Passed", sec.Passed.ToString(CultureInfo.InvariantCulture))); list.Add(("NotChecked", sec.NotChecked.ToString(CultureInfo.InvariantCulture)));
                return list;
            case SensorReport rep:
                foreach (var g in rep.Groups.Where(g => g.Readings.Count > 0 && g.Id != "fans"))
                    if (g.Hottest is { } h) list.Add(($"Hottest {g.Title}", History.MeasurementFormat.Round("Hottest", h)));
                var fans = rep.Groups.FirstOrDefault(g => g.Id == "fans")?.Readings.Count ?? 0;
                list.Add(("Fans", fans.ToString(CultureInfo.InvariantCulture)));
                return list;
        }
        foreach (var p in payload.GetType().GetProperties(BindingFlags.Public | BindingFlags.Instance))
        {
            if (list.Count >= 40 || p.GetIndexParameters().Length > 0) continue;
            object? v;
            try { v = p.GetValue(payload); } catch { continue; }
            string? text = v switch
            {
                null => null,
                double dv => History.MeasurementFormat.Round(p.Name, dv),
                float fv => History.MeasurementFormat.Round(p.Name, fv),
                decimal or int or long or short or byte or uint or ulong => Convert.ToString(v, CultureInfo.InvariantCulture),
                bool b => b ? "yes" : "no",
                Enum e => e.ToString(),
                TimeSpan ts => ts.TotalSeconds.ToString("0.0", CultureInfo.InvariantCulture) + " s",
                string s when p.Name is "Headline" or "Summary" or "Notice" => s,
                ICollection c when v is not string => $"{c.Count} item(s)",
                _ => null,
            };
            if (text is not null) list.Add((p.Name, text));
        }
        return list;
    }
}
