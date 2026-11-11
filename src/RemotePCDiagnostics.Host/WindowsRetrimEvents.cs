using System.Diagnostics.Eventing.Reader;
using System.Text.RegularExpressions;
using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Host;

/// <summary>
/// Windows' own record of retrims: Application log, provider Microsoft-Windows-Defrag, event 258 ("The storage optimizer successfully
/// completed {operation} on {volume}"). Read-only, bounded (time window and at most <see cref="MaxEvents"/> events). The volume comes
/// from the event data ("(C:)", "Windows (C:)", "C:"), not from the English message; an event whose operation names defragmentation
/// is skipped (on SSDs Windows' scheduled optimization is a retrim).
/// </summary>
public sealed partial class WindowsRetrimEvents(ILogger? log = null) : IWindowsRetrimEvents
{
    public const string Provider = "Microsoft-Windows-Defrag";
    public const int EventId = 258, MaxEvents = 500;

    public IReadOnlyList<(char Letter, DateTimeOffset When)> Read(TimeSpan window)
    {
        var list = new List<(char, DateTimeOffset)>();
        var ms = (long)window.TotalMilliseconds;
        var q = new EventLogQuery("Application", PathType.LogName,
            $"*[System[Provider[@Name='{Provider}'] and (EventID={EventId}) and TimeCreated[timediff(@SystemTime) <= {ms}]]]") { ReverseDirection = true };
        try
        {
            using var reader = new EventLogReader(q);
            for (var i = 0; i < MaxEvents; i++)
            {
                using var e = reader.ReadEvent();
                if (e is null) break;
                if (e.TimeCreated is not { } t) continue;
                var data = e.Properties.Select(p => p.Value?.ToString() ?? "").ToList();
                foreach (var c in RetrimLetters(data)) list.Add((c, new DateTimeOffset(t)));
            }
        }
        catch (Exception ex) { log.Info($"retrim events (Application/{Provider}/{EventId}) unreadable: {ex.Message}"); }
        return list;
    }

    /// <summary>True when Defrag event 258's operation field (<c>data[0]</c>) represents an SSD retrim rather than analysis, defragmentation,
    /// slab/free-space consolidation, shrink estimation, boot optimization or storage tier optimization.</summary>
    public static bool IsRetrimOperation(string? operation)
    {
        if (string.IsNullOrWhiteSpace(operation)) return false;
        if (operation.Contains("defrag", StringComparison.OrdinalIgnoreCase)
            || operation.Contains("analy", StringComparison.OrdinalIgnoreCase)
            || operation.Contains("slab", StringComparison.OrdinalIgnoreCase)
            || operation.Contains("consolid", StringComparison.OrdinalIgnoreCase)
            || operation.Contains("konsolid", StringComparison.OrdinalIgnoreCase)
            || operation.Contains("shrink", StringComparison.OrdinalIgnoreCase)
            || operation.Contains("boot", StringComparison.OrdinalIgnoreCase)
            || operation.Contains("tier", StringComparison.OrdinalIgnoreCase))
            return false;
        return operation.Any(c => c > 127) || operation.Contains("trim", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Drive letters from a Defrag 258 event's data (<c>[operation, volume, ...]</c>), or empty when the operation isn't a retrim.</summary>
    public static IReadOnlyList<char> RetrimLetters(IReadOnlyList<string> data) =>
        data.Count < 2 || !IsRetrimOperation(data[0]) ? [] : [.. Letters(data.Skip(1))];

    /// <summary>Drive letters named in the event data: "(C:)", "Windows (C:)", "C:" or "C:\".</summary>
    public static IEnumerable<char> Letters(IEnumerable<string> data) =>
        data.SelectMany(s => VolumeLetter().Matches(s).Select(m => char.ToUpperInvariant(m.Groups[1].Value[0]))).Distinct();

    [GeneratedRegex(@"(?<![A-Za-z])([A-Za-z]):(?![A-Za-z])")]
    private static partial Regex VolumeLetter();
}
