using System.Globalization;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>What <c>powercfg /a</c> says: the sleep states this PC has, and why the others are missing.</summary>
public sealed record SleepStates(IReadOnlyList<string> Available, IReadOnlyList<(string State, string Reason)> Unavailable)
{
    /// <summary>Modern Standby (S0 Low Power Idle): the PC keeps running in a low-power state and can drain the battery in a bag.</summary>
    public bool ModernStandby => Available.Any(s => s.Contains("S0 Low Power Idle", StringComparison.OrdinalIgnoreCase));
    /// <summary>Classic sleep (S3): the PC is fully suspended, so drain is small unless something wakes it.</summary>
    public bool S3 => Available.Any(s => s.Contains("(S3)", StringComparison.OrdinalIgnoreCase));
    public bool Hibernate => Available.Any(s => s.Equals("Hibernate", StringComparison.OrdinalIgnoreCase));
    public bool AnyStandby => Available.Any(s => s.StartsWith("Standby", StringComparison.OrdinalIgnoreCase));
}

/// <summary>One wake source from <c>powercfg /lastwake</c> ("Type: Device", "Friendly Name: …").</summary>
public sealed record LastWakeSource(string Type, string Name, string InstancePath)
{
    public string Text => Name.Length > 0 ? $"{Type}: {Name}" : Type.Length > 0 ? Type : "Unknown";
}

/// <summary>An active wake timer from <c>powercfg /waketimers</c>.</summary>
public sealed record WakeTimer(string Owner, string Expires, string Reason);

/// <summary>A power request from <c>powercfg /requests</c>: <see cref="Category"/> is DISPLAY, SYSTEM, AWAYMODE, EXECUTION, PERFBOOST or ACTIVELOCKSCREEN.</summary>
public sealed record PowerRequest(string Category, string RequesterType, string Requester, string Detail)
{
    /// <summary>Requests that stop the PC from sleeping (SYSTEM, AWAYMODE) or the screen from turning off (DISPLAY).</summary>
    public bool BlocksSleep => Category is "SYSTEM" or "AWAYMODE" or "DISPLAY";
}

/// <summary>Plain-text parsers for the powercfg reports this check reads (English output, as Windows prints it).</summary>
public static class SleepWakeParsers
{
    private static IEnumerable<string> Lines(string? s) => (s ?? "").Replace("\r", "").Split('\n');

    /// <summary>
    /// <c>powercfg /a</c>: two sections ("…are available…", "…are not available…"). A state is indented by spaces (4 on Windows 11);
    /// the reasons under an unavailable state are indented deeper or by a tab.
    /// </summary>
    public static SleepStates? ParseSleepStates(string? stdout)
    {
        if (string.IsNullOrWhiteSpace(stdout)) return null;
        var available = new List<string>();
        var unavailable = new List<(string, List<string>)>();
        int section = 0; // 1 available, 2 not available
        int? stateIndent = null;
        foreach (var raw in Lines(stdout))
        {
            if (raw.Trim().Length == 0) continue;
            var indent = raw.Length - raw.TrimStart().Length;
            var text = raw.Trim();
            if (indent == 0)
            {
                if (text.Contains("not available", StringComparison.OrdinalIgnoreCase)) section = 2;
                else if (text.Contains("available", StringComparison.OrdinalIgnoreCase)) section = 1;
                else section = 0;
                stateIndent = null;
                continue;
            }
            if (section == 0) continue;
            var hasTab = raw[..indent].Contains('\t');
            stateIndent ??= hasTab ? null : indent;
            var isState = !hasTab && stateIndent is { } si && indent <= si;
            if (section == 1)
            {
                if (isState) available.Add(text);
            }
            else if (isState || unavailable.Count == 0) unavailable.Add((text, []));
            else unavailable[^1].Item2.Add(text);
        }
        if (section == 0 && available.Count == 0 && unavailable.Count == 0) return null;
        return new(available, unavailable.Select(u => (u.Item1, string.Join(" ", u.Item2))).ToList());
    }

    /// <summary><c>powercfg /lastwake</c>: the "Wake Source [n]" blocks of the latest wake. Empty when Windows recorded none.</summary>
    public static IReadOnlyList<LastWakeSource> ParseLastWake(string? stdout)
    {
        var list = new List<LastWakeSource>();
        Dictionary<string, string>? cur = null;
        void Flush()
        {
            if (cur is null) return;
            string V(string k) => cur.TryGetValue(k, out var v) ? v : "";
            var name = V("Friendly Name") is { Length: > 0 } f ? f : V("Description") is { Length: > 0 } d ? d : V("Owner");
            list.Add(new(V("Type"), name, V("Instance Path")));
            cur = null;
        }
        foreach (var raw in Lines(stdout))
        {
            var text = raw.Trim();
            if (text.StartsWith("Wake Source [", StringComparison.OrdinalIgnoreCase)) { Flush(); cur = new(StringComparer.OrdinalIgnoreCase); continue; }
            if (text.StartsWith("Wake History", StringComparison.OrdinalIgnoreCase)) { Flush(); continue; }
            if (cur is null) continue;
            var colon = text.IndexOf(':');
            if (colon > 0) cur[text[..colon].Trim()] = text[(colon + 1)..].Trim();
        }
        Flush();
        return list;
    }

    /// <summary>
    /// <c>powercfg /waketimers</c>: "Timer set by [SERVICE] … expires at 3:15:11 AM on 11/20/2026." followed by an indented
    /// "Reason: …" line. "There are no active wake timers in the system." gives an empty list.
    /// </summary>
    public static IReadOnlyList<WakeTimer> ParseWakeTimers(string? stdout)
    {
        var list = new List<WakeTimer>();
        const string Head = "Timer set by ";
        const string Expires = " expires at ";
        foreach (var raw in Lines(stdout))
        {
            var text = raw.Trim();
            if (text.StartsWith(Head, StringComparison.OrdinalIgnoreCase))
            {
                var body = text[Head.Length..];
                var at = body.LastIndexOf(Expires, StringComparison.OrdinalIgnoreCase);
                var owner = at >= 0 ? body[..at] : body;
                var when = at >= 0 ? body[(at + Expires.Length)..].TrimEnd('.') : "";
                list.Add(new(owner.Trim(), when.Trim(), ""));
            }
            else if (list.Count > 0 && text.StartsWith("Reason:", StringComparison.OrdinalIgnoreCase) && list[^1].Reason.Length == 0)
                list[^1] = list[^1] with { Reason = text["Reason:".Length..].Trim() };
        }
        return list;
    }

    /// <summary>
    /// <c>powercfg /requests</c>: sections "DISPLAY:", "SYSTEM:", … each "None." or one or more requests. A request starts with its
    /// requester ("[PROCESS] \Device\…\chrome.exe", "[DRIVER] …", "[SERVICE] …"); the lines after it, up to the next requester, describe it.
    /// </summary>
    public static IReadOnlyList<PowerRequest>? ParseRequests(string? stdout)
    {
        if (string.IsNullOrWhiteSpace(stdout)) return null;
        var list = new List<PowerRequest>();
        string? category = null;
        var sawSection = false;
        foreach (var raw in Lines(stdout))
        {
            var text = raw.Trim();
            if (text.Length == 0) continue;
            if (IsSection(text)) { category = text[..^1]; sawSection = true; continue; }
            if (category is null || text.Equals("None.", StringComparison.OrdinalIgnoreCase)) continue;
            if (text.StartsWith('[') && text.IndexOf(']') is var close and > 1)
                list.Add(new(category, text[1..close], text[(close + 1)..].Trim(), ""));
            else if (list.Count > 0 && list[^1].Category == category)
                list[^1] = list[^1] with { Detail = list[^1].Detail.Length == 0 ? text : list[^1].Detail + " " + text };
        }
        return sawSection ? list : null;
    }

    private static bool IsSection(string text) =>
        text.Length > 1 && text[^1] == ':' && text[..^1].All(c => c is >= 'A' and <= 'Z');

    /// <summary>The file name of a requester path ("\Device\HarddiskVolume3\…\chrome.exe" → "chrome.exe"); other requesters as they are.</summary>
    public static string ShortRequester(string requester)
    {
        var r = requester.Trim();
        if (!r.StartsWith('\\')) return r;
        var name = r[(r.LastIndexOf('\\') + 1)..];
        return name.Length > 0 ? name : r;
    }

    /// <summary>A duration as "3 h 20 min", "45 min" or "under a minute".</summary>
    public static string Duration(TimeSpan d)
    {
        if (d < TimeSpan.FromMinutes(1)) return "under a minute";
        if (d.TotalHours >= 48) return $"{(int)d.TotalDays} days {d.Hours} h";
        if (d.TotalHours >= 1) return d.Minutes > 0 ? $"{(int)d.TotalHours} h {d.Minutes} min" : $"{(int)d.TotalHours} h";
        return $"{(int)d.TotalMinutes} min";
    }

    internal static DateTimeOffset? Time(string? s) =>
        DateTimeOffset.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var t) && t.Year > 1601 ? t : null;
}
