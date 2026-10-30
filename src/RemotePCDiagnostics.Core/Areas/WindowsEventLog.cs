using System.Globalization;
using System.Xml;
using System.Xml.Linq;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>One Windows event (from <c>wevtutil qe ... /f:RenderedXml</c>).</summary>
public sealed record WinEvent(DateTimeOffset Time, string Channel, string Provider, int EventId, int Level, string Message,
    IReadOnlyList<string> Data, IReadOnlyDictionary<string, string> NamedData)
{
    /// <summary>Provider without the "Microsoft-Windows-" prefix.</summary>
    public string Source => Provider.StartsWith("Microsoft-Windows-", StringComparison.OrdinalIgnoreCase) ? Provider["Microsoft-Windows-".Length..] : Provider;

    /// <summary>First line of the message, shortened for a table cell.</summary>
    public string ShortMessage
    {
        get
        {
            var line = Message.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault() ?? "";
            if (line.Length == 0) return "No description was recorded.";
            return line.Length > 240 ? line[..240] + "…" : line;
        }
    }

    public string DataAt(int index, string name) =>
        NamedData.TryGetValue(name, out var v) && v.Length > 0 ? v : index < Data.Count ? Data[index] : "";
}

/// <summary>
/// Reads Windows event logs with the built-in <c>wevtutil</c>. osquery's <c>windows_events</c> table needs the
/// osquery daemon's event subscriber (not available to osqueryi one-shot queries), so wevtutil is used instead.
/// </summary>
public sealed class WindowsEventLog(SystemCommandRunner commands)
{
    public static string Wevtutil => SystemCommandRunner.SystemTool("wevtutil.exe");

    public static IReadOnlyList<string> Arguments(string channel, string xpath, int max) =>
        ["qe", channel, "/q:" + xpath, "/c:" + max.ToString(CultureInfo.InvariantCulture), "/rd:true", "/f:RenderedXml"];

    /// <summary>XPath for events of the given levels (1=critical, 2=error) in the last <paramref name="days"/> days.</summary>
    public static string LevelQuery(int days, params int[] levels) =>
        $"*[System[({string.Join(" or ", levels.Select(l => $"Level={l}"))}) and TimeCreated[timediff(@SystemTime) <= {(long)days * 86_400_000}]]]";

    /// <summary>Returns events newest first, or null when the log couldn't be read (details logged).</summary>
    public async Task<IReadOnlyList<WinEvent>?> QueryAsync(string channel, string xpath, int max, CancellationToken ct)
    {
        var pr = await commands.RunAsync(Wevtutil, Arguments(channel, xpath, max), ct).ConfigureAwait(false);
        if (pr is null) return null;
        if (pr.ExitCode != 0) return null;
        try { return Parse(pr.StdOut, channel); }
        catch (XmlException ex)
        {
            try { commands.Log?.Invoke($"wevtutil {channel}: unreadable output: {ex.Message}"); } catch { }
            return null;
        }
    }

    private static readonly XNamespace Ns = "http://schemas.microsoft.com/win/2004/08/events/event";

    public static IReadOnlyList<WinEvent> Parse(string xml, string channel = "")
    {
        if (string.IsNullOrWhiteSpace(xml)) return [];
        var settings = new XmlReaderSettings { CheckCharacters = false, DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
        using var reader = XmlReader.Create(new StringReader("<Events>" + xml + "</Events>"), settings);
        var doc = XDocument.Load(reader);
        var list = new List<WinEvent>();
        foreach (var e in doc.Root!.Elements().Where(x => x.Name.LocalName == "Event"))
        {
            XElement? El(XElement? parent, string name) => parent?.Element(Ns + name) ?? parent?.Element(name);
            var sys = El(e, "System");
            var render = El(e, "RenderingInfo");
            var provider = El(sys, "Provider")?.Attribute("Name")?.Value ?? El(render, "Provider")?.Value ?? "";
            int.TryParse(El(sys, "EventID")?.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var id);
            int.TryParse(El(sys, "Level")?.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var level);
            DateTimeOffset.TryParse(El(sys, "TimeCreated")?.Attribute("SystemTime")?.Value, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal, out var time);
            var data = new List<string>();
            var named = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var d in (El(e, "EventData")?.Elements() ?? []).Where(x => x.Name.LocalName == "Data"))
            {
                data.Add(d.Value.Trim());
                if (d.Attribute("Name")?.Value is { Length: > 0 } n) named[n] = d.Value.Trim();
            }
            var ch = El(sys, "Channel")?.Value;
            list.Add(new WinEvent(time, !string.IsNullOrEmpty(ch) ? ch : channel, provider, id, level, CleanMessage(El(render, "Message")?.Value), data, named));
        }
        return list.OrderByDescending(x => x.Time).ToList();
    }

    private static readonly System.Text.RegularExpressions.Regex BidiArtifact =
        new(@"(?<=^|[\s/(\-.:])\?(?=\d)", System.Text.RegularExpressions.RegexOptions.Compiled);

    /// <summary>
    /// Removes invisible direction marks Windows puts around dates in messages (U+200E etc.). When wevtutil's console
    /// output lost them they arrive as '?' right before a digit ("on ?10/?29/?2026"); those are removed too.
    /// </summary>
    public static string CleanMessage(string? message)
    {
        if (string.IsNullOrEmpty(message)) return "";
        var s = new string(message.Where(c => c is not ('\u200E' or '\u200F' or >= '\u202A' and <= '\u202E' or >= '\u2066' and <= '\u2069')).ToArray());
        return BidiArtifact.Replace(s, "").Trim();
    }

    /// <summary>Friendly time, e.g. "Oct 29, 2:15 PM" (year added when not this year).</summary>
    public static string FormatTime(DateTimeOffset t) => FormatTime(t, DateTimeOffset.Now);
    public static string FormatTime(DateTimeOffset t, DateTimeOffset now)
    {
        if (t == default) return "";
        var l = t.ToLocalTime();
        return l.ToString(l.Year == now.ToLocalTime().Year ? "MMM d, h:mm tt" : "MMM d yyyy, h:mm tt", CultureInfo.InvariantCulture);
    }
}
