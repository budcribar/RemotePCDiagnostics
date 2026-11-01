using System.Globalization;
using System.Net;
using System.Text;

namespace RemotePCDiagnostics.Core.NetworkUsage;

public sealed record NetworkUsageEntry(string AppId, string App, string User, string Adapter,
    DateTimeOffset? TimeUtc, ulong Uploaded, ulong Downloaded);

public sealed record NetworkUsageTotal(string AppId, string App, string User, ulong Uploaded, ulong Downloaded)
{
    public decimal Total => (decimal)Uploaded + Downloaded;
}

public sealed record NetworkUsageReport(string Source, DateTimeOffset StartUtc, DateTimeOffset EndUtc,
    IReadOnlyList<NetworkUsageEntry> Entries, IReadOnlyList<string> Warnings)
{
    public const string Limitation = "Historical recorded traffic, not live speed or request frequency. High usage does not prove waste or justify stopping an app. Coverage may be incomplete; absent entries do not prove zero usage. Traffic can include local network transfers and virtual adapters.";

    public IReadOnlyList<NetworkUsageTotal> TopApps(int count = 5) => Entries
        .GroupBy(e => (e.AppId, e.App, e.User))
        .Select(g => new NetworkUsageTotal(g.Key.AppId, g.Key.App, g.Key.User,
            g.Aggregate(0UL, (sum, e) => checked(sum + e.Uploaded)),
            g.Aggregate(0UL, (sum, e) => checked(sum + e.Downloaded))))
        .OrderByDescending(e => e.Total).ThenBy(e => e.App, StringComparer.OrdinalIgnoreCase).Take(count).ToList();

    public static string Size(decimal value) => value >= 1_000_000_000 ? (value / 1_000_000_000).ToString("0.00", CultureInfo.InvariantCulture) + " GB"
        : (value / 1_000_000).ToString("0.00", CultureInfo.InvariantCulture) + " MB";

    public string ToHtml()
    {
        static string H(string? s) => WebUtility.HtmlEncode(s ?? "");
        var html = new StringBuilder("<!doctype html><html lang='en'><meta charset='utf-8'><title>Network usage prototype</title><style>body{font:16px system-ui;max-width:1100px;margin:40px auto;padding:0 24px;color:#17202a}table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:12px;border-bottom:1px solid #ddd;overflow-wrap:anywhere}aside{background:#fff4ce;padding:16px}small{color:#555}</style><h1>Top network consumers</h1>");
        html.Append($"<p>Source: {H(Source)}</p><p>Requested window (UTC): {StartUtc:u} to {EndUtc:u}</p><aside>{H(Limitation)}</aside>");
        foreach (var warning in Warnings) html.Append($"<p><strong>{H(warning)}</strong></p>");
        var timestamps = Entries.Where(e => e.TimeUtc.HasValue).Select(e => e.TimeUtc!.Value).ToList();
        if (timestamps.Count > 0) html.Append($"<p>Record timestamps observed (UTC): {timestamps.Min():u} to {timestamps.Max():u}. These do not prove continuous coverage.</p>");
        if (Entries.Count == 0) html.Append("<h2>No attributed records available</h2><p>This is not evidence of zero network usage. See warnings and diagnostics.json.</p>");
        else
        {
            html.Append("<h2>Top five apps / attribution buckets</h2><table><tr><th>App / bucket</th><th>User</th><th>Downloaded</th><th>Uploaded</th><th>Total</th></tr>");
            foreach (var app in TopApps()) html.Append($"<tr><td>{H(app.App)}<br><small>{H(app.AppId)}</small></td><td>{H(app.User)}</td><td>{Size(app.Downloaded)}</td><td>{Size(app.Uploaded)}</td><td>{Size(app.Total)}</td></tr>");
            html.Append("</table><p>Review high-usage apps with the user. No apps or services were stopped and no startup settings were changed.</p>");
        }
        return html.Append("</html>").ToString();
    }

    public string ToCsv()
    {
        static string Q(string s) => "\"" + ((s.Length > 0 && "=+-@\t\r\n".Contains(s[0])) ? "'" + s : s).Replace("\"", "\"\"") + "\"";
        var csv = new StringBuilder("AppId,App,User,Adapter,RecordTimeUtc,UploadedBytes,DownloadedBytes\r\n");
        foreach (var e in Entries) csv.AppendLine(string.Join(",", Q(e.AppId), Q(e.App), Q(e.User), Q(e.Adapter), Q(e.TimeUtc?.ToString("O") ?? ""), e.Uploaded.ToString(CultureInfo.InvariantCulture), e.Downloaded.ToString(CultureInfo.InvariantCulture)));
        return csv.ToString();
    }
}
