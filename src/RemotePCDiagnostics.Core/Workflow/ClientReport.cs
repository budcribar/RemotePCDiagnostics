using System.Net;
using System.Text;
using RemotePCDiagnostics.Core.Benchmarks;

namespace RemotePCDiagnostics.Core.Workflow;

/// <summary>
/// The report the tech hands to the client: one self-contained HTML page (prints to PDF from any browser), in plain language:
/// what was found, what was fixed, what the before/after measurements show, and what's still recommended.
/// </summary>
public static class ClientReport
{
    private static string E(string? s) => WebUtility.HtmlEncode(s ?? "");

    public static string Build(WorkflowState s, BenchmarkRun? before, BenchmarkRun? after, BenchmarkComparison cmp, DateTimeOffset generated)
    {
        var applied = s.Outcomes.Where(o => o.Success && !o.Skipped).ToList();
        var failed = s.Outcomes.Where(o => !o.Success && !o.Skipped).ToList();
        var skipped = s.Outcomes.Where(o => o.Skipped).ToList();
        var notApproved = s.Fixes.Where(f => !s.IsApproved(f.Id)).ToList();
        var sb = new StringBuilder();
        sb.Append("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
          .Append("<title>PC service report – ").Append(E(s.Machine)).Append("</title><style>")
          .Append("body{font-family:Segoe UI,system-ui,sans-serif;color:#1f2937;max-width:860px;margin:32px auto;padding:0 20px;line-height:1.5}")
          .Append("h1{font-size:26px;margin:0 0 4px}h2{font-size:18px;margin:28px 0 8px;border-bottom:1px solid #e5e7eb;padding-bottom:4px}")
          .Append(".meta{color:#6b7280;font-size:14px}.hero{background:#ecfdf5;border:1px solid #a7f3d0;border-radius:12px;padding:16px 20px;margin:20px 0}")
          .Append(".hero.same{background:#f3f4f6;border-color:#e5e7eb}.hero.worse{background:#fff7ed;border-color:#fed7aa}.hero strong{font-size:22px;display:block}")
          .Append("table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;padding:8px;border-bottom:1px solid #e5e7eb;vertical-align:top}")
          .Append("th{font-size:12px;text-transform:uppercase;color:#6b7280}.better{color:#047857;font-weight:600}.worse{color:#b45309;font-weight:600}.same{color:#6b7280}")
          .Append("ul{padding-left:20px}li{margin:3px 0}.note{background:#fffbeb;border:1px solid #fde68a;border-radius:8px;padding:8px 12px;margin:8px 0;font-size:14px}")
          .Append("@media print{body{margin:0}.hero{break-inside:avoid}}</style></head><body>");

        sb.Append("<h1>PC service report</h1><div class=\"meta\">").Append(E(s.Machine));
        if (s.HardwareSummary.Length > 0) sb.Append(" · ").Append(E(s.HardwareSummary));
        sb.Append("<br>").Append(E(generated.ToString("dddd, MMMM d, yyyy h:mm tt", System.Globalization.CultureInfo.InvariantCulture)));
        if (s.Actor is { Length: > 0 } a) sb.Append(" · by ").Append(E(a));
        sb.Append("</div>");

        // Headline
        var heroKind = cmp.OverallPercent switch { >= 2 => "", <= -2 => " worse", _ => " same" };
        sb.Append("<div class=\"hero").Append(heroKind).Append("\"><strong>")
          .Append(E(before is not null && after is not null ? cmp.OverallText : "Service completed"))
          .Append("</strong>").Append(applied.Count).Append(" improvement").Append(applied.Count == 1 ? "" : "s").Append(" applied");
        if (failed.Count > 0) sb.Append(" · ").Append(failed.Count).Append(" couldn't be applied");
        sb.Append(". Measured before and after, each time right after a fresh restart.</div>");

        // Benchmarks
        if (before is not null && after is not null)
        {
            sb.Append("<h2>Before and after</h2><table><tr><th>What we measured</th><th>Before</th><th>After</th><th>Result</th></tr>");
            foreach (var d in cmp.Deltas)
            {
                var cls = d.Verdict switch
                {
                    BenchmarkVerdict.Better => "better",
                    BenchmarkVerdict.Worse => "worse",
                    _ => "same",
                };
                var text = d.ChangeSummary;
                sb.Append("<tr><td><strong>").Append(E(d.Info.Title)).Append("</strong><div class=\"meta\">").Append(E(d.Info.ClientMeaning)).Append("</div></td><td>")
                  .Append(d.Before is { } b ? E(d.Info.Show(b)) : "—").Append("</td><td>").Append(d.After is { } v ? E(d.Info.Show(v)) : "—")
                  .Append("</td><td class=\"").Append(cls).Append("\">").Append(E(text)).Append(d.Note is { } n ? $"<div class=\"meta\">{E(n)}</div>" : "").Append("</td></tr>");
            }
            sb.Append("</table><p class=\"meta\">Each test was run several times and the middle result used. Changes smaller than the normal run-to-run variation are shown as \"No real change\".</p>");
            foreach (var w in cmp.Warnings) sb.Append("<div class=\"note\">").Append(E(w)).Append("</div>");
        }

        // Findings
        sb.Append("<h2>What we found</h2>");
        if (s.Findings.Count == 0) sb.Append("<p>No problems were found by the checks.</p>");
        else { sb.Append("<ul>"); foreach (var f in s.Findings) sb.Append("<li>").Append(E(f)).Append("</li>"); sb.Append("</ul>"); }

        // Fixes
        sb.Append("<h2>What we fixed</h2>");
        if (applied.Count == 0) sb.Append("<p>No changes were needed.</p>");
        else { sb.Append("<ul>"); foreach (var o in applied) sb.Append("<li><strong>").Append(E(o.Title)).Append("</strong> — ").Append(E(o.Message)).Append("</li>"); sb.Append("</ul>"); }
        if (failed.Count > 0)
        {
            sb.Append("<h2>Couldn't be applied</h2><ul>");
            foreach (var o in failed) sb.Append("<li><strong>").Append(E(o.Title)).Append("</strong> — ").Append(E(o.Message)).Append("</li>");
            sb.Append("</ul>");
        }
        if (skipped.Count > 0)
        {
            sb.Append("<p class=\"meta\">Not needed after the restart: ").Append(E(string.Join(", ", skipped.Select(o => o.Title)))).Append(".</p>");
        }
        if (notApproved.Count > 0)
            sb.Append("<p class=\"meta\">Left as they were, by choice: ").Append(E(string.Join(", ", notApproved.Select(f => f.Title)))).Append(".</p>");

        // Recommendations
        if (s.Recommendations.Count > 0)
        {
            sb.Append("<h2>Recommended next steps</h2><ul>");
            foreach (var r in s.Recommendations) sb.Append("<li>").Append(E(r)).Append("</li>");
            sb.Append("</ul>");
        }

        sb.Append("<h2>Good to know</h2><ul><li>Every setting we changed can be put back; ask your technician if you'd like something restored.</li>")
          .Append("<li>Deleted temporary files and emptied Recycle Bin items can't be recovered, and installed updates stay installed.</li></ul>")
          .Append("<p class=\"meta\">Generated by Remote PC Diagnostics.</p></body></html>");
        return sb.ToString();
    }
}
