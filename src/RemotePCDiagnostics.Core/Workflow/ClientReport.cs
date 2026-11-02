using System.Net;
using System.Text;
using RemotePCDiagnostics.Core.Benchmarks;

namespace RemotePCDiagnostics.Core.Workflow;

/// <summary>
/// The report the tech hands to the client: one self-contained HTML page (prints to PDF from any browser), in plain language:
/// what was found, what was fixed (with the exact settings changed), what the before/after measurements show, what the service itself
/// did to the PC (restarts, temporary automatic sign-in, its restart task), what can be undone, and what's still recommended.
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
        var attempted = s.Outcomes.Select(o => o.FixId).ToHashSet();
        List<WorkflowFix> notAttempted = s.StartedUtc is null ? [] : s.Fixes.Where(f => s.IsApproved(f.Id) && !attempted.Contains(f.Id)).ToList();
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
          .Append(".alert{background:#fef2f2;border:2px solid #dc2626;color:#7f1d1d;border-radius:8px;padding:12px 16px;margin:12px 0}")
          .Append("@media print{body{margin:0}.hero{break-inside:avoid}}</style></head><body>");

        sb.Append("<h1>PC service report</h1><div class=\"meta\">").Append(E(s.Machine));
        if (s.HardwareSummary.Length > 0) sb.Append(" · ").Append(E(s.HardwareSummary));
        sb.Append("<br>").Append(E(generated.ToString("dddd, MMMM d, yyyy h:mm tt", System.Globalization.CultureInfo.InvariantCulture)));
        if (s.Actor is { Length: > 0 } a) sb.Append(" · by ").Append(E(a));
        sb.Append("</div>");

        // Headline
        var stopped = s.Stage is WorkflowStage.Cancelled or WorkflowStage.Failed;
        var heroKind = stopped ? " worse" : cmp.OverallPercent switch { >= 2 => "", <= -2 => " worse", _ => " same" };
        var headline = s.Stage switch
        {
            WorkflowStage.Cancelled => "Service stopped before it finished",
            WorkflowStage.Failed => "Service couldn't finish",
            _ => before is not null && after is not null ? cmp.OverallText : "Service completed",
        };
        sb.Append("<div class=\"hero").Append(heroKind).Append("\"><strong>").Append(E(headline)).Append("</strong>")
          .Append(applied.Count).Append(" improvement").Append(applied.Count == 1 ? "" : "s").Append(" applied");
        if (failed.Count > 0) sb.Append(" · ").Append(failed.Count).Append(" couldn't be applied");
        if (skipped.Count > 0) sb.Append(" · ").Append(skipped.Count).Append(" skipped");
        sb.Append('.');
        if (before is not null && after is not null) sb.Append(" Measured before and after, each time right after a fresh restart.");
        if (s.Stage == WorkflowStage.Failed && s.Error is { Length: > 0 } err) sb.Append("<div>").Append(E(err)).Append("</div>");
        sb.Append("</div>");

        // Anything the service itself couldn't put back goes first, where nobody can miss it.
        if (s.AutoLogonRestoreError is { } alErr)
            sb.Append("<div class=\"alert\"><strong>Important: automatic sign-in could not be turned off.</strong> This PC may still sign in")
              .Append(s.AutoLogonUser is { Length: > 0 } au ? " to " + E(au) : "").Append(" by itself after a restart, without asking for a password. ")
              .Append("Ask your technician to turn it off now (run netplwiz and tick \"Users must enter a user name and password\", or use Sysinternals Autologon &gt; Disable). Windows said: ")
              .Append(E(alErr)).Append("</div>");
        if (s.ResumeTaskRemoved == false)
            sb.Append("<div class=\"alert\"><strong>A scheduled task was left behind.</strong> The Task Scheduler task \"").Append(E(WorkflowService.ResumeTaskName))
              .Append("\" couldn't be removed; it starts Remote PC Diagnostics each time you sign in. Delete it in Task Scheduler (Task Scheduler Library).</div>");

        // Benchmarks
        sb.Append("<h2>Before and after</h2>");
        if (before is not null && after is not null)
        {
            sb.Append("<table><tr><th>What we measured</th><th>Before</th><th>After</th><th>Result</th></tr>");
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
        else
        {
            sb.Append("<p>").Append(E(before is null
                ? stopped ? "No measurements were taken: the service stopped before the before measurement." : "The before measurement couldn't be taken, so there's nothing to compare."
                : stopped ? "Only the before measurement was taken: the service stopped before the after measurement, so there's nothing to compare." : "The after measurement couldn't be taken, so there's nothing to compare."))
              .Append("</p>");
        }

        // Findings
        sb.Append("<h2>What we found</h2>");
        sb.Append("<p class=\"meta\">Saved scan snapshot: ").Append(E(s.ReviewedUtc is { } reviewed ? T(reviewed) : "scan time unavailable"))
          .Append(". Memory and space figures are estimates from that scan.</p>");
        var dnsEvidence = s.Fixes.Where(f => f.Remediation?.Kind == Areas.RemediationKind.SetPublicDns).ToList();
        if (dnsEvidence.Count > 0)
        {
            sb.Append("<h3>DNS measurement evidence</h3><ul>");
            foreach (var f in dnsEvidence) sb.Append("<li>").Append(E(f.Why)).Append("</li>");
            sb.Append("</ul>");
        }
        if (s.Findings.Count == 0) sb.Append("<p>No problems were found by the checks.</p>");
        else { sb.Append("<ul>"); foreach (var f in s.Findings) sb.Append("<li>").Append(E(f)).Append("</li>"); sb.Append("</ul>"); }

        // Fixes: each with its result, the exact settings it changed, and whether undo puts it back.
        sb.Append("<h2>What we fixed</h2>");
        if (applied.Count == 0) sb.Append("<p>").Append(s.Outcomes.Count == 0 && notAttempted.Count > 0 ? "No changes were made." : "No changes were needed.").Append("</p>");
        else { sb.Append("<ul>"); foreach (var o in applied) Outcome(o); sb.Append("</ul>"); }
        if (failed.Count > 0)
        {
            sb.Append("<h2>Couldn't be applied</h2><ul>");
            foreach (var o in failed) Outcome(o);
            sb.Append("</ul>");
        }
        if (skipped.Count > 0)
        {
            sb.Append("<h2>Skipped</h2><ul>");
            foreach (var o in skipped) sb.Append("<li><strong>").Append(E(o.Title)).Append("</strong> — ").Append(E(o.Message)).Append("</li>");
            sb.Append("</ul>");
        }
        if (notAttempted.Count > 0)
        {
            sb.Append("<h2>Not applied (the service stopped first)</h2><ul>");
            foreach (var f in notAttempted) sb.Append("<li>").Append(E(f.Title)).Append("</li>");
            sb.Append("</ul>");
        }
        if (notApproved.Count > 0)
        {
            sb.Append("<h2>Left as they were, by choice</h2><p class=\"meta\">Found by the checks, but your technician chose not to change these:</p><ul>");
            foreach (var f in notApproved) sb.Append("<li>").Append(E(f.Title)).Append("</li>");
            sb.Append("</ul>");
        }
        if (s.NotOffered.Count > 0)
        {
            sb.Append("<h2>Found but not done by the service</h2><ul>");
            foreach (var n in s.NotOffered) sb.Append("<li>").Append(E(n)).Append("</li>");
            sb.Append("</ul>");
        }

        // Recommendations
        if (s.Recommendations.Count > 0)
        {
            sb.Append("<h2>Recommended next steps</h2><ul>");
            foreach (var r in s.Recommendations) sb.Append("<li>").Append(E(r)).Append("</li>");
            sb.Append("</ul>");
        }

        // What the service itself did to the PC (not fixes): restarts, automatic sign-in, the restart task, the report file.
        if (s.StartedUtc is not null)
        {
            sb.Append("<h2>What the service itself did</h2><ul>");
            foreach (var r in s.Restarts)
            {
                if (r.Accepted)
                    sb.Append("<li>Restarted the PC at ").Append(E(T(r.RequestedUtc))).Append(r.BootedUtc is { } up ? $" (back up at {E(T(up))})" : "")
                      .Append(" — ").Append(E(r.Why)).Append("</li>");
                else sb.Append("<li>Asked Windows to restart at ").Append(E(T(r.RequestedUtc))).Append(", but Windows didn't accept it.</li>");
            }
            if (s.RestartAborted) sb.Append("<li>A restart that was about to happen was called off when the service was cancelled.</li>");
            if (s.AutoLogonUsed)
            {
                var who = s.AutoLogonUser is { Length: > 0 } u ? " for " + E(u) : "";
                sb.Append("<li>");
                if (s.AutoLogonRestoreError is not null)
                    sb.Append("<strong>Turned on automatic sign-in").Append(who).Append(" for the restarts, and it could NOT be turned off again</strong> (see the warning at the top).");
                else if (s.AutoLogonEnabled)
                    sb.Append("<strong>Turned on automatic sign-in").Append(who).Append(" for the restarts; it is still on.</strong> Ask your technician to turn it off.");
                else
                    sb.Append("Turned on automatic sign-in").Append(who).Append(" so the PC could sign in by itself after the restarts, then turned it off again")
                      .Append(s.AutoLogonRestoredUtc is { } back ? $" at {E(T(back))}" : "")
                      .Append(": the stored password was removed and the previous sign-in settings").Append(s.AutoLogonBackup?.PasswordLessBuildVersion is 2 ? " (including \"Only allow Windows Hello sign-in\")" : "").Append(" were put back.");
                sb.Append("</li>");
            }
            else if (s.AutoLogonAlreadyOn) sb.Append("<li>This PC already signed in by itself; the service didn't change that.</li>");
            else sb.Append("<li>Automatic sign-in wasn't used: someone signed in after each restart.</li>");
            if (s.ResumeTaskCreated)
            {
                sb.Append("<li>Created the Task Scheduler task \"").Append(E(WorkflowService.ResumeTaskName)).Append("\" so the app carried on by itself after each restart; ")
                  .Append(s.ResumeTaskRemoved switch { true => "removed it again at the end.", false => "<strong>it couldn't be removed</strong> (see the warning at the top).", null => "<strong>it hasn't been removed yet.</strong>" })
                  .Append("</li>");
            }
            sb.Append("<li>").Append(s.ReportPath is { } path ? "This report was saved on this PC: " + E(path) : "This report couldn't be saved as a file on this PC.").Append("</li>");
            sb.Append("</ul>");
        }

        // Undo: what can be put back, what's permanent, and how.
        var undoable = new List<string>(); var reinstall = new List<string>(); var permanent = new List<string>();
        foreach (var o in s.Outcomes.Where(o => !o.Skipped))
        {
            if (o.Changes is { Count: > 0 } ch)
                foreach (var c in ch)
                    (c.Undo switch { Changes.UndoSupport.None or Changes.UndoSupport.PlaceholdersOnly => permanent, Changes.UndoSupport.Reinstall => reinstall, _ => undoable }).Add(c.Text);
            else if (o.Success)
                switch (UndoOf(o))
                {
                    case Changes.UndoSupport.Full: undoable.Add(o.Title); break;
                    case Changes.UndoSupport.Reinstall when !s.ChangesTracked: reinstall.Add(o.Title); break;
                    case Changes.UndoSupport.None or Changes.UndoSupport.PlaceholdersOnly when !s.ChangesTracked: permanent.Add(o.Title); break;
                }
        }
        sb.Append("<h2>Undoing changes</h2>");
        if (undoable.Count + reinstall.Count + permanent.Count == 0) sb.Append("<p>Nothing lasting was changed, so there's nothing to undo.</p>");
        else
        {
            if (undoable.Count > 0) { sb.Append("<p>Can be put back exactly as it was:</p><ul>"); foreach (var x in undoable) sb.Append("<li>").Append(E(x)).Append("</li>"); sb.Append("</ul>"); }
            if (reinstall.Count > 0)
            {
                sb.Append("<p>Removed apps that undo reinstalls from the Microsoft Store (for the account signed in at the time; needs internet). Their settings and data aren't restored:</p><ul>");
                foreach (var x in reinstall) sb.Append("<li>").Append(E(x)).Append("</li>");
                sb.Append("</ul>");
            }
            if (permanent.Count > 0) { sb.Append("<p>Permanent (can't be undone; for example, installed updates stay installed and deleted files can't be recovered):</p><ul>"); foreach (var x in permanent) sb.Append("<li>").Append(E(x)).Append("</li>"); sb.Append("</ul>"); }
            sb.Append("<p>To put changes back, your technician opens Remote PC Diagnostics and clicks \"Undo all changes\" (History page), or runs <code>RemotePCDiagnostics.Host.exe --undo-all</code> as administrator (add <code>--restart</code> to restart afterwards). Permanent changes are left as they are.")
              .Append(reinstall.Count > 0 ? " If an app can't be reinstalled automatically, undo says so and it can be reinstalled from the Microsoft Store by hand." : "").Append("</p>");
        }
        if (s.EarlierChanges > 0)
            sb.Append("<p class=\"meta\">\"Undo all changes\" also puts back ").Append(s.EarlierChanges).Append(" earlier change").Append(s.EarlierChanges == 1 ? "" : "s")
              .Append(" this app made on this PC before this service.</p>");
        if (stopped && applied.Count > 0) sb.Append("<p class=\"meta\">Fixes applied before the service stopped stay in place until they're undone.</p>");

        sb.Append("<p class=\"meta\">Generated by Remote PC Diagnostics.</p></body></html>");

        string T(DateTimeOffset t) => t.ToOffset(generated.Offset).ToString("MMM d, h:mm tt", System.Globalization.CultureInfo.InvariantCulture);

        Changes.UndoSupport UndoOf(FixOutcome o) => s.Fixes.FirstOrDefault(f => f.Id == o.FixId)?.Undo ?? Changes.UndoSupport.Full;

        void Outcome(FixOutcome o)
        {
            sb.Append("<li><strong>").Append(E(o.Title)).Append("</strong> — ").Append(E(o.Message));
            if (o.Changes is { Count: > 0 } ch)
            {
                sb.Append("<ul>");
                foreach (var c in ch)
                    sb.Append("<li>").Append(E(c.Text)).Append(" <span class=\"meta\">(").Append(c.Undo switch
                    {
                        Changes.UndoSupport.None or Changes.UndoSupport.PlaceholdersOnly => "permanent",
                        Changes.UndoSupport.Reinstall => "undo reinstalls it from the Microsoft Store; settings and data aren't restored",
                        _ => "can be undone",
                    }).Append(")</span></li>");
                sb.Append("</ul>");
            }
            else if (o.Success)
            {
                var undo = UndoOf(o) switch
                {
                    Changes.UndoSupport.Full => "can be undone.",
                    Changes.UndoSupport.PlaceholdersOnly => "deleted files can't be recovered.",
                    Changes.UndoSupport.None => s.ChangesTracked ? "nothing permanent was changed." : "permanent, can't be undone.",
                    Changes.UndoSupport.Reinstall => s.ChangesTracked ? "nothing was removed." : "undo reinstalls it from the Microsoft Store (needs internet); its settings and data aren't restored.",
                    _ => "nothing lasting to undo.",
                };
                sb.Append("<div class=\"meta\">Undo: ").Append(undo).Append("</div>");
            }
            sb.Append("</li>");
        }

        return sb.ToString();
    }
}
