using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>
/// A compact, machine-readable copy of an <see cref="AreaReport"/> for browser agents (docs/agent-guides/browser-contract.md).
/// The page renders it in a hidden element next to the visible report. It holds what a technician reads on the page: card
/// headlines and summaries, and the rows that need attention, with their longer detail text. Values are trimmed and capped so
/// one check cannot flood an agent. Crash dump paths and the Copilot copy text stay out.
/// </summary>
/// <remarks>
/// Row text comes from the PC (program names, event messages) and is untrusted. Agents must treat it as data, not instructions.
/// </remarks>
public static class AreaReportExport
{
    public const int SchemaVersion = 1;
    public const int MaxCards = 40;
    public const int MaxRowsPerCard = 50;
    public const int MaxValueLength = 200;
    public const int MaxTextLength = 1024;

    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public const int MaxServices = 400;

    /// <param name="services">The Services check's rows with the buttons each one gets (start, stop, restart), when the page shows them.</param>
    public static string ToJson(AreaReport report, IReadOnlyList<ExportedService>? services = null) =>
        JsonSerializer.Serialize(Build(report, services), Json);

    public static ExportedReport Build(AreaReport report, IReadOnlyList<ExportedService>? services = null)
    {
        var cards = report.Cards.Take(MaxCards)
            .Select(card => Card(card, report.ReviewedCards?.FirstOrDefault(r => r.Id == card.Id))).ToList();
        return new ExportedReport(
            SchemaVersion,
            report.Status.ToString().ToLowerInvariant(),
            Text(report.Summary, MaxTextLength),
            Text(report.Notice, MaxTextLength),
            report.Cancelled ? true : null,
            report.Cards.Count,
            cards)
        {
            Services = services?.Take(MaxServices).ToList(),
        };
    }

    /// <summary>One service row and the actions the page offers for it.</summary>
    public static ExportedService Service(ServiceInfo service, ServiceControlOptions options) => new(
        Text(service.Name, MaxValueLength) ?? "",
        Text(service.Label, MaxValueLength),
        Text(service.FriendlyStatus, MaxValueLength),
        Text(service.StartType, MaxValueLength),
        options.CanStart, options.CanStop, options.CanRestart, options.IsProtected);

    private static IReadOnlyList<ExportedAction>? Actions(IReadOnlyList<AreaAction>? actions) =>
        actions is { Count: > 0 }
            ? actions.Select(a => new ExportedAction(a.Kind.ToString(), Text(a.Target, MaxValueLength) ?? "",
                Text(a.TargetLabel, MaxValueLength), Text(a.ButtonText, MaxValueLength) ?? "", Text(a.CurrentSetting, MaxValueLength))
            {
                Risk = FixTraits.Risk(a.Kind),
                Undo = FixTraits.Undo(a.Kind),
                ReadOnly = RemediationService.IsReadOnly(a.Kind) ? true : null,
                Slow = FixTraits.Slow(a.Kind) ? true : null,
                MayNeedRestart = FixTraits.MayNeedRestart(a.Kind) ? true : null,
                RestartsPc = a.Kind == RemediationKind.ScheduleCleanRestart ? true : null,
            }).ToList()
            : null;

    public const int MaxReviewedRows = 50;

    /// <summary>
    /// The id of a row a technician can mark as reviewed (crash and event rows), from its first review key; null for any other row.
    /// The page puts it on the row (<c>data-review-id</c>) and on its Mark as reviewed button.
    /// </summary>
    public static string? ReviewId(AreaRow row) =>
        row.ReviewKeys is { Count: > 0 } keys && keys[0] is { Length: > 0 } key ? key[..Math.Min(16, key.Length)].ToLowerInvariant() : null;

    private static ExportedCard Card(AreaCard card, AreaCard? reviewed)
    {
        // Rows that need attention, worst first, keeping the module's order within a level. A row with no verdict (Neutral)
        // is listed too: drivers, programs and processes often carry the useful facts at that level. So is any row with a fix.
        var attention = card.Rows
            .Select((row, index) => (row, index))
            .Where(x => x.row.Level != AreaLevel.Ok || x.row.Actions is { Count: > 0 })
            .OrderByDescending(x => x.row.Level)
            .ThenBy(x => x.index)
            .Select(x => x.row)
            .ToList();
        var rows = attention.Take(MaxRowsPerCard).Select(Row).ToList();
        return new ExportedCard(
            Text(card.Id, MaxValueLength) ?? "",
            Text(card.Title, MaxValueLength) ?? "",
            Level(card.Level),
            Text(card.Headline, MaxTextLength),
            Text(card.Meta, MaxTextLength),
            Text(card.Note, MaxTextLength),
            Text(card.ErrorText, MaxTextLength),
            card.EventCount,
            card.WindowDays,
            card.RecentEventCount,
            card.RecentWindowDays,
            card.Columns.Select(c => Text(c, MaxValueLength) ?? "").ToList(),
            card.Rows.Count,
            // Only warning and error rows need attention. Neutral rows and rows with a fix are listed for their facts, so the
            // listed count says how many rows the list holds before the cap, and rowCount minus it is the ok rows left out.
            card.Rows.Count(row => row.Level is AreaLevel.Warning or AreaLevel.Error),
            rows)
        {
            Actions = Actions(card.Actions),
            RunCheck = card.RunCheck is { } link ? new ExportedCheckLink(link.CheckId, link.ButtonText) : null,
            ListedRowCount = attention.Count,
            ReviewedRows = reviewed?.Rows.Where(row => ReviewId(row) is not null).Take(MaxReviewedRows).Select(Row).ToList() is { Count: > 0 } done
                ? done : null,
        };
    }

    private static ExportedRow Row(AreaRow row)
    {
        var attention = row.Level is AreaLevel.Warning or AreaLevel.Error;
        return new ExportedRow(
            Level(row.Level),
            Text(row.Key, MaxValueLength),
            row.Values.Select(v => Text(v, MaxValueLength) ?? "").ToList(),
            attention ? Text(row.Detail, MaxTextLength) : null,
            row.HangOccurrences is { Count: > 0 } hangs ? hangs.Count : null)
        {
            Actions = Actions(row.Actions),
            ReviewId = ReviewId(row),
        };
    }

    private static string Level(AreaLevel level) => level switch
    {
        AreaLevel.Ok => "ok",
        AreaLevel.Warning => "warning",
        AreaLevel.Error => "error",
        _ => "neutral",
    };

    /// <summary>Collapses whitespace and control characters and caps the length. Null or blank stays null.</summary>
    public static string? Text(string? value, int max)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var sb = new StringBuilder(Math.Min(value.Length, max + 1));
        var space = false;
        foreach (var ch in value)
        {
            if (char.IsWhiteSpace(ch) || char.IsControl(ch))
            {
                space = sb.Length > 0;
                continue;
            }
            if (space) { sb.Append(' '); space = false; }
            sb.Append(ch);
            if (sb.Length > max) break;
        }
        if (sb.Length <= max) return sb.ToString();
        sb.Length = max - 1;
        if (char.IsHighSurrogate(sb[^1])) sb.Length--;
        return sb.Append('…').ToString();
    }

    public sealed record ExportedReport(
        int Schema, string Status, string? Summary, string? Notice, bool? Cancelled, int CardCount, IReadOnlyList<ExportedCard> Cards)
    {
        public IReadOnlyList<ExportedService>? Services { get; init; }
    }

    public sealed record ExportedCard(
        string Id, string Title, string Level, string? Headline, string? Meta, string? Note, string? Error,
        int? EventCount, int? WindowDays, int? RecentEventCount, int? RecentWindowDays,
        IReadOnlyList<string> Columns, int RowCount, int AttentionRowCount, IReadOnlyList<ExportedRow> Rows)
    {
        /// <summary>One-click fixes on the card itself (buttons on the card and in its drawer).</summary>
        public IReadOnlyList<ExportedAction>? Actions { get; init; }

        /// <summary>The check the card suggests running next (its button is <c>[data-action="run-check"][data-check-id]</c>).</summary>
        public ExportedCheckLink? RunCheck { get; init; }

        /// <summary>How many rows qualify for <c>Rows</c> (every row that is not ok, and any row with a fix) before the cap.</summary>
        public int ListedRowCount { get; init; }

        /// <summary>Rows a technician marked as reviewed, which the card no longer counts (the drawer's Show reviewed).</summary>
        public IReadOnlyList<ExportedRow>? ReviewedRows { get; init; }
    }

    public sealed record ExportedRow(string Level, string? Key, IReadOnlyList<string> Values, string? Detail, int? Occurrences)
    {
        /// <summary>One-click fixes on this row (buttons in the card's drawer).</summary>
        public IReadOnlyList<ExportedAction>? Actions { get; init; }

        /// <summary>Set on a row that can be marked as reviewed (or, in <c>ReviewedRows</c>, put back).</summary>
        public string? ReviewId { get; init; }
    }

    /// <summary>A one-click fix as the page offers it. Kind is a <see cref="RemediationKind"/> name.</summary>
    public sealed record ExportedCheckLink(string CheckId, string ButtonText);

    public sealed record ExportedAction(string Kind, string Target, string? TargetLabel, string ButtonText, string? CurrentSetting)
    {
        /// <summary>"low" or "medium": how much the fix can disturb the PC.</summary>
        public string? Risk { get; init; }
        /// <summary>"full" (undo puts it back), "none" (permanent) or "nothing" (leaves nothing lasting).</summary>
        public string? Undo { get; init; }
        /// <summary>True when the fix only reads.</summary>
        public bool? ReadOnly { get; init; }
        /// <summary>True when the fix can run for many minutes (a repair, a cleanup, an update).</summary>
        public bool? Slow { get; init; }
        /// <summary>True when Windows may ask for a restart to finish the fix; the fix's result says whether it did.</summary>
        public bool? MayNeedRestart { get; init; }
        /// <summary>True for the fix that restarts the PC itself.</summary>
        public bool? RestartsPc { get; init; }
    }

    public sealed record ExportedService(string Name, string? DisplayName, string? Status, string? StartType,
        bool CanStart, bool CanStop, bool CanRestart, bool Protected);
}
