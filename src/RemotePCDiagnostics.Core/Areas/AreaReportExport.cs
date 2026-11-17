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
        var cards = report.Cards.Take(MaxCards).Select(Card).ToList();
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
                Text(a.TargetLabel, MaxValueLength), Text(a.ButtonText, MaxValueLength) ?? "", Text(a.CurrentSetting, MaxValueLength))).ToList()
            : null;

    private static ExportedCard Card(AreaCard card)
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
            attention.Count,
            rows)
        {
            Actions = Actions(card.Actions),
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
    }

    public sealed record ExportedRow(string Level, string? Key, IReadOnlyList<string> Values, string? Detail, int? Occurrences)
    {
        /// <summary>One-click fixes on this row (buttons in the card's drawer).</summary>
        public IReadOnlyList<ExportedAction>? Actions { get; init; }
    }

    /// <summary>A one-click fix as the page offers it. Kind is a <see cref="RemediationKind"/> name.</summary>
    public sealed record ExportedAction(string Kind, string Target, string? TargetLabel, string ButtonText, string? CurrentSetting);

    public sealed record ExportedService(string Name, string? DisplayName, string? Status, string? StartType,
        bool CanStart, bool CanStop, bool CanRestart, bool Protected);
}
