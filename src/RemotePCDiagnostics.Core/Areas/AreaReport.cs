namespace RemotePCDiagnostics.Core.Areas;

/// <summary>Status dot for a card or a drawer row.</summary>
public enum AreaLevel { Neutral, Ok, Warning, Error }

/// <summary>One drawer table row; <see cref="Values"/> line up with <see cref="AreaCard.Columns"/>. All text is end-user friendly.</summary>
public sealed record AreaRow(AreaLevel Level, IReadOnlyList<string> Values, IReadOnlyList<string?>? SortKeys = null, string? Key = null);
/// <remarks><see cref="AreaRow.Key"/> is an optional stable id (e.g. the service name) used for row actions.</remarks>

/// <summary>A summary card plus its drill-down drawer content. Text here is shown to the user; technical detail goes to the log.</summary>
public sealed record AreaCard(
    string Id, string Title, AreaLevel Level, string Headline, string Meta,
    IReadOnlyList<string> Columns, IReadOnlyList<AreaRow> Rows,
    string? ErrorText = null, string? EmptyText = null, string? Note = null)
{
    public static AreaCard Failed(string id, string title, string errorText) =>
        new(id, title, AreaLevel.Error, "", "", [], [], ErrorText: errorText);
}

/// <summary>Payload of an area module: the cards, a one-line summary for the Dashboard, and the overall status.</summary>
public sealed record AreaReport(IReadOnlyList<AreaCard> Cards, string Summary, DiagnosticStatus Status, string? Notice = null)
{
    public static AreaReport Failed(string message) => new([], message, DiagnosticStatus.Error);

    public static DiagnosticStatus Worst(IEnumerable<AreaLevel> levels) =>
        levels.DefaultIfEmpty(AreaLevel.Ok).Max() switch
        {
            AreaLevel.Error => DiagnosticStatus.Error,
            AreaLevel.Warning => DiagnosticStatus.Warning,
            _ => DiagnosticStatus.Ok,
        };
}
