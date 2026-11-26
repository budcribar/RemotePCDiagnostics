namespace RemotePCDiagnostics.Core.Areas;

/// <summary>
/// Reviews saved since the check's last result: a card's rows are moved between its open and reviewed lists right away, so "Mark as
/// reviewed" and "Undo review" show at once instead of waiting for the check to read every event log again. The check's next result
/// counts them itself, and then the page forgets them (<see cref="Clear"/>).
/// </summary>
public sealed class PendingEventReviews
{
    private readonly Dictionary<string, bool> _keys = new(StringComparer.Ordinal);

    public bool IsEmpty => _keys.Count == 0;

    public void Set(IEnumerable<string> keys, bool reviewed)
    {
        foreach (var key in keys) _keys[key] = reviewed;
    }

    public void Clear() => _keys.Clear();

    /// <summary>The card's open and reviewed rows with the pending reviews applied. A row moves when every one of its events was marked the
    /// other way. Both cards come back unchanged when nothing is pending.</summary>
    public (AreaCard Open, AreaCard? Reviewed) Apply(AreaCard open, AreaCard? reviewed)
    {
        if (IsEmpty) return (open, reviewed);
        var nowReviewed = open.Rows.Where(row => AllMarked(row, true)).ToList();
        var nowOpen = reviewed?.Rows.Where(row => AllMarked(row, false)).ToList() ?? [];
        if (nowReviewed.Count == 0 && nowOpen.Count == 0) return (open, reviewed);
        var newOpen = open with { Rows = Without(open.Rows, nowReviewed).Concat(nowOpen).ToList() };
        var baseReviewed = reviewed ?? open with { Rows = [] };
        var newReviewed = baseReviewed with { Rows = Without(baseReviewed.Rows, nowOpen).Concat(nowReviewed).ToList() };
        return (newOpen, newReviewed);
    }

    private static IEnumerable<AreaRow> Without(IEnumerable<AreaRow> rows, IReadOnlyList<AreaRow> moved)
    {
        var gone = new HashSet<AreaRow>(moved, ReferenceEqualityComparer.Instance);
        return rows.Where(row => !gone.Contains(row));
    }

    private bool AllMarked(AreaRow row, bool reviewed) =>
        row.ReviewKeys is { Count: > 0 } keys && keys.All(k => _keys.TryGetValue(k, out var v) && v == reviewed);
}
