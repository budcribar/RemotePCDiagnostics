using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Tests;

public class PendingEventReviewsTests
{
    private static AreaCard Card(params AreaRow[] rows) => new("crashes", "Apps that closed unexpectedly", AreaLevel.Warning, "", "", ["App"], rows);
    private static AreaRow Row(string app, params string[] keys) => new(AreaLevel.Warning, [app], ReviewKeys: keys);

    [Fact]
    public void Nothing_pending_returns_the_same_cards()
    {
        var open = Card(Row("a.exe", "k1"));
        var reviewed = Card();
        var (o, r) = new PendingEventReviews().Apply(open, reviewed);
        Assert.Same(open, o);
        Assert.Same(reviewed, r);
    }

    [Fact]
    public void Reviewed_row_moves_to_the_reviewed_card_and_undo_moves_it_back()
    {
        var a = Row("a.exe", "k1", "k2");
        var b = Row("b.exe", "k3");
        var pending = new PendingEventReviews();
        pending.Set(["k1", "k2"], reviewed: true);

        var (open, reviewed) = pending.Apply(Card(a, b), null);
        Assert.Equal([b], open.Rows);
        Assert.Equal([a], reviewed!.Rows);
        Assert.Equal("crashes", reviewed.Id);

        pending.Set(["k1", "k2"], reviewed: false);
        (open, reviewed) = pending.Apply(Card(b), Card(a));
        Assert.Equal([b, a], open.Rows);
        Assert.Empty(reviewed!.Rows);
    }

    [Fact]
    public void Row_moves_only_when_all_its_events_are_marked()
    {
        var a = Row("a.exe", "k1", "k2");
        var pending = new PendingEventReviews();
        pending.Set(["k1"], reviewed: true);
        var (open, _) = pending.Apply(Card(a), Card());
        Assert.Equal([a], open.Rows);
    }

    [Fact]
    public void Rows_without_review_keys_stay_put_and_clear_forgets_everything()
    {
        var info = new AreaRow(AreaLevel.Neutral, ["note"]);
        var a = Row("a.exe", "k1");
        var pending = new PendingEventReviews();
        pending.Set(["k1"], reviewed: true);
        Assert.Equal([info], pending.Apply(Card(info, a), Card()).Open.Rows);

        pending.Clear();
        Assert.True(pending.IsEmpty);
        Assert.Equal([info, a], pending.Apply(Card(info, a), Card()).Open.Rows);
    }
}
