using RemotePCDiagnostics.Core;

namespace RemotePCDiagnostics.Tests;

public class ResultStoreTests
{
    [Fact]
    public void Get_Unknown_ReturnsNotRun() =>
        Assert.Equal(DiagnosticStatus.NotRun, new ResultStore().Get("nope").Status);

    [Fact]
    public void Set_KeepsLatest_AndRaisesChanged()
    {
        var store = new ResultStore();
        var seen = new List<DiagnosticResult>();
        store.Changed += (_, r) => seen.Add(r);
        store.Set(new DiagnosticResult("A", DiagnosticStatus.Running, "1", DateTimeOffset.Now));
        store.Set(new DiagnosticResult("A", DiagnosticStatus.Ok, "2", DateTimeOffset.Now));
        Assert.Equal("2", store.Get("A").Message);
        Assert.Single(store.Snapshot);
        Assert.Equal(2, seen.Count);
    }
}
