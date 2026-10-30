using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Tests;

public class AreaSortTests
{
    private static AreaRow R(string when, string key, string app, string n) => new(AreaLevel.Neutral, [when, app, n], [key, null, null]);
    private static readonly AreaRow[] Rows =
    [
        R("Oct 9, 1:00 PM", "2026-10-09T13:00:00", "beta", "10"),
        R("Oct 29, 2:15 PM", "2026-10-29T14:15:00", "Alpha", "2"),
        R("Oct 10, 9:00 AM", "2026-10-10T09:00:00", "gamma", "2"),
    ];

    [Fact]
    public void Time_UsesSortKey_NotDisplayText()
    {
        Assert.Equal(["Oct 29, 2:15 PM", "Oct 10, 9:00 AM", "Oct 9, 1:00 PM"], AreaSort.Sort(Rows, 0, true).Select(r => r.Values[0]));
        Assert.Equal(["Oct 9, 1:00 PM", "Oct 10, 9:00 AM", "Oct 29, 2:15 PM"], AreaSort.Sort(Rows, 0, false).Select(r => r.Values[0]));
    }

    [Fact]
    public void Text_CaseInsensitive_Numbers_Numeric_Stable()
    {
        Assert.Equal(["Alpha", "beta", "gamma"], AreaSort.Sort(Rows, 1, false).Select(r => r.Values[1]));
        Assert.Equal(["Alpha", "gamma", "beta"], AreaSort.Sort(Rows, 2, false).Select(r => r.Values[1])); // 2,2 keep order, 10 last
        Assert.Same(Rows, AreaSort.Sort(Rows, -1, false));
    }

    [Fact]
    public void Default_NewestFirst_ForTimeColumns()
    {
        Assert.Equal((0, true), AreaSort.Default(["When", "App"]));
        Assert.Equal((3, true), AreaSort.Default(["App", "Crashes", "Stopped responding", "Last time"]));
        Assert.Equal((-1, false), AreaSort.Default(["Name", "State"]));
    }

    [Fact]
    public void FriendlyTimeFormat()
    {
        var now = new DateTimeOffset(2026, 10, 29, 12, 0, 0, TimeSpan.Zero);
        var t = new DateTimeOffset(2026, 10, 29, 14, 15, 0, TimeZoneInfo.Local.GetUtcOffset(new DateTime(2026, 10, 29, 14, 15, 0)));
        Assert.Equal("Oct 29, 2:15 PM", WindowsEventLog.FormatTime(t, now));
        Assert.Equal("", WindowsEventLog.FormatTime(default, now));
    }
}
