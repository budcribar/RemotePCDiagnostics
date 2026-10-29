using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Tests;

public class ProgramsTests
{
    private static readonly DateOnly Today = new(2026, 10, 29);
    private const string Os = """[{"name":"Microsoft Windows 11 Pro","version":"10.0.26100","build":"26100","display_version":"24H2","arch":"64-bit"}]""";
    private const string Patches = """[{"hotfix_id":"KB5044284","description":"Security Update","installed_on":"10/14/2026"},{"hotfix_id":"KB5000001","description":"Update","installed_on":""}]""";
    private const string Programs = """
    [{"name":"Google Chrome","version":"130.0.1","publisher":"Google LLC","install_date":"20261020"},
     {"name":"Google Chrome","version":"130.0.1","publisher":"Google LLC","install_date":"20261020"},
     {"name":"7-Zip","version":"24.08","publisher":"Igor Pavlov","install_date":""}]
    """;

    private static ScriptedLauncher Launcher(bool failPatches = false) => new((f, a) => a[^1] switch
    {
        var s when s.Contains("os_version") => ScriptedLauncher.Ok(Os),
        var s when s.Contains("patches") => failPatches ? ScriptedLauncher.Fail() : ScriptedLauncher.Ok(Patches),
        _ => ScriptedLauncher.Ok(Programs),
    });

    [Fact]
    public async Task Builds_Version_Updates_Programs()
    {
        var m = new ProgramsModule(ScriptedLauncher.Osquery(Launcher()), () => Today);
        var r = await m.RefreshAsync(null);
        Assert.Equal(DiagnosticStatus.Ok, r.Status);
        Assert.Equal("Microsoft Windows 11 Pro · last update 15 days ago · 2 programs", r.Message);
        var rep = Assert.IsType<AreaReport>(r.Payload);
        Assert.Equal("Version 24H2 · Build 26100", rep.Cards.Single(c => c.Id == "windows").Meta);
        var upd = rep.Cards.Single(c => c.Id == "updates");
        Assert.Equal("KB5044284", upd.Rows[0].Values[0]);
        Assert.Equal("Unknown", upd.Rows[1].Values[2]);
        var progs = rep.Cards.Single(c => c.Id == "programs");
        Assert.Equal(["7-Zip", "Google Chrome"], progs.Rows.Select(x => x.Values[0]));
        Assert.Equal("1 installed or updated in the last 30 days", progs.Meta);
    }

    [Fact]
    public void StaleUpdates_Warn()
    {
        var rep = ProgramsModule.Build(null, true, [new("KB1", "Update", new DateOnly(2026, 6, 1))], [], Today);
        Assert.Equal(DiagnosticStatus.Warning, rep.Status);
        Assert.Contains("run Windows Update", rep.Cards.Single(c => c.Id == "updates").Meta);
    }

    [Fact]
    public async Task OnePartFails_OthersStillShown_FriendlyCardError()
    {
        var r = await new ProgramsModule(ScriptedLauncher.Osquery(Launcher(failPatches: true)), () => Today).RefreshAsync(null);
        var rep = Assert.IsType<AreaReport>(r.Payload);
        Assert.Equal(DiagnosticStatus.Warning, r.Status);
        Assert.Equal("Couldn't read installed updates.", rep.Cards.Single(c => c.Id == "updates").ErrorText);
        Assert.Equal(2, rep.Cards.Single(c => c.Id == "programs").Rows.Count);
    }

    [Theory]
    [InlineData("20260115", 2026, 1, 15)]
    [InlineData("10/14/2026", 2026, 10, 14)]
    [InlineData("2026-03-02", 2026, 3, 2)]
    [InlineData("1792619134", 2026, 10, 21)]
    public void ParseDate_Formats(string s, int y, int m, int d) => Assert.Equal(new DateOnly(y, m, d), ProgramsModule.ParseDate(s));

    [Fact]
    public void ParseDate_Garbage_IsNull() => Assert.Null(ProgramsModule.ParseDate("not a date"));

    [Fact]
    public void AllFail_FriendlyError() =>
        Assert.Equal(DiagnosticStatus.Error, ProgramsModule.Build(null, false, null, null, Today).Status);
}
