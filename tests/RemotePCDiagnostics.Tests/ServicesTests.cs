using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Tests;

public class ServicesTests
{
    private const string Json = """
    [{"name":"Dhcp","display_name":"DHCP Client","status":"RUNNING","start_type":"AUTO_START","user_account":"NT Authority\\LocalService","description":""},
     {"name":"Spooler","display_name":"Print Spooler","status":"STOPPED","start_type":"AUTO_START","user_account":"LocalSystem","description":""},
     {"name":"Fax","display_name":"","status":"STOPPED","start_type":"DISABLED","user_account":"","description":""},
     {"name":"BITS","display_name":"Background Intelligent Transfer Service","status":"STOPPED","start_type":"DEMAND_START","user_account":"LocalSystem","description":""}]
    """;

    [Fact]
    public async Task Builds_Cards_WithFriendlyLabels()
    {
        var log = new List<string>();
        var l = new ScriptedLauncher((f, a) => ScriptedLauncher.Ok(Json));
        var m = new ServicesModule(ScriptedLauncher.Osquery(l, log));
        var r = await m.RefreshAsync(null);
        Assert.Equal(DiagnosticStatus.Ok, r.Status);
        Assert.Equal("1 running · 1 automatic service not running", r.Message);
        var rep = Assert.IsType<AreaReport>(r.Payload);
        var stopped = rep.Cards.Single(c => c.Id == "stopped");
        Assert.Equal(AreaLevel.Warning, stopped.Level);
        Assert.Equal(["Print Spooler", "Stopped", "Automatic", "System"], stopped.Rows.Single().Values);
        Assert.Equal("Fax", rep.Cards.Single(c => c.Id == "disabled").Rows.Single().Values[0]);
        Assert.Equal(4, rep.Cards.Single(c => c.Id == "all").Rows.Count);
        Assert.Equal("Local service", rep.Cards.Single(c => c.Id == "running").Rows.Single().Values[3]);
        Assert.Equal(ServicesModule.Sql, l.Calls.Single().Args[^1]);
        Assert.Contains(log, s => s.Contains("FROM services"));
        Assert.DoesNotContain("services;", r.Message);
    }

    [Fact]
    public async Task QueryFails_FriendlyError()
    {
        var m = new ServicesModule(ScriptedLauncher.Osquery(new ScriptedLauncher((f, a) => ScriptedLauncher.Fail())));
        var r = await m.RefreshAsync(null);
        Assert.Equal(DiagnosticStatus.Error, r.Status);
        Assert.Equal("Couldn't read the list of services on this PC.", r.Message);
    }

    [Fact]
    public async Task ToolMissing_UnavailableWithFriendlyText()
    {
        var runner = new OsqueryRunner(options: new OsqueryOptions { ExecutablePath = "/nope/osqueryi.exe" }, fileExists: _ => false);
        var store = new ResultStore();
        var svc = new DiagnosticsService(store, [new ServicesModule(runner)]);
        var r = await svc.RunAsync("Services");
        Assert.Equal(DiagnosticStatus.Error, r.Status);
        Assert.Equal(OsqueryAreaModuleBase.ToolMissingMessage, r.Message);
        Assert.DoesNotContain("/nope", r.Message);
    }

    [Fact]
    public void Empty_IsFriendlyWarning() =>
        Assert.Equal("No services were found on this PC.", ServicesModule.Build([]).Summary);
}
