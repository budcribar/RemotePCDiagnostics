using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Tests;

public class ServiceControlTests
{
    private sealed class FakeBackend : IServiceControlBackend
    {
        public Dictionary<string, ServiceState> States { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> Drivers { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, List<DependentService>> Dependents { get; } = new(StringComparer.OrdinalIgnoreCase);
        public List<string> Calls { get; } = [];
        public bool NeverReaches { get; set; }
        public HashSet<string> NeverReachesServices { get; } = new(StringComparer.OrdinalIgnoreCase);
        public bool ThrowOnStart { get; set; }
        public HashSet<string> ThrowOnStartServices { get; } = new(StringComparer.OrdinalIgnoreCase);
        public bool BlockUntilCancelled { get; set; }

        public ServiceState GetState(string name) => States.TryGetValue(name, out var s) ? s : ServiceState.NotFound;
        public bool IsDriver(string name) => Drivers.Contains(name);
        public IReadOnlyList<DependentService> GetRunningDependents(string name) =>
            Dependents.TryGetValue(name, out var d) ? d.Where(x => GetState(x.Name) == ServiceState.Running).ToList() : [];
        public void Start(string name)
        {
            Calls.Add("start:" + name);
            if (ThrowOnStart || ThrowOnStartServices.Contains(name)) throw new InvalidOperationException($"Cannot start service {name} on computer '.' (raw)");
            if (!NeverReaches && !NeverReachesServices.Contains(name)) States[name] = ServiceState.Running;
        }
        public void Stop(string name)
        {
            Calls.Add("stop:" + name);
            if (NeverReaches || NeverReachesServices.Contains(name)) return;
            foreach (var d in GetRunningDependents(name)) States[d.Name] = ServiceState.Stopped;
            States[name] = ServiceState.Stopped;
        }
        public async Task<bool> WaitForStateAsync(string name, ServiceState target, TimeSpan timeout, CancellationToken ct)
        {
            Calls.Add($"wait:{name}:{target}");
            if (BlockUntilCancelled) await Task.Delay(Timeout.Infinite, ct);
            return GetState(name) == target;
        }
    }

    private static ServiceInfo Svc(string name, string display, string status, string start = "DEMAND_START", string desc = "") =>
        new(name, display, status, start, "LocalSystem", desc);

    private static (ServiceActionService svc, FakeBackend be, List<string> log) Make(SessionMode mode = SessionMode.Local, IChangeJournal? journal = null)
    {
        var be = new FakeBackend();
        var log = new List<string>();
        return (new ServiceActionService(be, new SessionContext(mode), new LineLogger(log.Add), TimeSpan.FromSeconds(1), journal), be, log);
    }

    [Theory]
    [InlineData("RpcSs")] [InlineData("DcomLaunch")] [InlineData("EventLog")] [InlineData("winmgmt")] [InlineData("WinDefend")] [InlineData("MdCoreSvc")] [InlineData("VSStandardCollectorService150")]
    [InlineData("Dhcp")] [InlineData("Dnscache")] [InlineData("BFE")] [InlineData("mpssvc")] [InlineData("TrustedInstaller")]
    public void Protected_Running_NoStopOrRestart(string name)
    {
        var o = ServiceProtection.For(Svc(name, name, "RUNNING"));
        Assert.True(o.IsProtected);
        Assert.False(o.CanStop); Assert.False(o.CanRestart); Assert.False(o.CanStart);
        Assert.Equal(name.StartsWith("VSStandardCollector") ? "Manual-only: change startup type without stopping the collector" : "Protected by Windows", o.ProtectedText);
    }

    [Fact]
    public void Protected_Stopped_CanStart()
    {
        var o = ServiceProtection.For(Svc("wscsvc", "Security Center", "STOPPED", "AUTO_START"));
        Assert.True(o.IsProtected); Assert.True(o.CanStart);
    }

    [Fact]
    public void Ordinary_ButtonsMatchStatus()
    {
        var run = ServiceProtection.For(Svc("Spooler", "Print Spooler", "RUNNING"));
        Assert.False(run.CanStart); Assert.True(run.CanStop); Assert.True(run.CanRestart); Assert.False(run.IsProtected);
        var stop = ServiceProtection.For(Svc("Spooler", "Print Spooler", "STOPPED"));
        Assert.True(stop.CanStart); Assert.False(stop.CanStop); Assert.False(stop.CanRestart);
        var disabled = ServiceProtection.For(Svc("Fax", "Fax", "STOPPED", "DISABLED"));
        Assert.False(disabled.CanStart);
        var pending = ServiceProtection.For(Svc("Spooler", "Print Spooler", "STOP_PENDING"));
        Assert.False(pending.CanStart || pending.CanStop || pending.CanRestart);
    }

    [Fact]
    public void Drivers_And_SelfComponents_AreLocked()
    {
        var (svc, be, _) = Make();
        be.Drivers.Add("disk");
        Assert.True(svc.OptionsFor(Svc("disk", "Disk Driver", "RUNNING")).IsProtected);
        Assert.False(svc.OptionsFor(Svc("disk", "Disk Driver", "STOPPED")).CanStart);
        var self = ServiceProtection.For(Svc("RemoteWebViewService", "Remote WebView", "RUNNING"));
        Assert.True(self.IsProtected); Assert.False(self.CanStop);
    }

    [Fact]
    public void Plan_Stop_WarnsAndNamesRunningDependents()
    {
        var (svc, be, _) = Make();
        be.States["LanmanServer"] = ServiceState.Running;
        be.States["Browser"] = ServiceState.Running;
        be.States["Other"] = ServiceState.Stopped;
        be.Dependents["LanmanServer"] = [new("Browser", "Computer Browser"), new("Other", "Stopped One")];
        var p = svc.Plan(Svc("LanmanServer", "Server", "RUNNING", desc: "Supports file and print sharing."), ServiceAction.Stop);
        Assert.True(p.Allowed);
        Assert.Equal("Stop Server?", p.Title);
        Assert.Contains("Supports file and print sharing.", p.WhatItIs);
        Assert.Contains("Computer Browser", p.Warning);
        Assert.DoesNotContain("Stopped One", p.Warning);
        Assert.Single(p.Dependents);
    }

    [Fact]
    public void Plan_Protected_NotAllowed()
    {
        var (svc, _, _) = Make();
        var p = svc.Plan(Svc("RpcSs", "Remote Procedure Call (RPC)", "RUNNING"), ServiceAction.Stop);
        Assert.False(p.Allowed);
        Assert.Contains("protected by Windows", p.Warning);
    }

    [Fact]
    public async Task Execute_Protected_RefusedWithoutCallingBackend()
    {
        var (svc, be, _) = Make();
        be.States["MdCoreSvc"] = ServiceState.Running;
        var r = await svc.ExecuteAsync(Svc("MdCoreSvc", "Microsoft Defender Core Service", "RUNNING"), ServiceAction.Stop);
        Assert.False(r.Success);
        Assert.DoesNotContain(be.Calls, c => c.StartsWith("stop"));
        Assert.Single(svc.Recent);
    }

    [Fact]
    public async Task Restart_StopsThenStarts_AndRestartsDependents()
    {
        var (svc, be, log) = Make();
        be.States["Spooler"] = ServiceState.Running;
        be.States["Dep"] = ServiceState.Running;
        be.Dependents["Spooler"] = [new("Dep", "Dependent")];
        var r = await svc.ExecuteAsync(Svc("Spooler", "Print Spooler", "RUNNING"), ServiceAction.Restart);
        Assert.True(r.Success);
        Assert.Equal("Print Spooler restarted", r.Message);
        Assert.Equal(ServiceState.Running, r.NewState);
        Assert.Equal(["stop:Spooler", "wait:Spooler:Stopped", "start:Spooler", "wait:Spooler:Running", "start:Dep", "wait:Dep:Running"], be.Calls);
        Assert.Equal(ServiceState.Running, be.States["Dep"]);
        Assert.Contains(log, l => l.Contains("AUDIT") && l.Contains("Local user") && l.Contains("Restart"));
    }

    [Fact]
    public async Task Start_Success_Message_And_Recent()
    {
        var (svc, be, _) = Make(SessionMode.Remote);
        be.States["Spooler"] = ServiceState.Stopped;
        ServiceActionRecord? seen = null;
        svc.ActionCompleted += r => seen = r;
        var r = await svc.ExecuteAsync(Svc("Spooler", "Print Spooler", "STOPPED"), ServiceAction.Start);
        Assert.True(r.Success);
        Assert.Equal("Print Spooler started", r.Message);
        Assert.Equal("Remote user", svc.Recent.Single().Actor);
        Assert.Equal("Remote user", seen!.Actor);
    }

    [Fact]
    public async Task Stop_Timeout_PlainMessage()
    {
        var (svc, be, log) = Make();
        be.States["wuauserv"] = ServiceState.Running;
        be.NeverReaches = true;
        var r = await svc.ExecuteAsync(Svc("wuauserv", "Windows Update", "RUNNING"), ServiceAction.Stop);
        Assert.False(r.Success);
        Assert.Equal("Couldn't stop Windows Update: it didn't respond in time.", r.Message);
        Assert.Contains(log, l => l.Contains("Timed out"));
    }

    [Fact]
    public async Task Failure_NoRawExceptionText()
    {
        var (svc, be, log) = Make();
        be.States["Spooler"] = ServiceState.Stopped;
        be.ThrowOnStart = true;
        var r = await svc.ExecuteAsync(Svc("Spooler", "Print Spooler", "STOPPED"), ServiceAction.Start);
        Assert.False(r.Success);
        Assert.Equal("Couldn't start Print Spooler: Windows didn't allow it.", r.Message);
        Assert.DoesNotContain("computer", r.Message);
        Assert.Contains(log, l => l.Contains("InvalidOperationException"));
    }

    [Fact]
    public async Task Cancel_StopsWaiting()
    {
        var (svc, be, _) = Make();
        be.States["Spooler"] = ServiceState.Running;
        be.BlockUntilCancelled = true;
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        var r = await svc.ExecuteAsync(Svc("Spooler", "Print Spooler", "RUNNING"), ServiceAction.Stop, cts.Token);
        Assert.False(r.Success);
        Assert.StartsWith("Stopped waiting for Print Spooler", r.Message);
    }

    [Fact]
    public async Task Recent_IsCapped()
    {
        var (svc, be, _) = Make();
        be.States["Spooler"] = ServiceState.Stopped;
        for (var i = 0; i < ServiceActionService.MaxRecent + 5; i++)
            await svc.ExecuteAsync(Svc("Spooler", "Print Spooler", "STOPPED"), ServiceAction.Start);
        Assert.Equal(ServiceActionService.MaxRecent, svc.Recent.Count);
    }

    [Fact]
    public void Rows_CarryServiceNameKey()
    {
        var rep = ServicesModule.Build([Svc("Spooler", "Print Spooler", "RUNNING")]);
        Assert.Equal("Spooler", rep.Cards.Single(c => c.Id == "running").Rows.Single().Key);
    }

    [Fact]
    public async Task Stop_WithRunningDependents_JournalsAll_AndUndoRestartsParentBeforeDependents()
    {
        var journal = new MemoryChangeJournal();
        var (svc, be, _) = Make(SessionMode.Remote, journal);
        be.States["LanmanServer"] = ServiceState.Running;
        be.States["MidDep"] = ServiceState.Running;
        be.States["LeafDep"] = ServiceState.Running;
        be.States["AlreadyStopped"] = ServiceState.Stopped;
        be.Dependents["LanmanServer"] = [new("MidDep", "Mid Service"), new("LeafDep", "Leaf Service"), new("AlreadyStopped", "Stopped Service")];

        var r = await svc.ExecuteAsync(Svc("LanmanServer", "Server", "RUNNING"), ServiceAction.Stop);
        Assert.True(r.Success);
        Assert.Equal(["LeafDep", "MidDep", "LanmanServer"], journal.All.Select(c => c.Target));
        Assert.All(journal.All, c => Assert.Equal((ChangeKind.ServiceRunning, "Running", "Remote user"), (c.Kind, c.Previous, c.Actor)));

        be.Calls.Clear();
        var undo = await new UndoService(journal, new SystemCommandRunner(new ScriptedLauncher((_, _) => ScriptedLauncher.Ok(""))), services: be).UndoAllAsync("Remote user");
        Assert.Equal(3, undo.Succeeded);
        Assert.Empty(journal.All);
        Assert.Equal(["start:LanmanServer", "wait:LanmanServer:Running", "start:MidDep", "wait:MidDep:Running", "start:LeafDep", "wait:LeafDep:Running"], be.Calls);
    }

    [Fact]
    public async Task Restart_DependentFailureOrTimeout_SurfacesPlainMessage_AndJournalsStoppedDependents()
    {
        var journal = new MemoryChangeJournal();
        var (svc, be, log) = Make(SessionMode.Local, journal);
        be.States["Spooler"] = ServiceState.Running;
        be.States["DepThrow"] = ServiceState.Running;
        be.States["DepSlow"] = ServiceState.Running;
        be.States["DepOk"] = ServiceState.Running;
        be.Dependents["Spooler"] = [new("DepOk", "Healthy Dependent"), new("DepThrow", "Broken Dependent"), new("DepSlow", "Slow Dependent")];
        be.ThrowOnStartServices.Add("DepThrow");
        be.NeverReachesServices.Add("DepSlow");

        var r = await svc.ExecuteAsync(Svc("Spooler", "Print Spooler", "RUNNING"), ServiceAction.Restart);
        Assert.False(r.Success);
        Assert.Contains("Broken Dependent", r.Message);
        Assert.Contains("Slow Dependent", r.Message);
        Assert.DoesNotContain("Healthy Dependent", r.Message);
        Assert.DoesNotContain("computer", r.Message); // no raw exception text
        Assert.Contains(log, l => l.Contains("InvalidOperationException"));
        Assert.Equal(["DepSlow", "DepThrow"], journal.All.Select(c => c.Target));
        Assert.All(journal.All, c => Assert.Equal("Running", c.Previous));
    }
}
