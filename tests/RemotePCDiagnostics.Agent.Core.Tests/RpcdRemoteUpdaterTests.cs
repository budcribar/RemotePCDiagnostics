using System.Net;
using RemotePCDiagnostics.Agent;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Agent.Core.Tests;

/// <summary>
/// The agent service and an app's elevated helper each own an updater over the same staging folder. These check that they share state.
/// </summary>
public class RpcdRemoteUpdaterTests
{
    private static readonly RpcdUpdateRequest Approved = new("stable", null, Approved: true, ApprovedBy: "shop owner");

    [Fact]
    public void Activity_reported_to_the_helper_lets_the_service_accept_a_hub_update()
    {
        var dir = TempDir();
        using var http = new HttpClient(new Stub(() => new HttpResponseMessage(HttpStatusCode.NotFound)));
        using var helper = NewUpdater(dir, http);
        using var service = NewUpdater(dir, http);

        // The app talks to its helper only. Without the shared report the service would say it could not confirm the PC is idle.
        helper.ReportActivity(null);
        var status = service.Start(Approved, relaunch: null, trustCallerBusyReason: false);

        Assert.Equal(RpcdUpdateStages.Checking, status.Stage);
    }

    [Fact]
    public void A_busy_report_to_the_helper_refuses_the_hub_update_on_the_service()
    {
        var dir = TempDir();
        using var http = new HttpClient(new Stub(() => new HttpResponseMessage(HttpStatusCode.NotFound)));
        using var helper = NewUpdater(dir, http);
        using var service = NewUpdater(dir, http);

        helper.ReportActivity("A fix is running.");
        var status = service.Start(Approved, relaunch: null, trustCallerBusyReason: false);

        Assert.Equal(RpcdUpdateStages.Refused, status.Stage);
        Assert.Equal("A fix is running.", status.Error);
    }

    [Fact]
    public async Task An_update_running_in_one_agent_process_refuses_one_in_the_other()
    {
        var dir = TempDir();
        var hold = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var http = new HttpClient(new Stub(() => hold.Task));
        using var helper = NewUpdater(dir, http);
        using var service = NewUpdater(dir, http);

        var first = helper.Start(Approved with { BusyReason = "" }, relaunch: null, trustCallerBusyReason: true);
        Assert.Equal(RpcdUpdateStages.Checking, first.Stage);

        var second = service.Start(Approved with { BusyReason = "" }, relaunch: null, trustCallerBusyReason: true);
        Assert.Equal(RpcdUpdateStages.Refused, second.Stage);
        Assert.Contains("already in progress", second.Error);

        // The service also reports the helper's update when polled.
        Assert.Equal(first.RequestId, service.Current(null)?.RequestId);

        hold.SetResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (helper.Current(first.RequestId) is { Terminal: false } && DateTime.UtcNow < deadline)
            await Task.Delay(50);
        Assert.Equal(RpcdUpdateStages.Failed, helper.Current(first.RequestId)?.Stage);
    }

    [Fact]
    public void Relaunch_command_line_splits_back_into_restart_arguments()
    {
        var host = @"C:\Program Files\RemotePCDiagnostics\RemotePCDiagnostics.Host.exe";
        string[] args = ["-u=https://server.example.com:34544", "-i=748279c7-4309-452c-8b30-e02ec52e498f", "-g=acme", "--admin", "--restarted"];
        var line = WindowsCommandLine.Join([host, .. args]);

        Assert.Equal(args, RpcdRemoteUpdater.SplitRestartCommandLine(line, host));
        Assert.Null(RpcdRemoteUpdater.SplitRestartCommandLine(line + " --evil", host));
        Assert.Null(RpcdRemoteUpdater.SplitRestartCommandLine(line, @"C:\Other\RemotePCDiagnostics.Host.exe"));
    }

    private static RpcdRemoteUpdater NewUpdater(string dir, HttpClient http) => new(
        installedVersion: () => "1.2.0",
        hostRunning: () => true,
        relaunchArguments: () => null,
        log: null,
        http: http,
        stagingDirectory: dir);

    private static string TempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "rpcd-updater-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    private sealed class Stub(Func<Task<HttpResponseMessage>> respond) : HttpMessageHandler
    {
        public Stub(Func<HttpResponseMessage> respond) : this(() => Task.FromResult(respond())) { }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            respond();
    }
}
