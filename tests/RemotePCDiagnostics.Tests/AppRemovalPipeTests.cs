using RemotePCDiagnostics.Core.Optimizations;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;
using Xunit;

namespace RemotePCDiagnostics.Tests;

/// <summary>
/// Removing Store apps for every account, running uninstallers and changing system tasks need administrator rights, so the Agent does
/// them over the admin pipe (<see cref="AppRemovalAgent"/>). The app never runs as administrator. The Agent checks every request
/// against its own allowlists and builds the scripts itself.
/// </summary>
public sealed class AppRemovalPipeTests
{
    private static RemovableAppx Maps => AppRemoval.Packages.Single(p => p.Id == "maps");
    private static RemovableAppx People => AppRemoval.Packages.Single(p => p.Id == "people");

    [Fact]
    public async Task The_agent_removes_allowlisted_packages_for_all_users_and_says_what_is_left()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var launcher = new ScriptedLauncher((file, _) => ScriptedLauncher.Ok("noise\nLEFT:" + People.FamilyName + "\n"));
        var (server, task, client) = await StartAsync(launcher, cts.Token);
        using (server)
        {
            await using (client)
            {
                var r = await client.RemoveAppxPackagesAsync([Maps, People], cts.Token);
                Assert.True(r.Ok);
                Assert.Equal([People.FamilyName], r.Left);
            }
            await task;
        }
        var call = Assert.Single(launcher.Calls);
        Assert.EndsWith("powershell.exe", call.File);
        var script = string.Join(" ", call.Args);
        Assert.Contains("Remove-AppxPackage", script);
        Assert.Contains("-AllUsers", script);
        Assert.Contains("Remove-AppxProvisionedPackage", script);
        Assert.Contains($"'{Maps.Name}|{Maps.PublisherId}'", script);
    }

    [Fact]
    public async Task The_agent_refuses_packages_that_arent_on_its_allowlist()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var launcher = new ScriptedLauncher((_, _) => ScriptedLauncher.Ok("LEFT:"));
        var (server, task, client) = await StartAsync(launcher, cts.Token);
        using (server)
        {
            await using (client)
            {
                // The Store itself is never removed, and an app made up by the caller isn't on the list.
                var store = Maps with { Name = "Microsoft.WindowsStore" };
                var r = await client.RemoveAppxPackagesAsync([store], cts.Token);
                Assert.False(r.Ok);
                Assert.Null(r.Left);
                var made = await client.RemoveAppxPackagesAsync([Maps with { Name = "Evil'; Remove-Item C:\\ -Recurse;'" }], cts.Token);
                Assert.False(made.Ok);
                var none = await client.RemoveAppxPackagesAsync([], cts.Token);
                Assert.False(none.Ok);
            }
            await task;
        }
        Assert.Empty(launcher.Calls);
    }

    [Fact]
    public async Task A_removal_that_doesnt_finish_reports_no_left_list()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var launcher = new ScriptedLauncher((_, _) => new ProcessResult(1, "", "Access is denied."));
        var (server, task, client) = await StartAsync(launcher, cts.Token);
        using (server)
        {
            await using (client)
            {
                var r = await client.RemoveAppxPackagesAsync([Maps], cts.Token);
                Assert.False(r.Ok);
                Assert.Null(r.Left);
                Assert.Contains("Access is denied", r.Error);
            }
            await task;
        }
    }

    [Fact]
    public async Task The_agent_runs_only_allowlisted_uninstallers()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var launcher = new ScriptedLauncher((_, _) => ScriptedLauncher.Ok(""));
        var (server, task, client) = await StartAsync(launcher, cts.Token);
        using (server)
        {
            await using (client)
            {
                var notVendor = await client.RunUninstallerAsync(new UninstallCommand(false, @"C:\Windows\System32\cmd.exe", ["/c", "whoami"]), cts.Token);
                Assert.False(notVendor.Ok);
                Assert.Contains("isn't one this app may run", notVendor.Error);
                var badMsi = await client.RunUninstallerAsync(new UninstallCommand(true, "{3CE8B8E8-B33B-453C-BB7A-821ED6E18A24}", ["/i", "evil.msi"]), cts.Token);
                Assert.False(badMsi.Ok);
                var wrongArgs = await client.RunUninstallerAsync(new UninstallCommand(false, @"C:\Program Files\Lenovo\Lenovo Now\unins000.exe", ["/LOG=C:\\x"]), cts.Token);
                Assert.False(wrongArgs.Ok);
            }
            await task;
        }
        Assert.Empty(launcher.Calls);
    }

    [Fact]
    public async Task The_agent_turns_allowlisted_tasks_off_and_on_and_reports_their_state()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var launcher = new ScriptedLauncher((_, args) => ScriptedLauncher.Ok(string.Join(" ", args).Contains("Disable-ScheduledTask") ? "Disabled\r\n" : "Ready\r\n"));
        var (server, task, client) = await StartAsync(launcher, cts.Token);
        using (server)
        {
            await using (client)
            {
                var off = await client.SetScheduledTaskEnabledAsync(@"\Microsoft\XblGameSave\XblGameSaveTask", false, cts.Token);
                Assert.True(off.Ok);
                Assert.Equal("Disabled", off.TaskState);
                var on = await client.SetScheduledTaskEnabledAsync(@"\Microsoft\XblGameSave\XblGameSaveTask", true, cts.Token);
                Assert.Equal("Ready", on.TaskState);

                var other = await client.SetScheduledTaskEnabledAsync(@"\Microsoft\Windows\Defender\Scan", false, cts.Token);
                Assert.False(other.Ok);
                Assert.Null(other.TaskState);
            }
            await task;
        }
        Assert.Equal(2, launcher.Calls.Count);
    }

    [Fact]
    public async Task A_bridge_without_app_removal_says_its_not_supported()
    {
        IElevatedCommandBridge bridge = new OldBridge();
        await Assert.ThrowsAsync<NotSupportedException>(() => bridge.RemoveAppxPackagesAsync([Maps]));
        await Assert.ThrowsAsync<NotSupportedException>(() => bridge.RunUninstallerAsync(new UninstallCommand(true, "{3CE8B8E8-B33B-453C-BB7A-821ED6E18A24}", [])));
        await Assert.ThrowsAsync<NotSupportedException>(() => bridge.SetScheduledTaskEnabledAsync(@"\Microsoft\XblGameSave\XblGameSaveTask", true));
    }

    private static async Task<(AdminPipeServer, Task, AdminPipeClient)> StartAsync(IProcessLauncher launcher, CancellationToken ct)
    {
        var pipeName = $"rpd-test-{Guid.NewGuid():N}";
        var server = new AdminPipeServer(new AdminPipeServerOptions { PipeName = pipeName, ExpectedClientPid = Environment.ProcessId }, launcher);
        var task = server.RunSingleSessionAsync(ct);
        var client = await AdminPipeClient.ConnectAsync(pipeName, TimeSpan.FromSeconds(10), ct);
        return (server, task, client);
    }

    private sealed class OldBridge : IElevatedCommandBridge
    {
        public bool IsConnected => true;
        public Task<ProcessResult?> RunElevatedAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct, Action<string>? outputLine = null) =>
            Task.FromResult<ProcessResult?>(null);
        public Task<RemotePCDiagnostics.Core.Sensors.SensorSnapshot?> ReadSensorsAsync(CancellationToken ct = default) => Task.FromResult<RemotePCDiagnostics.Core.Sensors.SensorSnapshot?>(null);
        public Task<IReadOnlyList<RemotePCDiagnostics.Core.Areas.DriveHealth>?> ReadDrivesAsync(CancellationToken ct = default) =>
            Task.FromResult<IReadOnlyList<RemotePCDiagnostics.Core.Areas.DriveHealth>?>(null);
    }
}
