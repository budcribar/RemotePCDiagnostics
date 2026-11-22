using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;
using Xunit;

namespace RemotePCDiagnostics.Tests.Bios;

/// <summary>
/// Long BIOS installs run as Agent jobs: other Agent requests keep working meanwhile, and a second request for the same firmware joins
/// the running install instead of starting another one.
/// </summary>
public sealed class BiosAgentJobTests
{
    private static readonly Guid UpdateId = Guid.Parse("748279c7-4309-452c-8b30-e02ec52e498f");

    [Fact]
    public async Task Other_requests_are_answered_while_a_firmware_update_runs()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var wua = new BlockingWuaApi();
        var ops = new AgentBiosOperations(new NoProcessLauncher(), wuaApiFactory: () => wua);
        var (server, serverTask, client) = await StartPipeAsync(ops, cts.Token);
        using (server)
        {
            await using (client)
            {
                var install = client.InstallBiosWindowsUpdateAsync(UpdateId, TimeSpan.FromMinutes(5), cts.Token);
                await wua.InstallStarted.Task.WaitAsync(cts.Token);

                // The firmware install is still running, yet a ping gets through.
                var ping = await client.PingAsync(cts.Token);
                Assert.True(ping.Ok);
                Assert.False(install.IsCompleted);

                wua.Release.TrySetResult();
                var outcome = await install;
                Assert.True(outcome.Succeeded, outcome.Message);
                Assert.Equal(1, wua.InstallCalls);
            }
            await serverTask;
        }
    }

    [Fact]
    public async Task A_repeated_request_for_the_same_update_joins_the_running_install()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var wua = new BlockingWuaApi();
        var ops = new AgentBiosOperations(new NoProcessLauncher(), wuaApiFactory: () => wua);

        // The first request gives up waiting (its timeout) while Windows Update keeps installing.
        var first = await ops.InstallWindowsUpdateAsync(UpdateId, TimeSpan.FromSeconds(1), cts.Token);
        Assert.False(first.Succeeded);
        Assert.Contains("still installing", first.Message);

        var second = ops.InstallWindowsUpdateAsync(UpdateId, TimeSpan.FromSeconds(20), cts.Token);
        wua.Release.TrySetResult();
        var outcome = await second;

        Assert.True(outcome.Succeeded, outcome.Message);
        Assert.Equal(1, wua.InstallCalls);
    }

    private static async Task<(AdminPipeServer Server, Task ServerTask, AdminPipeClient Client)> StartPipeAsync(
        IAgentBiosOperations ops, CancellationToken ct)
    {
        var pipeName = $"rpd-bios-job-{Guid.NewGuid():N}";
        var server = new AdminPipeServer(
            new AdminPipeServerOptions { PipeName = pipeName, ExpectedClientPid = Environment.ProcessId },
            launcher: new NoProcessLauncher(),
            biosOperations: ops);
        var serverTask = server.RunSingleSessionAsync(ct);
        var client = await AdminPipeClient.ConnectAsync(pipeName, TimeSpan.FromSeconds(10), ct);
        return (server, serverTask, client);
    }

    private sealed class NoProcessLauncher : IProcessLauncher
    {
        public Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct) =>
            throw new InvalidOperationException($"No process should start in this test ({fileName}).");
    }

    private sealed class Update : IFoundUpdate
    {
        public string Title => "System Firmware 1.2.3";
        public bool EulaAccepted => true;
        public void AcceptEula() { }
        public bool IsDownloaded => true;
    }

    private sealed class BlockingWuaApi : IWindowsUpdateApi
    {
        private int _installCalls;
        public TaskCompletionSource InstallStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public int InstallCalls => Volatile.Read(ref _installCalls);

        public IReadOnlyList<IFoundUpdate> Search(string criteria) => [new Update()];
        public int Download(IReadOnlyList<IFoundUpdate> updates) => 2;

        public UpdateInstallOutcome Install(IReadOnlyList<IFoundUpdate> updates)
        {
            Interlocked.Increment(ref _installCalls);
            InstallStarted.TrySetResult();
            Release.Task.Wait(TimeSpan.FromSeconds(30));
            return new UpdateInstallOutcome(2, 0, false);
        }

        public void StartInteractiveScan() { }
    }
}
