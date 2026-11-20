using RemotePCDiagnostics.Core.Migrations;
using RemotePCDiagnostics.Core.Session;
using Xunit;

namespace RemotePCDiagnostics.Tests;

/// <summary>
/// The app never runs as administrator: the Agent secures the state folder, registers the Event Log source and runs the history updates
/// for it, over the admin pipe.
/// </summary>
public sealed class MachineSetupPipeTests
{
    [Fact]
    public async Task The_agent_does_the_machine_setup_and_reports_what_it_did()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var setup = new FakeSetup(new MachineSetupResult(true, true, nameof(MigrationOutcome.Completed), nameof(MigrationOutcome.NeedsRestart)));
        var (server, task, client) = await StartAsync(setup, cts.Token);
        using (server)
        {
            await using (client)
            {
                var result = await client.PrepareMachineAsync(cts.Token);
                Assert.Equal(setup.Result, result);
                Assert.True(result!.Done);
                Assert.Equal(1, setup.Calls);
            }
            await task;
        }
    }

    [Fact]
    public void Setup_isnt_done_while_a_part_failed()
    {
        Assert.False(new MachineSetupResult(false, true, "AlreadyDone", "AlreadyDone").Done);
        Assert.False(new MachineSetupResult(true, false, "AlreadyDone", "AlreadyDone").Done);
        Assert.False(new MachineSetupResult(true, true, nameof(MigrationOutcome.Failed), "AlreadyDone").Done);
        Assert.False(new MachineSetupResult(true, true, "AlreadyDone", nameof(MigrationOutcome.Failed)).Done);
        Assert.True(new MachineSetupResult(true, true, nameof(MigrationOutcome.NeedsElevation), nameof(MigrationOutcome.Waiting)).Done);
    }

    [Fact]
    public async Task An_older_agent_says_its_not_supported()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var (server, task, client) = await StartAsync(null, cts.Token);
        using (server)
        {
            await using (client)
            {
                Assert.Null(await client.PrepareMachineAsync(cts.Token));
            }
            await task;
        }
    }

    private static async Task<(AdminPipeServer, Task, AdminPipeClient)> StartAsync(IMachineSetup? setup, CancellationToken ct)
    {
        var pipeName = $"rpd-test-{Guid.NewGuid():N}";
        var server = new AdminPipeServer(new AdminPipeServerOptions { PipeName = pipeName, ExpectedClientPid = Environment.ProcessId },
            new ScriptedLauncher((_, _) => ScriptedLauncher.Ok("")), machineSetup: setup);
        var task = server.RunSingleSessionAsync(ct);
        var client = await AdminPipeClient.ConnectAsync(pipeName, TimeSpan.FromSeconds(10), ct);
        return (server, task, client);
    }

    private sealed class FakeSetup(MachineSetupResult result) : IMachineSetup
    {
        public MachineSetupResult Result => result;
        public int Calls { get; private set; }
        public MachineSetupResult Prepare() { Calls++; return result; }
    }
}
