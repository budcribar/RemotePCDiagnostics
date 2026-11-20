using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Benchmarks;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Sensors;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Workflow;
using Xunit;

namespace RemotePCDiagnostics.Tests;

/// <summary>
/// The app isn't elevated, so the Agent reads and saves the state folder for it (only administrators can open it): the undo journal,
/// the workflow and the benchmarks.
/// </summary>
public sealed class AgentStateTests : IDisposable
{
    private readonly string _folder = Path.Combine(Path.GetTempPath(), $"rpd-state-{Guid.NewGuid():N}");

    public AgentStateTests() => Directory.CreateDirectory(_folder);
    public void Dispose() { try { Directory.Delete(_folder, recursive: true); } catch { } }

    [Fact]
    public async Task Workflow_and_benchmark_state_are_read_and_saved_by_the_agent()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var (server, task, client) = await StartAsync(_folder, cts.Token);
        using (server)
        {
            await using (client)
            {
                var workflow = new AgentWorkflowStore(new AgentStateFile(client, ProtectedState.WorkflowFile));
                Assert.Null(workflow.Load());
                workflow.Save(new WorkflowState { Stage = WorkflowStage.RestartBefore, Machine = "PC" });
                Assert.Equal(WorkflowStage.RestartBefore, workflow.Load()?.Stage);
                Assert.Equal("PC", WorkflowState.FromJson(File.ReadAllText(Path.Combine(_folder, ProtectedState.WorkflowFile)))?.Machine);

                var bench = new AgentBenchmarkStore(new AgentStateFile(client, ProtectedState.BenchmarksFile));
                bench.Save(new BenchmarkState(new BenchmarkSettings(), RunAfterOnStartup: true));
                Assert.True(bench.Load()?.RunAfterOnStartup);

                Assert.True(await client.WriteStateFileAsync(ProtectedState.BenchmarksFile, null, cts.Token)); // deletes it
                Assert.False(File.Exists(Path.Combine(_folder, ProtectedState.BenchmarksFile)));
                Assert.Equal(new AgentStateRead(true, null), await client.ReadStateFileAsync(ProtectedState.BenchmarksFile, cts.Token));
            }
            await task;
        }
    }

    [Theory]
    [InlineData("changes.json")]       // the journal has its own checked requests
    [InlineData("pending-reboot.json")]
    [InlineData(@"..\workflow.json")]
    [InlineData("../workflow.json")]
    [InlineData("")]
    public async Task Only_the_named_state_files_can_be_read_or_saved(string name)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var (server, task, client) = await StartAsync(_folder, cts.Token);
        using (server)
        {
            await using (client)
            {
                Assert.False((await client.ReadStateFileAsync(name, cts.Token)).Ok);
                Assert.False(await client.WriteStateFileAsync(name, "[]", cts.Token));
            }
            await task;
        }
        Assert.Empty(Directory.GetFiles(_folder));
    }

    [Fact]
    public async Task The_agent_saves_only_real_state_and_never_creates_the_folder()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var missing = Path.Combine(_folder, "not-set-up");
        var (server, task, client) = await StartAsync(_folder, cts.Token);
        using (server)
        {
            await using (client)
            {
                Assert.False(await client.WriteStateFileAsync(ProtectedState.WorkflowFile, "not json", cts.Token));
                Assert.False(File.Exists(Path.Combine(_folder, ProtectedState.WorkflowFile)));
            }
            await task;
        }

        var (server2, task2, client2) = await StartAsync(missing, cts.Token);
        using (server2)
        {
            await using (client2)
                Assert.False(await client2.WriteStateFileAsync(ProtectedState.WorkflowFile, new WorkflowState().ToJson(), cts.Token));
            await task2;
        }
        Assert.False(Directory.Exists(missing));
    }

    [Fact]
    public void Changes_made_before_the_agent_connects_are_saved_when_it_does()
    {
        var agent = new FakeAgent();
        var earlier = ChangeRecord.New(ChangeKind.PowerPlan, "plan", "old", "Power plan", "test");
        agent.Saved.Add(earlier);
        using var journal = new AgentChangeJournal(agent, agent);
        Assert.False(journal.IsLoaded);

        var now = ChangeRecord.New(ChangeKind.Transparency, "transparency", "1", "Transparency", "test");
        journal.Add(now);
        journal.Remove(earlier.Id); // e.g. undone through a per-item button while the list wasn't read yet
        Assert.Equal([now], journal.All);
        Assert.Equal(2, journal.UnsentCount);

        var synced = new ManualResetEventSlim();
        journal.Changed += () => { if (journal.IsLoaded) synced.Set(); };
        agent.Connect();
        Assert.True(synced.Wait(TimeSpan.FromSeconds(10)));

        Assert.True(journal.IsLoaded);
        Assert.Equal(0, journal.UnsentCount);
        Assert.Equal([now], agent.Saved.All);
        Assert.Equal([now], journal.All);
    }

    [Fact]
    public void Without_the_agent_nothing_is_saved_and_the_page_is_told()
    {
        var agent = new FakeAgent();
        var file = new AgentStateFile(agent, ProtectedState.WorkflowFile);
        Assert.Null(file.Read());
        Assert.False(file.Write(new WorkflowState().ToJson()));
        using var journal = new AgentChangeJournal(agent, agent);
        Assert.False(journal.IsLoaded);
    }

    [Fact]
    public void An_app_that_can_open_the_folder_itself_uses_the_file_until_the_agent_connects()
    {
        var agent = new FakeAgent();
        var path = Path.Combine(_folder, ProtectedState.ChangesFile);
        using var journal = new AgentChangeJournal(agent, agent, path);
        Assert.True(journal.IsLoaded);
        var c = ChangeRecord.New(ChangeKind.Transparency, "transparency", "1", "Transparency", "test");
        journal.Add(c);
        Assert.Equal(0, journal.UnsentCount);
        Assert.Equal([c], new FileChangeJournal(path).All);

        var state = new AgentStateFile(agent, ProtectedState.WorkflowFile, Path.Combine(_folder, ProtectedState.WorkflowFile));
        Assert.True(state.Write("{}"));
        Assert.Equal("{}", state.Read());
        Assert.False(new AgentStateFile(agent, ProtectedState.WorkflowFile, Path.Combine(_folder, "missing", ProtectedState.WorkflowFile)).Write("{}"));
    }

    private static async Task<(AdminPipeServer, Task, AdminPipeClient)> StartAsync(string stateFolder, CancellationToken ct)
    {
        var pipeName = $"rpd-test-{Guid.NewGuid():N}";
        var server = new AdminPipeServer(new AdminPipeServerOptions { PipeName = pipeName, ExpectedClientPid = Environment.ProcessId },
            new ScriptedLauncher((_, _) => ScriptedLauncher.Ok("")), stateFolder: stateFolder);
        var task = server.RunSingleSessionAsync(ct);
        var client = await AdminPipeClient.ConnectAsync(pipeName, TimeSpan.FromSeconds(10), ct);
        return (server, task, client);
    }

    /// <summary>An Agent that connects when the test says so, keeping the journal in memory.</summary>
    private sealed class FakeAgent : IElevatedCommandBridge, IElevationContext
    {
        public readonly MemoryChangeJournal Saved = new();
        private volatile bool _connected;
        public bool IsConnected => _connected;
        public bool IsProcessElevated => false;
        public bool IsAdminHelperConnected => _connected;
        public event Action? Changed;
        public void Connect() { _connected = true; Changed?.Invoke(); }
        public Task<ElevationResult> EnableAdminModeAsync(CancellationToken ct = default) => Task.FromResult(new ElevationResult(false, true, ""));

        public Task<ProcessResult?> RunElevatedAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct, Action<string>? outputLine = null) =>
            Task.FromResult<ProcessResult?>(null);
        public Task<SensorSnapshot?> ReadSensorsAsync(CancellationToken ct = default) => Task.FromResult<SensorSnapshot?>(null);
        public Task<IReadOnlyList<DriveHealth>?> ReadDrivesAsync(CancellationToken ct = default) => Task.FromResult<IReadOnlyList<DriveHealth>?>(null);

        public Task<IReadOnlyList<ChangeRecord>?> ReadChangeJournalAsync(CancellationToken ct = default) =>
            Task.FromResult<IReadOnlyList<ChangeRecord>?>(_connected ? Saved.All : null);
        public Task<bool> AddJournalChangeAsync(ChangeRecord change, CancellationToken ct = default)
        {
            if (_connected) Saved.Add(change);
            return Task.FromResult(_connected);
        }
        public Task<bool> RemoveJournalChangeAsync(Guid id, CancellationToken ct = default)
        {
            if (_connected) Saved.Remove(id);
            return Task.FromResult(_connected);
        }
    }
}
