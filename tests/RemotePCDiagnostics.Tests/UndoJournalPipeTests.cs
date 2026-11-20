using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Session;
using Xunit;

namespace RemotePCDiagnostics.Tests;

/// <summary>
/// --undo-all runs un-elevated: the Agent reads the undo journal (which only administrators can open) and takes undone changes off it.
/// </summary>
public sealed class UndoJournalPipeTests
{
    [Fact]
    public async Task The_agent_lists_the_journal_and_takes_undone_changes_off_the_file()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var path = Path.Combine(Path.GetTempPath(), $"rpd-journal-{Guid.NewGuid():N}.json");
        try
        {
            var file = new FileChangeJournal(path);
            var a = ChangeRecord.New(ChangeKind.PowerPlan, "plan", "old-guid", "Power plan", "test");
            var b = ChangeRecord.New(ChangeKind.HiberFileType, "hiberfile", "full", "Hibernation file", "test", needsRestart: true);
            file.Add(a);
            file.Add(b);

            var (server, task, client) = await StartAsync(() => new FileChangeJournal(path), cts.Token);
            using (server)
            {
                await using (client)
                {
                    var journal = await AgentChangeJournal.LoadAsync(client, ct: cts.Token);
                    Assert.NotNull(journal);
                    Assert.Equal([a, b], journal.All);

                    journal.Remove(a.Id);
                    Assert.Equal([b], journal.All);
                    Assert.Equal([b], new FileChangeJournal(path).All); // the Agent wrote the file

                    Assert.True(await client.RemoveJournalChangeAsync(a.Id, cts.Token)); // already gone is fine
                    Assert.Throws<NotSupportedException>(() => journal.Add(a));
                }
                await task;
            }
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task Undo_all_through_the_agent_runs_the_commands_there_and_empties_the_journal()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var path = Path.Combine(Path.GetTempPath(), $"rpd-journal-{Guid.NewGuid():N}.json");
        var ran = new List<string>();
        try
        {
            new FileChangeJournal(path).Add(ChangeRecord.New(ChangeKind.HiberFileType, "hiberfile", "full", "Hibernation file", "test"));
            var launcher = new ScriptedLauncher((file, args) => { lock (ran) ran.Add($"{Path.GetFileName(file)} {string.Join(' ', args)}"); return ScriptedLauncher.Ok(""); });
            var (server, task, client) = await StartAsync(() => new FileChangeJournal(path), cts.Token, launcher);
            using (server)
            {
                await using (client)
                {
                    var journal = await AgentChangeJournal.LoadAsync(client, ct: cts.Token);
                    Assert.NotNull(journal);
                    // The app's own runner never starts powercfg itself: it fails, so a pass means the Agent ran it.
                    var local = new ScriptedLauncher((_, _) => throw new InvalidOperationException("ran in the app"));
                    var commands = new SystemCommandRunner(local, elevatedBridge: client, isProcessElevated: () => false);
                    var result = await new UndoService(journal, commands).UndoAllAsync("test", cts.Token);

                    Assert.Equal(1, result.Succeeded);
                    Assert.Empty(new FileChangeJournal(path).All);
                    Assert.Contains(ran, r => r.StartsWith("powercfg.exe /h /type full", StringComparison.OrdinalIgnoreCase));
                }
                await task;
            }
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task An_agent_without_the_journal_gives_nothing_to_undo()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var (server, task, client) = await StartAsync(null, cts.Token);
        using (server)
        {
            await using (client)
            {
                Assert.Null(await AgentChangeJournal.LoadAsync(client, ct: cts.Token));
                Assert.False(await client.RemoveJournalChangeAsync(Guid.NewGuid(), cts.Token));
            }
            await task;
        }
    }

    private static async Task<(AdminPipeServer, Task, AdminPipeClient)> StartAsync(Func<IChangeJournal>? journal, CancellationToken ct,
        ScriptedLauncher? launcher = null)
    {
        var pipeName = $"rpd-test-{Guid.NewGuid():N}";
        var server = new AdminPipeServer(new AdminPipeServerOptions { PipeName = pipeName, ExpectedClientPid = Environment.ProcessId },
            launcher ?? new ScriptedLauncher((_, _) => ScriptedLauncher.Ok("")), changeJournal: journal);
        var task = server.RunSingleSessionAsync(ct);
        var client = await AdminPipeClient.ConnectAsync(pipeName, TimeSpan.FromSeconds(10), ct);
        return (server, task, client);
    }
}
