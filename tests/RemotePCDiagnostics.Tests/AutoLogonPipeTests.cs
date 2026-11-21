using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Workflow;
using Xunit;

namespace RemotePCDiagnostics.Tests;

/// <summary>The workflow's automatic sign-in is set up by the Agent over the admin pipe; the app never writes Winlogon or LSA itself.</summary>
public sealed class AutoLogonPipeTests
{
    [Fact]
    public async Task The_agent_checks_the_password_and_turns_auto_sign_in_on_and_off()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var backend = new FakeBackend();
        var (server, task, client) = await StartAsync(backend, cts.Token);
        using (server)
        {
            await using (client)
            {
                Assert.True(await client.ValidateCredentialsAsync("bud", "PC", "right", cts.Token));
                Assert.False(await client.ValidateCredentialsAsync("bud", "PC", "wrong", cts.Token));

                var backup = await client.EnableAutoLogonAsync("bud", "PC", "right", 3, cts.Token);
                Assert.Equal(FakeBackend.Saved, backup);
                Assert.Equal(("bud", "PC", "right", 3), backend.Enabled);

                await client.DisableAutoLogonAsync(backup, cts.Token);
                Assert.Equal(FakeBackend.Saved, backend.Restored);
            }
            await task;
        }
    }

    [Fact]
    public async Task The_agent_refuses_too_many_sign_ins_and_settings_that_arent_winlogons()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var backend = new FakeBackend();
        var (server, task, client) = await StartAsync(backend, cts.Token);
        using (server)
        {
            await using (client)
            {
                await Assert.ThrowsAsync<InvalidOperationException>(() =>
                    client.EnableAutoLogonAsync("bud", "PC", "right", AdminPipeServer.MaxAutoLogons + 1, cts.Token));
                await Assert.ThrowsAsync<InvalidOperationException>(() =>
                    client.EnableAutoLogonAsync("", "PC", "right", 1, cts.Token));
                await Assert.ThrowsAsync<InvalidOperationException>(() =>
                    client.DisableAutoLogonAsync(FakeBackend.Saved with { AutoAdminLogon = "cmd.exe" }, cts.Token));
                Assert.Null(backend.Enabled);
                Assert.Null(backend.Restored);
            }
            await task;
        }
    }

    [Fact]
    public async Task An_older_agent_without_auto_sign_in_says_its_not_supported()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var (server, task, client) = await StartAsync(null, cts.Token);
        using (server)
        {
            await using (client)
            {
                await Assert.ThrowsAsync<NotSupportedException>(() => client.ValidateCredentialsAsync("bud", "PC", "right", cts.Token));
                await Assert.ThrowsAsync<NotSupportedException>(() => client.EnableAutoLogonAsync("bud", "PC", "right", 1, cts.Token));
                await Assert.ThrowsAsync<NotSupportedException>(() => client.DisableAutoLogonAsync(null, cts.Token));
            }
            await task;
        }
    }

    private static async Task<(AdminPipeServer, Task, AdminPipeClient)> StartAsync(IAutoLogonBackend? backend, CancellationToken ct)
    {
        var pipeName = $"rpd-test-{Guid.NewGuid():N}";
        var server = new AdminPipeServer(new AdminPipeServerOptions { PipeName = pipeName, ExpectedClientPid = Environment.ProcessId },
            new ScriptedLauncher((_, _) => ScriptedLauncher.Ok("")), autoLogon: backend);
        var task = server.RunSingleSessionAsync(ct);
        var client = await AdminPipeClient.ConnectAsync(pipeName, TimeSpan.FromSeconds(10), ct);
        return (server, task, client);
    }

    private sealed class FakeBackend : IAutoLogonBackend
    {
        public static readonly AutoLogonBackup Saved = new("0", "old", "PC", null, 2);
        public (string, string, string, int)? Enabled { get; private set; }
        public AutoLogonBackup? Restored { get; private set; }

        public bool Validate(string user, string domain, string password) => password == "right";

        public AutoLogonBackup Enable(string user, string domain, string password, int logons)
        {
            Enabled = (user, domain, password, logons);
            return Saved;
        }

        public void Disable(AutoLogonBackup? backup) => Restored = backup;
    }
}
