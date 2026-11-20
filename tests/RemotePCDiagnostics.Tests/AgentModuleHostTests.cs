using System.Threading.Channels;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Plugins;
using RemotePCDiagnostics.Core.Session;
using Xunit;

namespace RemotePCDiagnostics.Tests;

/// <summary>
/// Modules that ship with the app and need administrator run out of process in a module host the Agent starts (the app never runs as
/// administrator): only those modules, from the app's own builtin-modules folder, over a pipe only the app can open.
/// </summary>
public sealed class AgentModuleHostTests : IDisposable
{
    private const string Dism = "RemotePCDiagnostics.Modules.DismScanHealth.dll";
    private const string Services = "RemotePCDiagnostics.Modules.Services.dll";

    private readonly string _root = Path.Combine(Path.GetTempPath(), "rpcd-agent-mod-" + Guid.NewGuid().ToString("N"));
    private string Bundled => Path.Combine(_root, ModuleLoaderOptions.BundledFolderName);

    public AgentModuleHostTests()
    {
        Directory.CreateDirectory(Bundled);
        foreach (var f in new[] { Dism, Services }) File.Copy(Path.Combine(AppContext.BaseDirectory, f), Path.Combine(Bundled, f));
    }

    public void Dispose() { try { Directory.Delete(_root, true); } catch { } }

    [Fact]
    public void Only_modules_in_the_apps_folder_that_need_administrator_are_allowed()
    {
        var host = new AgentModuleHost(_root);
        Assert.True(host.IsAllowed(Path.Combine(Bundled, Dism)));
        Assert.True(host.IsAllowed(Path.Combine(Bundled, "..", ModuleLoaderOptions.BundledFolderName, Dism)));
        Assert.False(host.IsAllowed(Path.Combine(Bundled, Services))); // doesn't need administrator
        Assert.False(host.IsAllowed(Path.Combine(AppContext.BaseDirectory, Dism))); // not the app's builtin-modules folder
        Assert.False(host.IsAllowed(Path.Combine(Bundled, "missing.dll")));
        Assert.False(host.IsAllowed(AgentModuleHost.Shared));
        Assert.False(host.IsAllowed(null));
        Assert.Throws<UnauthorizedAccessException>(() => host.Start(Path.Combine(Bundled, Services)));
    }

    [Fact]
    public async Task The_agent_relays_a_shared_host_and_refuses_lines_for_other_modules()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var fake = new FakeHost();
        string? started = null;
        var (server, task, client) = await StartAsync(new AgentModuleHost(_root, start: m => { started = m; return fake; }), cts.Token);
        using (server)
        {
            await using (client)
            {
                var dism = Path.Combine(Bundled, Dism);
                using var conn = await client.StartModuleHostAsync(AgentModuleHost.Shared, cts.Token);
                Assert.Equal(AgentModuleHost.Shared, started);

                await conn.WriteLineAsync(new ModuleHostMessage { Type = "availability", Module = dism }.ToLine(), cts.Token);
                var got = ModuleHostMessage.Parse(await fake.Received.Reader.ReadAsync(cts.Token))!;
                Assert.Equal(("availability", dism), (got.Type, got.Module));

                fake.Send(new ModuleHostMessage { Type = "availability", Module = dism, Available = true }.ToLine());
                var back = ModuleHostMessage.Parse(await conn.ReadLineAsync(cts.Token))!;
                Assert.Equal(("availability", true), (back.Type, back.Available));

                // A module that doesn't need administrator (or isn't the app's) never reaches the host: the app gets an error for it.
                var services = Path.Combine(Bundled, Services);
                await conn.WriteLineAsync(new ModuleHostMessage { Type = "refresh", Module = services }.ToLine(), cts.Token);
                var refused = ModuleHostMessage.Parse(await conn.ReadLineAsync(cts.Token))!;
                Assert.Equal(("error", services, AgentModuleHost.NotAllowed), (refused.Type, refused.Module, refused.Message));
                Assert.False(fake.Received.Reader.TryRead(out _));

                // Closing the app's end ends the host.
                conn.Dispose();
                await fake.Disposed.Task.WaitAsync(cts.Token);
            }
            await task;
        }
    }

    [Fact]
    public async Task The_host_ending_closes_the_apps_end()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var fake = new FakeHost();
        var (server, task, client) = await StartAsync(new AgentModuleHost(_root, start: _ => fake), cts.Token);
        using (server)
        {
            await using (client)
            {
                using var conn = await client.StartModuleHostAsync(Path.Combine(Bundled, Dism), cts.Token);
                fake.Send(new ModuleHostMessage { Type = "ready" }.ToLine());
                Assert.Equal("ready", ModuleHostMessage.Parse(await conn.ReadLineAsync(cts.Token))!.Type);
                fake.Exit();
                Assert.Null(await conn.ReadLineAsync(cts.Token));
            }
            await task;
        }
    }

    [Fact]
    public async Task The_agent_refuses_a_module_that_isnt_allowed_and_an_older_agent_says_its_not_supported()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var started = false;
        var (server, task, client) = await StartAsync(new AgentModuleHost(_root, start: _ => { started = true; return new FakeHost(); }), cts.Token);
        using (server)
        {
            await using (client)
            {
                var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => client.StartModuleHostAsync(Path.Combine(Bundled, Services), cts.Token));
                Assert.Equal(AgentModuleHost.NotAllowed, ex.Message);
                await Assert.ThrowsAsync<InvalidOperationException>(() => client.StartModuleHostAsync(Path.Combine(AppContext.BaseDirectory, Dism), cts.Token));
                Assert.False(started);
            }
            await task;
        }

        var (old, oldTask, oldClient) = await StartAsync(null, cts.Token);
        using (old)
        {
            await using (oldClient)
                await Assert.ThrowsAsync<NotSupportedException>(() => oldClient.StartModuleHostAsync(AgentModuleHost.Shared, cts.Token));
            await oldTask;
        }
    }

    [Fact]
    public async Task Without_the_agent_the_app_says_to_turn_on_admin_repair_mode()
    {
        using var elevation = new ElevationService(new SessionContext(SessionMode.Local), isProcessElevated: () => false);
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => elevation.StartModuleHostAsync(AgentModuleHost.Shared));
        Assert.Contains(ElevationService.AdminRepairHint, ex.Message);
    }

    /// <summary>The whole path with the real RemotePCDiagnostics.ModuleHost: the app's stand-in for DISM asks the Agent's host.</summary>
    [Fact]
    public async Task A_module_that_needs_administrator_runs_in_the_agents_module_host()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var agent = new AgentModuleHost(_root, start: m => new ProcessModuleHostLauncher(AppContext.BaseDirectory).Start(m, "test"));
        var (server, task, client) = await StartAsync(agent, cts.Token);
        using (server)
        {
            await using (client)
            {
                var dll = Path.Combine(Bundled, Dism);
                var (manifest, _) = ModuleManifest.ReadFromAssembly(File.ReadAllBytes(dll));
                var descriptor = RemotePCDiagnostics.Core.BuiltInModules.Descriptors.Single(d => d.Id == manifest.Id);
                var um = new UserModeModule(dll, manifest, descriptor) { Bundled = true, Elevated = true };
                using var proxy = new UserModeModuleProxy(um, new BridgeLauncher(client));
                var availability = await proxy.CheckAvailabilityAsync(cts.Token);
                // The module answered from the Agent's host.
                Assert.True(availability.IsAvailable, availability.Reason);
            }
            await task;
        }
    }

    private static async Task<(AdminPipeServer, Task, AdminPipeClient)> StartAsync(AgentModuleHost? moduleHost, CancellationToken ct)
    {
        var pipeName = $"rpd-test-{Guid.NewGuid():N}";
        var server = new AdminPipeServer(new AdminPipeServerOptions { PipeName = pipeName, ExpectedClientPid = Environment.ProcessId },
            new ScriptedLauncher((_, _) => ScriptedLauncher.Ok("")), moduleHost: moduleHost);
        var task = server.RunSingleSessionAsync(ct);
        var client = await AdminPipeClient.ConnectAsync(pipeName, TimeSpan.FromSeconds(10), ct);
        return (server, task, client);
    }

    /// <summary>What the app's launcher does for a module that needs administrator: one shared host, from the Agent.</summary>
    private sealed class BridgeLauncher(IElevatedCommandBridge agent) : IModuleHostLauncher
    {
        private readonly SharedBundledHost _shared = new(m => agent.StartModuleHostAsync(m.Path).GetAwaiter().GetResult());
        public IModuleHostConnection Start(UserModeModule module) => _shared.Start(module);
    }

    private sealed class FakeHost : IModuleHostConnection
    {
        private readonly Channel<string?> _out = Channel.CreateUnbounded<string?>();
        public Channel<string> Received { get; } = Channel.CreateUnbounded<string>();
        public TaskCompletionSource Disposed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public void Send(string line) => _out.Writer.TryWrite(line);
        public void Exit() => _out.Writer.TryWrite(null);

        public Task WriteLineAsync(string line, CancellationToken ct) { Received.Writer.TryWrite(line); return Task.CompletedTask; }
        public async Task<string?> ReadLineAsync(CancellationToken ct)
        {
            try { return await _out.Reader.ReadAsync(ct); }
            catch (ChannelClosedException) { return null; }
        }
        public bool HasExited => Disposed.Task.IsCompleted;
        public void Kill() => Dispose();
        public void Dispose() { _out.Writer.TryComplete(); Disposed.TrySetResult(); }
    }
}
