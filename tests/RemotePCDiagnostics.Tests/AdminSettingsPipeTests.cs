using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Optimizations;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;
using Xunit;

namespace RemotePCDiagnostics.Tests;

/// <summary>
/// Machine-wide startup apps, service start types and start/stop, hibernation, Fast Startup and DNS are changed by the Agent over the
/// admin pipe; the app never makes these changes itself (it never runs as administrator).
/// </summary>
public sealed class AdminSettingsPipeTests
{
    [Fact]
    public async Task The_agent_makes_each_change_the_fixes_and_undo_ask_for()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var backend = new FakeBackend();
        var (server, task, client) = await StartAsync(backend, cts.Token);
        using (server)
        {
            await using (client)
            {
                var app = new AgentAdminSettings(new ClientBridge(client));
                var disabled = StartupParsing.DisabledValue(new DateTime(2026, 11, 20, 0, 0, 0, DateTimeKind.Utc));
                app.SetStartupApproved("hklm:OneDrive", disabled);
                app.SetStartupApproved("hklm32:Teams", null);
                app.SetServiceStartType("DiagTrack", "Manual");
                app.RestoreServiceValue("DiagTrack", ServiceDelayedStart.ValueName, null);
                app.StartService("Spooler");
                app.StopService("Spooler");
                app.SetHibernateType(reduced: true);
                app.DeleteHibernateValue("HiberFileType");
                app.SetFastStartup(0);
                app.SetAdapterDns("Wi-Fi", ["1.1.1.1", "8.8.8.8"]);
                app.SetAdapterDns("Wi-Fi", []);
            }
            await task;
        }

        Assert.Equal(
        [
            "startup hklm:OneDrive 12 bytes", "startup hklm32:Teams delete", "starttype DiagTrack Manual", "value DiagTrack DelayedAutostart delete",
            "start Spooler", "stop Spooler", "hibernate reduced", "hibernate-delete HiberFileType", "faststartup 0",
            "dns Wi-Fi 1.1.1.1,8.8.8.8", "dns Wi-Fi ",
        ], backend.Calls);
    }

    [Theory]
    [InlineData(AdminPipeSetting.StartupApproved, "OneDrive")]            // a per-user (HKCU) entry: the app changes those itself
    [InlineData(AdminPipeSetting.StartupApproved, "uwp:Spotify")]
    [InlineData(AdminPipeSetting.ServiceStartType, @"..\..\Control\Lsa")] // not a service name
    [InlineData(AdminPipeSetting.ServiceStartType, "RpcSs")]              // protected
    [InlineData(AdminPipeSetting.ServiceStartType, "RemotePCDiagnosticsAgent")]
    [InlineData(AdminPipeSetting.ServiceStop, "WinDefend")]
    [InlineData(AdminPipeSetting.ServiceStop, "VSStandardCollectorService150")]
    [InlineData(AdminPipeSetting.ServiceStop, "fakedriver")]
    [InlineData(AdminPipeSetting.ServiceStart, "fakedriver")]
    [InlineData(AdminPipeSetting.ServiceStart, "RemoteWebViewService")]
    [InlineData(AdminPipeSetting.ServiceValue, "DiagTrack")]              // only DelayedAutostart (Name is null here)
    [InlineData(AdminPipeSetting.HibernateValueDelete, null)]
    [InlineData(AdminPipeSetting.FastStartup, null)]                      // Number is null
    [InlineData(AdminPipeSetting.AdapterDns, "Wi-Fi*")]
    [InlineData("write_registry", "HKLM")]
    public async Task The_agent_refuses_anything_else(string action, string? target)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var backend = new FakeBackend();
        var (server, task, client) = await StartAsync(backend, cts.Token);
        using (server)
        {
            await using (client)
            {
                var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                    client.ChangeSystemSettingAsync(new AdminPipeSetting(action, Target: target, Text: "Manual"), cts.Token));
                Assert.IsNotType<AdminRequiredException>(ex);
            }
            await task;
        }
        Assert.Empty(backend.Calls);
    }

    [Fact]
    public void The_rules_refuse_bad_values_for_allowed_targets()
    {
        Assert.NotNull(AdminSettingsRules.Refusal(new(AdminPipeSetting.ServiceStartType, Target: "DiagTrack", Text: "Boot")));
        Assert.NotNull(AdminSettingsRules.Refusal(new(AdminPipeSetting.ServiceValue, Target: "DiagTrack", Name: "ImagePath", Number: 1)));
        Assert.NotNull(AdminSettingsRules.Refusal(new(AdminPipeSetting.ServiceValue, Target: "DiagTrack", Name: ServiceDelayedStart.ValueName, Number: 7)));
        Assert.NotNull(AdminSettingsRules.Refusal(new(AdminPipeSetting.HibernateValueDelete, Name: "HiberFileSizePercent")));
        Assert.NotNull(AdminSettingsRules.Refusal(new(AdminPipeSetting.FastStartup, Number: 2)));
        Assert.NotNull(AdminSettingsRules.Refusal(new(AdminPipeSetting.HibernateType, Number: 5)));
        Assert.NotNull(AdminSettingsRules.Refusal(new(AdminPipeSetting.StartupApproved, Target: "hklm:OneDrive", Bytes: new byte[64])));
        Assert.NotNull(AdminSettingsRules.Refusal(new(AdminPipeSetting.AdapterDns, Target: "Wi-Fi", Servers: ["1.1.1.1", "evil.example"])));
        Assert.NotNull(AdminSettingsRules.Refusal(new(AdminPipeSetting.AdapterDns, Target: "Wi-Fi", Servers: ["::1"])));
        Assert.NotNull(AdminSettingsRules.Refusal(new(AdminPipeSetting.AdapterDns, Target: "Wi-Fi", Servers: ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9"])));

        // Starting a stopped protected service only brings Windows back to normal (as the Services page allows); stopping it isn't allowed.
        Assert.Null(AdminSettingsRules.Refusal(new(AdminPipeSetting.ServiceStart, Target: "WinDefend")));
        Assert.Null(AdminSettingsRules.Refusal(new(AdminPipeSetting.ServiceValue, Target: "DiagTrack", Name: ServiceDelayedStart.ValueName, Number: 1)));
        Assert.Null(AdminSettingsRules.Refusal(new(AdminPipeSetting.HibernateType, Number: 0)));
    }

    [Fact]
    public void Without_the_agent_nothing_is_changed_and_the_message_says_what_to_do()
    {
        var notConnected = new FakeBridge { IsConnected = false };
        var ex = Assert.Throws<AdminRequiredException>(() => new AgentAdminSettings(notConnected).SetFastStartup(0));
        Assert.Contains("Admin Repair Mode", ex.Message);
        Assert.Empty(notConnected.Sent);
        Assert.Throws<AdminRequiredException>(() => new AgentAdminSettings(null).StopService("Spooler"));
    }

    [Fact]
    public async Task An_older_agent_without_these_changes_says_to_update()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var (server, task, client) = await StartAsync(null, cts.Token);
        using (server)
        {
            await using (client)
            {
                var ex = await Assert.ThrowsAsync<AdminRequiredException>(() =>
                    client.ChangeSystemSettingAsync(new AdminPipeSetting(AdminPipeSetting.FastStartup, Number: 0), cts.Token));
                Assert.Contains("Update", ex.Message);
            }
            await task;
        }
    }

    [Fact]
    public async Task A_service_start_without_the_agent_shows_what_to_do()
    {
        var log = new List<string>();
        var svc = new ServiceActionService(new AgentServiceBackend(new AgentAdminSettings(null)), new SessionContext(SessionMode.Local), new LineLogger(log.Add), TimeSpan.FromSeconds(1));
        var r = await svc.ExecuteAsync(new ServiceInfo("Spooler", "Print Spooler", "STOPPED", "DEMAND_START", "LocalSystem", ""), ServiceAction.Start);
        Assert.False(r.Success);
        Assert.Equal("Couldn't start Print Spooler: The Agent isn't connected. " + ElevationService.AdminRepairHint, r.Message);
    }

    [Fact]
    public async Task A_fix_without_the_agent_shows_what_to_do()
    {
        var launcher = new ScriptedLauncher((_, _) => ScriptedLauncher.Ok(""));
        var remediation = new RemediationService(new SystemCommandRunner(launcher), new SessionContext(SessionMode.Local), settings: new AgentOnlySettings());
        var r = await remediation.ExecuteAsync(new AreaAction(RemediationKind.DisableFastStartup, "Turn off Fast Startup"));
        Assert.False(r.Success);
        Assert.Contains("Admin Repair Mode", r.Message);
    }

    private static async Task<(AdminPipeServer, Task, AdminPipeClient)> StartAsync(IAdminSettingsBackend? backend, CancellationToken ct)
    {
        var pipeName = $"rpd-test-{Guid.NewGuid():N}";
        var server = new AdminPipeServer(new AdminPipeServerOptions { PipeName = pipeName, ExpectedClientPid = Environment.ProcessId },
            new ScriptedLauncher((_, _) => ScriptedLauncher.Ok("")), adminSettings: backend);
        var task = server.RunSingleSessionAsync(ct);
        var client = await AdminPipeClient.ConnectAsync(pipeName, TimeSpan.FromSeconds(10), ct);
        return (server, task, client);
    }

    private sealed class FakeBackend : IAdminSettingsBackend
    {
        public List<string> Calls { get; } = [];
        public void SetStartupApproved(string name, byte[]? value) => Calls.Add($"startup {name} {(value is null ? "delete" : value.Length + " bytes")}");
        public void SetServiceStartType(string service, string startType) => Calls.Add($"starttype {service} {startType}");
        public void RestoreServiceValue(string service, string name, int? value) => Calls.Add($"value {service} {name} {value?.ToString() ?? "delete"}");
        public void StartService(string service) => Calls.Add("start " + service);
        public void StopService(string service) => Calls.Add("stop " + service);
        public void SetHibernateType(bool reduced) => Calls.Add("hibernate " + (reduced ? "reduced" : "full"));
        public void DeleteHibernateValue(string name) => Calls.Add("hibernate-delete " + name);
        public void SetFastStartup(int value) => Calls.Add("faststartup " + value);
        public void SetAdapterDns(string alias, IReadOnlyList<string> servers) => Calls.Add($"dns {alias} {string.Join(",", servers)}");
        public bool IsDriver(string service) => service == "fakedriver";
    }

    /// <summary>The app's bridge, as the window has it: the connected client.</summary>
    private sealed class ClientBridge(AdminPipeClient client) : FakeBridge
    {
        public override Task ChangeSystemSettingAsync(AdminPipeSetting setting, CancellationToken ct = default) => client.ChangeSystemSettingAsync(setting, ct);
    }

    private class FakeBridge : IElevatedCommandBridge
    {
        public bool IsConnected { get; set; } = true;
        public List<AdminPipeSetting> Sent { get; } = [];
        public Task<ProcessResult?> RunElevatedAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct, Action<string>? outputLine = null) =>
            Task.FromResult<ProcessResult?>(null);
        public Task<RemotePCDiagnostics.Core.Sensors.SensorSnapshot?> ReadSensorsAsync(CancellationToken ct = default) =>
            Task.FromResult<RemotePCDiagnostics.Core.Sensors.SensorSnapshot?>(null);
        public Task<IReadOnlyList<DriveHealth>?> ReadDrivesAsync(CancellationToken ct = default) =>
            Task.FromResult<IReadOnlyList<DriveHealth>?>(null);
        public virtual Task ChangeSystemSettingAsync(AdminPipeSetting setting, CancellationToken ct = default) { Sent.Add(setting); return Task.CompletedTask; }
    }

    /// <summary>The Host's service backend shape: states read here, start/stop through the Agent.</summary>
    private sealed class AgentServiceBackend(IAdminSettingsBackend admin) : IServiceControlBackend
    {
        public ServiceState GetState(string name) => ServiceState.Stopped;
        public bool IsDriver(string name) => false;
        public IReadOnlyList<DependentService> GetRunningDependents(string name) => [];
        public void Start(string name) => admin.StartService(name);
        public void Stop(string name) => admin.StopService(name);
        public Task<bool> WaitForStateAsync(string name, ServiceState target, TimeSpan timeout, CancellationToken ct) => Task.FromResult(false);
    }

    private sealed class AgentOnlySettings : ISystemSettings
    {
        private readonly AgentAdminSettings _admin = new(null);
        public int? GetFastStartup() => 1;
        public void SetFastStartup(int value) => _admin.SetFastStartup(value);
        public int? GetUserProxyEnable() => null;
        public void SetUserProxyEnable(int value) { }
        public string? GetAdapterDns(string alias) => "";
        public void SetAdapterDns(string alias, IReadOnlyList<string> servers) => _admin.SetAdapterDns(alias, servers);
    }
}
