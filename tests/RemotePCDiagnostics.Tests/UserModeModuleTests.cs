using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Plugins;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Tests;

/// <summary>Runs the unsigned sample module in the real RemotePCDiagnostics.ModuleHost process through the in-app proxy.</summary>
public sealed class UserModeModuleTests : IDisposable
{
    private static readonly Guid SampleId = new("e38471d6-d5da-4ef8-9063-155f4bd2ec1a");
    private readonly string _root = Path.Combine(Path.GetTempPath(), "rpcd-usermode-" + Guid.NewGuid().ToString("N"));
    private string Modules => Path.Combine(_root, "modules");

    public UserModeModuleTests()
    {
        Directory.CreateDirectory(Modules);
        File.Copy(Path.Combine(AppContext.BaseDirectory, "sample-module", "SampleModule.dll"), Path.Combine(Modules, "SampleModule.dll"));
    }

    public void Dispose() { try { Directory.Delete(_root, true); } catch { } }

    private (ModuleLoader Loader, PluginRegistrar Registrar, ServiceCollection Services) Load(bool allowUnsigned)
    {
        var registrar = new PluginRegistrar(new SessionContext(SessionMode.Local), new Version(1, 2, 0));
        var launcher = new ProcessModuleHostLauncher(AppContext.BaseDirectory);
        var loader = new ModuleLoader(new ModuleLoaderOptions
        {
            ModulesFolder = Modules, CatalogFolder = Path.Combine(_root, "catalog"), PublicKeyPem = "", HostVersion = new Version(1, 2, 0), AllowUnsigned = allowUnsigned,
        }, registrar, userMode: um => new UserModeModuleProxy(um, launcher));
        var services = new ServiceCollection();
        loader.LoadAll(services);
        return (loader, registrar, services);
    }

    [Fact]
    public async Task An_unsigned_module_runs_in_the_module_host_and_reports_back()
    {
        var (_, registrar, services) = Load(allowUnsigned: true);
        var record = Assert.Single(registrar.Records);
        Assert.Equal(PluginState.Loaded, record.State);
        Assert.True(record.UserMode);

        using var sp = services.BuildServiceProvider();
        var module = Assert.Single(sp.GetServices<IDiagnosticModule>());
        var proxy = Assert.IsType<UserModeModuleProxy>(module);
        Assert.Equal(SampleId, module.Id);
        Assert.Equal("sample.uptime", module.Name);
        Assert.Equal("Uptime (sample plugin)", module.DisplayName);

        var diag = new DiagnosticsService(new ResultStore(), [module]);
        registrar.ApplyTo(diag.Catalog);
        var r = await diag.RunAsync("sample.uptime");
        Assert.NotEqual(DiagnosticStatus.Error, r.Status);
        Assert.StartsWith("Up ", r.Message);
        var report = Assert.IsType<AreaReport>(r.Payload);
        Assert.Equal("Uptime", Assert.Single(report.Cards).Title);
        Assert.Equal(ModuleSource.Plugin, diag.Catalog.Get(SampleId)!.Source);

        // A second run reuses the running host.
        Assert.StartsWith("Up ", (await diag.RunAsync("sample.uptime")).Message);
        proxy.Dispose();
    }

    [Fact]
    public void Without_the_toggle_an_unsigned_module_is_listed_but_not_registered()
    {
        var (loader, registrar, services) = Load(allowUnsigned: false);
        Assert.Equal(PluginState.Disabled, Assert.Single(registrar.Records).State);
        Assert.DoesNotContain(services, d => d.ServiceType == typeof(IDiagnosticModule));
        Assert.Empty(loader.UserMode);
    }

    [Fact]
    public async Task A_missing_module_host_is_a_couldnt_run_result_not_a_crash()
    {
        var (manifest, _) = ModuleManifest.ReadFromAssembly(File.ReadAllBytes(Path.Combine(Modules, "SampleModule.dll")));
        using var proxy = new UserModeModuleProxy(new UserModeModule(Path.Combine(Modules, "SampleModule.dll"), manifest, manifest.ToDescriptor(manifest.Slug)),
            new ProcessModuleHostLauncher(Path.Combine(_root, "nowhere")));
        Assert.False((await proxy.CheckAvailabilityAsync()).IsAvailable);
        var r = await proxy.RefreshAsync(null);
        Assert.IsType<CouldNotRun>(r.Payload);
    }

    [Fact]
    public void One_click_actions_are_removed_from_an_unsigned_report()
    {
        var action = new AreaAction(RemediationKind.CleanTempFiles, "Clean");
        var report = new AreaReport([new AreaCard("c", "C", AreaLevel.Warning, "h", "m", ["A"], [new AreaRow(AreaLevel.Warning, ["x"], Actions: [action])], Actions: [action])],
            "s", DiagnosticStatus.Warning);
        var clean = UserModeModuleProxy.WithoutActions(report);
        Assert.Null(clean.Cards[0].Actions);
        Assert.Null(clean.Cards[0].Rows[0].Actions);
    }

    [Fact]
    public void The_unsigned_modules_switch_is_a_file_in_the_modules_folder()
    {
        Assert.False(UnsignedModulesSetting.IsOn(Modules));
        UnsignedModulesSetting.Set(true, Modules);
        Assert.True(UnsignedModulesSetting.IsOn(Modules));
        UnsignedModulesSetting.Set(false, Modules);
        Assert.False(UnsignedModulesSetting.IsOn(Modules));
    }

    [Fact]
    public void Protocol_messages_round_trip()
    {
        var m = new ModuleHostMessage { Type = "result", Status = DiagnosticStatus.Warning, Message = "m", Report = new AreaReport([], "s", DiagnosticStatus.Warning) };
        var back = ModuleHostMessage.Parse(m.ToLine())!;
        Assert.Equal("result", back.Type);
        Assert.Equal(DiagnosticStatus.Warning, back.Status);
        Assert.Equal("s", back.Report!.Summary);
        Assert.Null(ModuleHostMessage.Parse("not json"));
    }

    [Fact]
    public async Task Shared_host_completes_stranded_readers_on_kill_and_leaves_reopened_host_alone()
    {
        var raws = new List<FakeRawConnection>();
        var shared = new SharedBundledHost(_ =>
        {
            var raw = new FakeRawConnection();
            raws.Add(raw);
            return raw;
        });
        var (manifest, _) = ModuleManifest.ReadFromAssembly(File.ReadAllBytes(Path.Combine(Modules, "SampleModule.dll")));
        var modA = new UserModeModule("a.dll", manifest, manifest.ToDescriptor("a")) { Bundled = true };
        var modB = new UserModeModule("b.dll", manifest, manifest.ToDescriptor("b")) { Bundled = true };

        using var vcA = shared.Start(modA);
        using var vcB = shared.Start(modB);
        var readA = vcA.ReadLineAsync(CancellationToken.None);
        var readB = vcB.ReadLineAsync(CancellationToken.None);

        // Kill on one virtual connection completes all active readers on that raw host immediately.
        vcA.Kill();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        Assert.Null(await readA.WaitAsync(cts.Token));
        Assert.Null(await readB.WaitAsync(cts.Token));

        // Opening a fresh virtual connection starts a second raw host; the first raw host's read loop exiting afterwards must not close the new inbox.
        using var vcA2 = shared.Start(modA);
        Assert.Equal(2, raws.Count);
        raws[0].EndOutput();
        await Task.Delay(50);

        raws[1].PushOutput(new ModuleHostMessage { Type = "availability", Available = true, Module = "a.dll" }.ToLine());
        var reply = ModuleHostMessage.Parse((await vcA2.ReadLineAsync(cts.Token))!);
        Assert.Equal("availability", reply?.Type);
    }

    [Fact]
    public async Task Shared_host_orders_virtual_exit_strictly_before_reopened_refresh_and_ignores_superseded_dispose()
    {
        var raw = new FakeRawConnection();
        var shared = new SharedBundledHost(_ => raw);
        var (manifest, _) = ModuleManifest.ReadFromAssembly(File.ReadAllBytes(Path.Combine(Modules, "SampleModule.dll")));
        var modA = new UserModeModule("a.dll", manifest, manifest.ToDescriptor("a")) { Bundled = true };
        var modB = new UserModeModule("b.dll", manifest, manifest.ToDescriptor("b")) { Bundled = true };

        using var keepAlive = shared.Start(modB);
        var firstWriteGate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        raw.HoldNextWrite(firstWriteGate.Task);

        var vc1 = shared.Start(modA);
        var slowWrite = vc1.WriteLineAsync(new ModuleHostMessage { Type = "refresh" }.ToLine(), CancellationToken.None);
        vc1.Dispose(); // queues exit behind slowWrite

        using var vc2 = shared.Start(modA);
        var nextRefresh = vc2.WriteLineAsync(new ModuleHostMessage { Type = "refresh" }.ToLine(), CancellationToken.None);

        firstWriteGate.SetResult();
        await Task.WhenAll(slowWrite, nextRefresh);

        var types = raw.WrittenLines.Select(l => ModuleHostMessage.Parse(l)!.Type).ToArray();
        Assert.Equal(["refresh", "exit", "refresh"], types);

        // Superseded connection: opening vc3 while vc2 is still open sends one exit now; disposing vc2 afterwards must not send a second exit.
        raw.ClearWritten();
        using var vc3 = shared.Start(modA);
        vc2.Dispose();
        await vc3.WriteLineAsync(new ModuleHostMessage { Type = "availability" }.ToLine(), CancellationToken.None);
        var afterSupersede = raw.WrittenLines.Select(l => ModuleHostMessage.Parse(l)!.Type).ToArray();
        Assert.Equal(["exit", "availability"], afterSupersede);
    }

    [Fact]
    public async Task Proxy_forwards_live_updated_messages_during_refresh()
    {
        var (manifest, _) = ModuleManifest.ReadFromAssembly(File.ReadAllBytes(Path.Combine(Modules, "SampleModule.dll")));
        var raw = new FakeRawConnection(onWrite: (r, line) =>
        {
            if (ModuleHostMessage.Parse(line)?.Type == "refresh")
            {
                var (payload, payloadType) = ModuleHostPayloads.Write(42.5d)!.Value;
                r.PushOutput(new ModuleHostMessage { Type = "updated", Status = DiagnosticStatus.Running, Message = "Scan 42.5% complete", Payload = payload, PayloadType = payloadType }.ToLine());
                r.PushOutput(new ModuleHostMessage { Type = "result", Status = DiagnosticStatus.Ok, Message = "Done", Report = new AreaReport([], "Done", DiagnosticStatus.Ok) }.ToLine());
            }
        });
        using var proxy = new UserModeModuleProxy(new UserModeModule("x.dll", manifest, BuiltInModules.Descriptors.First()) { Bundled = true },
            new DelegateLauncher(_ => raw));
        var updates = new List<DiagnosticResult>();
        proxy.Updated += (_, u) => updates.Add(u);

        var final = await proxy.RefreshAsync(null);
        Assert.Equal(DiagnosticStatus.Ok, final.Status);
        var live = Assert.Single(updates);
        Assert.Equal(DiagnosticStatus.Running, live.Status);
        Assert.Equal(42.5d, Assert.IsType<DiagnosticResult<double>>(live).Data);
    }

    private sealed class DelegateLauncher(Func<UserModeModule, IModuleHostConnection> start) : IModuleHostLauncher
    {
        public IModuleHostConnection Start(UserModeModule module) => start(module);
    }

    private sealed class FakeRawConnection(Action<FakeRawConnection, string>? onWrite = null) : IModuleHostConnection
    {
        private readonly System.Threading.Channels.Channel<string> _out = System.Threading.Channels.Channel.CreateUnbounded<string>();
        private readonly List<string> _written = [];
        private Task? _holdNext;
        private bool _exited;

        public IReadOnlyList<string> WrittenLines { get { lock (_written) return [.. _written]; } }
        public void ClearWritten() { lock (_written) _written.Clear(); }
        public void HoldNextWrite(Task gate) { lock (_written) _holdNext = gate; }
        public void PushOutput(string line) => _out.Writer.TryWrite(line);
        public void EndOutput() { _exited = true; _out.Writer.TryComplete(); }

        public async Task WriteLineAsync(string line, CancellationToken ct)
        {
            Task? hold;
            lock (_written) { hold = _holdNext; _holdNext = null; }
            if (hold is not null) await hold.WaitAsync(ct);
            lock (_written) _written.Add(line);
            onWrite?.Invoke(this, line);
        }

        public async Task<string?> ReadLineAsync(CancellationToken ct)
        {
            try { return await _out.Reader.ReadAsync(ct); }
            catch (System.Threading.Channels.ChannelClosedException) { return null; }
        }

        public bool HasExited => _exited;
        public void Kill() => _exited = true;
        public void Dispose() => EndOutput();
    }
}
