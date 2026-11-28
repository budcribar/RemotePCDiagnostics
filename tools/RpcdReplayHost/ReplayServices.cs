using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Benchmarks;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.History;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Tests.Replay;

namespace RpcdReplayHost;

/// <summary>
/// What the pages inject, as small as the app's Host (src/RemotePCDiagnostics.Host/HostServices.cs) allows: the checks answer from the
/// recording; nothing reads or changes this PC (fixes, benchmarks, history and updates have no backend, so their buttons fail closed).
/// </summary>
internal static class ReplayServices
{
    public static void Add(IServiceCollection services, ReplayedPc pc, ReplayHostOptions options)
    {
        services.AddSingleton<ISessionContext>(new SessionContext(SessionMode.Local));
        services.AddSingleton<ResultStore>();
        services.AddSingleton(sp =>
        {
            var diag = new DiagnosticsService(sp.GetRequiredService<ResultStore>(), Checks(pc, options.Store));
            // Its page is the module's own (it ships as a module DLL), so it's attached here as the plugin would.
            if (pc.HasSecurityAudit && !options.Store)
                diag.Catalog.SetDetailsComponent(ModuleIds.SecurityAudit, typeof(RemotePCDiagnostics.Modules.SecurityAudit.SecurityAuditPage));
            return diag;
        });
        services.AddSingleton(sp => new ChecksScreenState(sp.GetRequiredService<DiagnosticsService>(), sp.GetRequiredService<ResultStore>()));
        services.AddSingleton<IHistoryStore, NullHistoryStore>();
        services.AddSingleton<IChangeJournal, MemoryChangeJournal>();
        services.AddSingleton<RemoteUsers>();
        services.AddSingleton(_ => new RemotePCDiagnostics.Agent.Core.AgentModeMonitor(_ => RemotePCDiagnostics.Agent.Core.AgentModeSnapshot.LocalOnly, startLoop: false));
        services.AddSingleton(_ => new BenchmarkService(new BenchmarkRunner(new NoBenchmarkProbes()), new MemoryBenchmarkStore()));
        services.AddSingleton(sp => new RemotePCDiagnostics.UI.AppServices());
        services.AddSingleton(sp => new RemotePCDiagnostics.UI.BenchmarkUploader(sp.GetRequiredService<BenchmarkService>(),
            sp.GetRequiredService<RemotePCDiagnostics.UI.AppServices>(), sp.GetRequiredService<ISessionContext>()));
    }

    /// <summary>The checks the recordings hold answers for, as the Setup edition (WMI through the Agent) or the Store edition without one runs them.</summary>
    private static IDiagnosticModule[] Checks(ReplayedPc pc, bool store) =>
        [.. Edition(pc, store), .. pc.HasAudio ? [pc.Sound()] : Array.Empty<IDiagnosticModule>(), .. pc.HasUsb ? [pc.UsbPorts()] : Array.Empty<IDiagnosticModule>(), .. pc.HasDisplays ? [pc.Displays()] : Array.Empty<IDiagnosticModule>(),
            .. pc.HasSecurityAudit && !store ? [pc.SecurityAudit()] : Array.Empty<IDiagnosticModule>()];

    private static IDiagnosticModule[] Edition(ReplayedPc pc, bool store) => store
        ?
        [
            pc.InventoryOld(), pc.BatteryPowerOld(), pc.DriveHealthOld(), pc.ServicesOld(), pc.DeviceDriversOld(), pc.ProgramsOld(),
            pc.NetworkOld(), pc.SecurityEssentialsOld(), pc.ResourceHogsOld(), pc.CrashesOld(), pc.EventLog(), pc.SleepWake(),
        ]
        :
        [
            pc.Inventory(), pc.BatteryPower(), pc.DriveHealth(), pc.Services(), pc.DeviceDrivers(), pc.Programs(),
            pc.Network(), pc.SecurityEssentials(), pc.ResourceHogs(), pc.Crashes(), pc.EventLog(), pc.SleepWake(),
        ];

    private sealed class MemoryBenchmarkStore : IBenchmarkStore
    {
        private BenchmarkState? _state;
        public BenchmarkState? Load() => _state;
        public void Save(BenchmarkState state) => _state = state;
    }

    /// <summary>Benchmarks measure live hardware, so a replayed PC has none to run.</summary>
    private sealed class NoBenchmarkProbes : IBenchmarkProbes
    {
        public BenchmarkConditions ReadConditions() => new(null, null);
        public Task<IdleSample?> SampleIdleAsync(TimeSpan duration, CancellationToken ct) => Task.FromResult<IdleSample?>(null);
        public Task<double?> StartProgramAsync(BuiltInProgram program, CancellationToken ct) => Task.FromResult<double?>(null);
        public Task<double?> DiskRandomReadIopsAsync(TimeSpan duration, CancellationToken ct) => Task.FromResult<double?>(null);
        public Task<IReadOnlyList<RemotePCDiagnostics.Core.Areas.WinEvent>> ReadBootEventsAsync(CancellationToken ct) =>
            Task.FromResult<IReadOnlyList<RemotePCDiagnostics.Core.Areas.WinEvent>>([]);
    }
}
