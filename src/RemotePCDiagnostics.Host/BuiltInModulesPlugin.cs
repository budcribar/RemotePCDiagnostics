using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Plugins;
using RemotePCDiagnostics.Core.Security;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Sensors;
using RemotePCDiagnostics.Core.Stress;
using RemotePCDiagnostics.Host.Sensors;

namespace RemotePCDiagnostics.Host;

/// <summary>
/// The modules that ship with the app, registered through <see cref="IModulePlugin"/> exactly as a loaded plugin would be. The shared
/// services they use (command runner, osquery, sensors, audio, NPU and the rest) are registered by <see cref="HostServices"/>.
/// </summary>
public sealed class BuiltInModulesPlugin(Microsoft.Extensions.Logging.ILoggerFactory loggers) : IModulePlugin
{
    public const string Id = "builtin";

    private ILogger L<T>() => HostServices.For<T>(loggers); // each module and adapter logs under its own category

    public void Register(IServiceCollection services, IPluginContext context)
    {
        var session = context.Session;
        services.AddSingleton<IDiagnosticModule, OsqueryModule>();
        services.AddSingleton<IDiagnosticModule, LibreHardwareMonitorModule>();
        // On demand only: not auto-run and excluded from Run All; runs when the user presses Start on its page.
        services.AddSingleton<IDiagnosticModule>(sp => new CpuStressModule(sp.GetRequiredService<ISensorProvider>(), L<CpuStressModule>(), ecFan: sp.GetRequiredService<IEcFanSource>()));
        services.AddSingleton<IDiagnosticModule>(sp => new DiskSpeedModule(new PhysicalDiskTestFileSystem(L<PhysicalDiskTestFileSystem>()), sp.GetRequiredService<ISensorProvider>(), L<DiskSpeedModule>()));
        services.AddSingleton<IDiagnosticModule>(sp => new MemoryTestModule(new SystemMemoryInfo(), new ProcessMemTestHelperLauncher(log: L<ProcessMemTestHelperLauncher>()),
            sp.GetRequiredService<ISensorProvider>(), new MdschedLauncher(L<MdschedLauncher>()), L<MemoryTestModule>()));
        services.AddSingleton<IDiagnosticModule>(sp =>
        {
            var settings = NetworkTestSettings.FromEnvironment(Environment.GetEnvironmentVariable);
            return new NetworkTestModule(new SystemPinger(), new SystemGatewayResolver(), new HttpSpeedTester(settings, log: L<HttpSpeedTester>()),
                new SystemAdapterCounters(sp.GetRequiredService<SystemCommandRunner>()), sp.GetRequiredService<ISensorProvider>(), settings, L<NetworkTestModule>());
        });
        services.AddSingleton<IDiagnosticModule>(sp => new GpuStressModule(new RemotePCDiagnostics.Host.Gpu.D3D11GpuDeviceFactory(L<RemotePCDiagnostics.Host.Gpu.D3D11GpuDeviceFactory>()), sp.GetRequiredService<ISensorProvider>(), L<GpuStressModule>()));
        services.AddSingleton<IDiagnosticModule>(sp => new DriveHealthModule(sp.GetRequiredService<SystemCommandRunner>(), sp.GetRequiredService<OsqueryRunner>(), sp.GetRequiredService<IRetrimHistory>()));
        services.AddSingleton<IDiagnosticModule>(sp => sp.GetRequiredService<ServicesModule>());
        services.AddSingleton<IDiagnosticModule, ProgramsModule>(sp => new ProgramsModule(sp.GetRequiredService<OsqueryRunner>()));
        services.AddSingleton<IDiagnosticModule, NetworkModule>(sp => new NetworkModule(sp.GetRequiredService<OsqueryRunner>(), sp.GetRequiredService<SystemCommandRunner>(), includeWifiAndIpConfig: true));
        services.AddSingleton<IDiagnosticModule>(sp => new EventLogModule(sp.GetRequiredService<SystemCommandRunner>(), excludeCrashEvents: true));
        services.AddSingleton<IDiagnosticModule>(sp => new CrashesModule(sp.GetRequiredService<SystemCommandRunner>(), includeSystemCrashes: true));
        services.AddSingleton<IDiagnosticModule>(sp => new ResourceHogsModule(sp.GetRequiredService<OsqueryRunner>(), sp.GetRequiredService<SystemCommandRunner>()));
        services.AddSingleton<IDiagnosticModule>(sp => new DeviceDriversModule(sp.GetRequiredService<OsqueryRunner>(), sp.GetRequiredService<SystemCommandRunner>()));
        services.AddSingleton<IDiagnosticModule>(sp => new DismScanHealthModule(sp.GetRequiredService<SystemCommandRunner>()));
        services.AddSingleton<IDiagnosticModule>(sp => new SfcVerifyOnlyModule(sp.GetRequiredService<SystemCommandRunner>()));
        services.AddSingleton<IDiagnosticModule>(sp => new BatteryPowerModule(sp.GetRequiredService<OsqueryRunner>(), sp.GetRequiredService<SystemCommandRunner>()));
        services.AddSingleton<IDiagnosticModule>(sp => new RemotePCDiagnostics.Core.Security.SecurityEssentialsModule(sp.GetRequiredService<SystemCommandRunner>()));
        // On-demand only (Start button on its page): not in AutoRun below and excluded from Run All (IncludeInRunAll=false).
        services.AddSingleton<IDiagnosticModule>(new SecurityAuditModule(new SecurityAuditOptions { Log = L<SecurityAuditModule>() }));
        services.AddSingleton<IDiagnosticModule>(sp => new RemotePCDiagnostics.Core.Audio.SpeakerToMicModule(sp.GetRequiredService<RemotePCDiagnostics.Core.Audio.IAudioIo>(), L<RemotePCDiagnostics.Core.Audio.SpeakerToMicModule>()));
        services.AddSingleton<IDiagnosticModule>(sp => new RemotePCDiagnostics.Core.Audio.MicToSpeakerModule(sp.GetRequiredService<RemotePCDiagnostics.Core.Audio.IAudioIo>(), L<RemotePCDiagnostics.Core.Audio.MicToSpeakerModule>()));
        // Webcam test: on-demand only, own page, not part of Run All or the stress run. Frames are analysed in memory only.
        services.AddSingleton<IDiagnosticModule>(new RemotePCDiagnostics.Core.Webcam.WebcamTestModule(new MediaCaptureWebcamIo(L<MediaCaptureWebcamIo>(), showPreview: session.Mode == SessionMode.Local), L<RemotePCDiagnostics.Core.Webcam.WebcamTestModule>()));
        services.AddSingleton<IDiagnosticModule>(sp => new RemotePCDiagnostics.Core.Npu.NpuTestModule(sp.GetRequiredService<RemotePCDiagnostics.Core.Npu.INpuIo>(), L<RemotePCDiagnostics.Core.Npu.NpuTestModule>()));
        foreach (var (id, type) in RemotePCDiagnostics.UI.BuiltInModuleUi.Components) context.SetDetailsComponent(id, type);
    }
}
