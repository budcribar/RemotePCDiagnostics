using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Sensors;
using RemotePCDiagnostics.Core.Stress;

namespace RemotePCDiagnostics.Modules.NetworkTest;

/// <summary>Network stability test, with its own page.</summary>
public sealed class NetworkTestPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp =>
        {
            var settings = NetworkTestSettings.FromEnvironment(Environment.GetEnvironmentVariable);
            return new NetworkTestModule(new SystemPinger(), new SystemGatewayResolver(), new HttpSpeedTester(settings, log: sp.LoggerFor<HttpSpeedTester>()),
                new SystemAdapterCounters(sp.GetRequiredService<SystemCommandRunner>()), sp.GetRequiredService<ISensorProvider>(), settings, sp.LoggerFor<NetworkTestModule>());
        }, ModuleIds.NetworkTest, typeof(NetworkTestPage));
}

