using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Memory;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Host;

namespace RemotePCDiagnostics.Host.Tests;

/// <summary>
/// Builds the app's real container (<see cref="HostServices.AddRemotePCDiagnosticsHost"/>) the way the window does, so a missing or
/// mis-wired dependency fails here instead of at launch. Constructing the services only reads saved state; nothing runs.
/// </summary>
public class HostServicesTests
{
    private static (ServiceProvider Provider, IServiceCollection Services) Build(SessionMode mode)
    {
        var session = mode == SessionMode.Remote
            ? new SessionContext(SessionMode.Remote, new Uri("https://relay.invalid"))
            : new SessionContext(SessionMode.Local);
        var services = new ServiceCollection().AddRemotePCDiagnosticsHost(session, _ => { }, (_, _, _) => { });
        var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateOnBuild = true, ValidateScopes = true });
        return (provider, services);
    }

    [Theory]
    [InlineData(SessionMode.Local)]
    [InlineData(SessionMode.Remote)]
    public void Container_builds_with_validation(SessionMode mode)
    {
        var (provider, _) = Build(mode);
        using (provider) Assert.NotNull(provider);
    }

    /// <summary>ValidateOnBuild can't see inside factory registrations (most of ours), so resolve every app service for real.</summary>
    [Theory]
    [InlineData(SessionMode.Local)]
    [InlineData(SessionMode.Remote)]
    public void Every_app_service_resolves(SessionMode mode)
    {
        var (provider, services) = Build(mode);
        using (provider)
        {
            var appTypes = services
                .Select(d => d.ServiceType)
                .Where(t => !t.IsGenericTypeDefinition && t.Namespace?.StartsWith("RemotePCDiagnostics", StringComparison.Ordinal) == true)
                .Distinct()
                .ToList();
            Assert.NotEmpty(appTypes);
            var failures = new List<string>();
            foreach (var type in appTypes)
            {
                try
                {
                    if (!provider.GetServices(type).Any(s => s is not null)) failures.Add($"{type.FullName}: resolved nothing");
                }
                catch (Exception ex) { failures.Add($"{type.FullName}: {ex.GetType().Name}: {ex.Message}"); }
            }
            Assert.True(failures.Count == 0, "Services that failed to resolve:\n" + string.Join("\n", failures));
        }
    }

    [Fact]
    public void Modules_have_unique_names_and_the_diagnostics_service_sees_them()
    {
        var (provider, _) = Build(SessionMode.Local);
        using (provider)
        {
            var modules = provider.GetServices<IDiagnosticModule>().ToList();
            Assert.True(modules.Count >= 20, $"Expected the full module set, got {modules.Count}");
            var duplicates = modules.GroupBy(m => m.Name, StringComparer.OrdinalIgnoreCase).Where(g => g.Count() > 1).Select(g => g.Key).ToList();
            Assert.Empty(duplicates);
            // DiagnosticsService throws on a duplicate name, so resolving it proves the registered set is consistent.
            Assert.NotNull(provider.GetRequiredService<DiagnosticsService>());
            foreach (var name in StressSuite.Order)
                Assert.Contains(modules, m => string.Equals(m.Name, name, StringComparison.OrdinalIgnoreCase));
        }
    }

    [Fact]
    public void One_memory_system_is_shared()
    {
        var (provider, services) = Build(SessionMode.Local);
        using (provider)
        {
            Assert.Single(services, d => d.ServiceType == typeof(IMemorySystem));
            Assert.Same(provider.GetRequiredService<IMemorySystem>(), provider.GetRequiredService<IMemorySystem>());
        }
    }

    [Fact]
    public void Copilot_handoff_is_local_only()
    {
        var (local, _) = Build(SessionMode.Local);
        var (remote, _) = Build(SessionMode.Remote);
        using (local) using (remote)
        {
            Assert.NotNull(local.GetService<RemotePCDiagnostics.Core.Areas.ICopilotHandoff>());
            Assert.Null(remote.GetService<RemotePCDiagnostics.Core.Areas.ICopilotHandoff>());
        }
    }
}
