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
    // An empty modules folder, so module DLLs installed on this PC (e.g. an unsigned sample) don't change the registered set.
    private static readonly string EmptyModulesFolder = System.IO.Directory.CreateDirectory(System.IO.Path.Combine(System.IO.Path.GetTempPath(), "rpcd-host-tests-modules-" + Guid.NewGuid().ToString("N"))).FullName;

    private static (ServiceProvider Provider, IServiceCollection Services) Build(SessionMode mode)
    {
        var session = mode == SessionMode.Remote
            ? new SessionContext(SessionMode.Remote, new Uri("https://relay.invalid"))
            : new SessionContext(SessionMode.Local);
        var services = new ServiceCollection().AddRemotePCDiagnosticsHost(session, _ => { }, (_, _, _) => { }, EmptyModulesFolder);
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
            var diag = provider.GetRequiredService<DiagnosticsService>();
            Assert.Equal([ModuleSlugs.CpuStress, ModuleSlugs.MemoryTest, ModuleSlugs.DiskSpeed, ModuleSlugs.GpuStress, ModuleSlugs.NetworkTest], diag.StressOrder);
            // Every registered module uses its permanent built-in id, and its name is the slug that id was given.
            foreach (var m in modules)
            {
                Assert.True(ModuleIds.BuiltIn.TryGetValue(m.Id, out var slug), $"{m.Name} has id {m.Id}, which is not in ModuleIds");
                Assert.Equal(slug, m.Name);
            }
            Assert.Equal(modules.Count, modules.Select(m => m.Id).Distinct().Count());
        }
    }

    [Fact]
    public void Lists_and_details_UI_come_from_the_catalog()
    {
        var (provider, _) = Build(SessionMode.Local);
        using (provider)
        {
            var diag = provider.GetRequiredService<DiagnosticsService>();
            // Every built-in details component is registered on its descriptor.
            foreach (var (id, type) in RemotePCDiagnostics.UI.BuiltInModuleUi.Components)
                Assert.Equal(type, diag.Catalog.Get(id)!.DetailsComponent);
            Assert.Null(diag.Catalog.Get(ModuleIds.DriveHealth)!.DetailsComponent); // generic report view

            // Same Stress tests list as before it was data-driven: suite order, then audio, webcam, NPU, then SFC/DISM.
            var screen = provider.GetRequiredService<ChecksScreenState>();
            string[] expected = [ModuleSlugs.CpuStress, ModuleSlugs.MemoryTest, ModuleSlugs.DiskSpeed, ModuleSlugs.GpuStress, ModuleSlugs.NetworkTest,
                ModuleSlugs.SpeakerToMic, ModuleSlugs.MicToSpeaker, ModuleSlugs.Webcam, ModuleSlugs.NpuTest, ModuleSlugs.DismScanHealth, ModuleSlugs.SfcVerifyOnly];
            var shown = screen.StressModules.Select(m => m.Name).ToList();
            Assert.Equal(expected.Where(shown.Contains), shown); // the NPU test is hidden until its hardware is found
            Assert.DoesNotContain(ModuleSlugs.SecurityAudit, shown);
            Assert.Equal("security-audit", screen.PageFor(ModuleSlugs.SecurityAudit));
            Assert.NotNull(provider.GetRequiredService<RemotePCDiagnostics.UI.AppServices>().Remediation);
        }
    }

    [Theory]
    [InlineData(SessionMode.Local, true)]
    [InlineData(SessionMode.Remote, false)]
    public void Pages_reach_module_UI_frames_through_AppServices_in_local_mode_only(SessionMode mode, bool expected)
    {
        var (provider, _) = Build(mode);
        using (provider)
            Assert.Equal(expected, provider.GetRequiredService<RemotePCDiagnostics.UI.AppServices>().ModuleUiFrames is not null);
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
