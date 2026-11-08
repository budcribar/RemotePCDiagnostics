using System.IO;
using System.Diagnostics;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Plugins;
using RemotePCDiagnostics.Host;

namespace RemotePCDiagnostics.Host.Tests;

/// <summary>
/// The restricted module host for real on this PC (category WindowsReadOnly): each host gets only its own pipe ends, so two started at the
/// same moment both talk to the app and each one exits as soon as the app closes its stdin.
/// </summary>
[Trait("Category", "WindowsReadOnly")]
public class RestrictedModuleHostTests
{
    private static UserModeModule Module(string slug)
    {
        var path = Path.Combine(AppContext.BaseDirectory, ModuleLoaderOptions.BundledFolderName, $"RemotePCDiagnostics.Modules.{slug}.dll");
        var manifest = ModuleManifest.ReadFromAssembly(File.ReadAllBytes(path)).Manifest;
        return new UserModeModule(path, manifest, BuiltInModules.Descriptors.Single(d => d.Id == manifest.Id)) { Bundled = true };
    }

    [Fact]
    public async Task Several_hosts_started_together_each_answer_and_each_exit_when_their_stdin_closes()
    {
        var launcher = new RestrictedModuleHostLauncher(directory: AppContext.BaseDirectory);
        var connections = await Task.WhenAll(
            Enumerable.Range(0, 4).Select(i => Task.Run(() => launcher.Start(Module(i % 2 == 0 ? "EventLog" : "Network")))));
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            foreach (var c in connections)
                Assert.Equal("ready", ModuleHostMessage.Parse((await c.ReadLineAsync(cts.Token))!)?.Type);
        }
        finally
        {
            foreach (var c in connections)
            {
                // Dispose closes stdin and waits 2 s before killing: a host that kept another's pipe end open wouldn't see EOF in time.
                var watch = Stopwatch.StartNew();
                c.Dispose();
                Assert.True(watch.Elapsed < TimeSpan.FromSeconds(1.9), $"the host didn't exit on EOF ({watch.Elapsed})");
                Assert.True(c.HasExited);
            }
        }
    }
}
