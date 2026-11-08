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

/// <summary>An unsigned module's host token (category WindowsReadOnly): no INTERACTIVE or Event Log Readers, so it can't read the event logs
/// itself; a module that ships with the app keeps them.</summary>
[Trait("Category", "WindowsReadOnly")]
public class UnsignedModuleTokenTests
{
    private static bool HasGroup(Microsoft.Win32.SafeHandles.SafeAccessTokenHandle token, string sid)
    {
        using var id = new System.Security.Principal.WindowsIdentity(token.DangerousGetHandle());
        // Groups leaves out deny-only ones.
        return id.Groups!.Any(g => g.Value == sid);
    }

    private static bool CanReadApplicationLog(Microsoft.Win32.SafeHandles.SafeAccessTokenHandle token) =>
        System.Security.Principal.WindowsIdentity.RunImpersonated(token, () =>
        {
            try
            {
                using var reader = new System.Diagnostics.Eventing.Reader.EventLogReader(
                    new System.Diagnostics.Eventing.Reader.EventLogQuery("Application", System.Diagnostics.Eventing.Reader.PathType.LogName) { ReverseDirection = true });
                using var e = reader.ReadEvent();
                return true;
            }
            catch (UnauthorizedAccessException) { return false; }
            catch (System.Diagnostics.Eventing.Reader.EventLogException) { return false; }
        });

    [Fact]
    public void The_unsigned_token_has_INTERACTIVE_and_Event_Log_Readers_deny_only()
    {
        using var unsigned = RestrictedModuleHostLauncher.CreateToken(unsigned: true);
        foreach (var sid in RestrictedModuleHostLauncher.UnsignedDenyOnly) Assert.False(HasGroup(unsigned, sid), sid);
        Assert.False(HasGroup(unsigned, "S-1-5-32-544")); // Administrators, as for every module host
    }

    [Fact]
    public void An_unsigned_module_cannot_read_the_event_log_itself_a_bundled_one_still_can()
    {
        using var bundled = RestrictedModuleHostLauncher.CreateToken(unsigned: false);
        // Only meaningful where this session is interactive (the Application log grants reading to INTERACTIVE).
        if (!HasGroup(bundled, "S-1-5-4")) return;
        Assert.True(CanReadApplicationLog(bundled));
        using var unsigned = RestrictedModuleHostLauncher.CreateToken(unsigned: true);
        Assert.False(CanReadApplicationLog(unsigned));
    }
}
