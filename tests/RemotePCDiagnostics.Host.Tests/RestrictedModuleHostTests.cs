using System.IO;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
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
            Enumerable.Range(0, 4).Select(i => Task.Run(() => launcher.StartRaw(Module(i % 2 == 0 ? "EventLog" : "Network")))));
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            foreach (var c in connections)
                Assert.Equal("ready", ModuleHostMessage.Parse((await c.ReadLineAsync(cts.Token))!)?.Type);

            foreach (var c in connections)
            {
                // Dispose closes stdin and waits 2 s before killing: a host that kept another's pipe end open wouldn't see EOF in time.
                var watch = Stopwatch.StartNew();
                c.Dispose();
                Assert.True(watch.Elapsed < TimeSpan.FromSeconds(1.9), $"the host didn't exit on EOF ({watch.Elapsed})");
                Assert.True(c.HasExited);
            }
        }
        finally
        {
            foreach (var c in connections)
            {
                try { c.Dispose(); } catch { }
            }
        }
    }

    [Fact]
    public async Task Bundled_modules_share_one_host_answer_concurrently_and_exit_when_the_last_closes()
    {
        var launcher = new RestrictedModuleHostLauncher(directory: AppContext.BaseDirectory);
        var slugs = new[] { "EventLog", "Network", "Programs", "BatteryPower" };
        var connections = await Task.WhenAll(slugs.Select(s => Task.Run(() => launcher.Start(Module(s)))));
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await Task.WhenAll(connections.Select(async c =>
            {
                await c.WriteLineAsync(new ModuleHostMessage { Type = "availability" }.ToLine(), cts.Token);
                var reply = ModuleHostMessage.Parse((await c.ReadLineAsync(cts.Token))!);
                Assert.NotNull(reply);
                Assert.Equal("availability", reply!.Type);
            }));

            for (var i = 0; i < connections.Length - 1; i++)
            {
                connections[i].Dispose();
                Assert.False(connections[^1].HasExited);
            }

            var watch = Stopwatch.StartNew();
            connections[^1].Dispose();
            Assert.True(watch.Elapsed < TimeSpan.FromSeconds(1.9), $"the shared host didn't exit on EOF ({watch.Elapsed})");
            Assert.True(connections[^1].HasExited);
        }
        finally
        {
            foreach (var c in connections)
            {
                try { c.Dispose(); } catch { }
            }
        }
    }
}

/// <summary>An unsigned module's host token (category WindowsReadOnly): no INTERACTIVE or Event Log Readers, so it can't read the event logs
/// itself; a module that ships with the app keeps them.</summary>
[Trait("Category", "WindowsReadOnly")]
public class UnsignedModuleTokenTests
{
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out SafeAccessTokenHandle token);

    private static bool HasGroup(SafeAccessTokenHandle token, string sid)
    {
        using var id = new System.Security.Principal.WindowsIdentity(token.DangerousGetHandle());
        // Groups leaves out deny-only ones.
        return id.Groups!.Any(g => g.Value == sid);
    }

    private static bool CanReadApplicationLog(SafeAccessTokenHandle token) =>
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

    [Fact]
    public void An_unsigned_ui_host_process_starts_without_INTERACTIVE_Event_Log_Readers_or_Administrators()
    {
        var exe = Path.Combine(AppContext.BaseDirectory, ProcessModuleHostLauncher.HostName + ".exe");
        var (process, input) = RestrictedModuleHostLauncher.StartRestrictedGuiWithInput(
            exe, "--shared", AppContext.BaseDirectory, unsigned: true);
        try
        {
            const uint TOKEN_DUPLICATE = 0x0002, TOKEN_QUERY = 0x0008;
            if (!OpenProcessToken(process.Handle, TOKEN_QUERY | TOKEN_DUPLICATE, out var childToken))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            using (childToken)
            {
                foreach (var sid in RestrictedModuleHostLauncher.UnsignedDenyOnly)
                    Assert.False(HasGroup(childToken, sid), sid);
                Assert.False(HasGroup(childToken, "S-1-5-32-544"));
            }
        }
        finally
        {
            try { input.Dispose(); } catch { }
            try { if (!process.WaitForExit(2000)) process.Kill(entireProcessTree: true); } catch { }
            try { process.Dispose(); } catch { }
        }
    }
}
