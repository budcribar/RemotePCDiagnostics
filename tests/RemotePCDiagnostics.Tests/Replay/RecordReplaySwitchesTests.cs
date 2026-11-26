using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Recording;

namespace RemotePCDiagnostics.Tests.Replay;

/// <summary>The app's RPCD_LOG and RPCD_REPLAY switches, on the app's own kind of registrations.</summary>
public sealed class RecordReplaySwitchesTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "rpcd-switch-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch (DirectoryNotFoundException) { }
    }

    public static TheoryData<string> Recordings => RecordingLibrary.Names();

    private static WmiRow Row(params (string Name, string Value)[] values) =>
        new(values.ToDictionary(v => v.Name, v => JsonSerializer.SerializeToElement(v.Value)));

    private sealed class FakePc : IWmiSource, IRegistrySource
    {
        public int Queries;
        public Task<WmiQueryResult> QueryAsync(string ns, string wql, CancellationToken ct = default)
        {
            Interlocked.Increment(ref Queries);
            if (wql.Contains("Win32_ComputerSystem ", StringComparison.Ordinal) || wql.EndsWith("Win32_ComputerSystem", StringComparison.Ordinal))
                return Task.FromResult(new WmiQueryResult(ns, wql, [Row(("Manufacturer", "LENOVO"), ("Model", "82R4"), ("SystemSKUNumber", "LENOVO_MT_82R4_BU_idea_FM_IdeaPad 1 15ALC7"))]));
            if (wql.Contains("Win32_Battery", StringComparison.Ordinal))
                return Task.FromResult(WmiQueryResult.Failed(ns, wql, "InvalidClass (0x80041010): Invalid class"));
            return Task.FromResult(new WmiQueryResult(ns, wql, [Row(("Name", "row of " + wql))]));
        }

        public Task<WmiQueryResult> ReadAsync(RegistryRead read, CancellationToken ct = default) =>
            Task.FromResult(new WmiQueryResult("registry", read.ToString(), [Row(("Value", "1"))]));
    }

    private static ServiceCollection AppLike(FakePc pc, IProcessLauncher launcher)
    {
        var services = new ServiceCollection();
        services.AddSingleton<IWmiSource>(_ => new NotingWmiSource(pc));
        services.AddSingleton<IRegistrySource>(pc);
        services.AddSingleton(_ => new SystemCommandRunner(launcher, isProcessElevated: () => false));
        return services;
    }

    private static ScriptedLauncher Tools() => new((file, args) => new ProcessResult(0, "out of " + Path.GetFileName(file) + " " + string.Join(" ", args), ""));

    [Fact]
    public async Task Log_records_what_the_checks_read_and_saves_a_recording()
    {
        var pc = new FakePc();
        var services = AppLike(pc, Tools());
        using var live = new LiveRecording(_root, "1.2.3", saveEvery: TimeSpan.Zero);
        RecordReplaySwitches.UseRecorder(services, live);
        using var sp = services.BuildServiceProvider();

        var wmi = sp.GetRequiredService<IWmiSource>();
        var cpu = await wmi.QueryAsync(@"root\cimv2", "SELECT Name FROM Win32_Processor");
        var battery = await wmi.QueryAsync(@"root\cimv2", "SELECT * FROM Win32_Battery");
        var tool = await sp.GetRequiredService<SystemCommandRunner>().Launcher.RunAsync("powercfg.exe", ["/a"], TimeSpan.FromSeconds(5), default);

        Assert.Equal("row of SELECT Name FROM Win32_Processor", cpu.Rows![0].Str("Name"));
        Assert.False(battery.Success);
        Assert.Equal("out of powercfg.exe /a", tool.StdOut);

        var folder = live.Save();
        Assert.NotNull(folder);
        Assert.StartsWith("LENOVO_MT_82R4_BU_idea_FM_IdeaPad_1_15ALC7-", Path.GetFileName(folder));
        Assert.True(File.Exists(Path.Combine(folder!, "scrub-report.txt")));
        var saved = MachineRecording.Load(folder!);
        Assert.Equal("1.2.3", saved.Machine.AppVersion);
        Assert.Contains("RPCD_LOG", saved.Machine.Notes);
        Assert.Equal(3, saved.Calls.Count); // describing the PC is not part of the recording
        Assert.Null(live.Save()); // nothing new since

        // The same answers come back when that folder is replayed.
        var replayed = new ServiceCollection();
        replayed.AddSingleton<IWmiSource>(_ => throw new InvalidOperationException("this PC must not be read"));
        replayed.AddSingleton(_ => new SystemCommandRunner(new SystemProcessLauncher(), isProcessElevated: () => false));
        RecordReplaySwitches.UseReplay(replayed, new RecordingReplay(saved));
        using var rp = replayed.BuildServiceProvider();
        var again = rp.GetRequiredService<IWmiSource>();
        Assert.IsType<NotingWmiSource>(again);
        Assert.Equal("row of SELECT Name FROM Win32_Processor", (await again.QueryAsync(@"root\cimv2", "SELECT Name FROM Win32_Processor")).Rows![0].Str("Name"));
        Assert.Equal(battery.Error, (await again.QueryAsync(@"root\cimv2", "SELECT * FROM Win32_Battery")).Error);
        var runner = rp.GetRequiredService<SystemCommandRunner>();
        Assert.True(runner.IsScripted);
        Assert.Equal("out of powercfg.exe /a", (await runner.Launcher.RunAsync("powercfg.exe", ["/a"], TimeSpan.FromSeconds(5), default)).StdOut);
    }

    [Fact]
    public void Log_keeps_the_real_tools_unscripted()
    {
        var services = AppLike(new FakePc(), new SystemProcessLauncher());
        using var live = new LiveRecording(_root, "1", saveEvery: TimeSpan.Zero);
        RecordReplaySwitches.UseRecorder(services, live);
        using var sp = services.BuildServiceProvider();
        var runner = sp.GetRequiredService<SystemCommandRunner>();
        Assert.IsType<RecordingProcessLauncher>(runner.Launcher);
        Assert.False(runner.IsScripted); // checks that skip work under test still do it while recording
    }

    [Fact]
    public void Log_leaves_sources_the_app_does_not_have_alone()
    {
        var services = AppLike(new FakePc(), Tools());
        using var live = new LiveRecording(_root, "1", saveEvery: TimeSpan.Zero);
        RecordReplaySwitches.UseRecorder(services, live);
        Assert.DoesNotContain(services, d => d.ServiceType == typeof(IPackageSource));
        Assert.Single(services, d => d.ServiceType == typeof(IWmiSource));
        Assert.Null(live.Save()); // nothing read, nothing saved
        Assert.False(Directory.Exists(_root));
    }

    [Fact]
    public void Switches_off_change_nothing()
    {
        Assert.Null(Environment.GetEnvironmentVariable(RecordReplaySwitches.ReplayVariable));
        Assert.Null(Environment.GetEnvironmentVariable(RecordReplaySwitches.LogVariable));
        var services = AppLike(new FakePc(), Tools());
        var before = services.ToList();
        Assert.Null(RecordReplaySwitches.Apply(services, allowReplay: true, "1"));
        Assert.Equal(before, services);
    }

    /// <summary>Every WMI answer in a real recording comes back through the app's replayed registrations, and nothing reads this PC.</summary>
    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task Replay_answers_every_recorded_wmi_query(string name)
    {
        var recording = RecordingLibrary.Load(name);
        var pc = new FakePc();
        var services = AppLike(pc, Tools());
        var replay = new RecordingReplay(recording);
        RecordReplaySwitches.UseReplay(services, replay);
        using var sp = services.BuildServiceProvider();
        var wmi = sp.GetRequiredService<IWmiSource>();
        var calls = recording.Calls.Where(c => c.Kind == RecordedCall.WmiKind).Take(200).ToList();
        foreach (var c in calls)
        {
            var r = await wmi.QueryAsync(c.Namespace!, c.Query!);
            Assert.Equal(c.Error, r.Error);
        }
        Assert.Empty(replay.Misses);
        Assert.Equal(0, pc.Queries);
    }
}
