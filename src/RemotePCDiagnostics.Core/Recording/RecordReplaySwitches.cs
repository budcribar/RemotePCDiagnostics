using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.DataSources;

namespace RemotePCDiagnostics.Core.Recording;

/// <summary>
/// The app's record and replay switches (docs/record-replay.md):
/// <list type="bullet">
/// <item><c>RPCD_REPLAY=&lt;recording folder&gt;</c> (Debug builds only): the checks read the recording instead of this PC, so a developer can
/// see another PC's results in the real app.</item>
/// <item><c>RPCD_LOG=&lt;folder&gt;</c>: the app records what the checks read from this PC, scrubbed, into a recording folder under it (as the
/// recorder tool saves them), so a problem a person sees can be replayed.</item>
/// </list>
/// Both act on what the checks read: WMI, the registry, Store packages, Security Center's antivirus list, the audio state and the tools the
/// checks run. Fixes are not replayed or recorded.
/// </summary>
public static class RecordReplaySwitches
{
    public const string ReplayVariable = "RPCD_REPLAY";
    public const string LogVariable = "RPCD_LOG";

    /// <summary>Applies the switches the environment sets, after the app's own registrations. Returns what to tell the log, or null.</summary>
    public static string? Apply(IServiceCollection services, bool allowReplay, string appVersion)
    {
        var replay = allowReplay ? Environment.GetEnvironmentVariable(ReplayVariable) : null;
        var log = Environment.GetEnvironmentVariable(LogVariable);
        if (!string.IsNullOrWhiteSpace(replay))
        {
            if (!MachineRecording.IsRecording(replay)) return $"{ReplayVariable}: {replay} is not a recording folder (no {MachineRecording.CallsFile}); reading this PC.";
            var recording = MachineRecording.Load(replay);
            UseReplay(services, new RecordingReplay(recording));
            return $"{ReplayVariable}: checks read the recording of {recording.Machine.ProductId} ({recording.CapturedAt:yyyy-MM-dd HH:mm}) in {replay}. {LogVariable} is ignored.";
        }
        if (!string.IsNullOrWhiteSpace(log))
        {
            UseRecorder(services, new LiveRecording(log, appVersion));
            return $"{LogVariable}: recording what the checks read into {log}.";
        }
        return null;
    }

    /// <summary>The checks read <paramref name="replay"/> instead of this PC.</summary>
    public static void UseReplay(IServiceCollection services, RecordingReplay replay)
    {
        services.AddSingleton(replay);
        Replace<IWmiSource>(services, _ => new NotingWmiSource(replay.Wmi));
        Replace(services, _ => replay.Registry);
        Replace(services, _ => replay.Packages);
        Replace(services, _ => replay.AntivirusProducts);
        Replace(services, _ => replay.Audio);
        Replace(services, _ => replay.DiskScans);
        Replace(services, _ => replay.SelfTest);
        Replace(services, _ => replay.GpuMemorySource);
        Decorate<SystemCommandRunner>(services, (_, c) =>
            new SystemCommandRunner(replay.Launcher, c.Log, c.Timeout, c.ElevatedBridge, c.IsProcessElevatedCheck, c.NativeOps));
    }

    /// <summary>Everything the checks read from this PC is also noted in <paramref name="recording"/>, which saves itself.</summary>
    public static void UseRecorder(IServiceCollection services, LiveRecording recording)
    {
        services.AddSingleton(recording);
        var calls = recording.Calls;
        Decorate<IWmiSource>(services, (_, w) => { recording.DescribeWith(w); return new RecordingWmiSource(w, calls); });
        Decorate<IRegistrySource>(services, (_, r) => new RecordingRegistrySource(r, calls));
        Decorate<IPackageSource>(services, (_, p) => new RecordingPackageSource(p, calls));
        Decorate<Security.IAntivirusProductSource>(services, (_, a) => new RecordingAntivirusProductSource(a, calls));
        Decorate<Audio.IAudioStateSource>(services, (_, a) => new RecordingAudioStateSource(a, calls));
        Decorate<Storage.IDiskScanSource>(services, (_, d) => new RecordingDiskScanSource(d, calls));
        Decorate<Storage.IDriveSelfTestSource>(services, (_, s) => new RecordingDriveSelfTestSource(s, calls));
        Decorate<GpuMemory.IGpuMemorySource>(services, (_, g) => new RecordingGpuMemorySource(g, calls));
        // The checks behave as they do without the recorder (scripted: false): it only notes what the real tools answer.
        Decorate<SystemCommandRunner>(services, (_, c) => new SystemCommandRunner(new RecordingProcessLauncher(c.Launcher, calls), c.Log, c.Timeout,
            c.ElevatedBridge, c.IsProcessElevatedCheck, c.NativeOps, scripted: c.IsScripted));
    }

    /// <summary>Replaces the registration of <typeparamref name="T"/> (all of them) with one singleton.</summary>
    public static void Replace<T>(IServiceCollection services, Func<IServiceProvider, T> create) where T : class
    {
        services.RemoveAll<T>();
        services.AddSingleton(create);
    }

    /// <summary>Wraps the last registration of <typeparamref name="T"/>; with none, nothing changes (that source isn't in this app).</summary>
    public static void Decorate<T>(IServiceCollection services, Func<IServiceProvider, T, T> wrap) where T : class
    {
        var last = services.LastOrDefault(d => d.ServiceType == typeof(T) && !d.IsKeyedService);
        if (last is null) return;
        services.RemoveAll<T>();
        services.AddSingleton(sp => wrap(sp, (T)Create(last, sp)));
    }

    private static object Create(ServiceDescriptor d, IServiceProvider sp) =>
        d.ImplementationInstance ?? d.ImplementationFactory?.Invoke(sp) ?? ActivatorUtilities.CreateInstance(sp, d.ImplementationType!);

    private static void RemoveAll<T>(this IServiceCollection services)
    {
        for (var i = services.Count - 1; i >= 0; i--)
            if (services[i].ServiceType == typeof(T) && !services[i].IsKeyedService) services.RemoveAt(i);
    }
}

/// <summary>
/// The app's live recording (RPCD_LOG): the answers the checks got, saved scrubbed as a recording folder
/// (&lt;product id&gt;-&lt;start time&gt; under the chosen folder) every few seconds while new answers arrive, and when the app exits.
/// </summary>
public sealed class LiveRecording : IDisposable
{
    private readonly string _root;
    private readonly string _appVersion;
    private readonly DateTimeOffset _started;
    private readonly Func<DateTimeOffset> _now;
    private readonly object _gate = new();
    private readonly Timer? _timer;
    private IWmiSource? _describe;
    private RecordedMachine? _machine;
    private int _saved = -1;

    public LiveRecording(string root, string appVersion, TimeSpan? saveEvery = null, Func<DateTimeOffset>? now = null)
    {
        _root = root;
        _appVersion = appVersion;
        _now = now ?? (() => DateTimeOffset.Now);
        _started = _now();
        var every = saveEvery ?? TimeSpan.FromSeconds(10);
        if (every > TimeSpan.Zero)
        {
            _timer = new Timer(_ => TrySave(), null, every, every);
            AppDomain.CurrentDomain.ProcessExit += OnExit;
        }
    }

    public CallRecorder Calls { get; } = new();

    /// <summary>The folder the last save wrote, or null before the first.</summary>
    public string? Folder { get; private set; }

    /// <summary>The WMI source (not recorded) the machine is described with when first saved.</summary>
    public void DescribeWith(IWmiSource wmi) => _describe ??= wmi;

    /// <summary>Saves when answers arrived since the last save. Returns the folder written, or null when nothing was new.</summary>
    public string? Save(CancellationToken ct = default)
    {
        lock (_gate)
        {
            var calls = Calls.Snapshot();
            if (calls.Count == 0 || calls.Count == _saved) return null;
            _machine ??= Describe(ct);
            var scrubber = new RecordingScrubber(Environment.MachineName, MachineDescription.UserNames());
            var recording = scrubber.Scrub(new MachineRecording { Machine = _machine, CapturedAt = _started, Calls = calls });
            var folder = Path.Combine(_root, MachineDescription.Safe(_machine.ProductId) + "-" + _started.ToString("yyyyMMdd-HHmm"));
            recording.Save(folder);
            File.WriteAllLines(Path.Combine(folder, "scrub-report.txt"),
                ["Replaced before saving (placeholder kind: count):", .. scrubber.Counts.Select(c => $"  {c.Key}: {c.Value}")]);
            _saved = calls.Count;
            return Folder = folder;
        }
    }

    private RecordedMachine Describe(CancellationToken ct)
    {
        var note = $"Recorded by the app ({RecordReplaySwitches.LogVariable}) from {_started:yyyy-MM-dd HH:mm} to {_now():HH:mm}.";
        if (_describe is null) return new RecordedMachine { ProductId = "unknown", AppVersion = _appVersion, Notes = note };
        try
        {
            // The app never runs as administrator; its WMI answers come from the Agent, which does.
            var m = MachineDescription.DescribeAsync(_describe, _appVersion, elevated: false, ct).GetAwaiter().GetResult();
            return m with { Notes = note };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new RecordedMachine { ProductId = "unknown", AppVersion = _appVersion, Notes = note + " The PC couldn't be described: " + ex.Message };
        }
    }

    private void TrySave()
    {
        try { Save(); } catch (Exception) { /* a recording that can't be saved must never break the app; the next tick tries again */ }
    }

    private void OnExit(object? sender, EventArgs e) => TrySave();

    public void Dispose()
    {
        _timer?.Dispose();
        AppDomain.CurrentDomain.ProcessExit -= OnExit;
        TrySave();
    }
}
