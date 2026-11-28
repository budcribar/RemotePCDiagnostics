using System.Text.Json;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Core.Recording;

/// <summary>Collects every answer the wrapped sources give, in order. Thread safe.</summary>
public sealed class CallRecorder
{
    private readonly List<RecordedCall> _calls = [];

    public void Add(RecordedCall call) { lock (_calls) _calls.Add(call); }

    public List<RecordedCall> Snapshot() { lock (_calls) return [.. _calls]; }
}

/// <summary>Passes each query to the real WMI source and records the answer.</summary>
public sealed class RecordingWmiSource(IWmiSource inner, CallRecorder recorder) : IWmiSource
{
    public async Task<WmiQueryResult> QueryAsync(string wmiNamespace, string wql, CancellationToken ct = default)
    {
        var r = await inner.QueryAsync(wmiNamespace, wql, ct).ConfigureAwait(false);
        recorder.Add(RecordedCall.FromWmi(r));
        return r;
    }
}

/// <summary>Passes each registry read to the real source and records the answer.</summary>
public sealed class RecordingPackageSource(IPackageSource inner, CallRecorder recorder) : IPackageSource
{
    public async Task<WmiQueryResult> ReadPackagesAsync(CancellationToken ct = default)
    {
        var r = await inner.ReadPackagesAsync(ct).ConfigureAwait(false);
        recorder.Add(RecordedCall.FromPackages(r));
        return r;
    }
}

/// <summary>Passes each Windows Security Center antivirus read to the real source and records the answer.</summary>
public sealed class RecordingAntivirusProductSource(Security.IAntivirusProductSource inner, CallRecorder recorder) : Security.IAntivirusProductSource
{
    public async Task<Security.AntivirusInventoryResult> ReadAsync(CancellationToken ct = default)
    {
        var r = await inner.ReadAsync(ct).ConfigureAwait(false);
        recorder.Add(RecordedCall.FromAntivirus(r));
        return r;
    }
}

/// <summary>Passes each of the Agent's alert readings to the real PC and records the answer.</summary>
public sealed class RecordingAlertReadings(Alerts.IAlertReadings inner, CallRecorder recorder) : Alerts.IAlertReadings
{
    public async Task<WmiQueryResult> ReadAsync(string reading, long afterRecordId, TimeSpan lookBack, CancellationToken ct)
    {
        var r = await inner.ReadAsync(reading, afterRecordId, lookBack, ct).ConfigureAwait(false);
        recorder.Add(RecordedCall.FromAlerts(r));
        return r;
    }
}

/// <summary>Passes each disk surface scan request to the Agent and records the answer.</summary>
public sealed class RecordingDiskScanSource(Storage.IDiskScanSource inner, CallRecorder recorder) : Storage.IDiskScanSource
{
    public async Task<Storage.DiskScanAnswer> SendAsync(Storage.DiskScanRequest request, CancellationToken ct)
    {
        var a = await inner.SendAsync(request, ct).ConfigureAwait(false);
        recorder.Add(RecordedCall.FromDiskScan(request, a));
        return a;
    }
}

/// <summary>Passes each cooling test sample and thermal mode request on and records the answer.</summary>
public sealed class RecordingCoolingSource(Cooling.ICoolingSource inner, CallRecorder recorder) : Cooling.ICoolingSource
{
    public async Task<Cooling.CoolingReading> SampleAsync(CancellationToken ct)
    {
        var r = await inner.SampleAsync(ct).ConfigureAwait(false);
        recorder.Add(RecordedCall.FromCoolingSample(r));
        return r;
    }

    public async Task<Cooling.CoolingModesReply> ModesAsync(IReadOnlyList<string> args, CancellationToken ct)
    {
        var r = await inner.ModesAsync(args, ct).ConfigureAwait(false);
        recorder.Add(RecordedCall.FromCoolingModes(args, r));
        return r;
    }
}

/// <summary>Passes each Core Audio read to the real source and records the answer.</summary>
public sealed class RecordingAudioStateSource(Audio.IAudioStateSource inner, CallRecorder recorder) : Audio.IAudioStateSource
{
    public async Task<Audio.AudioState> ReadAsync(CancellationToken ct = default)
    {
        var r = await inner.ReadAsync(ct).ConfigureAwait(false);
        recorder.Add(RecordedCall.FromAudio(r));
        return r;
    }
}

/// <summary>Passes each Wi-Fi radio read to the real source and records the answer with network names scrubbed.</summary>
public sealed class RecordingWifiRadioSource(Areas.IWifiRadioSource inner, CallRecorder recorder) : Areas.IWifiRadioSource
{
    public async Task<Areas.WifiRadioReading> ReadAsync(bool scan, CancellationToken ct)
    {
        var r = await inner.ReadAsync(scan, ct).ConfigureAwait(false);
        recorder.Add(RecordedCall.FromWifi(r));
        return r;
    }
}

public sealed class RecordingRegistrySource(IRegistrySource inner, CallRecorder recorder) : IRegistrySource
{
    public async Task<WmiQueryResult> ReadAsync(RegistryRead read, CancellationToken ct = default)
    {
        var r = await inner.ReadAsync(read, ct).ConfigureAwait(false);
        recorder.Add(RecordedCall.FromRegistry(r));
        return r;
    }
}

/// <summary>Passes each drive self-test request to the Agent and records the answer.</summary>
public sealed class RecordingDriveSelfTestSource(Storage.IDriveSelfTestSource inner, CallRecorder recorder) : Storage.IDriveSelfTestSource
{
    public async Task<Storage.SelfTestReply> RunAsync(IReadOnlyList<string> args, CancellationToken ct)
    {
        var r = await inner.RunAsync(args, ct).ConfigureAwait(false);
        recorder.Add(RecordedCall.FromSelfTest(args, r));
        return r;
    }
}

/// <summary>Passes each boot memory test request to the Agent and records the answer.</summary>
public sealed class RecordingMemoryDiagnosticSource(Stress.IMemoryDiagnosticSource inner, CallRecorder recorder) : Stress.IMemoryDiagnosticSource
{
    public async Task<Stress.MemoryDiagnosticReply> RunAsync(IReadOnlyList<string> args, CancellationToken ct)
    {
        var r = await inner.RunAsync(args, ct).ConfigureAwait(false);
        recorder.Add(RecordedCall.FromMemoryDiagnostic(args, r));
        return r;
    }
}

/// <summary>
/// Passes the graphics memory test to the real chips and records what they answered: the adapter list, each allocation, and every
/// dispatch that found wrong words or lost the device, keyed by its block and its number on that block. A run makes thousands of clean
/// dispatches; they aren't kept, and replay answers a dispatch with nothing recorded as clean.
/// </summary>
public sealed class RecordingGpuMemorySource(GpuMemory.IGpuMemorySource inner, CallRecorder recorder) : GpuMemory.IGpuMemorySource
{
    public IReadOnlyList<GpuMemory.GpuMemoryAdapter> ListAdapters()
    {
        var list = inner.ListAdapters();
        recorder.Add(RecordedCall.FromGpuMemory(RecordingReplay.GpuMemoryList, JsonSerializer.Serialize(list)));
        return list;
    }

    public GpuMemory.IGpuMemoryDevice Open(string adapterId)
    {
        try { return new Device(inner.Open(adapterId), recorder); }
        catch (Exception ex)
        {
            recorder.Add(RecordedCall.FromGpuMemory(RecordingReplay.GpuMemoryQuery(adapterId, "open"), null, ex.Message));
            throw;
        }
    }

    private sealed class Device(GpuMemory.IGpuMemoryDevice inner, CallRecorder recorder) : GpuMemory.IGpuMemoryDevice
    {
        private readonly Dictionary<int, int> _runs = [];
        public GpuMemory.GpuMemoryAdapter Adapter => inner.Adapter;
        public IReadOnlyList<long> Blocks => inner.Blocks;

        public bool TryAllocateBlock(long bytes)
        {
            var ok = inner.TryAllocateBlock(bytes);
            recorder.Add(RecordedCall.FromGpuMemory(RecordingReplay.GpuMemoryQuery(Adapter.Id, "allocate"), ok ? "true" : "false"));
            return ok;
        }

        public GpuMemory.GpuBlockResult Run(int block, GpuMemory.GpuMemoryOp op, GpuMemory.GpuMemoryPattern pattern, uint seed, bool inverted, uint baseWord)
        {
            var n = _runs[block] = _runs.GetValueOrDefault(block) + 1;
            var key = RecordingReplay.GpuMemoryRun(Adapter.Id, block, n);
            GpuMemory.GpuBlockResult r;
            try { r = inner.Run(block, op, pattern, seed, inverted, baseWord); }
            catch (Stress.GpuDeviceLostException ex)
            {
                recorder.Add(RecordedCall.FromGpuMemory(key, null, RecordingReplay.GpuLostPrefix + ex.Message));
                throw;
            }
            if (r.Errors > 0) recorder.Add(RecordedCall.FromGpuMemory(key, JsonSerializer.Serialize(r)));
            return r;
        }

        public void Dispose() => inner.Dispose();
    }
}

/// <summary>Records a report file under a fixed name (its real path changes every run).</summary>
public sealed class FileRecorder(CallRecorder recorder)
{
    public async Task<string?> ReadAsync(string name, Func<Task<string?>> read)
    {
        var text = await read().ConfigureAwait(false);
        recorder.Add(RecordedCall.FromFile(name, text));
        return text;
    }
}

/// <summary>Passes each program run (osquery, PowerShell, powercfg) to the real launcher and records the output.</summary>
public sealed class RecordingProcessLauncher(IProcessLauncher inner, CallRecorder recorder) : IProcessLauncher
{
    public async Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var r = await inner.RunAsync(fileName, arguments, timeout, cancellationToken).ConfigureAwait(false);
        recorder.Add(RecordedCall.FromProcess(fileName, arguments, r));
        return r;
    }
}

/// <summary>
/// Answers from a recording. A question the recording doesn't hold gets a failed answer and is listed in <see cref="Misses"/>, so a test
/// can fail on it (a check asked something new: record the PC again) or, for error-path tests, accept it.
/// </summary>
public sealed class RecordingReplay
{
    private readonly Dictionary<string, Queue<RecordedCall>> _byKey = new(StringComparer.Ordinal);
    private readonly Dictionary<string, RecordedCall> _last = new(StringComparer.Ordinal);
    private readonly List<string> _misses = [];
    private readonly HashSet<string> _asked = new(StringComparer.Ordinal);

    public RecordingReplay(MachineRecording recording) : this(recording.Calls) { }

    public RecordingReplay(IEnumerable<RecordedCall> calls)
    {
        foreach (var c in calls)
        {
            var key = Key(c);
            if (!_byKey.TryGetValue(key, out var q)) _byKey[key] = q = new();
            q.Enqueue(c);
        }
    }

    /// <summary>Questions asked that the recording doesn't hold.</summary>
    public IReadOnlyList<string> Misses { get { lock (_misses) return [.. _misses]; } }

    /// <summary>The <see cref="Key"/> of every question asked, held or not.</summary>
    public IReadOnlyCollection<string> Asked { get { lock (_byKey) return [.. _asked]; } }

    public IWmiSource Wmi => new ReplayWmi(this);
    public IRegistrySource Registry => new ReplayRegistry(this);
    public IPackageSource Packages => new ReplayPackages(this);
    public Security.IAntivirusProductSource AntivirusProducts => new ReplayAntivirusProducts(this);
    public Audio.IAudioStateSource Audio => new ReplayAudio(this);
    public Areas.IWifiRadioSource Wifi => new ReplayWifi(this);
    public IProcessLauncher Launcher => new ReplayLauncher(this);
    public Alerts.IAlertReadings Alerts => new ReplayAlerts(this);
    public Stress.IMemoryDiagnosticSource MemoryDiagnostic => new ReplayMemoryDiagnostic(this);
    /// <summary>The surface scan's recorded answers: a repeated status question gets the next one, then the last again.</summary>
    public Storage.IDiskScanSource DiskScans => new ReplayDiskScans(this);
    public Storage.IDriveSelfTestSource SelfTest => new ReplaySelfTest(this);
    public GpuMemory.IGpuMemorySource GpuMemorySource => new ReplayGpuMemory(this);
    /// <summary>The cooling test's recorded samples, in order (then the last again), and its thermal mode answers.</summary>
    public Cooling.ICoolingSource Cooling => new ReplayCooling(this);
    public VideoPlayback.IVideoPlaybackSource VideoPlayback => new ReplayVideoPlaybackSource(this);

    /// <summary>The next recorded answer to <paramref name="key"/> (see <see cref="Answer"/>), for replay sources kept in their own files.</summary>
    internal RecordedCall? AnswerFor(string key, string description) => Answer(key, description);

    /// <summary>The next recorded answer to <paramref name="key"/> without taking it, or null (not counted as a miss).</summary>
    internal RecordedCall? PeekFor(string key)
    {
        lock (_byKey)
        {
            if (_byKey.TryGetValue(key, out var q) && q.Count > 0) return q.Peek();
            return _last.GetValueOrDefault(key);
        }
    }

    /// <summary>The report file recorded under <paramref name="name"/>; null when it wasn't made or isn't in the recording.</summary>
    public string? FileText(string name) => Answer(FileKey(name), $"file {name}") is { Error: null } c ? c.StdOut : null;

    /// <summary>The next recorded answer to <paramref name="key"/> without taking it, or null (not counted as a miss).</summary>
    private RecordedCall? Peek(string key)
    {
        lock (_byKey) return _byKey.TryGetValue(key, out var q) && q.Count > 0 ? q.Peek() : null;
    }

    /// <summary>The same question asked twice gets the recorded answers in order, and the last one again after that.</summary>
    private RecordedCall? Answer(string key, string description)
    {
        lock (_byKey)
        {
            _asked.Add(key);
            if (_byKey.TryGetValue(key, out var q) && q.Count > 0) return _last[key] = q.Dequeue();
            if (_last.TryGetValue(key, out var last)) return last;
        }
        lock (_misses) _misses.Add(description);
        return null;
    }

    public static string Key(RecordedCall c) => c.Kind switch
    {
        RecordedCall.WmiKind => WmiKey(c.Namespace ?? "", c.Query ?? ""),
        RecordedCall.RegistryKind => RegistryKey(c.Namespace ?? "", c.Query ?? ""),
        RecordedCall.PackagesKind => PackagesKey,
        RecordedCall.AntivirusKind => AntivirusKey,
        RecordedCall.AudioKind => AudioKey,
        RecordedCall.WifiKind => WifiKey,
        RecordedCall.FileKind => FileKey(c.File ?? ""),
        RecordedCall.AlertsKind => AlertsKey(c.Query ?? ""),
        RecordedCall.MemoryDiagnosticKind => MemoryDiagnosticKey(c.Query ?? ""),
        RecordedCall.DiskScanKind => DiskScanKey(c.Query ?? ""),
        RecordedCall.SelfTestKind => SelfTestKey(c.Query ?? ""),
        RecordedCall.GpuMemoryKind => GpuMemoryKey(c.Query ?? ""),
        RecordedCall.CoolingKind => CoolingKey(c.Query ?? ""),
        RecordedCall.VideoKind => VideoKey(c.Query ?? ""),
        _ => ProcessKey(c.File ?? "", c.Args ?? []),
    };

    public const string PackagesKey = "packages";
    public const string AntivirusKey = "antivirus";
    public const string AudioKey = "audio";
    public const string WifiKey = "wifi";
    public static string FileKey(string name) => "file\n" + name;
    public static string AlertsKey(string reading) => "alerts\n" + reading;
    public static string MemoryDiagnosticKey(string request) => "memdiag\n" + request;
    public static string DiskScanKey(string request) => "diskscan\n" + request;
    public static string SelfTestKey(string request) => "selftest\n" + request;
    public static string GpuMemoryKey(string query) => "gpumemory\n" + query;
    public const string GpuMemoryList = "list";
    public const string GpuLostPrefix = "lost: ";
    public static string GpuMemoryQuery(string adapterId, string what) => adapterId + "\n" + what;
    public static string GpuMemoryRun(string adapterId, int block, int n) => GpuMemoryQuery(adapterId, "run") + "\n" + block.ToString(System.Globalization.CultureInfo.InvariantCulture)
        + "\n" + n.ToString(System.Globalization.CultureInfo.InvariantCulture);
    public static string CoolingKey(string request) => "cooling\n" + request;
    public static string VideoKey(string query) => "video\n" + query;
    public static string RegistryKey(string location, string read) => "registry\n" + location + "\n" + read;
    /// <remarks>WQL ignores case, and a path in a query is spelled as Windows gave it (C:\WINDOWS on one PC, C:\Windows on another).</remarks>
    public static string WmiKey(string ns, string wql) => "wmi\n" + ns.ToLowerInvariant() + "\n" + wql.ToLowerInvariant();
    public static string ProcessKey(string file, IReadOnlyList<string> args) => "process\n" + RecordedCall.FileKey(file) + "\n" + string.Join("\n", args);

    private sealed class ReplayWmi(RecordingReplay replay) : IWmiSource
    {
        public Task<WmiQueryResult> QueryAsync(string wmiNamespace, string wql, CancellationToken ct = default) =>
            Task.FromResult(replay.Answer(WmiKey(wmiNamespace, wql), $"wmi {wmiNamespace} \"{wql}\"")?.ToWmiResult()
                            ?? WmiQueryResult.Failed(wmiNamespace, wql, "Not in the recording."));
    }

    private sealed class ReplayRegistry(RecordingReplay replay) : IRegistrySource
    {
        public Task<WmiQueryResult> ReadAsync(RegistryRead read, CancellationToken ct = default) =>
            Task.FromResult(replay.Answer(RegistryKey(read.Location, read.Describe()), $"registry {read.Location} \"{read.Describe()}\"")?.ToWmiResult()
                            ?? WmiQueryResult.Failed(read.Location, read.Describe(), "Not in the recording."));
    }

    private sealed class ReplayPackages(RecordingReplay replay) : IPackageSource
    {
        public Task<WmiQueryResult> ReadPackagesAsync(CancellationToken ct = default) =>
            Task.FromResult(replay.Answer(PackagesKey, "packages")?.ToWmiResult() ?? PackageList.Failed("Not in the recording."));
    }

    private sealed class ReplayAntivirusProducts(RecordingReplay replay) : Security.IAntivirusProductSource
    {
        public Task<Security.AntivirusInventoryResult> ReadAsync(CancellationToken ct = default) =>
            Task.FromResult(replay.Answer(AntivirusKey, "antivirus") is { } c
                ? Security.AntivirusInventoryResult.FromRecordedResult(c.ToWmiResult())
                : Security.AntivirusInventoryResult.Unavailable("Not in the recording."));
    }

    private sealed class ReplayAudio(RecordingReplay replay) : RemotePCDiagnostics.Core.Audio.IAudioStateSource
    {
        public Task<RemotePCDiagnostics.Core.Audio.AudioState> ReadAsync(CancellationToken ct = default) =>
            Task.FromResult(replay.Answer(AudioKey, "audio") is { } c
                ? c.Error is { } e && c.StdOut is null ? RemotePCDiagnostics.Core.Audio.AudioState.Unavailable(e) : RemotePCDiagnostics.Core.Audio.AudioState.FromJson(c.StdOut)
                : RemotePCDiagnostics.Core.Audio.AudioState.Unavailable("Not in the recording."));
    }

    private sealed class ReplayWifi(RecordingReplay replay) : Areas.IWifiRadioSource
    {
        public Task<Areas.WifiRadioReading> ReadAsync(bool scan, CancellationToken ct) =>
            Task.FromResult(replay.Answer(WifiKey, "wifi") is { } c
                ? c.Error is { } e && c.StdOut is null ? Areas.WifiRadioReading.Unavailable(e) : Areas.WifiRadioReading.FromJson(c.StdOut)
                : Areas.WifiRadioReading.Unavailable("Not in the recording."));
    }

    private sealed class ReplayMemoryDiagnostic(RecordingReplay replay) : Stress.IMemoryDiagnosticSource
    {
        public Task<Stress.MemoryDiagnosticReply> RunAsync(IReadOnlyList<string> args, CancellationToken ct)
        {
            var request = string.Join(' ', args);
            return Task.FromResult(replay.Answer(MemoryDiagnosticKey(request), $"memdiag {request}")?.ToMemoryDiagnosticReply()
                                   ?? Stress.MemoryDiagnosticReply.Failed("Not in the recording."));
        }
    }

    /// <summary>The recorded events are replayed whatever the window asked for; the Agent drops the ones it has seen by record id.</summary>
    private sealed class ReplayAlerts(RecordingReplay replay) : Alerts.IAlertReadings
    {
        public Task<WmiQueryResult> ReadAsync(string reading, long afterRecordId, TimeSpan lookBack, CancellationToken ct) =>
            Task.FromResult(replay.Answer(AlertsKey(reading), $"alerts {reading}")?.ToWmiResult() ?? Core.Alerts.AlertReadings.Failed(reading, "Not in the recording."));
    }

    /// <summary>A request asked again (status while a test runs) gets the recorded answers in order, then the last one again.</summary>
    private sealed class ReplaySelfTest(RecordingReplay replay) : Storage.IDriveSelfTestSource
    {
        public Task<Storage.SelfTestReply> RunAsync(IReadOnlyList<string> args, CancellationToken ct)
        {
            var request = string.Join(' ', args);
            return Task.FromResult(replay.Answer(SelfTestKey(request), $"selftest {request}")?.ToSelfTestReply()
                                   ?? Storage.SelfTestReply.Failed("Not in the recording."));
        }
    }

    private sealed class ReplayDiskScans(RecordingReplay replay) : Storage.IDiskScanSource
    {
        public Task<Storage.DiskScanAnswer> SendAsync(Storage.DiskScanRequest request, CancellationToken ct) =>
            Task.FromResult(replay.Answer(DiskScanKey(request.Key), $"diskscan {request.Key}")?.ToDiskScanAnswer()
                            ?? new Storage.DiskScanAnswer(null, "Not in the recording."));
    }

    /// <summary>The recorded chips; each allocation and dispatch gets the recorded answers in order, then the last one again. A chip
    /// with nothing recorded for a request fails it as a missing answer (a "no more memory" or a thrown error).</summary>
    private sealed class ReplayGpuMemory(RecordingReplay replay) : GpuMemory.IGpuMemorySource
    {
        public IReadOnlyList<GpuMemory.GpuMemoryAdapter> ListAdapters() =>
            replay.Answer(GpuMemoryKey(GpuMemoryList), "gpumemory list") is { StdOut: { } json }
                ? JsonSerializer.Deserialize<List<GpuMemory.GpuMemoryAdapter>>(json) ?? []
                : [];

        public GpuMemory.IGpuMemoryDevice Open(string adapterId)
        {
            var adapter = ListAdapters().FirstOrDefault(a => a.Id == adapterId) ?? throw new InvalidOperationException($"adapter {adapterId} is not in the recording");
            if (replay.Peek(GpuMemoryKey(GpuMemoryQuery(adapterId, "open"))) is { Error: { } error }) throw new InvalidOperationException(error);
            return new Device(replay, adapter);
        }

        private sealed class Device(RecordingReplay replay, GpuMemory.GpuMemoryAdapter adapter) : GpuMemory.IGpuMemoryDevice
        {
            private readonly List<long> _blocks = [];
            public GpuMemory.GpuMemoryAdapter Adapter => adapter;
            public IReadOnlyList<long> Blocks => _blocks;

            public bool TryAllocateBlock(long bytes)
            {
                var ok = replay.Answer(GpuMemoryKey(GpuMemoryQuery(adapter.Id, "allocate")), $"gpumemory {adapter.Id} allocate") is { StdOut: "true" };
                if (ok) _blocks.Add(bytes);
                return ok;
            }

            private readonly Dictionary<int, int> _runs = [];

            /// <summary>A dispatch the recording holds nothing for was clean (only faulty ones are kept).</summary>
            public GpuMemory.GpuBlockResult Run(int block, GpuMemory.GpuMemoryOp op, GpuMemory.GpuMemoryPattern pattern, uint seed, bool inverted, uint baseWord)
            {
                var n = _runs[block] = _runs.GetValueOrDefault(block) + 1;
                var c = replay.Peek(GpuMemoryKey(GpuMemoryRun(adapter.Id, block, n)));
                if (c?.Error is { } e && e.StartsWith(GpuLostPrefix, StringComparison.Ordinal)) throw new Stress.GpuDeviceLostException(e[GpuLostPrefix.Length..]);
                return c?.StdOut is { } json ? JsonSerializer.Deserialize<GpuMemory.GpuBlockResult>(json) ?? GpuMemory.GpuBlockResult.Clean : GpuMemory.GpuBlockResult.Clean;
            }

            public void Dispose() { }
        }
    }

    private sealed class ReplayCooling(RecordingReplay replay) : Cooling.ICoolingSource
    {
        public Task<Cooling.CoolingReading> SampleAsync(CancellationToken ct) =>
            Task.FromResult(Core.Cooling.CoolingReading.Parse(replay.Answer(CoolingKey(RecordedCall.CoolingSampleQuery), "cooling sample")?.StdOut)
                            ?? new Core.Cooling.CoolingReading(null, null, null, null));

        public Task<Cooling.CoolingModesReply> ModesAsync(IReadOnlyList<string> args, CancellationToken ct)
        {
            var request = string.Join(' ', args);
            return Task.FromResult(replay.Answer(CoolingKey(request), $"cooling {request}")?.ToCoolingModesReply()
                                   ?? Core.Cooling.CoolingModesReply.Failed("Not in the recording."));
        }
    }

    private sealed class ReplayLauncher(RecordingReplay replay) : IProcessLauncher
    {
        public Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken) =>
            Task.FromResult(replay.Answer(ProcessKey(fileName, arguments), $"{RecordedCall.FileKey(fileName)} {string.Join(' ', arguments)}")?.ToProcessResult()
                            ?? new ProcessResult(1, "", "Not in the recording."));
    }
}

/// <summary>How a recording keeps the legacy reader's dump file lists (it lists the folders itself, so there is no WMI answer to keep): JSON, by name.</summary>
public static class CrashDumpFiles
{
    public const string Minidumps = "legacy minidumps", LiveKernelReports = "legacy live kernel reports";

    public static string Json(IReadOnlyList<Areas.MinidumpFile> files) => System.Text.Json.JsonSerializer.Serialize(files, MachineRecording.Json);

    public static IReadOnlyList<Areas.MinidumpFile> Parse(string? json) =>
        json is null ? [] : System.Text.Json.JsonSerializer.Deserialize<List<Areas.MinidumpFile>>(json, MachineRecording.Json) ?? [];
}
