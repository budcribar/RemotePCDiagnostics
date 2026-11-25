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

public sealed class RecordingRegistrySource(IRegistrySource inner, CallRecorder recorder) : IRegistrySource
{
    public async Task<WmiQueryResult> ReadAsync(RegistryRead read, CancellationToken ct = default)
    {
        var r = await inner.ReadAsync(read, ct).ConfigureAwait(false);
        recorder.Add(RecordedCall.FromRegistry(r));
        return r;
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
    public IProcessLauncher Launcher => new ReplayLauncher(this);

    /// <summary>The report file recorded under <paramref name="name"/>; null when it wasn't made or isn't in the recording.</summary>
    public string? FileText(string name) => Answer(FileKey(name), $"file {name}") is { Error: null } c ? c.StdOut : null;

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
        RecordedCall.FileKind => FileKey(c.File ?? ""),
        _ => ProcessKey(c.File ?? "", c.Args ?? []),
    };

    public const string PackagesKey = "packages";
    public const string AntivirusKey = "antivirus";
    public static string FileKey(string name) => "file\n" + name;
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
