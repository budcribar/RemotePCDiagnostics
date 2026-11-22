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

    public IWmiSource Wmi => new ReplayWmi(this);
    public IProcessLauncher Launcher => new ReplayLauncher(this);

    /// <summary>The same question asked twice gets the recorded answers in order, and the last one again after that.</summary>
    private RecordedCall? Answer(string key, string description)
    {
        lock (_byKey)
        {
            if (_byKey.TryGetValue(key, out var q) && q.Count > 0) return _last[key] = q.Dequeue();
            if (_last.TryGetValue(key, out var last)) return last;
        }
        lock (_misses) _misses.Add(description);
        return null;
    }

    public static string Key(RecordedCall c) => c.Kind == RecordedCall.WmiKind
        ? WmiKey(c.Namespace ?? "", c.Query ?? "")
        : ProcessKey(c.File ?? "", c.Args ?? []);

    public static string WmiKey(string ns, string wql) => "wmi\n" + ns.ToLowerInvariant() + "\n" + wql;
    public static string ProcessKey(string file, IReadOnlyList<string> args) => "process\n" + RecordedCall.FileKey(file) + "\n" + string.Join("\n", args);

    private sealed class ReplayWmi(RecordingReplay replay) : IWmiSource
    {
        public Task<WmiQueryResult> QueryAsync(string wmiNamespace, string wql, CancellationToken ct = default) =>
            Task.FromResult(replay.Answer(WmiKey(wmiNamespace, wql), $"wmi {wmiNamespace} \"{wql}\"")?.ToWmiResult()
                            ?? WmiQueryResult.Failed(wmiNamespace, wql, "Not in the recording."));
    }

    private sealed class ReplayLauncher(RecordingReplay replay) : IProcessLauncher
    {
        public Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken) =>
            Task.FromResult(replay.Answer(ProcessKey(fileName, arguments), $"{RecordedCall.FileKey(fileName)} {string.Join(' ', arguments)}")?.ToProcessResult()
                            ?? new ProcessResult(1, "", "Not in the recording."));
    }
}
