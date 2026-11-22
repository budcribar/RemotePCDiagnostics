using RemotePCDiagnostics.Core;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Recording;

namespace RemotePCDiagnostics.Tests.Replay;

/// <summary>
/// The recordings the replay tests run: the hand-made samples in <c>Replay/Recordings</c> (in the repo, so the harness is always tested), and
/// every recording under <c>RPD_RECORDINGS_DIR</c> (real PCs, kept out of the public repo). Each recording keeps its approved results in its
/// own <c>snapshots</c> folder.
/// </summary>
internal static class RecordingLibrary
{
    public const string RecordingsDirVariable = "RPD_RECORDINGS_DIR";

    public static string SamplesDir([CallerFilePath] string here = "") => Path.Combine(Path.GetDirectoryName(here)!, "Recordings");

    /// <summary>Display name → folder, for every recording found.</summary>
    public static IReadOnlyDictionary<string, string> All()
    {
        var found = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        void Scan(string root, string prefix)
        {
            if (!Directory.Exists(root)) return;
            foreach (var dir in Directory.EnumerateDirectories(root, "*", SearchOption.AllDirectories))
                if (MachineRecording.IsRecording(dir)) found[prefix + Path.GetRelativePath(root, dir).Replace('\\', '/')] = dir;
        }
        Scan(SamplesDir(), "sample/");
        if (Environment.GetEnvironmentVariable(RecordingsDirVariable) is { Length: > 0 } extra) Scan(extra, "pc/");
        return found;
    }

    public static TheoryData<string> Names()
    {
        var data = new TheoryData<string>();
        foreach (var name in All().Keys) data.Add(name);
        return data;
    }

    public static MachineRecording Load(string name) => MachineRecording.Load(All()[name]);
    public static string Folder(string name) => All()[name];
}

/// <summary>Builds checks whose every question is answered from a recording.</summary>
internal sealed class ReplayedPc(MachineRecording recording)
{
    public RecordingReplay Replay { get; } = new(recording);
    public MachineRecording Recording => recording;

    public OsqueryRunner Osquery => new(options: new OsqueryOptions { ExecutablePath = "osqueryi.exe" }, launcher: Replay.Launcher, fileExists: _ => true);
    public SystemCommandRunner Commands => new(Replay.Launcher, isProcessElevated: () => false);
    public IWmiSource Wmi => Replay.Wmi;

    /// <summary>The check as the app runs it now (WMI).</summary>
    public BatteryPowerModule BatteryPower() => new(Osquery, Commands, Wmi);
    /// <summary>The old path (osquery and powercfg), kept until parity is shown on real PCs.</summary>
    public BatteryPowerModule BatteryPowerOld() => new(Osquery, Commands);

    public bool Has(Func<RecordedCall, bool> match) => recording.Calls.Any(match);
}

/// <summary>
/// Compares a check's result with its approved snapshot (normalized JSON). A difference fails with both versions, and writes the new one next
/// to it as <c>.received.json</c>. Set <c>RPD_ACCEPT_SNAPSHOTS=1</c> to approve: the snapshot is rewritten, and the change shows in review.
/// </summary>
internal static class Snapshot
{
    public const string AcceptVariable = "RPD_ACCEPT_SNAPSHOTS";

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() },
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    /// <summary>What a snapshot holds: the verdict and the whole report, without the run's time.</summary>
    public static string Normalize(DiagnosticResult r) =>
        JsonSerializer.Serialize(new { r.ModuleName, r.Status, r.Message, Report = r.Payload }, Json).Replace("\r\n", "\n") + "\n";

    public static void Match(string recordingFolder, string checkName, DiagnosticResult result)
    {
        var dir = Path.Combine(recordingFolder, "snapshots");
        var path = Path.Combine(dir, checkName + ".json");
        var received = Path.Combine(dir, checkName + ".received.json");
        var actual = Normalize(result);
        if (Environment.GetEnvironmentVariable(AcceptVariable) == "1")
        {
            Directory.CreateDirectory(dir);
            File.WriteAllText(path, actual);
            if (File.Exists(received)) File.Delete(received);
            return;
        }
        var expected = File.Exists(path) ? File.ReadAllText(path).Replace("\r\n", "\n") : null;
        if (expected == actual)
        {
            if (File.Exists(received)) File.Delete(received);
            return;
        }
        Directory.CreateDirectory(dir);
        File.WriteAllText(received, actual);
        Assert.Fail(expected is null
            ? $"No approved snapshot at {path}. Review {received}, then rerun with {AcceptVariable}=1 to approve it."
            : $"{checkName} on {recordingFolder} no longer matches its snapshot. Compare {path} with {received}; rerun with {AcceptVariable}=1 to approve.\n"
              + FirstDifference(expected, actual));
    }

    private static string FirstDifference(string expected, string actual)
    {
        var e = expected.Split('\n');
        var a = actual.Split('\n');
        for (var i = 0; i < Math.Max(e.Length, a.Length); i++)
        {
            var el = i < e.Length ? e[i] : "(end)";
            var al = i < a.Length ? a[i] : "(end)";
            if (el != al) return $"First difference at line {i + 1}:\n  approved: {el}\n  now:      {al}";
        }
        return "";
    }
}

/// <summary>
/// Damages a real recording in one place at a time: a source that fails, times out or answers nothing, output that isn't what was expected,
/// and each recorded value made missing, null, zero, negative, the "unknown" marker, huge, or garbage text. Every check must survive all of them.
/// </summary>
internal static class FaultInjector
{
    private static readonly (string Name, JsonElement? Value)[] BadValues =
    [
        ("missing", null),
        ("null", JsonSerializer.SerializeToElement<object?>(null)),
        ("zero", JsonSerializer.SerializeToElement(0)),
        ("negative", JsonSerializer.SerializeToElement(-1)),
        ("unknown marker 0xFFFFFFFF", JsonSerializer.SerializeToElement(4294967295L)),
        ("huge", JsonSerializer.SerializeToElement(9_000_000_000_000_000_000L)),
        ("garbage text", JsonSerializer.SerializeToElement("@@ not a value ##")),
        ("German decimal", JsonSerializer.SerializeToElement("1.234,5")),
    ];

    public static IEnumerable<(string Fault, MachineRecording Recording)> Variants(MachineRecording rec)
    {
        for (var i = 0; i < rec.Calls.Count; i++)
        {
            var c = rec.Calls[i];
            var what = c.Describe();
            if (c.Kind == RecordedCall.WmiKind)
            {
                yield return ($"{what}: access denied", Replace(rec, i, c with { Rows = null, Error = "Access denied" }));
                yield return ($"{what}: timed out", Replace(rec, i, c with { Rows = null, Error = "The query timed out after 30s." }));
                yield return ($"{what}: no rows", Replace(rec, i, c with { Rows = [], Error = null }));
                if (c.Rows is not { } rows) continue;
                for (var r = 0; r < rows.Count; r++)
                    foreach (var prop in rows[r].Keys)
                        foreach (var (name, value) in BadValues)
                        {
                            var copy = rows.Select(x => new Dictionary<string, JsonElement>(x, StringComparer.OrdinalIgnoreCase)).ToList();
                            if (value is { } v) copy[r][prop] = v; else copy[r].Remove(prop);
                            yield return ($"{what}: row {r} {prop} {name}", Replace(rec, i, c with { Rows = copy }));
                        }
            }
            else
            {
                yield return ($"{what}: exit code 1", Replace(rec, i, c with { ExitCode = 1, StdOut = "", StdErr = "Access is denied." }));
                yield return ($"{what}: timed out", Replace(rec, i, c with { TimedOut = true, StdOut = "" }));
                yield return ($"{what}: empty output", Replace(rec, i, c with { StdOut = "" }));
                yield return ($"{what}: garbage output", Replace(rec, i, c with { StdOut = "@@ not what was expected ##\n\u0000\u0007" }));
                yield return ($"{what}: cut off halfway", Replace(rec, i, c with { StdOut = (c.StdOut ?? "")[..((c.StdOut ?? "").Length / 2)] }));
                foreach (var (fault, stdout) in JsonFieldFaults(c.StdOut))
                    yield return ($"{what}: {fault}", Replace(rec, i, c with { StdOut = stdout }));
            }
        }
    }

    /// <summary>For osquery output (a JSON array of rows of text): each field made missing, empty, negative, huge or garbage.</summary>
    private static IEnumerable<(string Fault, string StdOut)> JsonFieldFaults(string? stdout)
    {
        List<Dictionary<string, string>>? rows;
        try { rows = stdout is { Length: > 0 } ? JsonSerializer.Deserialize<List<Dictionary<string, string>>>(stdout) : null; }
        catch (JsonException) { rows = null; }
        if (rows is null) yield break;
        string?[] bad = [null, "", "-1", "4294967295", "99999999999999999999", "@@ garbage ##", "1.234,5"];
        for (var r = 0; r < rows.Count; r++)
            foreach (var key in rows[r].Keys)
                foreach (var b in bad)
                {
                    var copy = rows.Select(x => new Dictionary<string, string>(x)).ToList();
                    if (b is null) copy[r].Remove(key); else copy[r][key] = b;
                    yield return ($"row {r} {key} = {(b is null ? "missing" : "\"" + b + "\"")}", JsonSerializer.Serialize(copy));
                }
    }

    private static MachineRecording Replace(MachineRecording rec, int index, RecordedCall call)
    {
        var calls = rec.Calls.ToList();
        calls[index] = call;
        return new() { Schema = rec.Schema, Machine = rec.Machine, CapturedAt = rec.CapturedAt, Calls = calls };
    }
}

/// <summary>Edits a recording to make a known failure (a worn battery, power saver), for checks whose right answer we know.</summary>
internal static class RecordingEdits
{
    /// <summary>Sets <paramref name="property"/> on every row of every WMI answer whose query contains <paramref name="queryContains"/>.</summary>
    public static MachineRecording SetWmi(this MachineRecording rec, string queryContains, string property, object? value) => Map(rec, c =>
        c.Kind == RecordedCall.WmiKind && c.Query?.Contains(queryContains, StringComparison.OrdinalIgnoreCase) == true && c.Rows is { } rows
            ? c with { Rows = rows.Select(r => new Dictionary<string, JsonElement>(r, StringComparer.OrdinalIgnoreCase) { [property] = JsonSerializer.SerializeToElement(value) }).ToList() }
            : c);

    /// <summary>Makes every WMI answer whose query contains <paramref name="queryContains"/> fail with <paramref name="error"/>.</summary>
    public static MachineRecording FailWmi(this MachineRecording rec, string queryContains, string error) => Map(rec, c =>
        c.Kind == RecordedCall.WmiKind && c.Query?.Contains(queryContains, StringComparison.OrdinalIgnoreCase) == true ? c with { Rows = null, Error = error } : c);

    private static MachineRecording Map(MachineRecording rec, Func<RecordedCall, RecordedCall> f) =>
        new() { Schema = rec.Schema, Machine = rec.Machine, CapturedAt = rec.CapturedAt, Calls = rec.Calls.Select(f).ToList() };
}
