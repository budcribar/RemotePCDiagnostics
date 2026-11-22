using RemotePCDiagnostics.Core;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Recording;
using RemotePCDiagnostics.Legacy;

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
    public IRegistrySource Registry => Replay.Registry;
    public IPackageSource Packages => Replay.Packages;

    /// <summary>The check as the app runs it (WMI, through the Agent).</summary>
    public BatteryPowerModule BatteryPower() => new(new WmiBatteryPowerSource(Wmi));
    /// <summary>The Store edition without an Agent (osquery and powercfg).</summary>
    public BatteryPowerModule BatteryPowerOld() => new(new OsqueryBatteryPowerSource(Osquery, Commands));

    /// <summary>DriveHealth on WMI (in the app, the Agent's). The clock is the recording's, and nothing is saved.</summary>
    public DriveHealthModule DriveHealth() => Drives(new WmiDriveSource(Wmi));
    /// <summary>The Store edition without an Agent: the Get-PhysicalDisk PowerShell script, then osquery disk_info.</summary>
    public DriveHealthModule DriveHealthOld() => Drives(new PowerShellDriveSource(Commands, Osquery));
    private DriveHealthModule Drives(IDriveSource source) =>
        new(source, clock: () => recording.CapturedAt, historyStore: new DriveHealthHistoryStore(), volumes: () => []);

    /// <summary>Hardware inventory on WMI (the Agent's).</summary>
    public OsqueryModule Inventory() => new(new WmiHardwareInventorySource(Wmi));
    /// <summary>The Store edition without an Agent: osquery.</summary>
    public OsqueryModule InventoryOld() => new(new OsqueryHardwareInventorySource(Osquery));

    public ServicesModule Services() => new(new WmiServiceSource(Wmi));
    public ServicesModule ServicesOld() => new(new OsqueryServiceSource(Osquery));

    /// <summary>Device Manager and drivers on WMI. Pending driver updates aren't recorded, so they aren't asked.</summary>
    public DeviceDriversModule DeviceDrivers() => new(new WmiDeviceDriverSource(Wmi));
    /// <summary>The Store edition: the ProblemDevices PowerShell script and the osquery drivers table.</summary>
    public DeviceDriversModule DeviceDriversOld() => new(new OsqueryDeviceDriverSource(Osquery, Commands));

    /// <summary>Programs and updates on WMI and the registry; "today" is the day the PC was recorded.</summary>
    public ProgramsModule Programs() => new(new WmiProgramsSource(Wmi, Registry, HasPackages ? Packages : null), today: Today);
    /// <summary>Recordings before v5 have no Store-app list; replaying one, Programs lists the Uninstall keys only.</summary>
    private bool HasPackages => Has(c => c.Kind == RecordedCall.PackagesKind);
    public ProgramsModule ProgramsOld() => new(new OsqueryProgramsSource(Osquery), today: Today);
    private DateOnly Today() => DateOnly.FromDateTime(recording.CapturedAt.DateTime);

    /// <summary>Resource hogs on WMI (the Agent's) and the registry. The 2 s wait between process snapshots takes no time; no restart is pending.</summary>
    public ResourceHogsModule ResourceHogs() => new(new WmiResourceHogsSource(Wmi, Registry), timer: SampleTimer.Instant(), restartPending: () => false);
    /// <summary>The Store edition without an Agent: osquery and the FastStartupState script, with CPU % a share of the recorded PC's processors.</summary>
    public ResourceHogsModule ResourceHogsOld() => new(new OsqueryResourceHogsSource(Osquery, Commands, LogicalProcessors), timer: SampleTimer.Instant(),
        restartPending: () => false);
    private int LogicalProcessors() => recording.Calls
        .Where(c => c.Kind == RecordedCall.WmiKind && c.Query == WmiResourceHogsSource.ProcessorsSql && c.Rows is { Count: > 0 })
        .Select(c => c.ToWmiResult().Rows![0].Long("NumberOfLogicalProcessors")).FirstOrDefault(n => n is > 0) is { } n ? (int)n : 4;

    /// <summary>The checks that show event times: "now" is when the PC was recorded, and times are shown in UTC, wherever the tests run.</summary>
    public TimeProvider Clock => new FixedClock(recording.CapturedAt);

    /// <summary>Crashes with the dump files and graphics drivers on WMI (the Agent's); the event logs from wevtutil on both paths.</summary>
    public CrashesModule Crashes() => new(Commands, includeSystemCrashes: true, new WmiCrashDumpSource(Wmi, @"C:\Windows"), new WmiDeviceDriverSource(Wmi), clock: Clock);
    /// <summary>The Store edition without an Agent: the folders listed by the app itself (recorded as lists), and the osquery drivers table.</summary>
    public CrashesModule CrashesOld() => new(Commands, includeSystemCrashes: true, new ReplayedFileDumps(Replay), new OsqueryDeviceDriverSource(Osquery, Commands), clock: Clock);
    public EventLogModule EventLog() => new(Commands, excludeCrashEvents: true, clock: Clock);
    public SleepWakeModule SleepWake() => new(Commands, batteryReport: new ReplayedBatteryReport(Replay), clock: Clock);

    public bool HasFile(string name) => Has(c => c.Kind == RecordedCall.FileKind && c.File == name);

    private sealed class ReplayedFileDumps(RecordingReplay replay) : ICrashDumpSource
    {
        public Task<IReadOnlyList<MinidumpFile>> ReadMinidumpsAsync(CancellationToken ct) =>
            Task.FromResult(CrashDumpFiles.Parse(replay.FileText(CrashDumpFiles.Minidumps)));
        public Task<IReadOnlyList<MinidumpFile>> ReadLiveKernelReportsAsync(CancellationToken ct) =>
            Task.FromResult(CrashDumpFiles.Parse(replay.FileText(CrashDumpFiles.LiveKernelReports)));
    }

    private sealed class ReplayedBatteryReport(RecordingReplay replay) : IBatteryReportSource
    {
        public Task<string?> ReadXmlAsync(CancellationToken ct) => Task.FromResult(replay.FileText(PowerCfgBatteryReport.RecordingName));
    }

    public bool Has(Func<RecordedCall, bool> match) => recording.Calls.Any(match);
    public bool HasWmi(string query) => Has(c => c.Kind == RecordedCall.WmiKind && c.Query == query);
    public bool HasOsquery(string sql) => Has(c => c.Kind == RecordedCall.ProcessKind && c.Args?.LastOrDefault() == sql);

    /// <summary>The <see cref="RecordingReplay.Key"/> of every answer these checks ask for on this recording.</summary>
    public static async Task<HashSet<string>> AskedByAsync(MachineRecording rec, CancellationToken ct, params Func<ReplayedPc, IDiagnosticModule>[] checks)
    {
        var asked = new HashSet<string>(StringComparer.Ordinal);
        foreach (var make in checks)
        {
            var pc = new ReplayedPc(rec);
            await make(pc).RefreshAsync(null, ct);
            asked.UnionWith(pc.Replay.Asked);
        }
        return asked;
    }
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

    /// <param name="only">The answers to damage (their <see cref="RecordingReplay.Key"/>); null damages every answer.</param>
    /// <param name="maxRows">Damage values only in the first rows of each answer: long lists (services, drivers, programs) would
    /// otherwise make tens of thousands of variants, all the same kind of row.</param>
    public static IEnumerable<(string Fault, MachineRecording Recording)> Variants(MachineRecording rec, IReadOnlySet<string>? only = null, int maxRows = int.MaxValue)
    {
        for (var i = 0; i < rec.Calls.Count; i++)
        {
            var c = rec.Calls[i];
            if (only is not null && !only.Contains(RecordingReplay.Key(c))) continue;
            var what = c.Describe();
            if (c.HasRows)
            {
                yield return ($"{what}: access denied", Replace(rec, i, c with { Rows = null, Error = "Access denied" }));
                yield return ($"{what}: timed out", Replace(rec, i, c with { Rows = null, Error = "The query timed out after 30s." }));
                yield return ($"{what}: no rows", Replace(rec, i, c with { Rows = [], Error = null }));
                if (c.Rows is not { } rows) continue;
                for (var r = 0; r < Math.Min(rows.Count, maxRows); r++)
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
                foreach (var (fault, stdout) in JsonFieldFaults(c.StdOut, maxRows).Concat(EventFaults(c.StdOut)))
                    yield return ($"{what}: {fault}", Replace(rec, i, c with { StdOut = stdout }));
            }
        }
    }

    /// <summary>For osquery output (a JSON array of rows of text): each field made missing, empty, negative, huge or garbage.</summary>
    private static IEnumerable<(string Fault, string StdOut)> JsonFieldFaults(string? stdout, int maxRows)
    {
        List<Dictionary<string, string>>? rows;
        try { rows = stdout is { Length: > 0 } ? JsonSerializer.Deserialize<List<Dictionary<string, string>>>(stdout) : null; }
        catch (JsonException) { rows = null; }
        if (rows is null) yield break;
        string?[] bad = [null, "", "-1", "4294967295", "99999999999999999999", "@@ garbage ##", "1.234,5"];
        for (var r = 0; r < Math.Min(rows.Count, maxRows); r++)
            foreach (var key in rows[r].Keys)
                foreach (var b in bad)
                {
                    var copy = rows.Select(x => new Dictionary<string, string>(x)).ToList();
                    if (b is null) copy[r].Remove(key); else copy[r][key] = b;
                    yield return ($"row {r} {key} = {(b is null ? "missing" : "\"" + b + "\"")}", JsonSerializer.Serialize(copy));
                }
    }

    /// <summary>For wevtutil output (events as XML): in the newest event, each value (an element's text or an attribute) made missing or garbage.</summary>
    private static IEnumerable<(string Fault, string StdOut)> EventFaults(string? stdout)
    {
        const string close = "</Event>";
        var start = stdout?.IndexOf("<Event", StringComparison.Ordinal) ?? -1;
        var end = start < 0 ? -1 : stdout!.IndexOf(close, start, StringComparison.Ordinal);
        if (end < 0) yield break;
        end += close.Length;
        System.Xml.Linq.XElement first;
        try { first = System.Xml.Linq.XElement.Parse(stdout![start..end]); }
        catch (System.Xml.XmlException) { yield break; }
        string With(Action<System.Xml.Linq.XElement> edit)
        {
            var copy = new System.Xml.Linq.XElement(first);
            edit(copy);
            return stdout![..start] + copy.ToString(System.Xml.Linq.SaveOptions.DisableFormatting) + stdout[end..];
        }
        var leaves = first.Descendants().Where(e => !e.HasElements).ToList();
        for (var n = 0; n < leaves.Count; n++)
        {
            var at = n;
            System.Xml.Linq.XElement Leaf(System.Xml.Linq.XElement copy) => copy.Descendants().Where(e => !e.HasElements).ElementAt(at);
            var label = leaves[n].Name.LocalName + (leaves[n].Attribute("Name") is { } a ? $"[{a.Value}]" : "");
            yield return ($"event 0 {label} missing", With(c => Leaf(c).Remove()));
            if (leaves[n].Value.Length > 0) yield return ($"event 0 {label} garbage", With(c => Leaf(c).Value = "@@ garbage ##"));
            foreach (var attr in leaves[n].Attributes().Where(x => !x.IsNamespaceDeclaration).Select(x => x.Name).ToList())
                yield return ($"event 0 {label} @{attr.LocalName} garbage", With(c => Leaf(c).SetAttributeValue(attr, "@@ garbage ##")));
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

    /// <summary>Sets every row whose <paramref name="matchColumn"/> is <paramref name="matchValue"/>, in WMI, registry and package answers.</summary>
    public static MachineRecording SetRows(this MachineRecording rec, string matchColumn, string matchValue, string property, object? value) => Map(rec, c =>
        c.HasRows && c.Rows is { } rows
            ? c with
            {
                Rows = rows.Select(r => r.TryGetValue(matchColumn, out var v) && v.ValueKind == JsonValueKind.String && v.GetString() == matchValue
                    ? new Dictionary<string, JsonElement>(r, StringComparer.OrdinalIgnoreCase) { [property] = JsonSerializer.SerializeToElement(value) }
                    : r).ToList(),
            }
            : c);

    /// <summary>Adds a row to every WMI answer whose query contains <paramref name="queryContains"/>.</summary>
    public static MachineRecording AddWmiRow(this MachineRecording rec, string queryContains, IReadOnlyDictionary<string, object?> row) => Map(rec, c =>
        c.Kind == RecordedCall.WmiKind && c.Query?.Contains(queryContains, StringComparison.OrdinalIgnoreCase) == true && c.Rows is { } rows
            ? c with { Rows = [.. rows, row.ToDictionary(p => p.Key, p => JsonSerializer.SerializeToElement(p.Value), StringComparer.OrdinalIgnoreCase)] }
            : c);

    /// <summary>Makes every WMI answer whose query contains <paramref name="queryContains"/> fail with <paramref name="error"/>.</summary>
    public static MachineRecording FailWmi(this MachineRecording rec, string queryContains, string error) => Map(rec, c =>
        c.Kind == RecordedCall.WmiKind && c.Query?.Contains(queryContains, StringComparison.OrdinalIgnoreCase) == true ? c with { Rows = null, Error = error } : c);

    /// <summary>Sets the Temperature of each drive (in order) in the answer to the PowerShell drive script.</summary>
    public static MachineRecording WithPowerShellTemperatures(this MachineRecording rec, string script, IReadOnlyList<int?> temperatures) => Map(rec, c =>
    {
        if (c.Kind != RecordedCall.ProcessKind || c.Args?.LastOrDefault() != script || c.StdOut is null) return c;
        var drives = System.Text.Json.Nodes.JsonNode.Parse(c.StdOut)!.AsArray();
        for (var i = 0; i < drives.Count && i < temperatures.Count; i++)
            drives[i]!["Temperature"] = temperatures[i]?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "";
        return c with { StdOut = drives.ToJsonString() };
    });

    private static MachineRecording Map(MachineRecording rec, Func<RecordedCall, RecordedCall> f) =>
        new() { Schema = rec.Schema, Machine = rec.Machine, CapturedAt = rec.CapturedAt, Calls = rec.Calls.Select(f).ToList() };
}

/// <summary>
/// What a technician would see differently between two reports of the same PC: cards present, their level and headline, and their rows (as
/// sets, so order doesn't matter). Rows <paramref name="live"/> picks (values that change from second to second) aren't compared.
/// </summary>
internal static class ReportDiff
{
    public static List<string> Between(AreaReport old, AreaReport now, Func<AreaCard, AreaRow, bool>? live = null, int perCard = 8)
    {
        var diffs = new List<string>();
        if (old.Status != now.Status) diffs.Add($"status: old {old.Status}, new {now.Status}");
        var oldCards = old.Cards.ToDictionary(c => c.Id);
        var newCards = now.Cards.ToDictionary(c => c.Id);
        foreach (var id in oldCards.Keys.Except(newCards.Keys)) diffs.Add($"card {id}: only on the old path");
        foreach (var id in newCards.Keys.Except(oldCards.Keys)) diffs.Add($"card {id}: only on the new path");
        foreach (var (id, o) in oldCards)
        {
            if (!newCards.TryGetValue(id, out var n)) continue;
            if (o.Level != n.Level) diffs.Add($"card {id} level: old {o.Level}, new {n.Level}");
            if (o.Headline != n.Headline) diffs.Add($"card {id} headline: old \"{o.Headline}\", new \"{n.Headline}\"");
            if ((o.ErrorText is null) != (n.ErrorText is null)) diffs.Add($"card {id} error: old \"{o.ErrorText}\", new \"{n.ErrorText}\"");
            HashSet<string> Rows(AreaCard c) => c.Rows.Where(r => live?.Invoke(c, r) != true).Select(r => $"{r.Level}: {string.Join(" | ", r.Values)}").ToHashSet(StringComparer.Ordinal);
            var (or, nr) = (Rows(o), Rows(n));
            var onlyOld = or.Except(nr).Order(StringComparer.Ordinal).ToList();
            var onlyNew = nr.Except(or).Order(StringComparer.Ordinal).ToList();
            diffs.AddRange(onlyOld.Take(perCard).Select(r => $"card {id} row only old: {r}"));
            diffs.AddRange(onlyNew.Take(perCard).Select(r => $"card {id} row only new: {r}"));
            if (onlyOld.Count + onlyNew.Count > 2 * perCard) diffs.Add($"card {id}: {onlyOld.Count} rows only old, {onlyNew.Count} only new in all");
        }
        return diffs;
    }
}

/// <summary>Runs a check on every damaged variant of the answers it asks for, on each of its paths, and lists what went wrong.</summary>
internal static class DamagedRuns
{
    public static async Task AssertSurvivesAsync(MachineRecording source, Func<DiagnosticResult, IEnumerable<string>> problems, int maxRows,
        params (string Path, Func<ReplayedPc, IDiagnosticModule> Make)[] paths)
    {
        var ct = TestContext.Current.CancellationToken;
        var asked = await ReplayedPc.AskedByAsync(source, ct, [.. paths.Select(p => p.Make)]);
        var failures = new List<string>();
        var variants = 0;
        foreach (var (fault, rec) in FaultInjector.Variants(source, asked, maxRows))
            foreach (var (path, make) in paths)
            {
                variants++;
                try
                {
                    var r = await make(new ReplayedPc(rec)).RefreshAsync(null, ct);
                    failures.AddRange(problems(r).Select(p => $"{path}, {fault}: {p}"));
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    failures.Add($"{path}, {fault}: threw {ex.GetType().Name}: {ex.Message}");
                }
            }
        Assert.True(variants > 50, $"only {variants} damaged variants");
        Assert.True(failures.Count == 0, $"{failures.Count} of {variants} damaged runs went wrong:\n" + string.Join("\n", failures.Take(40)));
    }

    /// <summary>What no report may show, whatever the PC answered: an empty headline, NaN, infinity or a negative size.</summary>
    public static IEnumerable<string> CommonProblems(AreaReport report)
    {
        foreach (var card in report.Cards)
        {
            // An empty card says why (EmptyText) instead of a headline.
            if (string.IsNullOrWhiteSpace(card.Headline) && card.ErrorText is null && card.EmptyText is null) yield return $"card {card.Id} has no headline";
            foreach (var row in card.Rows)
                foreach (var v in row.Values)
                    if (v.Contains("NaN") || v.Contains("Infinity") || v.Contains("∞") || v.Contains("-1 GB") || v.Contains("-1 MB"))
                        yield return $"{card.Id}: \"{v}\"";
        }
        foreach (var m in report.KeyMetrics ?? [])
            if (!double.IsFinite(m.Value) || m.Value < 0) yield return $"metric {m.Id} = {m.Value}";
    }
}
