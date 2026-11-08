using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Serialization;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Sensors;

namespace RemotePCDiagnostics.Core.Plugins;

/// <summary>
/// The reads a module in user mode (RemotePCDiagnostics.ModuleHost, restricted token) asks the app for, because they need administrator
/// rights. Each is a narrow, typed question: the module never gets administrator rights, never runs a command of its choosing in the app,
/// and the app answers only what the module listed under <see cref="ModuleManifest.Capabilities"/>. For now only modules that ship with
/// the app may use them (an unsigned module's answers would need redaction first; see docs/host-queries.md).
/// </summary>
public interface IHostQueries
{
    /// <summary><c>sensors.read</c>: whether the app can read sensors here.</summary>
    Task<ModuleAvailability> SensorsAvailabilityAsync(CancellationToken ct = default);
    /// <summary><c>sensors.read</c>: every temperature and fan reading.</summary>
    Task<SensorSnapshot> ReadSensorsAsync(CancellationToken ct = default);
    /// <summary><c>osquery.select</c>: one of the app's own read-only statements (<see cref="HostCapabilities.AllowedSql"/>), run in the app.</summary>
    Task<OsqueryQueryResult> SelectAsync(string sql, CancellationToken ct = default);
    /// <summary><c>storage.drives</c>: the drive health script's output (health, wear and error counters per drive).</summary>
    Task<ProcessResult?> ReadDrivesAsync(CancellationToken ct = default);
    /// <summary><c>storage.retrims</c>: the last retrim per drive letter.</summary>
    Task<IReadOnlyDictionary<char, RetrimRecord>> ReadRetrimsAsync(CancellationToken ct = default);
    /// <summary><c>eventlog.query</c>: events from the System or Application log matching an XPath filter, newest first (null when the
    /// log couldn't be read).</summary>
    Task<IReadOnlyList<WinEvent>?> QueryEventsAsync(string log, string xpath, int max, CancellationToken ct = default);
    /// <summary><c>crashes.minidumps</c>: the blue screen dump files in the Windows folder.</summary>
    Task<IReadOnlyList<MinidumpFile>> ReadMinidumpsAsync(CancellationToken ct = default);
    /// <summary><c>events.reviewed</c>: the events the person marked as reviewed.</summary>
    Task<IReadOnlyCollection<string>> ReadEventReviewsAsync(CancellationToken ct = default);
}

/// <summary>The capability names a module lists in module.json, and the limits the app holds every query to.</summary>
public static class HostCapabilities
{
    public const string SensorsRead = "sensors.read";
    public const string OsquerySelect = "osquery.select";
    public const string StorageDrives = "storage.drives";
    public const string StorageRetrims = "storage.retrims";
    public const string EventLogQuery = "eventlog.query";
    public const string Minidumps = "crashes.minidumps";
    public const string EventReviews = "events.reviewed";

    public static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.Ordinal)
        { SensorsRead, OsquerySelect, StorageDrives, StorageRetrims, EventLogQuery, Minidumps, EventReviews };

    /// <summary>The only statements <c>osquery.select</c> runs: the app's own, verbatim. Anything else is refused.</summary>
    public static readonly IReadOnlySet<string> AllowedSql = new HashSet<string>(StringComparer.Ordinal) { ServicesModule.Sql, HardwareInventory.DiskSql };

    /// <summary>The logs <c>eventlog.query</c> reads (never Security).</summary>
    public static readonly IReadOnlySet<string> AllowedLogs = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "System", "Application" };

    public const int MaxEvents = 1000;
    public const int MaxXPathLength = 2000;

    /// <summary>How long one query may take in the app.</summary>
    public static readonly TimeSpan Timeout = TimeSpan.FromMinutes(2);

    /// <summary>Serialization for queries and answers (sensor readings can be NaN).</summary>
    public static readonly JsonSerializerOptions Json = new(ModuleHostMessage.Json) { NumberHandling = JsonNumberHandling.AllowNamedFloatingPointLiterals };
}

/// <summary>A query the app refused or couldn't answer. <see cref="Error"/>: notDeclared, notAllowed, badRequest, failed, timedOut.</summary>
public sealed class HostQueryException(string error, string reason) : Exception(reason)
{
    public string Error { get; } = error;
}

/// <summary>Where the app's answers to host queries come from: the same services the modules use in process.</summary>
public sealed record HostQueryBackend
{
    public ISensorProvider? Sensors { get; init; }
    public OsqueryRunner? Osquery { get; init; }
    public SystemCommandRunner? Commands { get; init; }
    public IRetrimHistory? Retrims { get; init; }
    public Func<IReadOnlyList<MinidumpFile>> Minidumps { get; init; } = BsodHistoryModule.ReadSystemMinidumps;
    public Func<IReadOnlyCollection<string>> EventReviews { get; init; } = Areas.EventReviews.Read;
}

/// <summary>
/// The app's end: answers one module host's queries. It checks every query before doing anything: the module ships with the app, its
/// manifest lists the capability, and the arguments are ones the app allows.
/// </summary>
/// <param name="backend">The app's services, once they exist (the module stand-ins are made before the app's container is built); null
/// until then, and queries meanwhile fail.</param>
public sealed class HostQueryServer(Func<HostQueryBackend?> backend, ILogger? log = null)
{
    public HostQueryServer(HostQueryBackend backend, ILogger? log = null) : this(() => backend, log) { }

    private HostQueryBackend? _backend;
    private HostQueryBackend Backend => _backend ??= backend() ?? throw new HostQueryException("failed", "the app isn't ready yet");

    public async Task<ModuleHostMessage> AnswerAsync(UserModeModule module, ModuleHostMessage query, CancellationToken ct = default)
    {
        var capability = query.Capability ?? "";
        try
        {
            var value = await AnswerCoreAsync(module, capability, query.Args, ct).ConfigureAwait(false);
            log.Info($"Module host [{module.Manifest.Slug}]: query {capability} ok");
            return new ModuleHostMessage { Type = "answer", Id = query.Id, Ok = true, Value = value };
        }
        catch (HostQueryException ex)
        {
            log.Info($"Module host [{module.Manifest.Slug}]: query {capability} refused ({ex.Error}): {ex.Message}");
            return new ModuleHostMessage { Type = "answer", Id = query.Id, Ok = false, Error = ex.Error, Reason = ex.Message };
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new ModuleHostMessage { Type = "answer", Id = query.Id, Ok = false, Error = "timedOut", Reason = $"{capability} took too long" };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.Info($"Module host [{module.Manifest.Slug}]: query {capability} failed: {ex.GetType().Name}: {ex.Message}");
            return new ModuleHostMessage { Type = "answer", Id = query.Id, Ok = false, Error = "failed", Reason = ex.Message };
        }
    }

    private async Task<JsonElement> AnswerCoreAsync(UserModeModule module, string capability, JsonElement? args, CancellationToken outer)
    {
        if (!module.Bundled) throw new HostQueryException("notAllowed", "host queries are only for modules that ship with the app");
        if (!HostCapabilities.All.Contains(capability)) throw new HostQueryException("badRequest", $"unknown capability {capability}");
        if (!module.Manifest.Capabilities.Contains(capability, StringComparer.Ordinal))
            throw new HostQueryException("notDeclared", $"{capability} isn't in the module's module.json");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(outer);
        timeout.CancelAfter(HostCapabilities.Timeout);
        var ct = timeout.Token;
        var backend = Backend;
        object? value;
        switch (capability)
        {
            case HostCapabilities.SensorsRead:
                var sensors = backend.Sensors ?? new UnavailableSensorProvider();
                if (Arg(args, "availability") == "true")
                {
                    var a = sensors.CheckAvailability();
                    value = new AvailabilityAnswer(a.IsAvailable, a.Reason);
                }
                else value = await Task.Run(sensors.Read, ct).ConfigureAwait(false);
                break;
            case HostCapabilities.OsquerySelect:
                var sql = Arg(args, "sql") ?? "";
                if (!HostCapabilities.AllowedSql.Contains(sql)) throw new HostQueryException("notAllowed", "only the app's own osquery statements can run");
                value = await Need(backend.Osquery).RunQueryAsync(sql, ct).ConfigureAwait(false);
                break;
            case HostCapabilities.StorageDrives:
                value = await Need(backend.Commands).RunAsync(SystemCommandRunner.PowerShell, DriveHealthModule.Arguments, ct).ConfigureAwait(false);
                break;
            case HostCapabilities.StorageRetrims:
                var retrims = backend.Retrims is { } r ? await r.LatestAsync(ct).ConfigureAwait(false) : new Dictionary<char, RetrimRecord>();
                value = retrims.ToDictionary(kv => kv.Key.ToString(), kv => kv.Value);
                break;
            case HostCapabilities.EventLogQuery:
                var logName = Arg(args, "log") ?? "";
                var xpath = Arg(args, "xpath") ?? "";
                var max = int.TryParse(Arg(args, "max"), out var m) ? m : 0;
                if (!HostCapabilities.AllowedLogs.Contains(logName)) throw new HostQueryException("notAllowed", $"the {logName} log can't be read");
                if (xpath.Length is 0 or > HostCapabilities.MaxXPathLength) throw new HostQueryException("badRequest", "the event filter is empty or too long");
                if (max is < 1 or > HostCapabilities.MaxEvents) throw new HostQueryException("badRequest", $"max must be 1 to {HostCapabilities.MaxEvents}");
                value = await new WindowsEventLog(Need(backend.Commands)).QueryAsync(logName, xpath, max, ct).ConfigureAwait(false);
                break;
            case HostCapabilities.Minidumps:
                value = await Task.Run(backend.Minidumps, ct).ConfigureAwait(false);
                break;
            case HostCapabilities.EventReviews:
                value = backend.EventReviews().ToList();
                break;
            default:
                throw new HostQueryException("badRequest", $"unknown capability {capability}");
        }
        return JsonSerializer.SerializeToElement(value, value?.GetType() ?? typeof(object), HostCapabilities.Json);
    }

    private static T Need<T>(T? service) where T : class => service ?? throw new HostQueryException("failed", "the app can't answer this here");

    private static string? Arg(JsonElement? args, string name) =>
        args is { ValueKind: JsonValueKind.Object } a && a.TryGetProperty(name, out var v)
            ? v.ValueKind == JsonValueKind.String ? v.GetString() : v.GetRawText()
            : null;
}

/// <summary>The answer to <c>sensors.read</c> with availability set.</summary>
public sealed record AvailabilityAnswer(bool Available, string? Reason);

/// <summary>
/// The module host's end: <see cref="IHostQueries"/> over the protocol. Each call writes a query line and waits for the answer with the
/// same id, which the module host's reader hands to <see cref="Complete"/>.
/// </summary>
public sealed class HostQueriesClient(Action<ModuleHostMessage> send) : IHostQueries
{
    private readonly ConcurrentDictionary<int, TaskCompletionSource<ModuleHostMessage>> _pending = new();
    private int _next;

    /// <summary>How long a query waits for its answer.</summary>
    public TimeSpan AnswerTimeout { get; init; } = HostCapabilities.Timeout + TimeSpan.FromSeconds(30);

    /// <summary>An answer arrived (false when nothing was waiting for it).</summary>
    public bool Complete(ModuleHostMessage answer) =>
        answer.Id is { } id && _pending.TryRemove(id, out var waiting) && waiting.TrySetResult(answer);

    /// <summary>The app went away: every waiting query fails.</summary>
    public void FailAll(string reason)
    {
        foreach (var id in _pending.Keys) if (_pending.TryRemove(id, out var w)) w.TrySetException(new HostQueryException("failed", reason));
    }

    public async Task<T> QueryAsync<T>(string capability, object? args, CancellationToken ct)
    {
        var id = Interlocked.Increment(ref _next);
        var waiting = new TaskCompletionSource<ModuleHostMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pending[id] = waiting;
        using var cancel = ct.Register(() => { if (_pending.TryRemove(id, out var w)) w.TrySetCanceled(ct); });
        // The app holds every query to its own limit; past that (plus a margin) the answer isn't coming, so the check gets a failure
        // instead of waiting forever.
        using var late = new Timer(_ => { if (_pending.TryRemove(id, out var w)) w.TrySetException(new HostQueryException("timedOut", $"the app didn't answer {capability}")); },
            null, AnswerTimeout, Timeout.InfiniteTimeSpan);
        send(new ModuleHostMessage
        {
            Type = "query", Id = id, Capability = capability,
            Args = args is null ? null : JsonSerializer.SerializeToElement(args, args.GetType(), HostCapabilities.Json),
        });
        var answer = await waiting.Task.ConfigureAwait(false);
        if (answer.Ok != true) throw new HostQueryException(answer.Error ?? "failed", answer.Reason ?? $"{capability} wasn't answered");
        return answer.Value is { } v ? v.Deserialize<T>(HostCapabilities.Json)! : default!;
    }

    public async Task<ModuleAvailability> SensorsAvailabilityAsync(CancellationToken ct = default)
    {
        var a = await QueryAsync<AvailabilityAnswer>(HostCapabilities.SensorsRead, new { availability = "true" }, ct).ConfigureAwait(false);
        return a.Available ? ModuleAvailability.Available : ModuleAvailability.Unavailable(a.Reason ?? "Unavailable");
    }

    public Task<SensorSnapshot> ReadSensorsAsync(CancellationToken ct = default) => QueryAsync<SensorSnapshot>(HostCapabilities.SensorsRead, null, ct);

    public Task<OsqueryQueryResult> SelectAsync(string sql, CancellationToken ct = default) =>
        QueryAsync<OsqueryQueryResult>(HostCapabilities.OsquerySelect, new { sql }, ct);

    public Task<ProcessResult?> ReadDrivesAsync(CancellationToken ct = default) => QueryAsync<ProcessResult?>(HostCapabilities.StorageDrives, null, ct);

    public async Task<IReadOnlyDictionary<char, RetrimRecord>> ReadRetrimsAsync(CancellationToken ct = default)
    {
        var byLetter = await QueryAsync<Dictionary<string, RetrimRecord>?>(HostCapabilities.StorageRetrims, null, ct).ConfigureAwait(false);
        return (byLetter ?? []).Where(kv => kv.Key.Length == 1).ToDictionary(kv => kv.Key[0], kv => kv.Value);
    }

    public async Task<IReadOnlyList<WinEvent>?> QueryEventsAsync(string log, string xpath, int max, CancellationToken ct = default) =>
        await QueryAsync<List<WinEvent>?>(HostCapabilities.EventLogQuery, new { log, xpath, max = max.ToString(System.Globalization.CultureInfo.InvariantCulture) }, ct).ConfigureAwait(false);

    public async Task<IReadOnlyList<MinidumpFile>> ReadMinidumpsAsync(CancellationToken ct = default) =>
        await QueryAsync<List<MinidumpFile>?>(HostCapabilities.Minidumps, null, ct).ConfigureAwait(false) ?? [];

    public async Task<IReadOnlyCollection<string>> ReadEventReviewsAsync(CancellationToken ct = default) =>
        await QueryAsync<List<string>?>(HostCapabilities.EventReviews, null, ct).ConfigureAwait(false) ?? [];
}

/// <summary>Sensors through the app (<c>sensors.read</c>), for the Temperatures &amp; fans module in user mode.</summary>
public sealed class HostSensorProvider(IHostQueries queries) : ISensorProvider
{
    public ModuleAvailability CheckAvailability()
    {
        try { return queries.SensorsAvailabilityAsync().GetAwaiter().GetResult(); }
        catch (HostQueryException ex) { return ModuleAvailability.Unavailable($"The app couldn't read sensors: {ex.Message}"); }
    }

    public SensorSnapshot Read() => queries.ReadSensorsAsync().GetAwaiter().GetResult();
}

/// <summary>The retrim history through the app (<c>storage.retrims</c>).</summary>
public sealed class HostRetrimHistory(IHostQueries queries) : IRetrimHistory
{
    public async Task<IReadOnlyDictionary<char, RetrimRecord>> LatestAsync(CancellationToken ct = default)
    {
        try { return await queries.ReadRetrimsAsync(ct).ConfigureAwait(false); }
        catch (HostQueryException) { return new Dictionary<char, RetrimRecord>(); }
    }
}

public static class HostQueryExtensions
{
    /// <summary>Runs a host query and returns null (logging a warning) when the app refused or couldn't answer it.</summary>
    public static async Task<T?> AskAsync<T>(this IHostQueries host, string moduleName, ILogger? log, Func<IHostQueries, Task<T>> query) where T : class?
    {
        try { return await query(host).ConfigureAwait(false); }
        catch (HostQueryException ex) { log.Warn($"{moduleName}: the app didn't answer ({ex.Error}): {ex.Message}"); return null; }
    }
}

