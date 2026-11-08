using System.Text.Json;
using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Core.Plugins;

/// <summary>
/// What a module's page in the app needs from the module itself, beyond its report, when the module runs out of process. In process the
/// page asks the module object (<see cref="IServiceRows"/>, <see cref="IHangEvidenceSource"/>); out of process that object is in the
/// module host, so:
/// <list type="bullet">
/// <item>data the page reads from the last run travels with the result (<see cref="ModuleHostMessage.PageData"/>, written by
/// <see cref="Write"/>): the services behind the Services rows, the card that can look up freeze evidence;</item>
/// <item>a click that needs the module (Crashes' "Find related evidence") is a call: the app sends <c>call</c> with a name and
/// arguments, the host runs it on the module (<see cref="InvokeAsync"/>) and sends <c>return</c> with the same id.</item>
/// </list>
/// The app takes either only from a module that ships with it. The fixes themselves (Start, Stop, Restart a service; one-click fixes) stay
/// in the app as before: the module only says which rows they apply to.
/// </summary>
public static class ModulePageCalls
{
    /// <summary>Page data: the services the last run found (<see cref="IServiceRows.Latest"/>), a list of <see cref="ServiceInfo"/>.</summary>
    public const string ServiceRows = "serviceRows";

    /// <summary>Page data: <c>{"cardId": ...}</c> (<see cref="IHangEvidenceSource.HangCardId"/>). Call: the freeze evidence for a list of
    /// <see cref="HangOccurrence"/> (<see cref="IHangEvidenceSource.FindHangEvidenceAsync"/>), returned as text.</summary>
    public const string HangEvidence = "hangEvidence";

    /// <summary>Page data: the module's extra panels (<see cref="IHasAreaPanels.Panels"/>, a number).</summary>
    public const string Panels = "panels";

    /// <summary>Page data of a per-device module: <c>{"keys": [...], "report": ...}</c>, its one report of the devices with those keys
    /// (<see cref="IInstanceSummary.Combine"/>, an <see cref="AreaReport"/>).</summary>
    public const string Combined = "combined";

    /// <summary>In the module host: the page data of <paramref name="module"/> after a run, or null when its page needs none. For a
    /// per-device module, <paramref name="instances"/> are the devices it found and <paramref name="results"/> the latest result of each
    /// device this host ran: what <see cref="IInstanceSummary.Combine"/> folds into one report.</summary>
    public static Dictionary<string, JsonElement>? Write(IDiagnosticModule module, IReadOnlyList<ModuleInstance>? instances = null,
        IReadOnlyDictionary<string, DiagnosticResult>? results = null)
    {
        Dictionary<string, JsonElement>? data = null;
        if (module is IHasAreaPanels { Panels: not AreaPanels.None } panels)
            (data ??= [])[Panels] = JsonSerializer.SerializeToElement((int)panels.Panels, ModuleHostMessage.Json);
        if (module is IInstanceSummary summary && instances is { Count: > 0 })
        {
            // A device this host didn't run counts by its key only (its result, from an earlier host, is in the app).
            var all = instances.Select(i => results?.GetValueOrDefault(i.Key)
                ?? new DiagnosticResult(module.Name, DiagnosticStatus.NotRun, "", DateTimeOffset.Now) { InstanceKey = i.Key, InstanceLabel = i.Label }).ToList();
            if (summary.Combine(all) is AreaReport report)
                (data ??= [])[Combined] = JsonSerializer.SerializeToElement(new CombinedReport([.. instances.Select(i => i.Key)], report), ModuleHostMessage.Json);
        }
        if (module is IServiceRows services)
            (data ??= [])[ServiceRows] = JsonSerializer.SerializeToElement(services.Latest.Values.ToList(), ModuleHostMessage.Json);
        if (module is IHangEvidenceSource hangs)
            (data ??= [])[HangEvidence] = JsonSerializer.SerializeToElement(new HangCard(hangs.HangCardId), ModuleHostMessage.Json);
        return data;
    }

    /// <summary>In the module host: runs call <paramref name="name"/> on <paramref name="module"/>. Throws <see cref="NotSupportedException"/>
    /// for a call the module doesn't offer.</summary>
    public static async Task<JsonElement> InvokeAsync(IDiagnosticModule module, string name, JsonElement? args, CancellationToken ct)
    {
        switch (name)
        {
            case HangEvidence when module is IHangEvidenceSource hangs:
                var occurrences = args is { ValueKind: JsonValueKind.Array } a ? a.Deserialize<List<HangOccurrence>>(ModuleHostMessage.Json) ?? [] : [];
                var text = await hangs.FindHangEvidenceAsync(occurrences, ct).ConfigureAwait(false);
                return JsonSerializer.SerializeToElement(text, ModuleHostMessage.Json);
            default:
                throw new NotSupportedException($"the module offers no call \"{name}\"");
        }
    }

    /// <summary>In the app: the services from page data, by name (as <see cref="ServicesModule.Latest"/>), or null when there are none.</summary>
    public static IReadOnlyDictionary<string, ServiceInfo>? ReadServiceRows(Dictionary<string, JsonElement>? data)
    {
        if (data is null || !data.TryGetValue(ServiceRows, out var e)) return null;
        try
        {
            var list = e.Deserialize<List<ServiceInfo>>(ModuleHostMessage.Json) ?? [];
            return list.Where(s => s is { Name.Length: > 0 }).GroupBy(s => s.Name, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
        }
        catch (JsonException) { return null; }
    }

    /// <summary>In the app: the card that can look up freeze evidence, from page data; null when the module offers none.</summary>
    public static string? ReadHangCard(Dictionary<string, JsonElement>? data)
    {
        if (data is null || !data.TryGetValue(HangEvidence, out var e)) return null;
        try { return e.Deserialize<HangCard>(ModuleHostMessage.Json)?.CardId is { Length: > 0 } id ? id : null; }
        catch (JsonException) { return null; }
    }

    /// <summary>In the app: the module's extra panels from page data.</summary>
    public static AreaPanels ReadPanels(Dictionary<string, JsonElement>? data)
    {
        if (data is null || !data.TryGetValue(Panels, out var e) || e.ValueKind != JsonValueKind.Number || !e.TryGetInt32(out var n)) return AreaPanels.None;
        return (AreaPanels)n & (AreaPanels.MemorySuggestions | AreaPanels.StorageCleanup);
    }

    /// <summary>In the app: a per-device module's one report and the device keys it covers, from page data.</summary>
    public static (HashSet<string> Keys, object? Report)? ReadCombined(Dictionary<string, JsonElement>? data)
    {
        if (data is null || !data.TryGetValue(Combined, out var e)) return null;
        try
        {
            return e.Deserialize<CombinedReport>(ModuleHostMessage.Json) is { Keys: { } keys, Report: { } report }
                ? (keys.ToHashSet(StringComparer.OrdinalIgnoreCase), report) : null;
        }
        catch (JsonException) { return null; }
    }

    private sealed record HangCard(string CardId);
    private sealed record CombinedReport(List<string> Keys, AreaReport Report);
}

/// <summary>A call from a module's page that the module host couldn't answer.</summary>
public sealed class ModuleCallException(string error, string message) : Exception(message)
{
    /// <summary>unknown (the module offers no such call), failed, timeout.</summary>
    public string Error { get; } = error;
}
