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

    /// <summary>In the module host: the page data of <paramref name="module"/> after a run, or null when its page needs none.</summary>
    public static Dictionary<string, JsonElement>? Write(IDiagnosticModule module)
    {
        Dictionary<string, JsonElement>? data = null;
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

    private sealed record HangCard(string CardId);
}

/// <summary>A call from a module's page that the module host couldn't answer.</summary>
public sealed class ModuleCallException(string error, string message) : Exception(message)
{
    /// <summary>unknown (the module offers no such call), failed, timeout.</summary>
    public string Error { get; } = error;
}
