using System.Text.Json;
using System.Text.Json.Nodes;

namespace RemotePCDiagnostics.Core.Optimizations;

/// <summary>
/// Reads/turns on the browser's memory-saving setting in its <c>Local State</c> JSON.
/// Chrome: <c>performance_tuning.high_efficiency_mode.state</c> (0 = off) or the older <c>.enabled</c> bool.
/// Edge: <c>performance_tuning.sleeping_tabs.enabled</c> or <c>performance_tuning.efficiency_mode.state</c>.
/// Writing only flips a key that already exists (never invents settings), and must only happen while the browser is closed
/// (a running browser overwrites the file on exit).
/// </summary>
public static class BrowserPrefs
{
    public static readonly IReadOnlyDictionary<BrowserKind, string> SettingsUrl = new Dictionary<BrowserKind, string>
    {
        [BrowserKind.Chrome] = "chrome://settings/performance",
        [BrowserKind.Edge] = "edge://settings/system/performance",
    };

    public static string Label(BrowserKind k) => k == BrowserKind.Chrome ? "Chrome" : "Microsoft Edge";
    public static string FeatureName(BrowserKind k) => k == BrowserKind.Chrome ? "Memory Saver" : "Sleeping tabs";
    public static string ProcessName(BrowserKind k) => k == BrowserKind.Chrome ? "chrome" : "msedge";

    private static string[][] Paths(BrowserKind k) => k == BrowserKind.Chrome
        ? [["performance_tuning", "high_efficiency_mode", "state"], ["performance_tuning", "high_efficiency_mode", "enabled"]]
        : [["performance_tuning", "sleeping_tabs", "enabled"], ["performance_tuning", "efficiency_mode", "state"]];

    private static JsonNode? Find(JsonNode? root, string[] path)
    {
        var n = root;
        foreach (var p in path) { n = (n as JsonObject)?[p]; if (n is null) return null; }
        return n;
    }

    private static bool? AsOn(JsonNode n)
    {
        if (n is not JsonValue v) return null;
        if (v.TryGetValue<bool>(out var b)) return b;
        if (v.TryGetValue<int>(out var i)) return i != 0;
        if (v.TryGetValue<long>(out var l)) return l != 0;
        if (v.TryGetValue<double>(out var d)) return d != 0;
        return null;
    }

    /// <summary>True/false when the setting is in the file; null when the JSON is invalid or the key isn't there.</summary>
    public static bool? ReadMemorySaver(string? json, BrowserKind kind)
    {
        var root = Parse(json);
        if (root is null) return null;
        foreach (var p in Paths(kind)) if (Find(root, p) is { } n && AsOn(n) is { } on) return on;
        return null;
    }

    /// <summary>Returns the JSON with the setting turned on, or null when there is no existing key to flip.</summary>
    public static string? EnableMemorySaver(string? json, BrowserKind kind)
    {
        var root = Parse(json);
        if (root is null) return null;
        foreach (var p in Paths(kind))
        {
            if (Find(root, p[..^1]) is not JsonObject parent || parent[p[^1]] is not JsonValue v) continue;
            if (v.TryGetValue<bool>(out _)) parent[p[^1]] = true;
            else if (AsOn(v) is not null) parent[p[^1]] = 1;
            else continue;
            return root.ToJsonString();
        }
        return null;
    }

    private static JsonNode? Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try { return JsonNode.Parse(json); } catch (JsonException) { return null; }
    }
}
