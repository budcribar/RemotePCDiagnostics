using System.Text.Json;
using System.Text.Json.Nodes;
using RemotePCDiagnostics.Core.Changes;

namespace RemotePCDiagnostics.Core.Optimizations;

/// <summary>
/// #19: what keeps a browser running in the background, read by the Host for Chrome and Edge.
/// </summary>
/// <param name="LocalStateOk">The browser's <c>Local State</c> file was read, is valid JSON, and <c>background_mode.enabled</c> is absent or a bool.</param>
/// <param name="BackgroundModePref"><c>background_mode.enabled</c> in Local State ("Continue running background apps when … is closed"); null = not set
/// (Chromium's default on Windows: on).</param>
/// <param name="BackgroundModePolicy">The <c>BackgroundModeEnabled</c> policy (HKLM, else HKCU); null = not set. When set, the browser ignores Local State.</param>
/// <param name="StartupBoostPolicy">Edge only: <c>HKLM\SOFTWARE\Policies\Microsoft\Edge\StartupBoostEnabled</c>; null = not set.</param>
/// <param name="StartupBoostUserPolicy">Edge only: the same policy under HKCU (set by an organization); null = not set.</param>
public sealed record BrowserBackgroundInfo(BrowserKind Kind, bool LocalStateOk, bool? BackgroundModePref, int? BackgroundModePolicy = null,
    int? StartupBoostPolicy = null, int? StartupBoostUserPolicy = null);

/// <summary>
/// #19: stop the browser the person doesn't use (the one that isn't the default) from running in the background.
/// <list type="bullet">
/// <item>Chrome and Edge: <c>background_mode.enabled = false</c> in the browser's <c>Local State</c> (the user-level setting behind
/// "Continue running background apps when Google Chrome is closed" / "Continue running background extensions and apps when Microsoft Edge is closed").
/// The browser must be closed while the file is written (it rewrites the file on exit), so its windowless background processes are ended first;
/// a browser with a window open is never closed.</item>
/// <item>Edge only: Startup Boost has no documented user-level setting this app can write (Edge stores it in its own, undocumented prefs), so the
/// <c>StartupBoostEnabled = 0</c> machine policy is used. Any Edge policy makes Edge say "Managed by your organization"; undo deletes it.</item>
/// <item>Its <c>--no-startup-window</c> auto-launch Run entries (<c>GoogleChromeAutoLaunch_*</c>, <c>MicrosoftEdgeAutoLaunch_*</c>) are offered as
/// ordinary startup apps (StartupApproved, like Task Manager), only for this browser.</item>
/// </list>
/// </summary>
public static class BrowserBackground
{
    /// <summary>The Local State value this fix changes, as a JSON path.</summary>
    public static readonly IReadOnlyList<string> BackgroundModePath = ["background_mode", "enabled"];

    /// <summary>Journal target for the Local State value: "Edge|background_mode.enabled". Only these two targets are ever restored.</summary>
    public static string Target(BrowserKind kind) => $"{kind}|{string.Join('.', BackgroundModePath)}";

    /// <summary>The browser named by an allowlisted journal target, or null (anything else is refused).</summary>
    public static BrowserKind? ParseTarget(string? target) =>
        Enum.GetValues<BrowserKind>().Cast<BrowserKind?>().FirstOrDefault(k => string.Equals(Target(k!.Value), target, StringComparison.Ordinal));

    /// <summary>The non-default browser (Chrome ↔ Edge), or null when the default browser is unknown or something else (Firefox, …).</summary>
    public static BrowserKind? Secondary(MemorySnapshot s) => s.DefaultBrowser switch
    {
        BrowserKind.Chrome => BrowserKind.Edge,
        BrowserKind.Edge => BrowserKind.Chrome,
        _ => null,
    };

    public static BrowserBackgroundInfo? For(MemorySnapshot s, BrowserKind kind) => s.BrowserBackground?.FirstOrDefault(b => b.Kind == kind);

    /// <summary>"Continue running background apps" is on and this app may turn it off: Local State readable, not set to false, and no policy controls it.</summary>
    public static bool BackgroundModeOn(BrowserBackgroundInfo b) => b.LocalStateOk && b.BackgroundModePref != false && b.BackgroundModePolicy is null;

    /// <summary>Edge's Startup Boost isn't turned off by policy yet, and no organization policy sets it (HKLM or HKCU).</summary>
    public static bool StartupBoostChangeable(BrowserBackgroundInfo b) => b.Kind == BrowserKind.Edge && b.StartupBoostPolicy is null && b.StartupBoostUserPolicy is null;

    /// <summary>The browser's processes are running and none of them has a window (Startup Boost or background apps).</summary>
    public static bool RunningInBackground(MemorySnapshot s, BrowserKind kind) => s.App(BrowserPrefs.ProcessName(kind)) is { HasWindow: false };

    private static string AutoLaunchPrefix(BrowserKind kind) => kind == BrowserKind.Chrome ? "GoogleChromeAutoLaunch_" : "MicrosoftEdgeAutoLaunch_";

    /// <summary>The browser's own background auto-launch entry: HKCU Run "GoogleChromeAutoLaunch_&lt;hash&gt;" / "MicrosoftEdgeAutoLaunch_&lt;hash&gt;"
    /// running chrome.exe / msedge.exe with <c>--no-startup-window</c> (no window opens; it only starts the browser in the background).</summary>
    public static bool IsAutoLaunch(StartupEntry e, BrowserKind kind) =>
        e.Scope == StartupScope.CurrentUser
        && e.Name.StartsWith(AutoLaunchPrefix(kind), StringComparison.OrdinalIgnoreCase)
        && e.ExeName.Equals(BrowserPrefs.ProcessName(kind), StringComparison.OrdinalIgnoreCase)
        && e.Command.Contains("--no-startup-window", StringComparison.OrdinalIgnoreCase);

    public static bool IsAutoLaunch(StartupEntry e) => Enum.GetValues<BrowserKind>().Any(k => IsAutoLaunch(e, k));

    /// <summary>The non-default browser's enabled auto-launch entries.</summary>
    public static IReadOnlyList<StartupEntry> AutoLaunchEntries(MemorySnapshot s) =>
        Secondary(s) is { } kind ? (s.Startup ?? []).Where(e => e.Enabled && IsAutoLaunch(e, kind)).ToList() : [];

    /// <summary>
    /// Offer the background fix for the non-default browser when there's something to turn off and a sign it actually runs in the
    /// background: its processes run with no window, or its auto-launch entry starts it at sign-in.
    /// </summary>
    public static bool Offer(MemorySnapshot s) =>
        Secondary(s) is { } kind && For(s, kind) is { } b
        && (BackgroundModeOn(b) || StartupBoostChangeable(b))
        && (RunningInBackground(s, kind) || AutoLaunchEntries(s).Count > 0);

    // ---- Local State JSON ----

    private static JsonNode? Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try { return JsonNode.Parse(json); } catch (JsonException) { return null; }
    }

    /// <summary>Reads <c>background_mode.enabled</c>: false when the JSON is invalid or the value isn't a bool; <paramref name="value"/> null = not set.</summary>
    public static bool TryReadBackgroundMode(string? json, out bool? value)
    {
        value = null;
        if (Parse(json) is not JsonObject root) return false;
        if (!root.TryGetPropertyValue(BackgroundModePath[0], out var parent) || parent is null) return true;
        if (parent is not JsonObject obj) return false;
        if (!obj.TryGetPropertyValue(BackgroundModePath[1], out var v) || v is null) return true;
        if (v is JsonValue jv && jv.TryGetValue<bool>(out var b)) { value = b; return true; }
        return false;
    }

    /// <summary>
    /// The JSON with <c>background_mode.enabled</c> set to <paramref name="value"/>, or removed when null (back to the browser's default;
    /// an emptied <c>background_mode</c> object is removed too). Everything else is kept. Null when the JSON can't be changed safely.
    /// </summary>
    public static string? SetBackgroundMode(string? json, bool? value)
    {
        if (!TryReadBackgroundMode(json, out _) || Parse(json) is not JsonObject root) return null;
        var obj = root[BackgroundModePath[0]] as JsonObject;
        if (value is { } on)
        {
            if (obj is null) root[BackgroundModePath[0]] = obj = new JsonObject();
            obj[BackgroundModePath[1]] = on;
        }
        else if (obj is not null)
        {
            obj.Remove(BackgroundModePath[1]);
            if (obj.Count == 0) root.Remove(BackgroundModePath[0]);
        }
        return root.ToJsonString();
    }

    /// <summary>Journal form: "true" / "false", or null when the value wasn't set.</summary>
    public static string? Encode(bool? value) => value switch { true => "true", false => "false", null => null };

    public static bool TryDecode(string? previous, out bool? value)
    {
        value = null;
        if (previous is null) return true;
        if (previous == "true") { value = true; return true; }
        if (previous == "false") { value = false; return true; }
        return false;
    }

    /// <summary>"was on" / "was off" / "was not set (on)", for journal labels.</summary>
    public static string Describe(bool? value) => value switch { true => "was on", false => "was off", null => "was not set, so on" };

    /// <summary>The Edge Startup Boost machine policy is the only registry value this fix writes.</summary>
    public static RegistrySetting StartupBoostSetting => RegistryAllowlist.EdgeStartupBoostPolicy;

    /// <summary>
    /// Puts a journaled Local State value back (or removes it when it wasn't set), then reads it back. Only allowlisted targets;
    /// the browser's windowless background processes are ended first, and a browser with a window open is left alone (close it, then undo).
    /// </summary>
    public static async Task<(bool Ok, string Message)> RestoreAsync(IBrowserSettings sys, string target, string? previous, CancellationToken ct)
    {
        if (ParseTarget(target) is not { } kind) return (false, "That browser setting isn't one this app changes, so it was left as is.");
        if (!TryDecode(previous, out var old)) return (false, "The original setting wasn't recorded.");
        var name = BrowserPrefs.Label(kind);
        if (sys.IsBrowserRunning(kind))
        {
            var end = await sys.EndBrowserBackgroundAsync(kind, ct).ConfigureAwait(false);
            if (!end.Success || sys.IsBrowserRunning(kind)) return (false, $"Close {name} first, then undo.");
        }
        var json = sys.ReadBrowserLocalState(kind);
        var updated = SetBackgroundMode(json, old);
        if (updated is null) return (false, $"Couldn't read {name}'s settings file, so it was left as is.");
        sys.WriteBrowserLocalState(kind, updated);
        return TryReadBackgroundMode(sys.ReadBrowserLocalState(kind), out var now) && now == old
            ? (true, $"{name} may run in the background again (\"Continue running background apps\" {(old == false ? "left off" : "back on")}).")
            : (false, $"{name} didn't keep its original setting.");
    }

    /// <summary>What one click changed, kept with its per-item undo entry.</summary>
    /// <param name="LocalStateChanged">background_mode.enabled was written; <paramref name="LocalStatePrevious"/> is its old journal form.</param>
    public sealed record Undo(bool LocalStateChanged, string? LocalStatePrevious, IReadOnlyList<RegistryUndo.Item> Registry);

    public static string EncodeUndo(Undo u) => JsonSerializer.Serialize(u);

    public static Undo? DecodeUndo(string? json)
    {
        try { return string.IsNullOrEmpty(json) ? null : JsonSerializer.Deserialize<Undo>(json); }
        catch (JsonException) { return null; }
    }
}
