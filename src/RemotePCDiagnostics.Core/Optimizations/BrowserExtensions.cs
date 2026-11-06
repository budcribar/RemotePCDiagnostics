using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using RemotePCDiagnostics.Core.Changes;

namespace RemotePCDiagnostics.Core.Optimizations;

/// <summary>
/// One junk, adware or discontinued browser extension this app may block (#22). Only these exact IDs can ever be written to a
/// browser's <c>ExtensionInstallBlocklist</c>.
/// </summary>
/// <param name="Id">The 32-letter extension ID (a–p), as in the store URL and the profile's <c>Extensions\&lt;id&gt;</c> folder.</param>
/// <param name="Browsers">Browsers it's offered in. A Chrome Web Store ID is the same extension when installed in Edge from that store.</param>
/// <param name="Source">Where the ID was verified (store listing), for reviewers.</param>
/// <param name="Why">One sentence for the card: what it does in the background.</param>
/// <param name="Loses">What the client loses, e.g. "automatic coupon codes and PayPal Honey cash back".</param>
public sealed record KnownExtension(string Id, string Name, IReadOnlyList<BrowserKind> Browsers, string Source, string Why, string Loses);

/// <summary>An allowlisted extension found installed in one browser, with the profiles it's in.</summary>
/// <param name="Profiles">Display names of the profiles (from Local State; the folder name when it has none).</param>
/// <param name="SizeBytes">Size of its <c>Extensions\&lt;id&gt;</c> folders (null = unknown).</param>
public sealed record FoundExtension(BrowserKind Browser, string Id, IReadOnlyList<string> Profiles, long? SizeBytes = null);

/// <summary>One value under a browser's <c>ExtensionInstallBlocklist</c> policy key. <paramref name="Data"/> is null when it isn't a REG_SZ.</summary>
public sealed record BlocklistEntry(string Name, string? Data);

/// <summary>
/// #22: allowlisted extensions found in Chrome and Edge (every profile of this Windows account), and each browser's current
/// machine blocklist. A null blocklist = couldn't be read (nothing is offered for that browser).
/// </summary>
public sealed record BrowserExtensionsInfo(
    IReadOnlyList<FoundExtension> Found,
    IReadOnlyList<BlocklistEntry>? ChromeBlocklist,
    IReadOnlyList<BlocklistEntry>? EdgeBlocklist)
{
    public IReadOnlyList<BlocklistEntry>? Blocklist(BrowserKind k) => k == BrowserKind.Chrome ? ChromeBlocklist : EdgeBlocklist;
}

/// <summary>Which extensions may be blocked (#22), the blocklist policy keys, and the pure rules for adding/removing one entry.</summary>
public static class BrowserExtensions
{
    private static readonly BrowserKind[] Both = [BrowserKind.Chrome, BrowserKind.Edge];

    /// <summary>
    /// The only extensions this app may block. Each ID was checked against its store listing; extensions whose ID couldn't be
    /// verified (e.g. Amazon Assistant's Edge Add-ons ID) are deliberately left out.
    /// </summary>
    public static readonly IReadOnlyList<KnownExtension> Allowlist =
    [
        new("bmnlcjabgnpnenekpadlanbbkooimhnj", "PayPal Honey", Both, "Chrome Web Store: chrome.google.com/webstore/detail/bmnlcjabgnpnenekpadlanbbkooimhnj",
            "It's a coupon and cash-back add-on that runs on every shopping page you open.",
            "automatic coupon codes and PayPal Honey cash back"),
        new("amnbcmdbanbkjhnfoeceemmmdiepnbpp", "PayPal Honey", [BrowserKind.Edge], "Edge Add-ons: microsoftedge.microsoft.com/addons/detail/honey/amnbcmdbanbkjhnfoeceemmmdiepnbpp",
            "It's a coupon and cash-back add-on that runs on every shopping page you open.",
            "automatic coupon codes and PayPal Honey cash back"),
        new("lklfbkdigihjaaeamncibechhgalldgl", "MSN New Tab", Both, "Chrome Web Store: chrome.google.com/webstore/detail/msn-new-tab/lklfbkdigihjaaeamncibechhgalldgl (Microsoft Corporation)",
            "It replaces the new tab page with an MSN news and ads feed that loads every time a tab opens.",
            "the MSN news page on new tabs (you get the browser's normal new tab page)"),
        new("pbjikboenpfhbbejgkoklgkhjpfogcam", "Amazon Assistant", Both, "Chrome Web Store: Amazon Assistant for Chrome (pbjikboenpfhbbejgkoklgkhjpfogcam)",
            "Amazon has discontinued it, so it no longer gets updates, but it still runs on the pages you visit.",
            "Amazon price comparisons and deal pop-ups"),
    ];

    /// <summary>The allowlisted extension with this ID for this browser, or null (never blocked then).</summary>
    public static KnownExtension? Known(BrowserKind browser, string? id) =>
        id is null ? null : Allowlist.FirstOrDefault(e => e.Id.Equals(id, StringComparison.OrdinalIgnoreCase) && e.Browsers.Contains(browser));

    public static IEnumerable<KnownExtension> KnownFor(BrowserKind browser) => Allowlist.Where(e => e.Browsers.Contains(browser));

    /// <summary>HKLM key of the browser's blocklist policy (a list of numbered REG_SZ values "1", "2", … = extension IDs).</summary>
    public static string BlocklistKey(BrowserKind k) => k == BrowserKind.Chrome
        ? @"SOFTWARE\Policies\Google\Chrome\ExtensionInstallBlocklist"
        : @"SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist";

    /// <summary>Journal / action target: "Chrome|bmnlcjabgnpnenekpadlanbbkooimhnj".</summary>
    public static string Target(BrowserKind browser, string id) => $"{browser}|{id.ToLowerInvariant()}";

    /// <summary>Parses <see cref="Target"/>; false for anything else (unknown browser, malformed ID).</summary>
    public static bool TryParseTarget(string? target, out BrowserKind browser, out string id)
    {
        browser = default; id = "";
        var sep = target?.IndexOf('|') ?? -1;
        if (sep <= 0) return false;
        var name = target![..sep];
        if (!Enum.TryParse(name, ignoreCase: false, out browser) || browser.ToString() != name) return false;
        id = target[(sep + 1)..];
        return IsExtensionId(id);
    }

    /// <summary>32 letters a–p (how Chrome and Edge encode extension IDs).</summary>
    public static bool IsExtensionId(string? id) => id is { Length: 32 } && id.All(c => c is >= 'a' and <= 'p');

    /// <summary>A blocklist value name this app uses: "1", "2", … (no sign, no leading zeros).</summary>
    public static bool IsEntryName(string? name) =>
        int.TryParse(name, NumberStyles.None, CultureInfo.InvariantCulture, out var n) && n > 0 && n.ToString(CultureInfo.InvariantCulture) == name;

    private static int? Number(string name) => IsEntryName(name) ? int.Parse(name, CultureInfo.InvariantCulture) : null;

    /// <summary>The ID is already blocked (any entry), or everything is ("*").</summary>
    public static bool IsBlocked(IReadOnlyList<BlocklistEntry> list, string id) =>
        list.Any(e => e.Data?.Trim() is { } d && (d == "*" || d.Equals(id, StringComparison.OrdinalIgnoreCase)));

    /// <summary>
    /// The value name for a new entry: the next number after 1..N. Null when the existing numbers aren't 1..N (a gap):
    /// browsers read the list in order, so this app leaves an unusual list alone rather than renumbering anything.
    /// </summary>
    public static string? NextName(IReadOnlyList<BlocklistEntry> list)
    {
        var numbers = list.Select(e => Number(e.Name)).OfType<int>().ToHashSet();
        var n = 0;
        while (numbers.Contains(n + 1)) n++;
        return numbers.Count == n ? (n + 1).ToString(CultureInfo.InvariantCulture) : null;
    }

    /// <summary>Entries numbered after <paramref name="name"/> (removing ours would leave a gap before them).</summary>
    public static bool HasEntriesAfter(IReadOnlyList<BlocklistEntry> list, string name) =>
        Number(name) is { } mine && list.Any(e => Number(e.Name) is { } n && n > mine);

    /// <summary>Found extensions that can be offered: allowlisted for that browser, blocklist readable, not blocked yet, and a clean 1..N list.</summary>
    public static IReadOnlyList<(FoundExtension Found, KnownExtension Known)> Offer(MemorySnapshot s)
    {
        if (s.Extensions is not { } info) return [];
        var list = new List<(FoundExtension, KnownExtension)>();
        foreach (var f in info.Found)
        {
            if (Known(f.Browser, f.Id) is not { } k || f.Profiles.Count == 0) continue;
            if (info.Blocklist(f.Browser) is not { } bl || IsBlocked(bl, f.Id) || NextName(bl) is null) continue;
            if (list.Any(x => x.Item1.Browser == f.Browser && x.Item2.Id == k.Id)) continue;
            list.Add((f, k));
        }
        return list;
    }

    /// <summary>Suggestion id: "ext-block-chrome-bmnlcjabgnpnenekpadlanbbkooimhnj".</summary>
    public static string SuggestionId(BrowserKind browser, string id) => $"ext-block-{browser.ToString().ToLowerInvariant()}-{id.ToLowerInvariant()}";

    // ---- profile files (parsed in Core, read by the Host) ----

    /// <summary>Profile folder → display name from Local State's <c>profile.info_cache</c> ("Default" → "Person 1"). Empty when unreadable.</summary>
    public static IReadOnlyDictionary<string, string> ProfileNames(string? localStateJson)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            if (string.IsNullOrWhiteSpace(localStateJson) || JsonNode.Parse(localStateJson)?["profile"]?["info_cache"] is not JsonObject cache) return map;
            foreach (var (dir, node) in cache)
                if (node?["name"] is JsonValue v && v.TryGetValue<string>(out var name) && !string.IsNullOrWhiteSpace(name)) map[dir] = name.Trim();
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException) { }
        return map;
    }

    /// <summary>
    /// Extension IDs registered in a profile: the keys of <c>extensions.settings</c> in <c>Secure Preferences</c> and/or <c>Preferences</c>.
    /// Null when neither file has that section (unreadable or a different format): the caller then relies on the Extensions folder alone.
    /// </summary>
    public static IReadOnlySet<string>? IdsInPreferences(params string?[] preferencesJson)
    {
        HashSet<string>? ids = null;
        foreach (var json in preferencesJson)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(json) || JsonNode.Parse(json)?["extensions"]?["settings"] is not JsonObject settings) continue;
                ids ??= new(StringComparer.OrdinalIgnoreCase);
                foreach (var (id, _) in settings) ids.Add(id);
            }
            catch (Exception ex) when (ex is JsonException or InvalidOperationException) { }
        }
        return ids;
    }

    // ---- undo (shared by per-item undo and Undo all) ----

    /// <summary>
    /// Removes the one blocklist entry this app added (<paramref name="valueName"/> holding the journaled ID) and reads it back.
    /// Never renumbers or touches other entries: if a later entry exists, or another entry (not ours) blocks the same ID,
    /// it's left as is and reported. May throw (access denied). Once our entry is gone, the policy keys the block created
    /// (<paramref name="createdKey"/>, e.g. "SOFTWARE\Policies\Google") are deleted again while empty, so the browser stops saying it's managed.
    /// </summary>
    public static (bool Ok, string Message) RemoveBlock(IMemorySystem sys, string? target, string? valueName, string? createdKey = null, ILogger? log = null)
    {
        if (!TryParseTarget(target, out var browser, out var id) || Known(browser, id) is not { } known)
            return (false, "That extension isn't one this app blocks, so the browser's list was left as is.");
        if (!IsEntryName(valueName)) return (false, "The blocklist entry wasn't recorded.");
        var label = BrowserPrefs.Label(browser);
        if (sys.ReadExtensionBlocklist(browser) is not { } list) return (false, $"Couldn't read {label}'s extension blocklist.");
        var mine = list.FirstOrDefault(e => e.Name == valueName);
        if (mine?.Data?.Trim().Equals(id, StringComparison.OrdinalIgnoreCase) != true)
            return IsBlocked(list, id)
                ? (false, $"{known.Name} is still blocked in {label} by an entry this app didn't add (your organization may manage it); left as is.")
                : Cleaned((true, $"{known.Name} wasn't blocked in {label} any more."));
        if (HasEntriesAfter(list, valueName!))
            return (false, $"Another extension was added to {label}'s blocklist after {known.Name}. Undo the extensions blocked later first; this app never renumbers the list.");
        sys.RemoveExtensionBlock(browser, valueName!, id);
        var after = sys.ReadExtensionBlocklist(browser);
        return after is not null && !after.Any(e => e.Name == valueName)
            ? Cleaned((true, $"{known.Name} is allowed in {label} again; the browser turns it back on by itself (if it doesn't, reinstall it from the store)."))
            : (false, $"Windows didn't remove {known.Name} from {label}'s blocklist (administrator rights needed).");

        (bool, string) Cleaned((bool, string) result)
        {
            RegistryKeyCleanup.Remove(sys, RegistryRoot.LocalMachine, BlocklistKey(browser), createdKey, log);
            return result;
        }
    }
}
