using System.Globalization;
using System.Text.Json;
using RemotePCDiagnostics.Core.Memory;

namespace RemotePCDiagnostics.Core.Changes;

public enum RegistryRoot { LocalMachine, CurrentUser }

/// <summary>One registry DWORD this app may change. <see cref="Target"/> is how the change journal names it.</summary>
public sealed record RegistrySetting(RegistryRoot Root, string Key, string Name)
{
    /// <summary>"HKLM\SOFTWARE\Policies\Microsoft\Dsh|AllowNewsAndInterests".</summary>
    public string Target => $"{(Root == RegistryRoot.LocalMachine ? "HKLM" : "HKCU")}\\{Key}|{Name}";
}

/// <summary>
/// The exact registry values this app may write, delete or restore. Applying a fix and undoing a journal record
/// (<see cref="ChangeKind.RegistryValue"/>) both go through <see cref="Find"/>, so a path read from the journal file
/// that isn't listed here is never touched.
/// </summary>
public static class RegistryAllowlist
{
    /// <summary>Windows 11 Widgets machine policy (#16): 0 = Widgets off for everyone.</summary>
    public static readonly RegistrySetting WidgetsPolicy = new(RegistryRoot.LocalMachine, @"SOFTWARE\Policies\Microsoft\Dsh", "AllowNewsAndInterests");

    /// <summary>Search highlights machine policy (#17): 0 = no Bing pictures / trending searches in the Search box.</summary>
    public static readonly RegistrySetting SearchHighlightsPolicy = new(RegistryRoot.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\Windows Search", "EnableDynamicContentInWSB");

    /// <summary>The per-account Settings toggle for Search highlights (Settings > Privacy & security > Search permissions).</summary>
    public static readonly RegistrySetting SearchHighlightsToggle = new(RegistryRoot.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\SearchSettings", "IsDynamicSearchBoxEnabled");

    public static readonly IReadOnlyList<RegistrySetting> All = [WidgetsPolicy, SearchHighlightsPolicy, SearchHighlightsToggle];

    /// <summary>The allowlisted setting with this target (case-insensitive), or null.</summary>
    public static RegistrySetting? Find(string? target) =>
        target is null ? null : All.FirstOrDefault(s => s.Target.Equals(target, StringComparison.OrdinalIgnoreCase));

    /// <summary>Journal form of a DWORD: decimal text, or null when the value didn't exist.</summary>
    public static string? Encode(int? value) => value?.ToString(CultureInfo.InvariantCulture);

    /// <summary>null = the value was absent (undo deletes it). False when the text isn't a recorded DWORD.</summary>
    public static bool TryDecode(string? previous, out int? value)
    {
        value = null;
        if (previous is null) return true;
        if (!int.TryParse(previous, NumberStyles.Integer, CultureInfo.InvariantCulture, out var v)) return false;
        value = v;
        return true;
    }

    /// <summary>"not set" / "set to 1", for journal labels.</summary>
    public static string Describe(int? value) => value is { } v ? $"set to {v.ToString(CultureInfo.InvariantCulture)}" : "not set";

    /// <summary>
    /// Puts a journaled value back (writes the old DWORD, or deletes it when it was absent) and reads it back.
    /// Refuses targets that aren't on the allowlist. May throw (access denied).
    /// </summary>
    public static (bool Ok, string Message) Restore(IMemorySystem sys, string target, string? previous)
    {
        if (Find(target) is not { } s) return (false, "That registry value isn't one this app changes, so it was left as is.");
        if (!TryDecode(previous, out var v)) return (false, "The original value wasn't recorded.");
        if (v is { } old) sys.WriteDword(s, old); else sys.DeleteDword(s);
        return sys.ReadDword(s) == v
            ? (true, v is null ? "Setting removed again (back to the Windows default)." : $"Setting back to {v}.")
            : (false, "Windows didn't keep the original value (administrator rights needed, or your organization manages it).");
    }
}

/// <summary>Several registry values changed by one click, saved with its per-item undo entry.</summary>
public static class RegistryUndo
{
    public sealed record Item(string Target, string? Previous);

    public static string Encode(IReadOnlyList<Item> items) => JsonSerializer.Serialize(items);

    public static IReadOnlyList<Item> Decode(string? json)
    {
        try { return string.IsNullOrEmpty(json) ? [] : JsonSerializer.Deserialize<List<Item>>(json) ?? []; }
        catch (JsonException) { return []; }
    }
}
