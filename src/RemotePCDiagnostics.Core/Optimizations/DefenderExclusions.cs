using System.Text.Json;

namespace RemotePCDiagnostics.Core.Optimizations;

/// <summary>
/// Microsoft Defender state for the "stop scanning code and build folders" fix.
/// <see cref="Active"/> is false when Defender isn't the PC's real-time antivirus (another antivirus, passive mode, turned off),
/// and then nothing is suggested.
/// </summary>
/// <param name="ProjectFolders">Code folders found on this PC (before removing ones already excluded); empty = no development here.</param>
/// <param name="MissingFolders">Folders to add: code folders and the NuGet package cache not yet excluded.</param>
/// <param name="MissingProcesses">Full paths of build tools to add (devenv, MSBuild, the compiler server) not yet excluded.</param>
public sealed record DefenderInfo(bool Active, IReadOnlyList<string> ProjectFolders, IReadOnlyList<string> MissingFolders, IReadOnlyList<string> MissingProcesses)
{
    public bool HasWork => Active && ProjectFolders.Count > 0 && (MissingFolders.Count > 0 || MissingProcesses.Count > 0);
}

/// <summary>Reads Defender's status and exclusions, and works out which exclusions are still missing.</summary>
public static class DefenderProbe
{
    public static string Script => Scripts.PowerShellScripts.Get("DefenderExclusions");

    public sealed record Status(bool Active, IReadOnlyList<string> Paths, IReadOnlyList<string> Processes, bool ExclusionsReadable);

    /// <summary>Null when the output can't be read. Non-admin reads return "N/A: Must be an administrator…" instead of the lists.</summary>
    public static Status? Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try
        {
            using var doc = JsonDocument.Parse(json);
            var r = doc.RootElement;
            var on = r.TryGetProperty("On", out var o) && string.Equals(o.GetString(), "True", StringComparison.OrdinalIgnoreCase);
            var mode = r.TryGetProperty("Mode", out var m) ? m.GetString() : null;
            // "Normal" = Defender is the active antivirus; "Passive Mode" / "EDR Block Mode" = another antivirus is.
            var active = on && (string.IsNullOrEmpty(mode) || mode.Equals("Normal", StringComparison.OrdinalIgnoreCase));
            var paths = Strings(r, "Paths");
            var procs = Strings(r, "Procs");
            var readable = !paths.Concat(procs).Any(x => x.StartsWith("N/A", StringComparison.OrdinalIgnoreCase));
            return new(active, readable ? paths : [], readable ? procs : [], readable);
        }
        catch (JsonException) { return null; }
    }

    private static List<string> Strings(JsonElement r, string name)
    {
        if (!r.TryGetProperty(name, out var e)) return [];
        if (e.ValueKind == JsonValueKind.String) return e.GetString() is { Length: > 0 } one ? [one] : [];
        if (e.ValueKind != JsonValueKind.Array) return [];
        return e.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()!).Where(x => x.Length > 0).ToList();
    }

    /// <summary>An existing exclusion covers a folder when it is that folder or a parent of it (C:\src and C:\src\* both cover C:\src\app).</summary>
    public static bool Covers(string existing, string folder)
    {
        var e = Normalize(existing);
        if (e.EndsWith("\\*", StringComparison.Ordinal)) e = e[..^2];
        if (e.Contains('*') || e.Contains('?')) return false; // other wildcards: don't guess
        var f = Normalize(folder);
        return f.Equals(e, StringComparison.OrdinalIgnoreCase) || f.StartsWith(e + "\\", StringComparison.OrdinalIgnoreCase);
    }

    private static string Normalize(string p) => Environment.ExpandEnvironmentVariables(p.Trim().Trim('"')).Replace('/', '\\').TrimEnd('\\');

    public static DefenderInfo Plan(Status status, IReadOnlyList<string> projectFolders, string? nugetPackages, IReadOnlyList<string> buildTools)
    {
        if (!status.Active || !status.ExclusionsReadable) return new(false, projectFolders, [], []);
        var wanted = projectFolders.Concat(nugetPackages is null ? [] : [nugetPackages]).Distinct(StringComparer.OrdinalIgnoreCase);
        var missing = wanted.Where(f => !status.Paths.Any(e => Covers(e, f))).ToList();
        var procs = buildTools.Where(t => !status.Processes.Any(e => Normalize(e).Equals(Normalize(t), StringComparison.OrdinalIgnoreCase))).ToList();
        return new(true, projectFolders, missing, procs);
    }

    /// <summary>
    /// "19 folders and 7 build tools": what the card offers (the missing exclusions) and what the result confirms, counted the same way.
    /// Folders include the NuGet package cache when it's one of them.
    /// </summary>
    public static string Describe(int folders, int processes) => (folders, processes) switch
    {
        ( > 0, > 0) => $"{MemoryText.Plural(folders, "folder")} and {MemoryText.Plural(processes, "build tool")}",
        ( > 0, _) => MemoryText.Plural(folders, "folder"),
        (_, > 0) => MemoryText.Plural(processes, "build tool"),
        _ => "nothing new",
    };

    private static string Q(string s) => "'" + s.Replace("'", "''") + "'";

    /// <summary>Adds the exclusions, then reads them back: an organization's policy can make local exclusions ineffective.</summary>
    public static string AddScript(IReadOnlyList<string> folders, IReadOnlyList<string> processes) =>
        "$ErrorActionPreference='Stop';" +
        (folders.Count > 0 ? $"Add-MpPreference -ExclusionPath @({string.Join(",", folders.Select(Q))});" : "") +
        (processes.Count > 0 ? $"Add-MpPreference -ExclusionProcess @({string.Join(",", processes.Select(Q))});" : "") +
        "$p=Get-MpPreference;[pscustomobject]@{Paths=@($p.ExclusionPath | Where-Object { $_ });Procs=@($p.ExclusionProcess | Where-Object { $_ })} | ConvertTo-Json -Compress";

    public static string RemoveScript(IReadOnlyList<string> folders, IReadOnlyList<string> processes) =>
        "$ErrorActionPreference='Stop';" +
        (folders.Count > 0 ? $"Remove-MpPreference -ExclusionPath @({string.Join(",", folders.Select(Q))});" : "") +
        (processes.Count > 0 ? $"Remove-MpPreference -ExclusionProcess @({string.Join(",", processes.Select(Q))});" : "");

    /// <summary>Which of the requested exclusions show up when read back after adding.</summary>
    public static (List<string> Folders, List<string> Processes) Confirmed(string? readBackJson, IReadOnlyList<string> folders, IReadOnlyList<string> processes)
    {
        if (string.IsNullOrWhiteSpace(readBackJson)) return ([], []);
        try
        {
            using var doc = JsonDocument.Parse(readBackJson);
            var paths = Strings(doc.RootElement, "Paths");
            var procs = Strings(doc.RootElement, "Procs");
            return (folders.Where(f => paths.Any(e => Covers(e, f))).ToList(),
                    processes.Where(t => procs.Any(e => Normalize(e).Equals(Normalize(t), StringComparison.OrdinalIgnoreCase))).ToList());
        }
        catch (JsonException) { return ([], []); }
    }

    /// <summary>Saved with the undo entry so one undo removes exactly what was added.</summary>
    public static string Encode(IReadOnlyList<string> folders, IReadOnlyList<string> processes) =>
        JsonSerializer.Serialize(new Dictionary<string, IReadOnlyList<string>> { ["Folders"] = folders, ["Processes"] = processes });

    public static (IReadOnlyList<string> Folders, IReadOnlyList<string> Processes) Decode(string? json)
    {
        try
        {
            var d = string.IsNullOrEmpty(json) ? null : JsonSerializer.Deserialize<Dictionary<string, List<string>>>(json);
            return (d?.GetValueOrDefault("Folders") ?? [], d?.GetValueOrDefault("Processes") ?? []);
        }
        catch (JsonException) { return ([], []); }
    }
}
