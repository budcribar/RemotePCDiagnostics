using System.Text.Json;
using NuGet.Versioning;

namespace RemotePCDiagnostics.Core.Memory;

/// <summary>
/// Read-only candidates for removal from ~/.nuget/packages. A version is a candidate only when all of these hold:
/// a newer version of the package is present; no project found on this PC references it (project.assets.json);
/// it was downloaded from nuget.org (so a build that still needs it simply downloads it again: never from a company feed
/// or a local folder); and it wasn't downloaded recently (a guard for projects the search didn't find).
/// </summary>
public static class NuGetCleanupScanner
{
    public static readonly TimeSpan KeepRecent = TimeSpan.FromDays(45);

    public static IReadOnlyList<string> FindSupersededVersions(string packagesRoot, string projectsRoot,
        ILogger? log = null, CancellationToken ct = default) =>
        Directory.Exists(projectsRoot) ? FindSupersededVersions(packagesRoot, [projectsRoot], log, ct) : [];

    public static IReadOnlyList<string> FindSupersededVersions(string packagesRoot, IReadOnlyList<string> projectRoots,
        ILogger? log = null, CancellationToken ct = default, DateTime? utcNow = null)
    {
        try
        {
            // An incomplete reference scan must never be interpreted as "nothing is in use".
            var roots = projectRoots.Where(Directory.Exists).ToList();
            if (roots.Count == 0 || !Directory.Exists(packagesRoot)) return [];
            var cutoff = (utcNow ?? DateTime.UtcNow) - KeepRecent;
            var referenced = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var dir in roots.SelectMany(r => Walk(r, ct)))
            {
                foreach (var assets in Directory.EnumerateFiles(dir, "project.assets.json"))
                {
                    ct.ThrowIfCancellationRequested();
                    if (IsLink(assets)) throw new IOException("Assets file is a reparse point: " + assets);
                    using var json = JsonDocument.Parse(File.ReadAllText(assets));
                    var libraries = json.RootElement.GetProperty("libraries");
                    foreach (var library in libraries.EnumerateObject())
                    {
                        if (library.Value.GetProperty("type").GetString() != "package") continue;
                        var slash = library.Name.LastIndexOf('/');
                        if (slash <= 0 || !NuGetVersion.TryParse(library.Name[(slash + 1)..], out var version))
                            throw new InvalidDataException("Invalid package identity in " + assets);
                        referenced.Add(Identity(library.Name[..slash], version));
                    }
                }
            }

            var candidates = new List<string>();
            foreach (var package in Directory.EnumerateDirectories(packagesRoot))
            {
                ct.ThrowIfCancellationRequested();
                if (IsLink(package)) continue;
                var versions = new List<(string Path, NuGetVersion Version)>();
                foreach (var folder in Directory.EnumerateDirectories(package))
                    if (!IsLink(folder) && NuGetVersion.TryParse(Path.GetFileName(folder), out var version))
                        versions.Add((folder, version)); // Unknown folder names are always retained.
                if (versions.Count < 2) continue;
                var newest = versions.Select(v => v.Version).Max(VersionComparer.VersionRelease)!;
                foreach (var version in versions)
                    if (VersionComparer.VersionRelease.Compare(version.Version, newest) < 0 &&
                        !referenced.Contains(Identity(Path.GetFileName(package), version.Version)) &&
                        FromNuGetOrg(version.Path, cutoff))
                        candidates.Add(version.Path);
            }
            return candidates;
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or JsonException or
            KeyNotFoundException or InvalidOperationException or FormatException)
        {
            log.Info("NuGet package pruning skipped: reference/candidate scan incomplete: " + ex.Message);
            return [];
        }
    }

    /// <summary>
    /// NuGet writes .nupkg.metadata when it extracts a package: {"version":2,"contentHash":"…","source":"https://api.nuget.org/v3/index.json"}.
    /// Missing or unreadable metadata, any other source, or a recent download → keep.
    /// </summary>
    public static bool FromNuGetOrg(string versionFolder, DateTime downloadedBeforeUtc)
    {
        var meta = Path.Combine(versionFolder, ".nupkg.metadata");
        try
        {
            if (!File.Exists(meta) || File.GetLastWriteTimeUtc(meta) >= downloadedBeforeUtc) return false;
            using var doc = JsonDocument.Parse(File.ReadAllText(meta));
            return doc.RootElement.TryGetProperty("source", out var src) && src.GetString() is { } s && IsNuGetOrg(s);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException) { return false; }
    }

    public static bool IsNuGetOrg(string source) =>
        Uri.TryCreate(source, UriKind.Absolute, out var u) && u.Scheme == Uri.UriSchemeHttps &&
        (u.Host.Equals("api.nuget.org", StringComparison.OrdinalIgnoreCase) || u.Host.Equals("www.nuget.org", StringComparison.OrdinalIgnoreCase));

    private static readonly HashSet<string> SkippedFolders = new(StringComparer.OrdinalIgnoreCase) { ".git", "node_modules" };

    private static string Identity(string package, NuGetVersion version) =>
        package + "/" + version.ToNormalizedString().Split('+')[0];

    private static bool IsLink(string path) => (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;

    private static IEnumerable<string> Walk(string root, CancellationToken ct)
    {
        var pending = new Stack<string>();
        pending.Push(root);
        while (pending.TryPop(out var dir))
        {
            ct.ThrowIfCancellationRequested();
            // Do not silently miss project references behind redirected directories.
            if (IsLink(dir)) throw new IOException("Project directory is a reparse point: " + dir);
            yield return dir;
            foreach (var child in Directory.EnumerateDirectories(dir))
            {
                // Never holds .NET project assets; node_modules is huge and pnpm fills it with links that would abort the scan.
                if (SkippedFolders.Contains(Path.GetFileName(child))) continue;
                pending.Push(child);
            }
        }
    }
}
