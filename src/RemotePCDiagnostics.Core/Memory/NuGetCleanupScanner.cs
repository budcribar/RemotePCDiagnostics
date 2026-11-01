using System.Text.Json;
using NuGet.Versioning;

namespace RemotePCDiagnostics.Core.Memory;

/// <summary>Read-only candidates: keep the highest NuGet version and every package referenced by project assets.</summary>
public static class NuGetCleanupScanner
{
    public static IReadOnlyList<string> FindSupersededVersions(string packagesRoot, string projectsRoot,
        Action<string>? log = null, CancellationToken ct = default)
    {
        try
        {
            // An incomplete reference scan must never be interpreted as "nothing is in use".
            if (!Directory.Exists(projectsRoot) || !Directory.Exists(packagesRoot)) return [];
            var referenced = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var dir in Walk(projectsRoot, ct))
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
                        !referenced.Contains(Identity(Path.GetFileName(package), version.Version)))
                        candidates.Add(version.Path);
            }
            return candidates;
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or JsonException or
            KeyNotFoundException or InvalidOperationException or FormatException)
        {
            log?.Invoke("NuGet package pruning skipped: reference/candidate scan incomplete: " + ex.Message);
            return [];
        }
    }

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
