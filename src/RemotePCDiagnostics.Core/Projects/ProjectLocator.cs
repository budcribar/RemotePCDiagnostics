using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace RemotePCDiagnostics.Core.Projects;

/// <summary>Folders this PC's user profile lives in (real ones from the Host; temp folders in tests).</summary>
public sealed record ProjectLocatorPaths(string UserProfile, string AppData, string LocalAppData, IReadOnlyList<string> FixedDriveRoots)
{
    public static ProjectLocatorPaths Current() => new(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed && d.IsReady).Select(d => d.RootDirectory.FullName).ToList());
}

/// <summary>Where a project folder was found (for the log and the suggestion text).</summary>
public enum ProjectSource { VsCode, VisualStudio, Rider, SearchIndex, CommonFolder }

public sealed record ProjectRoot(string Path, ProjectSource Source);

/// <summary>
/// Finds the folders where this PC's source code lives, without scanning whole drives: the folders VS Code (and Cursor,
/// Windsurf, VSCodium), Visual Studio and Rider have opened, project files Windows Search has indexed, and the usual
/// places people keep code. Each hit is widened to its repository root (the folder holding .git).
/// </summary>
public sealed class ProjectLocator(ProjectLocatorPaths paths, Func<CancellationToken, Task<IReadOnlyList<string>>>? searchIndex = null, ILogger? log = null)
{
    private void Log(string m) => log.Info("[projects] " + m);
    private void LogLine(string m) => log.Line("[projects] " + m);

    /// <summary>VS Code and its forks keep one workspace.json per folder ever opened under this folder.</summary>
    public static readonly string[] CodeEditors = ["Code", "Code - Insiders", "Cursor", "Windsurf", "VSCodium"];

    public async Task<IReadOnlyList<ProjectRoot>> FindAsync(CancellationToken ct = default)
    {
        var hits = new List<(string Path, ProjectSource Source)>();
        void Add(IEnumerable<string> found, ProjectSource src) { foreach (var p in found) hits.Add((p, src)); }

        Add(Safe(() => VsCodeFolders(paths.AppData)), ProjectSource.VsCode);
        Add(Safe(() => VisualStudioFolders(paths.LocalAppData)), ProjectSource.VisualStudio);
        Add(Safe(() => RiderFolders(paths.AppData, paths.UserProfile)), ProjectSource.Rider);
        if (searchIndex is not null)
        {
            try { Add((await searchIndex(ct).ConfigureAwait(false)).Select(ProjectFolderOf), ProjectSource.SearchIndex); }
            catch (Exception ex) when (ex is not OperationCanceledException) { Log("search index: " + ex.Message); }
        }
        Add(CommonFolders(paths).Where(Directory.Exists), ProjectSource.CommonFolder);

        var roots = new Dictionary<string, ProjectRoot>(StringComparer.OrdinalIgnoreCase);
        foreach (var (p, src) in hits)
        {
            ct.ThrowIfCancellationRequested();
            string full;
            try { full = Path.GetFullPath(p).TrimEnd('\\', '/'); } catch (Exception) { continue; }
            if (!Directory.Exists(full)) continue;
            var root = src == ProjectSource.CommonFolder ? full : RepoRootOf(full, paths);
            if (IsUnsafe(root, paths)) continue;
            roots.TryAdd(root, new(root, src));
        }
        var result = RemoveNested(roots.Values);
        Log($"found {result.Count} project folder(s): " + string.Join(", ", result.GroupBy(r => r.Source).Select(g => $"{g.Key} {g.Count()}")));
        return result;
    }

    private IEnumerable<string> Safe(Func<IEnumerable<string>> f)
    {
        try { return f().ToList(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or FormatException) { LogLine(ex.Message); return []; }
    }

    // ---- VS Code family: %APPDATA%\<editor>\User\workspaceStorage\<hash>\workspace.json ----
    public static IEnumerable<string> VsCodeFolders(string appData)
    {
        foreach (var editor in CodeEditors)
        {
            var storage = Path.Combine(appData, editor, "User", "workspaceStorage");
            if (!Directory.Exists(storage)) continue;
            foreach (var ws in Directory.EnumerateFiles(storage, "workspace.json", new EnumerationOptions { RecurseSubdirectories = true, MaxRecursionDepth = 1, IgnoreInaccessible = true }))
                if (ParseWorkspaceJson(File.ReadAllText(ws)) is { } p) yield return p;
        }
    }

    /// <summary>{"folder":"file:///d%3A/work/app"} → D:\work/app; a .code-workspace file → its folder. Remote (WSL, SSH) workspaces → null.</summary>
    public static string? ParseWorkspaceJson(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var r = doc.RootElement;
            if (r.TryGetProperty("folder", out var f) && f.GetString() is { } folder) return FileUriToPath(folder);
            if (r.TryGetProperty("workspace", out var w) && w.GetString() is { } file && FileUriToPath(file) is { } wf) return Path.GetDirectoryName(wf);
        }
        catch (JsonException) { }
        return null;
    }

    public static string? FileUriToPath(string uri)
    {
        if (!uri.StartsWith("file:///", StringComparison.OrdinalIgnoreCase)) return null; // vscode-remote://, etc.
        var p = WebUtility.UrlDecode(uri["file:///".Length..].Replace("+", "%2B")).Replace('/', '\\');
        return p.Length >= 2 && p[1] == ':' ? char.ToUpperInvariant(p[0]) + p[1..] : null;
    }

    // ---- Visual Studio: %LOCALAPPDATA%\Microsoft\VisualStudio\<ver>\ApplicationPrivateSettings.xml (recent solutions/folders as JSON inside XML) ----
    public static IEnumerable<string> VisualStudioFolders(string localAppData)
    {
        var vs = Path.Combine(localAppData, "Microsoft", "VisualStudio");
        if (!Directory.Exists(vs)) yield break;
        foreach (var dir in Directory.EnumerateDirectories(vs))
        {
            var file = Path.Combine(dir, "ApplicationPrivateSettings.xml");
            if (!File.Exists(file)) continue;
            foreach (var p in ParseVisualStudioSettings(File.ReadAllText(file))) yield return p;
        }
    }

    private static readonly Regex VsPath = new(@"""(?:FullPath|Key|LocalPath)""\s*:\s*""(?<p>[A-Za-z]:(?:\\\\|/)[^""]+)""", RegexOptions.Compiled);

    public static IEnumerable<string> ParseVisualStudioSettings(string xml)
    {
        var text = WebUtility.HtmlDecode(xml);
        foreach (Match m in VsPath.Matches(text))
        {
            var p = m.Groups["p"].Value.Replace(@"\\", @"\").Replace('/', '\\');
            yield return Path.HasExtension(p) && !Directory.Exists(p) ? Path.GetDirectoryName(p)! : p; // a .sln → its folder
        }
    }

    // ---- JetBrains Rider: %APPDATA%\JetBrains\Rider*\options\recentSolutions.xml ----
    public static IEnumerable<string> RiderFolders(string appData, string userProfile)
    {
        var jb = Path.Combine(appData, "JetBrains");
        if (!Directory.Exists(jb)) yield break;
        foreach (var dir in Directory.EnumerateDirectories(jb, "Rider*"))
        {
            var file = Path.Combine(dir, "options", "recentSolutions.xml");
            if (!File.Exists(file)) continue;
            foreach (var p in ParseRiderRecent(File.ReadAllText(file), userProfile)) yield return p;
        }
    }

    private static readonly Regex RiderEntry = new(@"<entry\s+key=""(?<p>[^""]+)""", RegexOptions.Compiled);

    public static IEnumerable<string> ParseRiderRecent(string xml, string userProfile)
    {
        foreach (Match m in RiderEntry.Matches(xml))
        {
            var p = WebUtility.HtmlDecode(m.Groups["p"].Value).Replace("$USER_HOME$", userProfile).Replace('/', '\\');
            if (p.Length < 3 || p[1] != ':') continue;
            yield return Path.HasExtension(p) ? Path.GetDirectoryName(p)! : p;
        }
    }

    // ---- Windows Search index hits (project.assets.json, .sln, .slnx, .csproj …) → project folder ----
    public static string ProjectFolderOf(string file)
    {
        var dir = Path.GetDirectoryName(file) ?? file;
        // ...\App\obj\project.assets.json → ...\App
        return Path.GetFileName(file).Equals("project.assets.json", StringComparison.OrdinalIgnoreCase) && Path.GetFileName(dir).Equals("obj", StringComparison.OrdinalIgnoreCase)
            ? Path.GetDirectoryName(dir) ?? dir : dir;
    }

    public static IEnumerable<string> CommonFolders(ProjectLocatorPaths p)
    {
        foreach (var rel in new[] { @"source\repos", @"Documents\GitHub", @"Documents\Visual Studio 2022\Projects", "Projects", "repos", "src", "dev", "code", "RiderProjects" })
            yield return Path.Combine(p.UserProfile, rel);
        foreach (var drive in p.FixedDriveRoots)
            foreach (var name in new[] { "src", "dev", "code", "repos", "source", "projects", "git", "work" })
                yield return Path.Combine(drive, name);
    }

    /// <summary>Moves up from a project folder to the folder holding .git (stopping at the profile or drive root).</summary>
    public static string RepoRootOf(string folder, ProjectLocatorPaths p)
    {
        var dir = new DirectoryInfo(folder);
        for (var d = dir; d is not null; d = d.Parent)
        {
            if (Same(d.FullName, p.UserProfile) || d.Parent is null) break;
            if (Directory.Exists(Path.Combine(d.FullName, ".git")) || File.Exists(Path.Combine(d.FullName, ".git"))) return d.FullName.TrimEnd('\\', '/');
        }
        return dir.FullName.TrimEnd('\\', '/');
    }

    /// <summary>
    /// Never offered as a project folder (Defender would stop scanning far too much, and pruning would walk huge trees):
    /// drive roots, the profile and its standard folders, Windows and program folders, and anything under Downloads or Temp.
    /// </summary>
    public static bool IsUnsafe(string folder, ProjectLocatorPaths p)
    {
        var f = folder.TrimEnd('\\', '/');
        if (f.Length <= 3 || Path.GetPathRoot(f) is { } root && Same(root, f)) return true;
        string[] exact =
        [
            p.UserProfile, Path.Combine(p.UserProfile, "Desktop"), Path.Combine(p.UserProfile, "Documents"), Path.Combine(p.UserProfile, "OneDrive"),
            Path.Combine(p.UserProfile, "source"), Path.Combine(p.UserProfile, "Downloads"), p.AppData, p.LocalAppData,
        ];
        if (exact.Any(e => Same(e, f))) return true;
        string[] under =
        [
            Path.Combine(p.UserProfile, "Downloads"), Path.Combine(p.LocalAppData, "Temp"), p.AppData, p.LocalAppData,
            Environment.GetFolderPath(Environment.SpecialFolder.Windows), Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        ];
        return under.Where(u => u.Length > 0).Any(u => IsUnder(f, u));
    }

    public static bool IsUnder(string path, string parent)
    {
        var a = path.TrimEnd('\\', '/') + "\\";
        var b = parent.TrimEnd('\\', '/') + "\\";
        return a.StartsWith(b, StringComparison.OrdinalIgnoreCase);
    }

    private static bool Same(string a, string b) => string.Equals(a.TrimEnd('\\', '/'), b.TrimEnd('\\', '/'), StringComparison.OrdinalIgnoreCase);

    /// <summary>Keeps only the outermost folders (a repo inside an already-listed folder isn't listed twice).</summary>
    public static IReadOnlyList<ProjectRoot> RemoveNested(IEnumerable<ProjectRoot> roots)
    {
        var sorted = roots.OrderBy(r => r.Path.Length).ToList();
        var kept = new List<ProjectRoot>();
        foreach (var r in sorted)
            if (!kept.Any(k => IsUnder(r.Path, k.Path))) kept.Add(r);
        return kept.OrderBy(r => r.Path, StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>
    /// For Defender: three or more repos side by side in one safe parent (D:\work\a, D:\work\b, D:\work\c) become that parent,
    /// so the exclusion list stays short and new repos cloned there are covered.
    /// </summary>
    public static IReadOnlyList<string> CollapseSiblings(IEnumerable<string> folders, ProjectLocatorPaths p, int minSiblings = 3)
    {
        var list = folders.Select(f => f.TrimEnd('\\', '/')).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var parents = list.GroupBy(f => Path.GetDirectoryName(f) ?? f, StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Count() >= minSiblings && !IsUnsafe(g.Key, p)).Select(g => g.Key).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var result = list.Select(f => Path.GetDirectoryName(f) is { } d && parents.Contains(d) ? d : f);
        return RemoveNested(result.Distinct(StringComparer.OrdinalIgnoreCase).Select(f => new ProjectRoot(f, ProjectSource.CommonFolder))).Select(r => r.Path).ToList();
    }
}
