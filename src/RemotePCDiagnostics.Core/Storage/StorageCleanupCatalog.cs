using System.Text.Json;
using System.Text.RegularExpressions;
using RemotePCDiagnostics.Core.Optimizations;

namespace RemotePCDiagnostics.Core.Storage;

/// <summary>
/// The storage cleanups the app may run (#1, #2, #5, #6, #13), one workflow fix each. Every rule is evaluated on disk when the scan
/// measures it and again right before anything is deleted. Temporary files are cleaned by <c>RemediationKind.CleanTempFiles</c>, and agent
/// worktrees (#1a) are only measured here (they need their own review and approval), so neither has a category.
/// </summary>
public static class StorageCleanupCatalog
{
    /// <summary><see cref="MemorySuggestion.Category"/> / workflow area of the storage fixes.</summary>
    public const string SuggestionCategory = "Storage";
    /// <summary><see cref="StorageCleanupItem.Category"/> of items that are measured but never deleted by this app (agent worktrees, #1a).</summary>
    public const string ReviewCategory = "Review";
    public const string GrokWorktreesId = "storage-grok-worktrees";
    /// <summary>Measured by the Host scan; cleaned by the "Clean up temporary files" fix, not here.</summary>
    public const string TempId = "storage-temp";

    public static readonly TimeSpan CacheAge = TimeSpan.FromDays(30);
    public static readonly TimeSpan BrowserCacheAge = TimeSpan.FromDays(60);
    public static readonly TimeSpan StagingAge = TimeSpan.FromDays(7);
    public static readonly TimeSpan CrashDumpAge = TimeSpan.FromDays(7);
    public static readonly TimeSpan OstAge = TimeSpan.FromDays(60);
    public const long LockFileMaxBytes = 4096;

    private static readonly string[] VsCodeApps = ["Code"];
    private static readonly string[] OutlookApps = ["olk", "OUTLOOK"];
    private static readonly string[] OfficeApps = ["WINWORD", "EXCEL", "POWERPNT", "OUTLOOK", "MSACCESS", "MSPUB", "ONENOTE", "VISIO", "WINPROJ"];
    private static readonly string[] NuGetMarkers = [".nupkg.metadata", "*.nupkg.sha512"];

    private static string L(StorageScanContext c, params string[] rel) => Path.Combine(rel.Prepend(c.Roots.LocalAppData).ToArray());
    private static string U(StorageScanContext c, params string[] rel) => Path.Combine(rel.Prepend(c.Roots.UserProfile).ToArray());
    private static string R(StorageScanContext c, params string[] rel) => Path.Combine(rel.Prepend(c.Roots.RoamingAppData).ToArray());

    public static string NuGetHttpCache(StorageScanContext c) => L(c, "NuGet", "v3-cache");
    public static string NuGetPackages(StorageScanContext c) => U(c, ".nuget", "packages");
    public static string VsCodeInstall(StorageScanContext c) => L(c, "Programs", "Microsoft VS Code");
    public static string VsCodeExtensions(StorageScanContext c) => U(c, ".vscode", "extensions");
    public static string ChromeUserData(StorageScanContext c) => L(c, "Google", "Chrome", "User Data");
    public static string EdgeUserData(StorageScanContext c) => L(c, "Microsoft", "Edge", "User Data");
    public static string NewOutlook(StorageScanContext c) => L(c, "Microsoft", "Olk");

    public static readonly IReadOnlyList<StorageCategory> All =
    [
        new("storage-nuget", "NuGet download cache & old package versions",
            "Clears NuGet's download cache and removes older package versions downloaded from nuget.org more than 45 days ago that no project on this PC uses " +
            "(projects found from Visual Studio, VS Code, Rider and Windows Search). The newest version of each package is kept, and anything from a company feed or " +
            "local folder is never touched. A build that still needs a removed version downloads it again.",
            AutoChecked: true, ["devenv", "MSBuild"], "Visual Studio",
            c => [NuGetHttpCache(c), NuGetPackages(c)],
            (c, ct) =>
            {
                var list = new List<StorageTarget>();
                if (Directory.Exists(NuGetHttpCache(c))) list.Add(StorageTarget.Contents(NuGetHttpCache(c)));
                var packages = StorageCleanupEngine.Normalize(NuGetPackages(c));
                foreach (var v in NuGetCleanupScanner.FindSupersededVersions(packages, c.ProjectRoots, c.Log, ct, c.UtcNow))
                {
                    var full = StorageCleanupEngine.Normalize(v);
                    // Only <packages>\<id>\<version>, nothing deeper or elsewhere.
                    if (string.Equals(Path.GetDirectoryName(Path.GetDirectoryName(full)), packages, StringComparison.OrdinalIgnoreCase))
                        list.Add(StorageTarget.Folder(packages, full, NuGetMarkers));
                }
                return list;
            }, UsesProjects: true),

        new("storage-npm", "npm download cache (older than 30 days)",
            "Removes package downloads in npm's cache that haven't been used for 30 days. npm downloads a package again the next time a project needs it.",
            AutoChecked: true, [], "npm",
            c => [L(c, "npm-cache", "_cacache")],
            (c, _) => [StorageTarget.Contents(L(c, "npm-cache", "_cacache"), c.UtcNow - CacheAge)]),

        new("storage-grok", "Old Grok CLI sessions & downloads (older than 30 days)",
            "Removes Grok CLI session history and downloaded files in ~/.grok that haven't changed for 30 days. Project worktrees in ~/.grok/worktrees are never touched by this cleanup.",
            AutoChecked: true, ["grok"], "Grok",
            c => [U(c, ".grok", "sessions"), U(c, ".grok", "downloads")],
            (c, ct) => [.. StaleEntries(U(c, ".grok", "sessions"), c.UtcNow - CacheAge, c.UtcNow, ct), .. StaleEntries(U(c, ".grok", "downloads"), c.UtcNow - CacheAge, c.UtcNow, ct)]),

        new("storage-codex", "Old OpenAI Codex runtime backups",
            "Removes the backup copies Codex keeps of its previous runtimes (codex-primary-runtime.previous-*). The runtime Codex uses now is kept.",
            AutoChecked: true, ["codex"], "Codex",
            c => [U(c, ".cache", "codex-runtimes")],
            (c, _) => [.. Children(U(c, ".cache", "codex-runtimes"), dirs: true)
                .Where(d => d.Name.StartsWith("codex-primary-runtime.previous-", StringComparison.OrdinalIgnoreCase))
                .Select(d => StorageTarget.Folder(U(c, ".cache", "codex-runtimes"), d.FullName))]),

        new("storage-copilot", "Microsoft Copilot app cache",
            "Clears the Copilot app's web cache. Sign-in and conversations aren't affected; the app downloads what it needs again.",
            AutoChecked: true, ["Copilot", "M365Copilot"], "Copilot",
            c => [L(c, "Microsoft", "Copilot", "User Data", "Default", "Cache")],
            (c, _) => [StorageTarget.Contents(L(c, "Microsoft", "Copilot", "User Data", "Default", "Cache"))]),

        new("storage-playwright", "Playwright test browsers not used for 60 days",
            "Removes Chromium, Firefox and WebKit copies that Playwright downloaded for automated tests and that haven't changed for 60 days. " +
            "Tests that need them stop working until \"playwright install\" is run again, so this is opt-in.",
            AutoChecked: false, [], "Playwright",
            c => [L(c, "ms-playwright")],
            (c, ct) => [.. StaleEntries(L(c, "ms-playwright"), c.UtcNow - BrowserCacheAge, c.UtcNow, ct, skip: n => n.Equals(".links", StringComparison.OrdinalIgnoreCase))]),

        new("storage-vscode", "Old VS Code versions, extension installers & crash reports",
            "Removes copies of older VS Code versions left behind by updates, already-installed extension installers (CachedExtensionVSIXs) and old crash reports (Crashpad). " +
            "The VS Code version in use, settings and extensions aren't touched.",
            AutoChecked: true, VsCodeApps, "VS Code",
            c => [VsCodeInstall(c), R(c, "Code", "CachedExtensionVSIXs"), R(c, "Code", "Crashpad")],
            (c, _) => [.. OldVsCodeVersions(VsCodeInstall(c), c.UtcNow).Select(d => StorageTarget.Folder(VsCodeInstall(c), d)),
                StorageTarget.Contents(R(c, "Code", "CachedExtensionVSIXs")), StorageTarget.Contents(R(c, "Code", "Crashpad"))]),

        new("storage-vscode-extensions", "Old VS Code extension versions & failed installs",
            "Removes older copies of VS Code extensions that a newer version replaced, and folders left by extension installs that failed more than 7 days ago. " +
            "VS Code then starts a little faster. Extensions VS Code lists as installed are never removed.",
            AutoChecked: true, VsCodeApps, "VS Code",
            c => [VsCodeExtensions(c)],
            (c, ct) => [.. SupersededExtensions(VsCodeExtensions(c), c.Log).Concat(StagingFolders(VsCodeExtensions(c), c.UtcNow, ct))
                .Select(d => StorageTarget.Folder(VsCodeExtensions(c), d))]),

        new("storage-onedrive-logs", "OneDrive diagnostic logs (older than 30 days)",
            "Removes OneDrive's own diagnostic log files that are more than 30 days old. Your OneDrive files and sync settings aren't touched.",
            AutoChecked: true, ["OneDrive"], "OneDrive",
            c => [L(c, "Microsoft", "OneDrive", "logs")],
            (c, _) => [StorageTarget.Contents(L(c, "Microsoft", "OneDrive", "logs"), c.UtcNow - CacheAge)]),

        new("storage-outlook-cache", "New Outlook logs & web caches (older than 30 days)",
            "Removes the new Outlook's log files and web caches that are more than 30 days old. Mail, calendar, attachments and settings aren't touched.",
            AutoChecked: true, OutlookApps, "Outlook",
            c => [L(c, "Microsoft", "Olk", "logs"), L(c, "Microsoft", "Olk", "EBWebView", "Default", "Cache"), L(c, "Microsoft", "Olk", "EBWebView", "Default", "Code Cache")],
            (c, _) => [StorageTarget.Contents(L(c, "Microsoft", "Olk", "logs"), c.UtcNow - CacheAge),
                StorageTarget.Contents(L(c, "Microsoft", "Olk", "EBWebView", "Default", "Cache"), c.UtcNow - CacheAge),
                StorageTarget.Contents(L(c, "Microsoft", "Olk", "EBWebView", "Default", "Code Cache"), c.UtcNow - CacheAge)]),

        new("storage-crashdumps", "Old app crash dumps",
            "Removes memory dumps Windows saved when apps crashed. Dumps from the last 7 days are kept in case they're needed to look into a recent crash.",
            AutoChecked: true, [], "Windows Error Reporting",
            c => [L(c, "CrashDumps")],
            (c, _) => [StorageTarget.Contents(L(c, "CrashDumps"), c.UtcNow - CrashDumpAge, "*.dmp", topLevelOnly: true)]),

        new("storage-app-webview", "Store app web caches (older than 60 days)",
            "Removes web page caches inside Store apps (their built-in Edge WebView) that are more than 60 days old. App data and sign-ins aren't touched.",
            AutoChecked: true, [], "the app",
            c => [.. AppWebViewCaches(c)],
            (c, _) => [.. AppWebViewCaches(c).Select(r => StorageTarget.Contents(r, c.UtcNow - BrowserCacheAge))]),

        new("storage-outlook-ost", "Unused classic Outlook offline mailbox copy (.ost)",
            "This PC uses the new Outlook, and classic Outlook's offline copy of the mailbox (.ost) hasn't changed for 60 days. The mail stays on the mail server; " +
            "if classic Outlook is used again it downloads a fresh copy (which can take a while). Personal archive files (.pst) are never touched. Opt-in.",
            AutoChecked: false, OutlookApps, "Outlook",
            c => [L(c, "Microsoft", "Outlook")],
            (c, ct) => [.. StaleOstFiles(c, ct).Select(f => StorageTarget.OneFile(L(c, "Microsoft", "Outlook"), f))]),

        BrowserCategory("storage-browser-chrome", "Chrome", ["chrome"], ChromeUserData),
        BrowserCategory("storage-browser-edge", "Microsoft Edge", ["msedge"], EdgeUserData),

        new("storage-office-locks", "Leftover Office lock files",
            "Removes leftover lock files (~$Normal.dotm and similar) in the Office templates folder, which can make Word say Normal.dotm is in use. " +
            "Only tiny lock files older than a day are removed; templates and recovered documents aren't touched.",
            AutoChecked: true, OfficeApps, "Word, Excel or another Office app",
            c => [R(c, "Microsoft", "Templates")],
            (c, _) => [StorageTarget.Contents(R(c, "Microsoft", "Templates"), c.UtcNow - TimeSpan.FromDays(1), "~$*", topLevelOnly: true, maxFileBytes: LockFileMaxBytes)],
            MinBytes: 1),
    ];

    private static StorageCategory BrowserCategory(string id, string browser, string[] apps, Func<StorageScanContext, string> userData) => new(
        id, $"Old {browser} website caches (not used for 60 days)",
        $"Removes offline copies websites stored in {browser} (Service Worker cache) and compiled page scripts (Code Cache) that haven't been used for 60 days, " +
        "in every profile. Cookies, saved passwords, sign-ins, history and bookmarks aren't touched; websites download what they need again.",
        AutoChecked: true, apps, browser,
        c => [.. BrowserProfiles(userData(c)).SelectMany(p => new[] { Path.Combine(p, "Service Worker", "CacheStorage"), Path.Combine(p, "Code Cache") })],
        (c, ct) => [.. BrowserProfiles(userData(c)).SelectMany(p =>
            StaleEntries(Path.Combine(p, "Service Worker", "CacheStorage"), c.UtcNow - BrowserCacheAge, c.UtcNow, ct)
                .Append(StorageTarget.Contents(Path.Combine(p, "Code Cache"), c.UtcNow - BrowserCacheAge)))]);

    /// <summary>Exact id match only (the workflow and the journal pass ids, never paths).</summary>
    public static StorageCategory? Find(string? id) => All.FirstOrDefault(c => string.Equals(c.Id, id, StringComparison.Ordinal));

    // ---- rule helpers ----

    private static IEnumerable<FileSystemInfo> Children(string dir, bool dirs)
    {
        if (!Directory.Exists(dir) || StorageCleanupEngine.IsReparsePoint(dir)) return [];
        return new DirectoryInfo(dir).EnumerateFileSystemInfos()
            .Where(e => (e.Attributes & FileAttributes.ReparsePoint) == 0 && (e is DirectoryInfo) == dirs).ToList();
    }

    /// <summary>Each entry directly inside <paramref name="root"/> (file or folder) in which nothing changed since <paramref name="cutoffUtc"/>.</summary>
    public static IEnumerable<StorageTarget> StaleEntries(string root, DateTime cutoffUtc, DateTime utcNow, CancellationToken ct, Func<string, bool>? skip = null)
    {
        if (!Directory.Exists(root) || StorageCleanupEngine.IsReparsePoint(root)) return [];
        var list = new List<StorageTarget>();
        foreach (var e in new DirectoryInfo(root).EnumerateFileSystemInfos())
        {
            ct.ThrowIfCancellationRequested();
            if ((e.Attributes & FileAttributes.ReparsePoint) != 0 || skip?.Invoke(e.Name) == true) continue;
            if (StorageCleanupEngine.NewestWriteUtc(e.FullName, utcNow, ct) >= cutoffUtc) continue;
            list.Add(e is DirectoryInfo ? StorageTarget.Folder(root, e.FullName) : StorageTarget.OneFile(root, e.FullName));
        }
        return list;
    }

    /// <summary>Chrome/Edge profiles: folders in User Data with a Preferences file (Default, Profile 1, …).</summary>
    public static IReadOnlyList<string> BrowserProfiles(string userData) =>
        [.. Children(userData, dirs: true).Where(d => File.Exists(Path.Combine(d.FullName, "Preferences"))).Select(d => d.FullName)];

    /// <summary>%LOCALAPPDATA%\Packages\&lt;app&gt;\LocalState\EBWebView\Default\Cache and Code Cache that exist.</summary>
    private static IEnumerable<string> AppWebViewCaches(StorageScanContext c) =>
        Children(L(c, "Packages"), dirs: true).SelectMany(p => new[]
        {
            Path.Combine(p.FullName, "LocalState", "EBWebView", "Default", "Cache"),
            Path.Combine(p.FullName, "LocalState", "EBWebView", "Default", "Code Cache"),
        }).Where(Directory.Exists).ToList();

    private static bool IsCommitFolder(string name) => name.Length == 10 && name.All(Uri.IsHexDigit);

    /// <summary>
    /// Older VS Code version folders (10-hex-digit commit names) in the per-user install. Kept: the newest by creation and by last change,
    /// anything changed in the last 7 days, and any version named in the launcher's small text files. Needs Code.exe and at least two versions.
    /// </summary>
    public static IReadOnlyList<string> OldVsCodeVersions(string installRoot, DateTime utcNow)
    {
        if (!Directory.Exists(installRoot) || StorageCleanupEngine.IsReparsePoint(installRoot) || !File.Exists(Path.Combine(installRoot, "Code.exe"))) return [];
        var dirs = Children(installRoot, dirs: true).Cast<DirectoryInfo>().Where(d => IsCommitFolder(d.Name)).ToList();
        if (dirs.Count < 2) return [];
        var keep = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            dirs.MaxBy(d => d.CreationTimeUtc)!.Name,
            dirs.MaxBy(d => d.LastWriteTimeUtc)!.Name,
        };
        foreach (var d in dirs) if (d.LastWriteTimeUtc > utcNow - StagingAge) keep.Add(d.Name);
        var texts = LauncherTexts(installRoot);
        foreach (var d in dirs) if (texts.Any(t => t.Contains(d.Name, StringComparison.OrdinalIgnoreCase))) keep.Add(d.Name);
        return [.. dirs.Where(d => !keep.Contains(d.Name)).Select(d => d.FullName)];
    }

    private static readonly HashSet<string> TextExtensions = new(StringComparer.OrdinalIgnoreCase) { "", ".json", ".xml", ".txt", ".cmd", ".bat", ".ini", ".ps1", ".sh" };

    private static List<string> LauncherTexts(string installRoot)
    {
        var texts = new List<string>();
        foreach (var dir in new[] { installRoot, Path.Combine(installRoot, "bin") })
            foreach (var f in Children(dir, dirs: false).Cast<FileInfo>())
                if (TextExtensions.Contains(f.Extension) && f.Length <= 256 * 1024)
                    try { texts.Add(File.ReadAllText(f.FullName)); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        return texts;
    }

    private static readonly Regex ExtensionFolder = new(@"^(?<id>[a-z0-9][a-z0-9-]*\.[a-z0-9][a-z0-9-]*)-(?<ver>\d+\.\d+\.\d+)(?<plat>-[a-z0-9-]+)?$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex StagingFolder = new(@"^\.[0-9a-f]{8}[0-9a-f-]*$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    /// <summary>"ms-dotnettools.csharp-2.140.9-win32-x64" → ("ms-dotnettools.csharp|-win32-x64", 2.140.9); null when the name isn't a versioned extension folder.</summary>
    public static (string Key, Version Version)? ParseExtensionFolder(string name)
    {
        var m = ExtensionFolder.Match(name);
        if (!m.Success || !Version.TryParse(m.Groups["ver"].Value, out var v)) return null;
        return (m.Groups["id"].Value.ToLowerInvariant() + "|" + m.Groups["plat"].Value.ToLowerInvariant(), v);
    }

    /// <summary>Folder names VS Code lists as installed in extensions.json (relativeLocation, or the last part of location.path). Null = not a list.</summary>
    public static HashSet<string>? ActiveExtensionFolders(string json)
    {
        using var doc = JsonDocument.Parse(json);
        if (doc.RootElement.ValueKind != JsonValueKind.Array) return null;
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in doc.RootElement.EnumerateArray())
        {
            if (e.ValueKind != JsonValueKind.Object) continue;
            if (e.TryGetProperty("relativeLocation", out var rel) && rel.ValueKind == JsonValueKind.String && rel.GetString() is { Length: > 0 } r) names.Add(LastPart(r));
            if (!e.TryGetProperty("location", out var loc)) continue;
            if (loc.ValueKind == JsonValueKind.String && loc.GetString() is { Length: > 0 } s) names.Add(LastPart(s));
            else if (loc.ValueKind == JsonValueKind.Object)
                foreach (var p in new[] { "path", "fsPath" })
                    if (loc.TryGetProperty(p, out var pv) && pv.ValueKind == JsonValueKind.String && pv.GetString() is { Length: > 0 } ps) names.Add(LastPart(ps));
        }
        return names;
    }

    private static string LastPart(string path) => path.TrimEnd('/', '\\').Split('/', '\\').Last();

    /// <summary>
    /// Extension folders a newer version of the same extension (and platform) replaced, ordered by version number (not dates).
    /// Never the newest version, never a folder extensions.json lists, and nothing at all when extensions.json is missing or unreadable.
    /// </summary>
    public static IReadOnlyList<string> SupersededExtensions(string extRoot, ILogger? log = null)
    {
        var manifest = Path.Combine(extRoot, "extensions.json");
        if (!Directory.Exists(extRoot) || StorageCleanupEngine.IsReparsePoint(extRoot) || !File.Exists(manifest)) return [];
        HashSet<string>? active;
        try { active = ActiveExtensionFolders(File.ReadAllText(manifest)); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidOperationException)
        {
            log.Info("[storage] VS Code extensions.json unreadable, old versions kept: " + ex.Message);
            return [];
        }
        if (active is not { Count: > 0 }) return [];
        var parsed = Children(extRoot, dirs: true)
            .Select(d => (d.FullName, d.Name, Parsed: ParseExtensionFolder(d.Name)))
            .Where(x => x.Parsed is not null)
            .GroupBy(x => x.Parsed!.Value.Key);
        var list = new List<string>();
        foreach (var g in parsed)
        {
            var newest = g.Max(x => x.Parsed!.Value.Version)!;
            list.AddRange(g.Where(x => x.Parsed!.Value.Version < newest && !active.Contains(x.Name)).Select(x => x.FullName));
        }
        return list;
    }

    /// <summary>".5e1e46e0…" folders VS Code leaves when an extension install fails, untouched for 7 days.</summary>
    public static IReadOnlyList<string> StagingFolders(string extRoot, DateTime utcNow, CancellationToken ct = default) =>
        [.. Children(extRoot, dirs: true).Where(d => StagingFolder.IsMatch(d.Name) && StorageCleanupEngine.NewestWriteUtc(d.FullName, utcNow, ct) < utcNow - StagingAge)
            .Select(d => d.FullName)];

    /// <summary>The new Outlook was used in the last 30 days (its folder or anything one level inside changed).</summary>
    public static bool NewOutlookInUse(string olkRoot, DateTime utcNow)
    {
        if (!Directory.Exists(olkRoot) || StorageCleanupEngine.IsReparsePoint(olkRoot)) return false;
        var since = utcNow - CacheAge;
        if (Directory.GetLastWriteTimeUtc(olkRoot) >= since) return true;
        foreach (var e in new DirectoryInfo(olkRoot).EnumerateFileSystemInfos())
        {
            if ((e.Attributes & FileAttributes.ReparsePoint) != 0) continue;
            if (e.LastWriteTimeUtc >= since) return true;
            if (e is DirectoryInfo d)
                try { if (d.EnumerateFileSystemInfos().Any(x => x.LastWriteTimeUtc >= since)) return true; }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
        return false;
    }

    /// <summary>Classic Outlook .ost files (exact extension; never .pst) untouched for 60 days, only when the new Outlook is in use.</summary>
    public static IReadOnlyList<string> StaleOstFiles(StorageScanContext c, CancellationToken ct = default)
    {
        if (!NewOutlookInUse(NewOutlook(c), c.UtcNow)) return [];
        return [.. Children(L(c, "Microsoft", "Outlook"), dirs: false).Cast<FileInfo>()
            .Where(f => f.Extension.Equals(".ost", StringComparison.OrdinalIgnoreCase) && f.LastWriteTimeUtc < c.UtcNow - OstAge)
            .Select(f => f.FullName)];
    }

    // ---- scan and workflow ----

    /// <summary>Measures every category with the same targets and walk the cleanup uses, plus the review-only worktree estimate.</summary>
    public static IReadOnlyList<StorageCleanupItem> Scan(StorageScanContext ctx, CancellationToken ct = default, IProgress<string>? progress = null, int stepOffset = 0, int totalSteps = 0)
    {
        var total = totalSteps > 0 ? totalSteps : All.Count + 1;
        var step = stepOffset;
        var items = new List<StorageCleanupItem>();
        foreach (var c in All)
        {
            ct.ThrowIfCancellationRequested();
            progress.ReportStep(++step, total, $"Measuring {c.Title}…");
            var size = Measure(c, ctx, ct);
            if (size is { Files: > 0 } s && s.Bytes >= c.MinBytes) items.Add(new(c.Id, c.Title, c.Description, s.Bytes, c.AutoChecked, SuggestionCategory));
        }
        progress.ReportStep(++step, total, "Measuring Grok agent worktrees…");
        if (GrokWorktrees(ctx, ct) is { } w) items.Add(w);
        return items;
    }

    /// <summary>What a category would delete right now; null when its rule couldn't be evaluated.</summary>
    public static (long Files, long Bytes)? Measure(StorageCategory c, StorageScanContext ctx, CancellationToken ct = default)
    {
        try
        {
            long files = 0, bytes = 0;
            var allowed = c.AllowedRoots(ctx);
            foreach (var t in c.Targets(ctx, ct))
            {
                if (!StorageCleanupEngine.IsAllowed(t, allowed, ctx.Roots, out _)) continue;
                var (f, b) = StorageCleanupEngine.Measure(t, ct);
                files += f;
                bytes += b;
            }
            return (files, bytes);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            ctx.Log.Warn($"[storage] {c.Id}: measure failed: {ex.Message}");
            return null;
        }
    }

    /// <summary>#1a: Grok agent worktrees are measured on their own and never deleted here (they need a separate review and approval).</summary>
    public static StorageCleanupItem? GrokWorktrees(StorageScanContext ctx, CancellationToken ct = default)
    {
        var root = U(ctx, ".grok", "worktrees");
        if (!Directory.Exists(root) || StorageCleanupEngine.IsReparsePoint(root)) return null;
        long bytes;
        try { bytes = StorageCleanupEngine.Measure(StorageTarget.Contents(root), ct).Bytes; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
        return bytes > 10L << 20
            ? new StorageCleanupItem(GrokWorktreesId, "Grok agent worktrees (not deleted automatically)",
                "Project copies Grok made for its agents in ~/.grok/worktrees. They can hold unsaved work, so they need their own review before anything is deleted; this cleanup never touches them.",
                bytes, AutoCheckedByDefault: false, Category: ReviewCategory)
            : null;
    }

    /// <summary>One one-click "Delete" suggestion (and so one workflow fix) per measured category; ticked when the item is auto-checked.</summary>
    public static IReadOnlyList<MemorySuggestion> Suggestions(IEnumerable<StorageCleanupItem> items) =>
        [.. items.Where(i => i.Category != ReviewCategory && Find(i.Id) is not null).OrderByDescending(i => i.SizeBytes).Select(i =>
        {
            var c = Find(i.Id)!;
            var size = StorageCleanupEngine.SizeText(i.SizeBytes);
            return new MemorySuggestion(c.Id, c.Title, $"Frees about {size}. {c.Description} Deleted files can't be put back.", null, SuggestionRisk.Low, SuggestionKind.Automated, [],
                [new MemoryAction(MemoryActionType.CleanStorage, c.Id, "Delete", $"Permanently delete about {size}? This can't be undone.")],
                SuggestionCategory, c.BlockingApps.Count > 0 ? $"Skipped while {c.AppLabel} is open." : null, i.AutoCheckedByDefault);
        })];
}
