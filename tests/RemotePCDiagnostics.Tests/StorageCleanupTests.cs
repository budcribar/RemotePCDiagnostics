using System.Diagnostics;
using System.Text.Json;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Memory;
using RemotePCDiagnostics.Core.Storage;
using RemotePCDiagnostics.Core.Workflow;

namespace RemotePCDiagnostics.Tests;

/// <summary>Storage cleanups (#1, #2, #5, #6, #13): every rule against real temp-folder fixtures, the safety rules, and the workflow wiring.</summary>
public sealed class StorageCleanupTests : IDisposable
{
    private static readonly DateTime Now = DateTime.UtcNow;
    private readonly string _tmp = Path.Combine(Path.GetTempPath(), "rpd-storage-tests-" + Guid.NewGuid().ToString("N"));
    private readonly StorageRoots _roots;

    public StorageCleanupTests()
    {
        var profile = Path.Combine(_tmp, "profile");
        _roots = new(profile, Path.Combine(profile, "AppData", "Local"), Path.Combine(profile, "AppData", "Roaming"));
        Directory.CreateDirectory(_roots.LocalAppData);
        Directory.CreateDirectory(_roots.RoamingAppData);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tmp, recursive: true); } catch (Exception) { /* best effort; links are removed, not followed */ }
    }

    // ---- fixtures ----

    private static string P(string first, params string[] rest) => Path.Combine(rest.Prepend(first).ToArray());
    private string L(params string[] rel) => P(_roots.LocalAppData, rel);
    private string U(params string[] rel) => P(_roots.UserProfile, rel);
    private string R(params string[] rel) => P(_roots.RoamingAppData, rel);

    private static string Make(string path, int bytes = 1000, double daysOld = 0)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, new byte[bytes]);
        File.SetLastWriteTimeUtc(path, Now.AddDays(-daysOld));
        return path;
    }

    /// <summary>Sets every file and folder in the tree (and the folder itself) to <paramref name="daysOld"/>.</summary>
    private static string Age(string path, double daysOld)
    {
        var t = Now.AddDays(-daysOld);
        if (File.Exists(path)) { File.SetLastWriteTimeUtc(path, t); return path; }
        foreach (var f in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories)) File.SetLastWriteTimeUtc(f, t);
        foreach (var d in Directory.EnumerateDirectories(path, "*", SearchOption.AllDirectories).OrderByDescending(x => x.Length)) Directory.SetLastWriteTimeUtc(d, t);
        Directory.SetLastWriteTimeUtc(path, t);
        return path;
    }

    private StorageScanContext Ctx(params string[] projects) => new(_roots, projects, Now);

    private StorageCleanResult Clean(string id, Func<string, bool>? running = null, params string[] projects) =>
        StorageCleanupEngine.Clean(StorageCleanupCatalog.Find(id)!, Ctx(projects), running ?? (_ => false));

    private IReadOnlyList<StorageCleanupItem> Scan(params string[] projects) => StorageCleanupCatalog.Scan(Ctx(projects));

    /// <summary>A directory symlink, or a junction when symlinks need privileges. False when neither can be made here (test is then inconclusive).</summary>
    private static bool TryLink(string link, string target)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(link)!);
        try { Directory.CreateSymbolicLink(link, target); return StorageCleanupEngine.IsReparsePoint(link); }
        catch (Exception) { }
        if (!OperatingSystem.IsWindows()) return false;
        try
        {
            using var p = Process.Start(new ProcessStartInfo("cmd.exe", $"/c mklink /J \"{link}\" \"{target}\"")
                { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true })!;
            p.WaitForExit(15000);
            return Directory.Exists(link) && StorageCleanupEngine.IsReparsePoint(link);
        }
        catch (Exception) { return false; }
    }

    // ---- catalog ----

    [Fact]
    public void Catalog_IdsUniqueAndExact_DefaultsAndBlockingApps()
    {
        var ids = StorageCleanupCatalog.All.Select(c => c.Id).ToList();
        Assert.Equal(ids.Count, ids.Distinct().Count());
        Assert.All(ids, id => Assert.StartsWith("storage-", id));
        Assert.Null(StorageCleanupCatalog.Find(StorageCleanupCatalog.TempId));           // CleanTempFiles does temp
        Assert.Null(StorageCleanupCatalog.Find(StorageCleanupCatalog.GrokWorktreesId));  // #1a: review only
        Assert.Null(StorageCleanupCatalog.Find("STORAGE-NUGET"));
        Assert.Null(StorageCleanupCatalog.Find(@"C:\Windows"));
        Assert.Null(StorageCleanupCatalog.Find(null));

        string[] optIn = ["storage-playwright", "storage-outlook-ost"];
        Assert.All(StorageCleanupCatalog.All, c => Assert.Equal(!optIn.Contains(c.Id), c.AutoChecked));

        Assert.Contains("Code", StorageCleanupCatalog.Find("storage-vscode")!.BlockingApps);
        Assert.Contains("Code", StorageCleanupCatalog.Find("storage-vscode-extensions")!.BlockingApps);
        Assert.Contains("chrome", StorageCleanupCatalog.Find("storage-browser-chrome")!.BlockingApps);
        Assert.Contains("msedge", StorageCleanupCatalog.Find("storage-browser-edge")!.BlockingApps);
        Assert.Contains("olk", StorageCleanupCatalog.Find("storage-outlook-cache")!.BlockingApps);
        Assert.Contains("OUTLOOK", StorageCleanupCatalog.Find("storage-outlook-ost")!.BlockingApps);
        Assert.Contains("OneDrive", StorageCleanupCatalog.Find("storage-onedrive-logs")!.BlockingApps);
        Assert.Contains("WINWORD", StorageCleanupCatalog.Find("storage-office-locks")!.BlockingApps);
    }

    // ---- age cutoffs ----

    [Fact]
    public void Npm_OnlyFilesOlderThan30Days_EmptiedFoldersRemoved_RootKept()
    {
        var root = L("npm-cache", "_cacache");
        var old = Make(P(root, "content-v2", "sha512", "aa", "old"), 5000, 31);
        var fresh = Make(P(root, "content-v2", "sha512", "bb", "new"), 5000, 29);
        var r = Clean("storage-npm");
        Assert.True(r.Ran);
        Assert.Equal((1L, 5000L), (r.FilesRemoved, r.BytesFreed));
        Assert.False(File.Exists(old));
        Assert.True(File.Exists(fresh));
        Assert.False(Directory.Exists(P(root, "content-v2", "sha512", "aa")));
        Assert.True(Directory.Exists(root));
        Assert.StartsWith("Freed", r.Message);
    }

    [Fact]
    public void Scan_MeasuresExactlyWhatCleanDeletes()
    {
        var root = L("npm-cache", "_cacache");
        Make(P(root, "a"), 11 << 20, 40);
        Make(P(root, "b"), 3 << 20, 1);
        var item = Scan().Single(i => i.Id == "storage-npm");
        Assert.Equal(11L << 20, item.SizeBytes);
        Assert.True(item.AutoCheckedByDefault);
        Assert.Equal(item.SizeBytes, Clean("storage-npm").BytesFreed);
        Assert.DoesNotContain(Scan(), i => i.Id == "storage-npm"); // what's left is too new
    }

    [Fact]
    public void Grok_StaleSessionsAndDownloads_WorktreesSplitOutAndNeverTouched()
    {
        var grok = U(".grok");
        var s1 = P(grok, "sessions", "s1");
        Make(P(s1, "log.json"), 20 << 20);
        Age(s1, 40);
        var s2 = P(grok, "sessions", "s2");
        var s2Old = Make(P(s2, "a.json"), 1000, 40);
        Make(P(s2, "b.json"), 1000, 1); // one recent file keeps the whole session
        var dl = Make(P(grok, "downloads", "x.zip"), 1000, 31);
        var wt = P(grok, "worktrees", "proj");
        var wtFile = Make(P(wt, "big.bin"), 12 << 20);
        Age(wt, 400);

        var items = Scan();
        Assert.Equal((20L << 20) + 1000, items.Single(i => i.Id == "storage-grok").SizeBytes); // worktrees not in the auto-checked estimate
        var review = items.Single(i => i.Id == StorageCleanupCatalog.GrokWorktreesId);
        Assert.Equal(StorageCleanupCatalog.ReviewCategory, review.Category);
        Assert.False(review.AutoCheckedByDefault);
        Assert.Equal(12L << 20, review.SizeBytes);
        Assert.DoesNotContain(StorageCleanupCatalog.Suggestions(items), s => s.Id == StorageCleanupCatalog.GrokWorktreesId);

        var r = Clean("storage-grok");
        Assert.True(r.Ran);
        Assert.False(Directory.Exists(s1));
        Assert.True(File.Exists(s2Old));
        Assert.False(File.Exists(dl));
        Assert.True(File.Exists(wtFile));
        Assert.True(Directory.Exists(P(grok, "sessions")));
    }

    [Fact]
    public void Browsers_AllProfiles_StaleCacheStorageAndCodeCache_ProfileDataUntouched()
    {
        var ud = L("Google", "Chrome", "User Data");
        var kept = new List<string>();
        var gone = new List<string>();
        foreach (var name in new[] { "Default", "Profile 1" })
        {
            var prof = P(ud, name);
            kept.Add(Make(P(prof, "Preferences"), 100));
            foreach (var data in new[] { "Cookies", "Login Data", "History", "Bookmarks", "Web Data" }) kept.Add(Make(P(prof, data), 100, 400));
            var oldOrigin = P(prof, "Service Worker", "CacheStorage", "oldhash");
            gone.Add(Make(P(oldOrigin, "index.txt"), 100));
            gone.Add(Make(P(oldOrigin, "uuid1", "data"), 3000));
            Age(oldOrigin, 61);
            var liveOrigin = P(prof, "Service Worker", "CacheStorage", "livehash");
            kept.Add(Make(P(liveOrigin, "uuid2", "data"), 3000, 90));
            kept.Add(Make(P(liveOrigin, "index.txt"), 100, 2));
            gone.Add(Make(P(prof, "Code Cache", "js", "old"), 2000, 61));
            kept.Add(Make(P(prof, "Code Cache", "js", "new"), 2000, 1));
        }
        kept.Add(Make(P(ud, "NotAProfile", "Code Cache", "js", "old"), 1000, 100)); // no Preferences file: not a profile

        var r = Clean("storage-browser-chrome");
        Assert.True(r.Ran);
        Assert.Equal(2L * (100 + 3000 + 2000), r.BytesFreed);
        Assert.All(gone, f => Assert.False(File.Exists(f), f));
        Assert.All(kept, f => Assert.True(File.Exists(f), f));
        Assert.False(Directory.Exists(P(ud, "Default", "Service Worker", "CacheStorage", "oldhash")));
    }

    [Fact]
    public void Browsers_OpenBrowserSkipsOnlyItsOwnCategory()
    {
        var chrome = Make(P(L("Google", "Chrome", "User Data"), "Default", "Code Cache", "js", "old"), 1000, 90);
        Make(P(L("Google", "Chrome", "User Data"), "Default", "Preferences"), 10);
        var edge = Make(P(L("Microsoft", "Edge", "User Data"), "Default", "Code Cache", "js", "old"), 1000, 90);
        Make(P(L("Microsoft", "Edge", "User Data"), "Default", "Preferences"), 10);
        bool Running(string n) => n == "chrome";

        var c = Clean("storage-browser-chrome", Running);
        Assert.False(c.Ran);
        Assert.Equal(["chrome"], c.RunningApps);
        Assert.Contains("Chrome is open", c.Message);
        Assert.True(File.Exists(chrome));

        Assert.True(Clean("storage-browser-edge", Running).Ran);
        Assert.False(File.Exists(edge));
    }

    [Fact]
    public void ProtectedFiles_NeverDeleted_EvenInsideAnOldFolder()
    {
        foreach (var n in new[] { "Cookies", "Login Data", "History", "Bookmarks", "Preferences", "Local State", "archive.pst", "ARCHIVE.PST" })
            Assert.True(StorageCleanupEngine.IsProtectedFile(n), n);
        Assert.False(StorageCleanupEngine.IsProtectedFile("data_0"));

        var prof = P(L("Google", "Chrome", "User Data"), "Default");
        Make(P(prof, "Preferences"), 10);
        var origin = P(prof, "Service Worker", "CacheStorage", "odd");
        var cookies = Make(P(origin, "Cookies"), 100);
        var pst = Make(P(origin, "mail.pst"), 100);
        var cache = Make(P(origin, "data"), 100);
        Age(origin, 100);
        Clean("storage-browser-chrome");
        Assert.True(File.Exists(cookies));
        Assert.True(File.Exists(pst));
        Assert.False(File.Exists(cache));
        Assert.True(Directory.Exists(origin)); // not empty, so it stays
    }

    [Fact]
    public void CrashDumps_OnlyDumpsOlderThan7Days_TopLevelOnly()
    {
        var root = L("CrashDumps");
        var old = Make(P(root, "app.exe.123.dmp"), 1000, 8);
        var recent = Make(P(root, "app.exe.456.dmp"), 1000, 3);
        var other = Make(P(root, "notes.txt"), 1000, 100);
        var nested = Make(P(root, "sub", "x.dmp"), 1000, 100);
        Assert.Equal(1, Clean("storage-crashdumps").FilesRemoved);
        Assert.False(File.Exists(old));
        Assert.True(File.Exists(recent));
        Assert.True(File.Exists(other));
        Assert.True(File.Exists(nested));
    }

    [Fact]
    public void OneDriveAndNewOutlook_LogsAndCachesOlderThan30Days()
    {
        var odOld = Make(L("Microsoft", "OneDrive", "logs", "Personal", "a.odl"), 1000, 31);
        var odNew = Make(L("Microsoft", "OneDrive", "logs", "Personal", "b.odl"), 1000, 2);
        var olkOld = Make(L("Microsoft", "Olk", "EBWebView", "Default", "Cache", "Cache_Data", "f_1"), 1000, 31);
        var olkLog = Make(L("Microsoft", "Olk", "logs", "x.log"), 1000, 45);
        var attachment = Make(L("Microsoft", "Olk", "Attachments", "report.docx"), 1000, 400); // never part of the cleanup
        var olkNew = Make(L("Microsoft", "Olk", "EBWebView", "Default", "Code Cache", "js", "n"), 1000, 1);
        Assert.Equal(1, Clean("storage-onedrive-logs").FilesRemoved);
        Assert.Equal(2, Clean("storage-outlook-cache").FilesRemoved);
        Assert.False(File.Exists(odOld));
        Assert.True(File.Exists(odNew));
        Assert.False(File.Exists(olkOld));
        Assert.False(File.Exists(olkLog));
        Assert.True(File.Exists(attachment));
        Assert.True(File.Exists(olkNew));
    }

    [Fact]
    public void StoreAppWebViewCaches_OlderThan60Days_InEveryPackage()
    {
        var a = Make(L("Packages", "Clipchamp.Clipchamp_yxz", "LocalState", "EBWebView", "Default", "Cache", "Cache_Data", "f_1"), 1000, 61);
        var b = Make(L("Packages", "Other_abc", "LocalState", "EBWebView", "Default", "Code Cache", "js", "x"), 1000, 90);
        var fresh = Make(L("Packages", "Other_abc", "LocalState", "EBWebView", "Default", "Code Cache", "js", "y"), 1000, 59);
        var appData = Make(L("Packages", "Other_abc", "LocalState", "settings.dat"), 1000, 400);
        Assert.Equal(2, Clean("storage-app-webview").FilesRemoved);
        Assert.False(File.Exists(a));
        Assert.False(File.Exists(b));
        Assert.True(File.Exists(fresh));
        Assert.True(File.Exists(appData));
    }

    [Fact]
    public void CodexBackups_CopilotCache_Playwright()
    {
        var prev = Make(U(".cache", "codex-runtimes", "codex-primary-runtime.previous-1", "bin", "codex.exe"), 1000);
        var current = Make(U(".cache", "codex-runtimes", "codex-primary-runtime", "bin", "codex.exe"), 1000);
        Clean("storage-codex");
        Assert.False(Directory.Exists(U(".cache", "codex-runtimes", "codex-primary-runtime.previous-1")));
        Assert.True(File.Exists(current));
        Assert.False(File.Exists(prev));

        var copilot = Make(L("Microsoft", "Copilot", "User Data", "Default", "Cache", "Cache_Data", "f"), 1000);
        var copilotData = Make(L("Microsoft", "Copilot", "User Data", "Default", "Local Storage", "x"), 1000, 100);
        Assert.Equal(["Copilot"], Clean("storage-copilot", n => n == "Copilot").RunningApps);
        Assert.True(File.Exists(copilot));
        Clean("storage-copilot");
        Assert.False(File.Exists(copilot));
        Assert.True(File.Exists(copilotData));

        var pw = L("ms-playwright");
        var oldBrowser = P(pw, "chromium-1140");
        Make(P(oldBrowser, "chrome.exe"), 11 << 20);
        Age(oldBrowser, 61);
        var newBrowser = Make(P(pw, "chromium-1200", "chrome.exe"), 1000, 5);
        var links = Make(P(pw, ".links", "abc"), 10, 400);
        var item = Scan().Single(i => i.Id == "storage-playwright");
        Assert.False(item.AutoCheckedByDefault);
        Assert.False(Assert.Single(StorageCleanupCatalog.Suggestions([item])).DefaultOn); // opt-in in the workflow
        Clean("storage-playwright");
        Assert.False(Directory.Exists(oldBrowser));
        Assert.True(File.Exists(newBrowser));
        Assert.True(File.Exists(links));
    }

    [Fact]
    public void ClassicOst_OnlyWhenNewOutlookIsUsed_StaleOnly_NeverPst()
    {
        var ost = Make(L("Microsoft", "Outlook", "bud@msn.com.ost"), 20 << 20, 90);
        var recentOst = Make(L("Microsoft", "Outlook", "work.ost"), 1000, 10);
        var pst = Make(L("Microsoft", "Outlook", "archive.pst"), 1000, 400);
        var olk = L("Microsoft", "Olk");
        Make(P(olk, "EBWebView", "x"), 10, 200);
        Age(olk, 200);
        Assert.Empty(StorageCleanupCatalog.StaleOstFiles(Ctx())); // new Outlook not used lately: classic may still be in use
        Assert.DoesNotContain(Scan(), i => i.Id == "storage-outlook-ost");

        Make(P(olk, "EBWebView", "y"), 10, 1);
        var item = Scan().Single(i => i.Id == "storage-outlook-ost");
        Assert.Equal(20L << 20, item.SizeBytes);
        Assert.False(item.AutoCheckedByDefault);
        Assert.False(Clean("storage-outlook-ost", n => n == "OUTLOOK").Ran);
        Assert.True(File.Exists(ost));
        Assert.Equal(1, Clean("storage-outlook-ost").FilesRemoved);
        Assert.False(File.Exists(ost));
        Assert.True(File.Exists(recentOst));
        Assert.True(File.Exists(pst));
    }

    [Fact]
    public void OfficeLocks_OnlyTinyOldOwnerFilesInTemplates()
    {
        var tpl = R("Microsoft", "Templates");
        var stale = Make(P(tpl, "~$Normal.dotm"), 162, 3);
        File.SetAttributes(stale, FileAttributes.Hidden);
        var normal = Make(P(tpl, "Normal.dotm"), 30000, 300);
        var big = Make(P(tpl, "~$Big.dotx"), 10000, 30);
        var fresh = Make(P(tpl, "~$Fresh.dotm"), 162);
        var nested = Make(P(tpl, "Sub", "~$x.dotm"), 162, 30);

        var item = Scan().Single(i => i.Id == "storage-office-locks"); // offered at any size
        Assert.Equal(162, item.SizeBytes);
        Assert.False(Clean("storage-office-locks", n => n == "WINWORD").Ran);
        Assert.True(File.Exists(stale));
        var r = Clean("storage-office-locks");
        Assert.Equal(1, r.FilesRemoved);
        Assert.Contains("KB", r.Message);
        Assert.False(File.Exists(stale));
        Assert.All(new[] { normal, big, fresh, nested }, f => Assert.True(File.Exists(f), f));
    }

    // ---- VS Code (#2, #5) ----

    private static string ExtDir(string root, string name)
    {
        var d = P(root, name);
        Make(P(d, "package.json"), 1000, 30);
        return Age(d, 30);
    }

    [Theory]
    [InlineData("ms-dotnettools.csharp-2.140.9-win32-x64", "ms-dotnettools.csharp|-win32-x64", "2.140.9")]
    [InlineData("anthropic.claude-code-2.1.251", "anthropic.claude-code|", "2.1.251")]
    [InlineData("Google.GeminiCodeAssist-2.98.0", "google.geminicodeassist|", "2.98.0")]
    public void ExtensionFolderNames(string name, string key, string version)
    {
        var p = StorageCleanupCatalog.ParseExtensionFolder(name);
        Assert.NotNull(p);
        Assert.Equal((key, Version.Parse(version)), p.Value);
    }

    [Theory]
    [InlineData("weird-folder")]
    [InlineData(".5e1e46e0-1111-2222-3333-444455556666")]
    [InlineData("publisher.name-latest")]
    public void ExtensionFolderNames_UnknownAreNotVersions(string name) => Assert.Null(StorageCleanupCatalog.ParseExtensionFolder(name));

    [Fact]
    public void VsCodeExtensions_SupersededByVersionOrdering_InstalledKept_StagingOlderThan7Days()
    {
        var ext = U(".vscode", "extensions");
        var old = ExtDir(ext, "ms-dotnettools.csharp-2.9.0-win32-x64");
        var newer = ExtDir(ext, "ms-dotnettools.csharp-2.10.0-win32-x64"); // 2.10 > 2.9 numerically
        var otherPlatform = ExtDir(ext, "ms-dotnettools.csharp-2.8.0");    // its own group: the only one, so kept
        var listedOld = ExtDir(ext, "google.geminicodeassist-2.98.0");     // listed in extensions.json: kept
        var gNew = ExtDir(ext, "google.geminicodeassist-2.99.0");
        var claudeOld = ExtDir(ext, "anthropic.claude-code-2.1.251");
        var claudeNew = ExtDir(ext, "anthropic.claude-code-2.1.300");
        var unknown = ExtDir(ext, "weird-folder");
        var stagingOld = ExtDir(ext, ".5e1e46e0-1111-2222-3333-444455556666");
        Age(stagingOld, 8);
        var stagingNew = P(ext, ".f73ca900-aaaa-bbbb-cccc-ddddeeeeffff");
        Make(P(stagingNew, "package.json"), 1000, 1);
        var dotOther = ExtDir(ext, ".cache");
        Age(dotOther, 30);
        File.WriteAllText(P(ext, "extensions.json"), JsonSerializer.Serialize(new object[]
        {
            new { identifier = new { id = "ms-dotnettools.csharp" }, version = "2.10.0", relativeLocation = "ms-dotnettools.csharp-2.10.0-win32-x64" },
            new { identifier = new { id = "google.geminicodeassist" }, version = "2.98.0", location = new { path = "/c:/Users/bud/.vscode/extensions/google.geminicodeassist-2.98.0", scheme = "file" } },
            new { identifier = new { id = "anthropic.claude-code" }, version = "2.1.300", relativeLocation = "anthropic.claude-code-2.1.300" },
        }));

        Assert.Equal(new[] { old, claudeOld }.OrderBy(x => x), StorageCleanupCatalog.SupersededExtensions(ext).OrderBy(x => x));
        Assert.Equal([stagingOld], StorageCleanupCatalog.StagingFolders(ext, Now));
        Assert.False(Clean("storage-vscode-extensions", n => n == "Code").Ran);
        Assert.True(Directory.Exists(old));
        Assert.True(Clean("storage-vscode-extensions").Ran);
        foreach (var d in new[] { old, claudeOld, stagingOld }) Assert.False(Directory.Exists(d), d);
        foreach (var d in new[] { newer, otherPlatform, listedOld, gNew, claudeNew, unknown, stagingNew, dotOther }) Assert.True(Directory.Exists(d), d);
        Assert.True(File.Exists(P(ext, "extensions.json")));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("not json")]
    [InlineData("{}")]
    [InlineData("[]")]
    public void VsCodeExtensions_NoReadableExtensionList_NoVersionsRemoved(string? manifest)
    {
        var ext = U(".vscode", "extensions");
        ExtDir(ext, "a.b-1.0.0");
        ExtDir(ext, "a.b-2.0.0");
        if (manifest is not null) File.WriteAllText(P(ext, "extensions.json"), manifest);
        Assert.Empty(StorageCleanupCatalog.SupersededExtensions(ext));
    }

    [Fact]
    public void VsCodeVersions_OldCommitFoldersOnly_NewestAndReferencedKept()
    {
        var inst = L("Programs", "Microsoft VS Code");
        Make(P(inst, "Code.exe"), 10);
        string Commit(string name, int days)
        {
            var d = P(inst, name);
            Make(P(d, "resources", "app", "product.json"), 2000);
            try { Directory.SetCreationTimeUtc(d, Now.AddDays(-days)); } catch (Exception) { }
            return Age(d, days);
        }
        var a = Commit("aaaaaaaaa1", 100);
        var referenced = Commit("dddddddd04", 80);
        var b = Commit("bbbbbbbbb2", 50);
        var current = Commit("ccccccccc3", 20);
        Make(P(inst, "bin", "code.cmd"), 0);
        File.WriteAllText(P(inst, "bin", "code.cmd"), "@\"%~dp0..\\dddddddd04\\Code.exe\" %*");
        var notCommit = Commit("resources1", 100); // 10 chars but not hex

        Assert.Equal(new[] { a, b }.OrderBy(x => x), StorageCleanupCatalog.OldVsCodeVersions(inst, Now).OrderBy(x => x));
        var vsix = Make(R("Code", "CachedExtensionVSIXs", "x.vsix"), 1000);
        var crash = Make(R("Code", "Crashpad", "reports", "r.dmp"), 1000);
        var settings = Make(R("Code", "User", "settings.json"), 100, 300);
        Assert.True(Clean("storage-vscode").Ran);
        Assert.False(Directory.Exists(a));
        Assert.False(Directory.Exists(b));
        Assert.True(Directory.Exists(current));
        Assert.True(Directory.Exists(referenced));
        Assert.True(Directory.Exists(notCommit));
        Assert.False(File.Exists(vsix));
        Assert.False(File.Exists(crash));
        Assert.True(File.Exists(settings));
        Assert.True(File.Exists(P(inst, "Code.exe")));
    }

    [Fact]
    public void VsCodeVersions_NotAVsCodeInstallOrOnlyOneVersion_Nothing()
    {
        var inst = L("Programs", "Microsoft VS Code");
        Age(Path.GetDirectoryName(Make(P(inst, "aaaaaaaaa1", "f"), 10))!, 100);
        Age(Path.GetDirectoryName(Make(P(inst, "bbbbbbbbb2", "f"), 10))!, 50);
        Assert.Empty(StorageCleanupCatalog.OldVsCodeVersions(inst, Now)); // no Code.exe
        Make(P(inst, "Code.exe"), 10);
        Directory.Delete(P(inst, "bbbbbbbbb2"), true);
        Assert.Empty(StorageCleanupCatalog.OldVsCodeVersions(inst, Now)); // only one version
    }

    // ---- NuGet (#1): the existing safety rules still decide ----

    private string NuGetPackage(string version, string? source = "https://api.nuget.org/v3/index.json", int daysAgo = 400)
    {
        var dir = U(".nuget", "packages", "example", version);
        Make(P(dir, "lib", "net8.0", "Example.dll"), 1000);
        Make(P(dir, $"example.{version}.nupkg.sha512"), 88);
        if (source is not null)
        {
            var meta = P(dir, ".nupkg.metadata");
            File.WriteAllText(meta, JsonSerializer.Serialize(new { version = 2, contentHash = "x", source }));
            File.SetLastWriteTimeUtc(meta, Now.AddDays(-daysAgo));
        }
        return dir;
    }

    private string Repos()
    {
        var repos = U("source", "repos");
        var obj = Directory.CreateDirectory(P(repos, "app", "obj")).FullName;
        File.WriteAllText(P(obj, "project.assets.json"), JsonSerializer.Serialize(new { libraries = new Dictionary<string, object> { ["Example/1.5.0"] = new { type = "package" } } }));
        return repos;
    }

    [Fact]
    public void NuGet_HttpCacheCleared_OnlyUnreferencedOldNuGetOrgVersionsRemoved()
    {
        var newest = NuGetPackage("3.0.0");
        var superseded = NuGetPackage("1.0.0");
        var referenced = NuGetPackage("1.5.0");
        var companyFeed = NuGetPackage("1.2.0", "https://pkgs.dev.azure.com/contoso/_packaging/feed/nuget/v3/index.json");
        var recent = NuGetPackage("1.1.0", daysAgo: 10);
        var noMetadata = NuGetPackage("1.3.0", source: null);
        var unknown = Directory.CreateDirectory(U(".nuget", "packages", "example", "not-a-version")).FullName;
        var http = Make(L("NuGet", "v3-cache", "abc", "x.nupkg"), 1000);
        var repos = Repos();

        var r = Clean("storage-nuget", null, repos);
        Assert.True(r.Ran);
        Assert.False(Directory.Exists(superseded));
        foreach (var d in new[] { newest, referenced, companyFeed, recent, noMetadata, unknown }) Assert.True(Directory.Exists(d), d);
        Assert.True(File.Exists(P(newest, ".nupkg.metadata")));
        Assert.False(File.Exists(http));
        Assert.True(Directory.Exists(L("NuGet", "v3-cache")));
        Assert.Equal(1000L + 88 + new FileInfo(P(newest, ".nupkg.metadata")).Length + 1000, r.BytesFreed);
    }

    [Fact]
    public void NuGet_NoProjectFolderFound_NoPackageVersionsRemoved()
    {
        NuGetPackage("2.0.0");
        var superseded = NuGetPackage("1.0.0");
        Clean("storage-nuget"); // no project roots: nothing is known to be unused
        Assert.True(Directory.Exists(superseded));
        Clean("storage-nuget", null, U("source", "missing"));
        Assert.True(Directory.Exists(superseded));
    }

    [Fact]
    public void NuGet_MarkerInUse_VersionFolderLeftComplete()
    {
        if (!OperatingSystem.IsWindows()) return; // file locks are Windows behaviour
        NuGetPackage("2.0.0");
        var superseded = NuGetPackage("1.0.0");
        var repos = Repos();
        StorageCleanResult r;
        using (new FileStream(P(superseded, "example.1.0.0.nupkg.sha512"), FileMode.Open, FileAccess.Read, FileShare.None))
            r = Clean("storage-nuget", null, repos);
        Assert.True(File.Exists(P(superseded, "lib", "net8.0", "Example.dll")));
        Assert.True(r.FilesSkipped >= 1);
    }

    // ---- locked files, links, allowlist, apps ----

    [Fact]
    public void LockedFile_SkippedAndTheRestContinues()
    {
        if (!OperatingSystem.IsWindows()) return; // file locks are Windows behaviour
        var root = L("CrashDumps");
        var locked = Make(P(root, "a.dmp"), 1000, 30);
        var other = Make(P(root, "b.dmp"), 1000, 30);
        StorageCleanResult r;
        using (new FileStream(locked, FileMode.Open, FileAccess.Read, FileShare.None))
            r = Clean("storage-crashdumps");
        Assert.True(File.Exists(locked));
        Assert.False(File.Exists(other));
        Assert.Equal((1L, 1), (r.FilesRemoved, r.FilesSkipped));
        Assert.Contains("in use", r.Message);
    }

    [Fact]
    public void ReparsePoints_InsideCaches_NeverFollowedOrDeleted()
    {
        var outside = P(_tmp, "outside");
        var precious = Make(P(outside, "precious.txt"), 1000, 400);
        var root = L("npm-cache", "_cacache");
        var old = Make(P(root, "old"), 1000, 400);
        if (!TryLink(P(root, "link"), outside)) return;
        Assert.Equal((1L, 1000L), StorageCleanupEngine.Measure(StorageTarget.Contents(root, Now.AddDays(-30))));

        var r = Clean("storage-npm");
        Assert.True(File.Exists(precious));
        Assert.False(File.Exists(old));
        Assert.True(Directory.Exists(P(root, "link")));
        Assert.True(r.LinksSkipped >= 1);

        // A whole-folder target with a link inside: the folder's own files go, the link and what it points to stay.
        var prev = U(".cache", "codex-runtimes", "codex-primary-runtime.previous-1");
        var exe = Make(P(prev, "bin", "codex.exe"), 1000);
        Assert.True(TryLink(P(prev, "bin", "link"), outside));
        Clean("storage-codex");
        Assert.False(File.Exists(exe));
        Assert.True(File.Exists(precious));
        Assert.True(Directory.Exists(prev));

        // An age rule never calls a folder stale when it contains a link (its contents can't be judged).
        var session = P(U(".grok"), "sessions", "s1");
        Make(P(session, "x.json"), 10, 100);
        Age(session, 100);
        Assert.True(TryLink(P(session, "l"), outside));
        Directory.SetLastWriteTimeUtc(session, Now.AddDays(-100)); // only the link is "new" to the rule
        Assert.Empty(StorageCleanupCatalog.StaleEntries(P(U(".grok"), "sessions"), Now.AddDays(-30), Now, default));
    }

    [Fact]
    public void ReparsePoints_RootOrFolderAboveItIsALink_Refused()
    {
        var elsewhere = P(_tmp, "elsewhere");
        var file = Make(P(elsewhere, "old"), 1000, 400);
        Directory.CreateDirectory(L("npm-cache"));
        if (!TryLink(L("npm-cache", "_cacache"), elsewhere)) return;
        var r = Clean("storage-npm");
        Assert.Equal((0L, 1), (r.FilesRemoved, r.Refused));
        Assert.True(File.Exists(file));

        var redirected = P(_tmp, "redirected");
        var log = Make(P(redirected, "OneDrive", "logs", "a.odl"), 1000, 400);
        Assert.True(TryLink(L("Microsoft"), redirected));
        var od = Clean("storage-onedrive-logs");
        Assert.Equal(1, od.Refused);
        Assert.True(File.Exists(log));
        Assert.Empty(Scan().Where(i => i.Id is "storage-npm" or "storage-onedrive-logs"));
    }

    [Fact]
    public void Allowlist_ExactRootsOnly()
    {
        var root = L("npm-cache", "_cacache");
        Directory.CreateDirectory(root);
        string[] allowed = [root];
        Assert.True(StorageCleanupEngine.IsAllowed(StorageTarget.Contents(root), allowed, _roots, out _));
        Assert.True(StorageCleanupEngine.IsAllowed(StorageTarget.Contents(root + Path.DirectorySeparatorChar), allowed, _roots, out _));
        Assert.False(StorageCleanupEngine.IsAllowed(StorageTarget.Contents(L("npm-cache")), allowed, _roots, out var why1));
        Assert.Contains("allowlist", why1);
        Assert.False(StorageCleanupEngine.IsAllowed(new StorageTarget(root, P(root, "..", "other"), StorageTargetMode.Directory), allowed, _roots, out _));
        Assert.False(StorageCleanupEngine.IsAllowed(StorageTarget.Folder(root, root), allowed, _roots, out _));            // never the root itself
        Assert.False(StorageCleanupEngine.IsAllowed(new StorageTarget(root, P(root, "x"), StorageTargetMode.Contents), allowed, _roots, out _));
        Assert.False(StorageCleanupEngine.IsAllowed(StorageTarget.OneFile(root, P(root, "mail.pst")), allowed, _roots, out _));
        Assert.False(StorageCleanupEngine.IsAllowed(StorageTarget.Contents(L("missing")), [L("missing")], _roots, out _));
        var notAccount = Directory.CreateDirectory(P(_tmp, "not-account")).FullName;
        Assert.False(StorageCleanupEngine.IsAllowed(StorageTarget.Contents(notAccount), [notAccount], _roots, out var why2));
        Assert.Contains("account", why2);
    }

    [Fact]
    public void Clean_RefusesTargetsOffItsAllowlist_EvenFromItsOwnRule()
    {
        Directory.CreateDirectory(L("safe"));
        var unsafeFile = Make(L("unsafe", "keep.txt"), 100, 400);
        var outside = Make(P(_tmp, "outside", "keep.txt"), 100, 400);
        var category = new StorageCategory("storage-test", "Test", "Test", true, [], "Test",
            _ => [L("safe")],
            (_, _) => [StorageTarget.Contents(L("unsafe")), StorageTarget.Folder(L("safe"), P(_tmp, "outside"))]);
        var r = StorageCleanupEngine.Clean(category, Ctx(), _ => false);
        Assert.Equal(2, r.Refused);
        Assert.Equal(0, r.FilesRemoved);
        Assert.True(File.Exists(unsafeFile));
        Assert.True(File.Exists(outside));
    }

    [Theory]
    [InlineData("storage-vscode", "Code")]
    [InlineData("storage-onedrive-logs", "OneDrive")]
    [InlineData("storage-outlook-cache", "olk")]
    [InlineData("storage-outlook-cache", "OUTLOOK")]
    [InlineData("storage-office-locks", "EXCEL")]
    [InlineData("storage-browser-edge", "msedge")]
    public void AppRunning_WholeCategorySkipped_NothingDeleted(string id, string app)
    {
        var files = new[]
        {
            Make(R("Code", "CachedExtensionVSIXs", "a.vsix"), 1000),
            Make(L("Microsoft", "OneDrive", "logs", "a.odl"), 1000, 60),
            Make(L("Microsoft", "Olk", "logs", "a.log"), 1000, 60),
            Make(R("Microsoft", "Templates", "~$Normal.dotm"), 162, 30),
            Make(P(L("Microsoft", "Edge", "User Data"), "Default", "Code Cache", "js", "a"), 1000, 90),
        };
        Make(P(L("Microsoft", "Edge", "User Data"), "Default", "Preferences"), 10);
        var r = Clean(id, n => string.Equals(n, app, StringComparison.OrdinalIgnoreCase));
        Assert.False(r.Ran);
        Assert.Contains(app, r.RunningApps!);
        Assert.StartsWith("Skipped:", r.Message);
        Assert.All(files, f => Assert.True(File.Exists(f), f));
    }

    [Fact]
    public void AppRunningCheckFails_TreatedAsOpen()
    {
        var vsix = Make(R("Code", "CachedExtensionVSIXs", "a.vsix"), 1000);
        Assert.False(Clean("storage-vscode", _ => throw new InvalidOperationException("access denied")).Ran);
        Assert.True(File.Exists(vsix));
        Assert.True(Clean("storage-vscode").Ran);
        Assert.False(File.Exists(vsix));
    }

    // ---- service, journal, undo, workflow listing ----

    private sealed class Sys : IMemorySystem
    {
        public IReadOnlyList<StorageCleanupItem> Items = [];
        public Func<string, StorageCleanResult> Cleaner = id => new(id, true, 3, 3L << 30, 0, "Freed 3.0 GB (3 files deleted).");
        public readonly List<string> Cleaned = [];
        public MemoryReading ReadMemory() => new(16L << 30, 8L << 30);
        public Task<MemorySnapshot> CaptureAsync(IReadOnlyList<ServiceInfo> s, CancellationToken ct) => Task.FromResult(new MemorySnapshot(ReadMemory(), []));
        public Task<ActionOutcome> CloseAppAsync(string p, CancellationToken ct) => Task.FromResult(new ActionOutcome(true, ""));
        public Task<ActionOutcome> ForceCloseAppAsync(string p, CancellationToken ct) => Task.FromResult(new ActionOutcome(true, ""));
        public Task<ActionOutcome> RunCommandAsync(string f, IReadOnlyList<string> a, CancellationToken ct) => Task.FromResult(new ActionOutcome(true, ""));
        public byte[]? GetStartupApproved(string n) => null;
        public void SetStartupApproved(string n, byte[]? v) { }
        public bool IsBrowserRunning(BrowserKind k) => false;
        public string? ReadBrowserLocalState(BrowserKind k) => null;
        public void WriteBrowserLocalState(BrowserKind k, string json) { }
        public void OpenUri(string uri) { }
        public string GetServiceStartType(string n) => "Automatic";
        public void SetServiceStartType(string n, string t) { }
        public Task<IReadOnlyList<StorageCleanupItem>> ScanStorageCleanupsAsync(bool refresh, CancellationToken ct) => Task.FromResult(Items);
        public Task<StorageCleanResult> CleanStorageAsync(string id, CancellationToken ct) { Cleaned.Add(id); return Task.FromResult(Cleaner(id)); }
    }

    private static readonly StorageCleanupItem NuGetItem = new("storage-nuget", "NuGet", "d", 3L << 30, AutoCheckedByDefault: true);

    [Fact]
    public void Suggestions_OnePerCategory_DefaultsFromAutoChecked_TempReviewAndUnknownLeftOut()
    {
        var items = new List<StorageCleanupItem>
        {
            new("storage-nuget", "x", "d", 5L << 30, true),
            new("storage-playwright", "x", "d", 4L << 30, false),
            new(StorageCleanupCatalog.TempId, "t", "d", 6L << 30, true),
            new(StorageCleanupCatalog.GrokWorktreesId, "w", "d", 7L << 30, false, StorageCleanupCatalog.ReviewCategory),
            new("storage-unknown", "u", "d", 1L << 30),
        };
        var s = StorageCleanupCatalog.Suggestions(items);
        Assert.Equal(["storage-nuget", "storage-playwright"], s.Select(x => x.Id));
        Assert.True(s[0].DefaultOn);
        Assert.False(s[1].DefaultOn);
        var a = Assert.Single(s[0].Actions);
        Assert.Equal((MemoryActionType.CleanStorage, "storage-nuget"), (a.Type, a.Target));
        Assert.Contains("can't be undone", a.Confirm);
        Assert.Contains("5.0 GB", s[0].Why);
        Assert.Contains("can't be put back", s[0].Why);
        Assert.Equal(StorageCleanupCatalog.SuggestionCategory, s[0].Category);
        Assert.Null(s[0].SavingBytes); // disk, not memory

        var fixes = FixCatalog.Build([], s);
        Assert.Equal(2, fixes.Count);
        Assert.All(fixes, f =>
        {
            Assert.Equal(UndoSupport.None, f.Undo);
            Assert.Equal("can't be undone", Undoability.Chip(f.Undo));
            Assert.False(f.NeedsAdmin);
            Assert.Equal("Storage", f.Area);
            Assert.Equal(MemoryActionType.CleanStorage, f.MemoryAction);
        });
        Assert.True(fixes.Single(f => f.MemoryTarget == "storage-nuget").DefaultOn);
        Assert.False(fixes.Single(f => f.MemoryTarget == "storage-playwright").DefaultOn);
        Assert.Contains(MemoryActionType.CleanStorage, FixCatalog.UnattendedMemoryActions);
        Assert.Equal(UndoSupport.None, Undoability.Of(MemoryActionType.CleanStorage));
        Assert.Empty(FixCatalog.Recommendations(s));
        Assert.Empty(FixCatalog.NotOffered([], s));
    }

    [Fact]
    public async Task Apply_DeletesById_JournalsOnePermanentRecordWithSize_CardGoes()
    {
        var sys = new Sys { Items = [NuGetItem] };
        var j = new MemoryChangeJournal();
        var svc = new MemorySuggestionService(sys, settle: TimeSpan.Zero, journal: j);
        await svc.ScanStorageAsync();
        Assert.True(svc.StorageScanned);
        Assert.Empty(svc.Suggestions); // kept apart from the memory suggestions
        var s = Assert.Single(svc.StorageSuggestions);

        var r = await svc.ApplyAsync(s, s.Actions[0]);
        Assert.True(r.Success, r.Message);
        Assert.StartsWith("Done: Freed 3.0 GB", r.Message);
        Assert.Equal(["storage-nuget"], sys.Cleaned);
        var rec = Assert.Single(j.All);
        Assert.Equal(ChangeKind.NotUndoable, rec.Kind);
        Assert.StartsWith("storage-nuget:", rec.Target);
        Assert.Contains("3.0 GB freed", rec.Label);
        Assert.Contains("3 files deleted", rec.Label);
        Assert.Contains("can't be undone", rec.Label);
        Assert.Equal(UndoSupport.None, Undoability.Of(rec));
        Assert.Empty(svc.StorageSuggestions);
        Assert.Equal(3L << 30, svc.StorageFreedBytes);
        Assert.Null(svc.UndoFor("storage-nuget"));
        Assert.Equal(0, svc.TotalFreedBytes); // RAM counter untouched

        // A later run journals its own record (permanent records are never merged away).
        await svc.ScanStorageAsync(refresh: true);
        await svc.ApplyAsync(svc.StorageSuggestions[0], svc.StorageSuggestions[0].Actions[0]);
        Assert.Equal(2, j.All.Count);
    }

    [Fact]
    public async Task Apply_AppOpen_IsSkipped_NothingDeletedOrJournaled_CardStays()
    {
        var sys = new Sys { Items = [NuGetItem], Cleaner = id => new(id, false, 0, 0, 0, "Skipped: Visual Studio is open, so nothing was deleted.", ["devenv"]) };
        var j = new MemoryChangeJournal();
        var svc = new MemorySuggestionService(sys, settle: TimeSpan.Zero, journal: j);
        await svc.ScanStorageAsync();
        var r = await svc.ApplyAsync(svc.StorageSuggestions[0], svc.StorageSuggestions[0].Actions[0]);
        Assert.False(r.Success);
        Assert.True(r.Skipped);
        Assert.StartsWith("Skipped:", r.Message);
        Assert.Empty(j.All);
        Assert.Single(svc.StorageSuggestions);
    }

    [Theory]
    [InlineData(2, false)] // everything was in use: a failure
    [InlineData(0, true)]  // nothing left by the time it ran: fine
    public async Task Apply_NothingDeleted_NothingJournaled(int inUse, bool success)
    {
        var sys = new Sys { Items = [NuGetItem], Cleaner = id => new(id, true, 0, 0, inUse, "Nothing was deleted.") };
        var j = new MemoryChangeJournal();
        var svc = new MemorySuggestionService(sys, settle: TimeSpan.Zero, journal: j);
        await svc.ScanStorageAsync();
        var r = await svc.ApplyAsync(svc.StorageSuggestions[0], svc.StorageSuggestions[0].Actions[0]);
        Assert.Equal(success, r.Success);
        Assert.Empty(j.All);
    }

    [Fact]
    public async Task Apply_UnknownCategory_RefusedWithoutTouchingThePc()
    {
        var sys = new Sys();
        var j = new MemoryChangeJournal();
        var svc = new MemorySuggestionService(sys, settle: TimeSpan.Zero, journal: j);
        var forged = new MemorySuggestion("x", "x", "x", null, SuggestionRisk.Low, SuggestionKind.Automated, [],
            [new MemoryAction(MemoryActionType.CleanStorage, @"C:\Windows\System32", "Delete")]);
        var r = await svc.ApplyAsync(forged, forged.Actions[0]);
        Assert.False(r.Success);
        Assert.Empty(sys.Cleaned);
        Assert.Empty(j.All);
    }

    [Fact]
    public async Task ScanFails_ReportedNotThrown()
    {
        var svc = new MemorySuggestionService(new ThrowingScan(), settle: TimeSpan.Zero);
        await svc.ScanStorageAsync();
        Assert.NotNull(svc.StorageError);
        Assert.Empty(svc.StorageSuggestions);
        Assert.False(svc.ScanningStorage);
    }

    private sealed class ThrowingScan : IMemorySystem
    {
        private readonly Sys _inner = new();
        public MemoryReading ReadMemory() => _inner.ReadMemory();
        public Task<MemorySnapshot> CaptureAsync(IReadOnlyList<ServiceInfo> s, CancellationToken ct) => _inner.CaptureAsync(s, ct);
        public Task<ActionOutcome> CloseAppAsync(string p, CancellationToken ct) => _inner.CloseAppAsync(p, ct);
        public Task<ActionOutcome> ForceCloseAppAsync(string p, CancellationToken ct) => _inner.ForceCloseAppAsync(p, ct);
        public Task<ActionOutcome> RunCommandAsync(string f, IReadOnlyList<string> a, CancellationToken ct) => _inner.RunCommandAsync(f, a, ct);
        public byte[]? GetStartupApproved(string n) => null;
        public void SetStartupApproved(string n, byte[]? v) { }
        public bool IsBrowserRunning(BrowserKind k) => false;
        public string? ReadBrowserLocalState(BrowserKind k) => null;
        public void WriteBrowserLocalState(BrowserKind k, string json) { }
        public void OpenUri(string uri) { }
        public string GetServiceStartType(string n) => "Automatic";
        public void SetServiceStartType(string n, string t) { }
        public Task<IReadOnlyList<StorageCleanupItem>> ScanStorageCleanupsAsync(bool refresh, CancellationToken ct) => throw new IOException("disk gone");
    }

    [Fact]
    public async Task UndoAll_ListsStorageCleanupAsLeftAsIs_AndForgetsIt()
    {
        var sys = new Sys { Items = [NuGetItem] };
        var j = new MemoryChangeJournal();
        var svc = new MemorySuggestionService(sys, settle: TimeSpan.Zero, journal: j);
        await svc.ScanStorageAsync();
        await svc.ApplyAsync(svc.StorageSuggestions[0], svc.StorageSuggestions[0].Actions[0]);
        var r = await new UndoService(j, new SystemCommandRunner(new ScriptedLauncher((_, _) => ScriptedLauncher.Ok(""))), sys).UndoAllAsync("x");
        Assert.Equal((0, 0, 1), (r.Succeeded, r.Failed, r.Skipped));
        Assert.Contains("left as is", r.Summary);
        Assert.Empty(j.All);
        Assert.Empty(sys.Cleaned.Skip(1)); // undo never re-runs or reverses a cleanup
    }
}
