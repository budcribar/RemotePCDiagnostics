using RemotePCDiagnostics.Core.Projects;

namespace RemotePCDiagnostics.Tests;

public sealed class ProjectLocatorTests : IDisposable
{
    private readonly string root = Path.Combine(Path.GetTempPath(), "rpd-projects-" + Guid.NewGuid().ToString("N"));
    private readonly ProjectLocatorPaths paths;

    public ProjectLocatorTests()
    {
        paths = new(Path.Combine(root, "home"), Path.Combine(root, "home", "AppData", "Roaming"), Path.Combine(root, "home", "AppData", "Local"), [Path.Combine(root, "D")]);
        Directory.CreateDirectory(paths.AppData);
        Directory.CreateDirectory(paths.LocalAppData);
    }

    private string Repo(params string[] parts)
    {
        var dir = Directory.CreateDirectory(Path.Combine([root, .. parts])).FullName;
        Directory.CreateDirectory(Path.Combine(dir, ".git"));
        return dir;
    }

    private static string Uri(string path) => "file:///" + path.Replace('\\', '/').Replace(":", "%3A");

    [Fact]
    public void ParsesVsCodeWorkspaceJson_FoldersWorkspacesAndRemote()
    {
        Assert.Equal(@"D:\work\my app", ProjectLocator.ParseWorkspaceJson("""{"folder":"file:///d%3A/work/my%20app"}"""));
        Assert.Equal(@"C:\src\mono", ProjectLocator.ParseWorkspaceJson("""{"workspace":"file:///c%3A/src/mono/all.code-workspace"}"""));
        Assert.Null(ProjectLocator.ParseWorkspaceJson("""{"folder":"vscode-remote://wsl%2Bubuntu/home/bud/app"}"""));
        Assert.Null(ProjectLocator.ParseWorkspaceJson("not json"));
    }

    [Fact]
    public void ParsesVisualStudioRecentSolutions()
    {
        var xml = """<content><collection name="CodeContainers.Offline"><value name="value">[{"Key":"D:\\work\\Shop\\Shop.sln","Value":{"LocalProperties":{"FullPath":"D:\\work\\Shop\\Shop.sln"}}},{"Key":"C:\\Repos\\Api"}]</value></collection></content>""";
        var found = ProjectLocator.ParseVisualStudioSettings(xml).Distinct().ToList();
        Assert.Contains(@"D:\work\Shop", found);
        Assert.Contains(@"C:\Repos\Api", found);
    }

    [Fact]
    public void ParsesRiderRecentSolutions()
    {
        var xml = """<application><component name="RiderRecentProjectsManager"><option name="additionalInfo"><map><entry key="$USER_HOME$/RiderProjects/Game/Game.sln"><value/></entry><entry key="E:/code/Tools"><value/></entry></map></option></component></application>""";
        Assert.Equal([@"C:\Users\bud\RiderProjects\Game", @"E:\code\Tools"], ProjectLocator.ParseRiderRecent(xml, @"C:\Users\bud").ToList());
    }

    [Fact]
    public void ProjectFolderOf_AssetsInObj_GoesToTheProject()
    {
        Assert.Equal(@"D:\work\App", ProjectLocator.ProjectFolderOf(@"D:\work\App\obj\project.assets.json"));
        Assert.Equal(@"D:\work", ProjectLocator.ProjectFolderOf(@"D:\work\Shop.sln"));
    }

    [Fact]
    public async Task FindAsync_CombinesSources_WidensToRepoRoot_DropsNestedAndUnsafe()
    {
        var shop = Repo("D", "clients", "shop"); // "D:\\work" would itself be a common folder
        var api = Directory.CreateDirectory(Path.Combine(shop, "src", "Api")).FullName;  // inside the shop repo
        var tools = Repo("D", "tools");
        var downloaded = Repo("home", "Downloads", "sample");                          // never offered
        var common = Directory.CreateDirectory(Path.Combine(paths.UserProfile, "source", "repos")).FullName;

        var ws = Directory.CreateDirectory(Path.Combine(paths.AppData, "Code", "User", "workspaceStorage", "abc")).FullName;
        File.WriteAllText(Path.Combine(ws, "workspace.json"), $$"""{"folder":"{{Uri(api)}}"}""");
        var ws2 = Directory.CreateDirectory(Path.Combine(paths.AppData, "Cursor", "User", "workspaceStorage", "def")).FullName;
        File.WriteAllText(Path.Combine(ws2, "workspace.json"), $$"""{"folder":"{{Uri(downloaded)}}"}""");

        var index = new[] { Path.Combine(tools, "obj", "project.assets.json"), Path.Combine(paths.UserProfile, "Profile.sln") };
        var found = await new ProjectLocator(paths, _ => Task.FromResult<IReadOnlyList<string>>(index)).FindAsync();

        Assert.Equal(new[] { common, shop, tools }.OrderBy(x => x, StringComparer.OrdinalIgnoreCase), found.Select(f => f.Path));
        Assert.Equal(ProjectSource.VsCode, found.Single(f => f.Path == shop).Source);
        Assert.Equal(ProjectSource.SearchIndex, found.Single(f => f.Path == tools).Source);
    }

    [Fact]
    public async Task FindAsync_SearchIndexFailure_StillReturnsTheRest()
    {
        var repo = Repo("D", "src", "app");
        var ws = Directory.CreateDirectory(Path.Combine(paths.AppData, "Code", "User", "workspaceStorage", "x")).FullName;
        File.WriteAllText(Path.Combine(ws, "workspace.json"), $$"""{"folder":"{{Uri(repo)}}"}""");
        var found = await new ProjectLocator(paths, _ => throw new InvalidOperationException("Windows Search is off")).FindAsync();
        // D\src is a common folder, so it is found as a whole and the repo inside it isn't listed separately.
        Assert.Equal([Path.Combine(root, "D", "src")], found.Select(f => f.Path));
    }

    [Fact]
    public void IsUnsafe_ProfileStandardFoldersDriveRootsAndDownloads()
    {
        Assert.True(ProjectLocator.IsUnsafe(paths.UserProfile, paths));
        Assert.True(ProjectLocator.IsUnsafe(Path.Combine(paths.UserProfile, "Documents"), paths));
        Assert.True(ProjectLocator.IsUnsafe(Path.Combine(paths.UserProfile, "Downloads", "repo"), paths));
        Assert.True(ProjectLocator.IsUnsafe(Path.Combine(paths.LocalAppData, "Temp", "x"), paths));
        Assert.True(ProjectLocator.IsUnsafe(@"D:\", paths));
        Assert.False(ProjectLocator.IsUnsafe(Path.Combine(paths.UserProfile, "Documents", "GitHub", "app"), paths));
        Assert.False(ProjectLocator.IsUnsafe(@"D:\work\shop", paths));
    }

    [Fact]
    public void CollapseSiblings_ThreeReposInOneSafeFolderBecomeTheFolder()
    {
        var list = ProjectLocator.CollapseSiblings([@"D:\work\a", @"D:\work\b", @"D:\work\c", @"E:\one\x", @"E:\one\y"], paths);
        Assert.Equal([@"D:\work", @"E:\one\x", @"E:\one\y"], list);
        // Never collapses into an unsafe parent (a drive root).
        Assert.Equal([@"D:\a", @"D:\b", @"D:\c"], ProjectLocator.CollapseSiblings([@"D:\a", @"D:\b", @"D:\c"], paths));
    }

    public void Dispose() { try { Directory.Delete(root, true); } catch { } }
}
