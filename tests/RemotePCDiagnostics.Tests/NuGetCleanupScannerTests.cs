using System.Text.Json;
using RemotePCDiagnostics.Core.Memory;

namespace RemotePCDiagnostics.Tests;

public sealed class NuGetCleanupScannerTests : IDisposable
{
    private readonly string root = Path.Combine(Path.GetTempPath(), "rpd-nuget-tests-" + Guid.NewGuid().ToString("N"));
    private string Packages => Path.Combine(root, "packages");
    private string Projects => Path.Combine(root, "repos");

    public NuGetCleanupScannerTests()
    {
        Directory.CreateDirectory(Packages);
        Directory.CreateDirectory(Projects);
    }

    /// <summary>A version folder as NuGet leaves it: .nupkg.metadata with its source, downloaded <paramref name="daysAgo"/> days ago.</summary>
    private string Package(string version, string name = "example", string? source = "https://api.nuget.org/v3/index.json", int daysAgo = 400)
    {
        var dir = Directory.CreateDirectory(Path.Combine(Packages, name, version)).FullName;
        if (source is not null)
        {
            var meta = Path.Combine(dir, ".nupkg.metadata");
            File.WriteAllText(meta, JsonSerializer.Serialize(new { version = 2, contentHash = "x", source }));
            File.SetLastWriteTimeUtc(meta, DateTime.UtcNow.AddDays(-daysAgo));
        }
        return dir;
    }
    private void Assets(string relative, params string[] identities)
    {
        var dir = Directory.CreateDirectory(Path.Combine(Projects, relative));
        File.WriteAllText(Path.Combine(dir.FullName, "project.assets.json"), JsonSerializer.Serialize(new
        {
            libraries = identities.ToDictionary(id => id, _ => new { type = "package" })
        }));
    }

    [Fact]
    public void KeepsHighestVersionRegardlessOfCreationOrder()
    {
        Package("2.0.0");
        var old = Package("1.9.0");
        Package("unknown-folder");
        Assert.Equal([old], NuGetCleanupScanner.FindSupersededVersions(Packages, Projects));
    }

    [Fact]
    public void PreservesReferencedVersionsAcrossNestedProjectsWithNormalizedIdentity()
    {
        Package("3.0.0");
        Package("1.0.0");
        Package("2.0.0");
        var unused = Package("1.5.0");
        Assets("team/app/obj", "Example/1.0");
        Assets("other/app/obj", "EXAMPLE/2.0.0");
        Assert.Equal([unused], NuGetCleanupScanner.FindSupersededVersions(Packages, Projects));
    }

    [Fact]
    public void UsesNuGetPrereleaseAndNumericOrdering()
    {
        var beta2 = Package("2.0.0-beta.2");
        Package("2.0.0-beta.10");
        Assert.Equal([beta2], NuGetCleanupScanner.FindSupersededVersions(Packages, Projects));
        var release = Package("2.0.0");
        Assert.DoesNotContain(release, NuGetCleanupScanner.FindSupersededVersions(Packages, Projects));
        Assert.Equal(2, NuGetCleanupScanner.FindSupersededVersions(Packages, Projects).Count);
    }

    [Theory]
    [InlineData("invalid json")]
    [InlineData("{}")]
    [InlineData("{\"libraries\":[]}")]
    [InlineData("{\"libraries\":{\"Example/not-a-version\":{\"type\":\"package\"}}}")]
    public void IncompleteReferenceScanReturnsNoCandidates(string json)
    {
        Package("1.0.0");
        Package("2.0.0");
        File.WriteAllText(Path.Combine(Projects, "project.assets.json"), json);
        var logs = new List<string>();
        Assert.Empty(NuGetCleanupScanner.FindSupersededVersions(Packages, Projects, logs.Add));
        Assert.Single(logs);
    }

    [Fact]
    public void MissingProjectsRootReturnsNoCandidates()
    {
        Package("1.0.0");
        Package("2.0.0");
        Assert.Empty(NuGetCleanupScanner.FindSupersededVersions(Packages, Path.Combine(root, "missing")));
    }

    [Fact]
    public void CancellationIsNotTreatedAsAnEmptyReferenceScan()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        Assert.Throws<OperationCanceledException>(() => NuGetCleanupScanner.FindSupersededVersions(Packages, Projects, ct: cts.Token));
    }

    [Fact]
    public void SkipsNodeModulesWithoutTreatingItsLinksAsAnIncompleteScan()
    {
        Package("2.0.0");
        var old = Package("1.0.0");
        var nm = Directory.CreateDirectory(Path.Combine(Projects, "web", "node_modules", "pkg")).FullName;
        try { Directory.CreateSymbolicLink(Path.Combine(nm, "linked"), Projects); } catch (Exception) { /* no symlink rights: still checks the skip */ }
        Assets("web/node_modules/pkg", "Example/1.0.0"); // ignored: not a .NET project folder
        Assert.Equal([old], NuGetCleanupScanner.FindSupersededVersions(Packages, Projects));
    }

    [Fact]
    public void KeepsVersionsFromOtherFeeds_LocalFolders_AndWithoutMetadata()
    {
        Package("3.0.0");
        var fromOrg = Package("1.0.0");
        Package("1.1.0", source: "https://pkgs.dev.azure.com/contoso/_packaging/feed/nuget/v3/index.json");
        Package("1.2.0", source: @"C:\LocalFeed");
        Package("1.3.0", source: "http://api.nuget.org/v3/index.json"); // not https: keep
        Package("1.4.0", source: null);
        Assert.Equal([fromOrg], NuGetCleanupScanner.FindSupersededVersions(Packages, Projects));
    }

    [Fact]
    public void KeepsRecentlyDownloadedVersions()
    {
        Package("2.0.0");
        var old = Package("1.0.0", daysAgo: 100);
        Package("1.5.0", daysAgo: 10); // a project we didn't find may have just restored it
        Assert.Equal([old], NuGetCleanupScanner.FindSupersededVersions(Packages, Projects));
    }

    [Fact]
    public void ReferencesFromEveryProjectRootAreKept_MissingRootsIgnored()
    {
        Package("3.0.0");
        Package("1.0.0");
        var unused = Package("2.0.0");
        var other = Directory.CreateDirectory(Path.Combine(root, "D-work", "app", "obj")).FullName;
        File.WriteAllText(Path.Combine(other, "project.assets.json"), JsonSerializer.Serialize(new { libraries = new Dictionary<string, object> { ["Example/1.0.0"] = new { type = "package" } } }));
        Assert.Equal([unused], NuGetCleanupScanner.FindSupersededVersions(Packages, [Projects, Path.Combine(root, "D-work"), Path.Combine(root, "gone")]));
        Assert.Empty(NuGetCleanupScanner.FindSupersededVersions(Packages, [Path.Combine(root, "gone")]));
    }

    [Theory]
    [InlineData("https://api.nuget.org/v3/index.json", true)]
    [InlineData("https://www.nuget.org/api/v2/", true)]
    [InlineData("https://nuget.pkg.github.com/acme/index.json", false)]
    [InlineData(@"C:\feed", false)]
    public void IsNuGetOrg(string source, bool expected) => Assert.Equal(expected, NuGetCleanupScanner.IsNuGetOrg(source));

    public void Dispose() => Directory.Delete(root, recursive: true);
}
