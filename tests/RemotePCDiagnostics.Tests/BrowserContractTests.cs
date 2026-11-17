using System.Text.RegularExpressions;
using RemotePCDiagnostics.Core;

namespace RemotePCDiagnostics.Tests;

public class BrowserContractTests
{
    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "RemotePCDiagnostics.sln")))
                return dir.FullName;
            dir = dir.Parent;
        }
        throw new DirectoryNotFoundException("Could not locate repository root containing RemotePCDiagnostics.sln.");
    }

    private static IEnumerable<string> RazorFiles() =>
        Directory.EnumerateFiles(Path.Combine(FindRepoRoot(), "src"), "*.razor", SearchOption.AllDirectories)
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}")
                && !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}"));

    [Fact]
    public void Every_page_marker_has_a_contract_version()
    {
        // Literal markers: data-rpcd-page="history". The Checks page switches between checks and stress in one expression.
        var literal = new Regex("data-rpcd-page=\"([a-z-]+)\"");
        var quoted = new Regex("data-rpcd-page=\"@\\([^\"]*\"([a-z-]+)\"[^\"]*\"([a-z-]+)\"\\)\"");
        var found = new HashSet<string>(StringComparer.Ordinal);
        foreach (var file in RazorFiles())
        {
            foreach (var line in File.ReadLines(file).Where(l => l.Contains("data-rpcd-page=", StringComparison.Ordinal)))
            {
                foreach (Match m in literal.Matches(line)) found.Add(m.Groups[1].Value);
                foreach (Match m in quoted.Matches(line)) { found.Add(m.Groups[1].Value); found.Add(m.Groups[2].Value); }
                Assert.True(line.Contains("data-rpcd-contract=", StringComparison.Ordinal),
                    $"{Path.GetFileName(file)}: a data-rpcd-page marker without data-rpcd-contract");
            }
        }

        Assert.NotEmpty(found);
        Assert.All(found, page => Assert.True(BrowserContract.Pages.ContainsKey(page), $"page '{page}' has no BrowserContract version"));
        Assert.Equal(found.OrderBy(p => p, StringComparer.Ordinal), BrowserContract.Pages.Keys.OrderBy(p => p, StringComparer.Ordinal));
    }

    [Fact]
    public void Versions_start_at_one_or_higher() =>
        Assert.All(BrowserContract.Pages.Values, version => Assert.True(version >= 1));
}
