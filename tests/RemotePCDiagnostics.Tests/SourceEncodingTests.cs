using System.Text;

namespace RemotePCDiagnostics.Tests;

/// <summary>
/// A single Windows-1252 byte (e.g. a bare 0xB7 "·" or 0x97 "—") makes a file invalid UTF-8; the compiler then reads
/// the WHOLE file as Windows-1252 and every correct "°"/"·" in it shows up as "Â°"/"Â·" in the app.
/// </summary>
public class SourceEncodingTests
{
    private static readonly string[] Extensions = [".cs", ".razor", ".cshtml", ".css", ".js", ".html", ".xaml", ".json", ".md"];

    [Fact]
    public void AllSourceFiles_AreValidUtf8()
    {
        var root = RepoRoot();
        var strict = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);
        var bad = new List<string>();
        foreach (var dir in new[] { "src", "tests", "docs" }.Select(d => Path.Combine(root, d)).Where(Directory.Exists))
            foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
            {
                if (!Extensions.Contains(Path.GetExtension(file), StringComparer.OrdinalIgnoreCase)) continue;
                var rel = Path.GetRelativePath(root, file);
                if (rel.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar).Any(p => p is "bin" or "obj" or "node_modules" or "lib")) continue;
                try { strict.GetString(File.ReadAllBytes(file)); }
                catch (DecoderFallbackException) { bad.Add(rel); }
            }
        Assert.True(bad.Count == 0, "Not valid UTF-8 (re-save as UTF-8): " + string.Join(", ", bad));
    }

    private static string RepoRoot()
    {
        for (var d = new DirectoryInfo(AppContext.BaseDirectory); d is not null; d = d.Parent)
            if (File.Exists(Path.Combine(d.FullName, "RemotePCDiagnostics.sln"))) return d.FullName;
        throw new InvalidOperationException("Repository root (RemotePCDiagnostics.sln) not found.");
    }
}
