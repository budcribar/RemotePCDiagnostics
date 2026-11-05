using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Tests;

public class CrashDumpDebuggerTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(@"\\server\share\MEMORY.DMP")]
    [InlineData("//server/share/MEMORY.DMP")]
    [InlineData(@"\\?\UNC\server\share\MEMORY.DMP")]
    public void Network_and_empty_paths_are_refused(string? path) => Assert.False(CrashDumpDebugger.IsLocalDump(path));

    [Fact]
    public void Only_an_existing_local_dmp_file_is_accepted()
    {
        var dir = Directory.CreateTempSubdirectory("rpcd-dump-");
        try
        {
            var dump = Path.Combine(dir.FullName, "test.dmp");
            var other = Path.Combine(dir.FullName, "test.txt");
            File.WriteAllText(dump, "x");
            File.WriteAllText(other, "x");
            Assert.True(CrashDumpDebugger.IsLocalDump(dump));
            Assert.False(CrashDumpDebugger.IsLocalDump(other));
            Assert.False(CrashDumpDebugger.IsLocalDump(Path.Combine(dir.FullName, "missing.dmp")));
        }
        finally { dir.Delete(recursive: true); }
    }
}
