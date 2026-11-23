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

    [Fact]
    public async Task SystemDumpPath_Allowlist_AndAgentPlan_WorkForMinidumpsOnly()
    {
        const string minidump = @"C:\WINDOWS\Minidump\120824-9500-01.dmp";
        Assert.True(CrashDumpDebugger.IsAllowedSystemDumpPath(minidump, @"C:\Windows"));
        Assert.True(CrashDumpDebugger.IsAllowedSystemDumpPath(@"C:\Windows\LiveKernelReports\WATCHDOG\wd.dmp", @"C:\Windows"));
        Assert.True(CrashDumpDebugger.IsAllowedSystemDumpPath(@"C:\Windows\MEMORY.DMP", @"C:\Windows"));
        Assert.False(CrashDumpDebugger.IsAllowedSystemDumpPath(@"C:\Users\me\foo.dmp", @"C:\Windows"));
        Assert.False(CrashDumpDebugger.IsAllowedSystemDumpPath(@"C:\Windows\Minidump\..\System32\x.dmp", @"C:\Windows"));

        var plan = RemotePCDiagnostics.Core.Session.AgentScripts.Plan(
            RemotePCDiagnostics.Core.Session.AgentScripts.Of(RemotePCDiagnostics.Core.Session.AgentScripts.AnalyzeCrashDump, minidump),
            null, out var refusal);
        Assert.Null(refusal);
        var native = Assert.IsType<RemotePCDiagnostics.Core.Session.AnalyzeCrashDumpAction>(plan!.Native);
        Assert.Equal(minidump, native.DumpPath);

        Assert.Null(RemotePCDiagnostics.Core.Session.AgentScripts.Plan(
            RemotePCDiagnostics.Core.Session.AgentScripts.Of(RemotePCDiagnostics.Core.Session.AgentScripts.AnalyzeCrashDump, @"C:\Users\me\secret.dmp"),
            null, out _));

        // When not directly readable and no Agent is connected, return a clear admin-required message instead of "missing".
        var msg = await CrashDumpDebugger.AnalyzeAsync(minidump);
        Assert.Contains("administrator access", msg, StringComparison.OrdinalIgnoreCase);
    }
}
