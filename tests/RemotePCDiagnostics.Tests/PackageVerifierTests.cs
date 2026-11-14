using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Tests;

public sealed class PackageVerifierTests
{
    [Fact]
    public void MissingLayout_NamesTheAbsentFilesAndDoesNotMentionTheRemovedAdminHelper()
    {
        var root = Directory.CreateTempSubdirectory("rpd-verify-");
        try
        {
            File.WriteAllText(Path.Combine(root.FullName, "RemotePCDiagnostics.Agent.dll"), "");
            var lines = new List<string>();
            var code = PackageVerifier.Run(root.FullName, lines.Add);

            Assert.Equal(1, code);
            var text = string.Join("\n", lines);
            Assert.Contains("Package check 'required files' failed.", text);
            Assert.Contains("RemotePCDiagnostics.Agent.exe", text);
            Assert.Contains("RemotePCDiagnostics.Agent.deps.json", text);
            Assert.Contains("RemotePCDiagnostics.Agent.runtimeconfig.json", text);
            Assert.Contains("Expected these files", text);
            Assert.Contains("Found: not present.", text);
            Assert.DoesNotContain("RemotePCDiagnostics.Admin.exe", text);
        }
        finally { root.Delete(recursive: true); }
    }

    [Fact]
    public void FailedSelfCheck_IsLoggedWithExitCodeAndStderr_AndTheAdminPipeIsNotProbed()
    {
        using var layout = new CompleteLayout();
        var probes = new FakeProbes
        {
            SelfCheckResult = PackageVerifier.DescribeAgentSelfCheck(exitCode: -2147450749, timedOut: false, stdout: "", stderr: "The library hostpolicy.dll required to execute the application was not found."),
        };
        var lines = new List<string>();

        var code = PackageVerifier.Run(layout.Path, lines.Add, probes);

        Assert.Equal(1, code);
        Assert.Equal(1, probes.MemTestCalls);
        Assert.Equal(1, probes.SelfCheckCalls);
        Assert.Equal(0, probes.PipeCalls);
        var text = string.Join("\n", lines);
        Assert.Contains("Package check 'Agent self-check' failed.", text);
        Assert.Contains("Expected RemotePCDiagnostics.Agent.exe --self-check exits 0", text);
        Assert.Contains("Found: exit -2147450749.", text);
        Assert.Contains("hostpolicy.dll", text);
        Assert.DoesNotContain("Package check 'Agent admin pipe'", text);
    }

    [Fact]
    public void FailedAdminPipe_NamesTheHelperCommandAndThePingThatWasExpected()
    {
        using var layout = new CompleteLayout();
        var probes = new FakeProbes
        {
            PipeResult = PackageProbeResult.Fail("Expected 'RemotePCDiagnostics.Agent.exe --mode=helper --parent-pid=4 --pipe=rpd-verify-abc' accepts an AdminPipeProtocol ping (op=ping, ok=true, helperPid equals the Agent process) from Host and then exits 0. Found: no ping response. Agent exit=-2147450749. stderr: missing deps.json."),
        };
        var lines = new List<string>();

        var code = PackageVerifier.Run(layout.Path, lines.Add, probes);

        Assert.Equal(1, code);
        Assert.Equal(1, probes.PipeCalls);
        var text = string.Join("\n", lines);
        Assert.Contains("Package check 'Agent admin pipe' failed.", text);
        Assert.Contains("--mode=helper", text);
        Assert.Contains("op=ping, ok=true", text);
        Assert.Contains("missing deps.json", text);
        Assert.DoesNotContain("RemotePCDiagnostics.Admin.exe", text);
    }

    [Fact]
    public void EmptyProbeDetail_StillNamesTheCheck()
    {
        using var layout = new CompleteLayout();
        var probes = new FakeProbes { MemTestResult = new PackageProbeResult(false, "  ") };
        var lines = new List<string>();

        var code = PackageVerifier.Run(layout.Path, lines.Add, probes);

        Assert.Equal(1, code);
        Assert.Contains(lines, l => l.Contains("Package check 'MemTest probe' failed.", StringComparison.Ordinal)
            && l.Contains("No detail was reported", StringComparison.Ordinal));
    }

    [Fact]
    public void PassingProbes_RequireTheInAgentAdminPipe()
    {
        using var layout = new CompleteLayout();
        var probes = new FakeProbes();
        var lines = new List<string>();

        var code = PackageVerifier.Run(layout.Path, lines.Add, probes);

        Assert.Equal(0, code);
        Assert.Equal(1, probes.PipeCalls);
        var text = string.Join("\n", lines);
        Assert.Contains("missing: (none).", text);
        Assert.Contains("Package check 'Agent admin pipe' passed.", text);
        Assert.Contains("op=ping, ok=true", probes.PipeResult.Detail);
    }

    [Fact]
    public void MemTestMismatch_ReportsExpectedDoneLineAndActualOutput()
    {
        var result = PackageVerifier.DescribeMemTest(exitCode: 0, timedOut: false, output: "MT DONE 1048576 0 1\n");

        Assert.False(result.Ok);
        Assert.Contains("MT DONE 1048576 <passes> 0", result.Detail);
        Assert.Contains("passes > 0", result.Detail);
        Assert.Contains("MT DONE 1048576 0 1", result.Detail);
    }

    [Fact]
    public void AgentHelperArguments_UseHelperModeOnTheAgent_NotTheRemovedAdminExe()
    {
        var args = PackageVerifier.AgentHelperArguments(parentPid: 42, pipeName: "rpd-verify-1");
        var command = "RemotePCDiagnostics.Agent.exe " + string.Join(' ', args);

        Assert.Equal(["--mode=helper", "--parent-pid=42", "--pipe=rpd-verify-1"], args);
        Assert.Contains("--mode=helper", command);
        Assert.DoesNotContain("RemotePCDiagnostics.Admin", command);
    }

    private sealed class CompleteLayout : IDisposable
    {
        public string Path { get; } = Directory.CreateTempSubdirectory("rpd-verify-ok-").FullName;

        public CompleteLayout()
        {
            foreach (var stem in new[] { "RemotePCDiagnostics.MemTest", "RemotePCDiagnostics.ModuleHost", "RemotePCDiagnostics.Agent", "moduleui/RemotePCDiagnostics.ModuleUiHost" })
                Write(stem + ".dll");
            foreach (var relative in PackageVerifier.RelativePathsRequired(Path))
                Write(relative);
        }

        public void Dispose() => Directory.Delete(Path, recursive: true);

        private void Write(string relative)
        {
            var full = System.IO.Path.Combine(Path, relative.Replace('/', System.IO.Path.DirectorySeparatorChar));
            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(full)!);
            if (!File.Exists(full)) File.WriteAllBytes(full, []);
        }
    }

    private sealed class FakeProbes : IPackageProbes
    {
        public int MemTestCalls, SelfCheckCalls, PipeCalls;
        public PackageProbeResult MemTestResult { get; set; } = PackageProbeResult.Pass("Expected a clean MemTest DONE line. Found: MT DONE 1048576 2 0.");
        public PackageProbeResult SelfCheckResult { get; set; } = PackageProbeResult.Pass("Expected --self-check to exit 0. Found: exit 0.");
        public PackageProbeResult PipeResult { get; set; } = PackageProbeResult.Pass("Expected an AdminPipeProtocol ping (op=ping, ok=true). Found: ping ok=true, helperPid=7, exit 0.");

        public PackageProbeResult MemTest(string baseDirectory) { MemTestCalls++; return MemTestResult; }
        public PackageProbeResult AgentSelfCheck(string baseDirectory) { SelfCheckCalls++; return SelfCheckResult; }
        public PackageProbeResult AgentAdminPipe(string baseDirectory) { PipeCalls++; return PipeResult; }
    }
}
