using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Bios;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Sensors;
using RemotePCDiagnostics.Core.Session;
using Xunit;

namespace RemotePCDiagnostics.Tests.Bios;

public sealed class BiosAgentElevationTests
{
    private static readonly HashSet<string> ForbiddenShellBinaries = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell", "powershell.exe", "pwsh", "pwsh.exe",
        "cmd", "cmd.exe", "sh", "bash", "zsh",
    };

    private static readonly string[] ForbiddenScriptExtensions = [".ps1", ".bat", ".cmd", ".sh"];

    private static readonly IReadOnlySet<int> RebootCodes = new HashSet<int> { 0, 3010 };
    private static readonly IReadOnlySet<int> CompletedCodes = new HashSet<int> { 2 };

    // -------------------------------------------------------------------------
    // Group A — Live Named-Pipe Round-Trips (All 3 Privileged BIOS Operations)
    // -------------------------------------------------------------------------

    [Fact]
    public async Task Pipe_SuspendBitLocker_ValidDrive_ExecutesAllowlistedManageBdeInAgent()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var agentLauncher = CreateGuardedLauncher((_, _) => Task.FromResult(new ProcessResult(0, "Protectors disabled.", "")));
        var ops = new AgentBiosOperations(agentLauncher);

        var (server, serverTask, client) = await StartPipeAsync(agentLauncher, ops, cts.Token);
        using (server)
        {
            await using (client)
            {
                var result = await client.SuspendBitLockerAsync("d:", cts.Token);

                Assert.True(result.Suspended);
                Assert.True(result.Allowed);
                Assert.Equal(0, result.ExitCode);
                Assert.Null(result.Error);
            }

            await serverTask;
        }

        var call = Assert.Single(agentLauncher.Calls);
        Assert.Equal("manage-bde.exe", call.BaseName, ignoreCase: true);
        Assert.Equal(["-protectors", "-disable", "D:", "-RebootCount", "1"], call.Arguments);
    }

    [Fact]
    public async Task Pipe_SuspendBitLocker_VolumeNotEncrypted_ReturnsNonZeroCleanly()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var agentLauncher = CreateGuardedLauncher((_, _) =>
            Task.FromResult(new ProcessResult(1, "", "ERROR: Volume C: is not encrypted.")));
        var ops = new AgentBiosOperations(agentLauncher);

        var (server, serverTask, client) = await StartPipeAsync(agentLauncher, ops, cts.Token);
        using (server)
        {
            await using (client)
            {
                var result = await client.SuspendBitLockerAsync("C:", cts.Token);

                Assert.False(result.Suspended);
                Assert.True(result.Allowed);
                Assert.Equal(1, result.ExitCode);
                Assert.Contains("not encrypted", result.Error ?? "", StringComparison.OrdinalIgnoreCase);
            }

            await serverTask;
        }
    }

    [Theory]
    [InlineData("hp", BiosAgentInstallModes.HpSoftPaq, "sp150000.exe", false, new[] { "-s", "-r" })]
    [InlineData("hp", BiosAgentInstallModes.HpSoftPaq, "sp150000.exe", true, new[] { "-s" })]
    [InlineData("hp", BiosAgentInstallModes.HpBiosUpdRec, "HPBIOSUPDREC64.exe", false, new[] { "-s", "-r" })]
    [InlineData("hp", BiosAgentInstallModes.HpBiosUpdRec, "HPBIOSUPDREC64.exe", true, new[] { "-s" })]
    [InlineData("dell", BiosAgentInstallModes.DellBiosExe, "Latitude_7430_1.15.0.exe", false, new[] { "/s" })]
    [InlineData("dell", BiosAgentInstallModes.DellBiosExe, "Latitude_7430_1.15.0.exe", true, new[] { "/s", "/r" })]
    [InlineData("lenovo", BiosAgentInstallModes.LenovoWinUptp, "winuptp64.exe", false, new[] { "-s" })]
    [InlineData("lenovo", BiosAgentInstallModes.LenovoWinUptp, "winuptp64.exe", true, new[] { "-s", "-r" })]
    [InlineData("lenovo", BiosAgentInstallModes.LenovoPackageSilent, "n32uj20w.exe", false, new[] { "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART" })]
    [InlineData("lenovo", BiosAgentInstallModes.LenovoPackageSilent, "n32uj20w.exe", true, new[] { "/VERYSILENT", "/SUPPRESSMSGBOXES" })]
    [InlineData("framework", BiosAgentInstallModes.FrameworkBiosExe, "Framework_BIOS_03.05.exe", false, new[] { "/silent", "/norestart" })]
    [InlineData("framework", BiosAgentInstallModes.FrameworkBiosExe, "Framework_BIOS_03.05.exe", true, new[] { "/silent" })]
    public async Task Pipe_RunBiosInstaller_AllExeModes_CopiesToAdminStagingVerifiesExecutesAndCleansUp(
        string vendorId,
        string mode,
        string fileName,
        bool allowReboot,
        string[] expectedArgs)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var userDir = new TempStagingDir();
        using var adminRoot = new TempStagingDir();

        var payload = TestPayload.FromString($"fake-signed-bios-binary-{vendorId}-{mode}");
        var userPkgPath = userDir.FilePath(fileName);
        await File.WriteAllBytesAsync(userPkgPath, payload.Bytes, cts.Token);

        var sigVerifier = new FakeSignatureVerifier(result: true);
        var agentLauncher = CreateGuardedLauncher((_, _) => Task.FromResult(new ProcessResult(3010, "Staged OK", "")));
        var ops = new AgentBiosOperations(
            launcher: agentLauncher,
            signatureVerifier: sigVerifier,
            stagingRoot: adminRoot.Path);

        var (server, serverTask, client) = await StartPipeAsync(agentLauncher, ops, cts.Token);
        using (server)
        {
            await using (client)
            {
                var req = new BiosAgentInstallRequest(
                    VendorId: vendorId,
                    InstallMode: mode,
                    PackagePath: userPkgPath,
                    ExpectedSha256: payload.Sha256,
                    AllowReboot: allowReboot,
                    TimeoutMs: 120_000);

                var result = await client.RunBiosInstallerAsync(req, cts.Token);

                Assert.True(result.Executed);
                Assert.True(result.Allowed);
                Assert.Equal(3010, result.ExitCode);
                Assert.False(result.TimedOut);
                Assert.Equal("Staged OK", result.LogTail);
            }

            await serverTask;
        }

        var call = Assert.Single(agentLauncher.Calls);
        Assert.Equal(expectedArgs, call.Arguments);
        AssertPathStrictlyInside(call.FileName, adminRoot.Path);
        // The Agent pins the signer to this vendor; it never accepts just any valid signature.
        Assert.Same(BiosAgentInstallModes.AllowedSignerOrganizations(mode), Assert.Single(sigVerifier.AllowedSignerSets));
        Assert.NotEqual(Path.GetFullPath(userPkgPath), Path.GetFullPath(call.FileName));

        var verifiedPath = Assert.Single(sigVerifier.VerifiedPaths);
        AssertPathStrictlyInside(verifiedPath, adminRoot.Path);
        Assert.Equal(Path.GetFullPath(call.FileName), Path.GetFullPath(verifiedPath));

        // Admin staging run subdirectory must be deleted in finally.
        Assert.Empty(Directory.GetFileSystemEntries(adminRoot.Path));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Pipe_RunBiosInstaller_MicrosoftSurfaceMsi_InvokesMsiexecOnAdminCopy(bool allowReboot)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var userDir = new TempStagingDir();
        using var adminRoot = new TempStagingDir();

        var payload = TestPayload.FromString("surface-firmware-msi-bytes");
        var userMsiPath = userDir.FilePath("SurfaceLaptop5_Win11_22621_24.051.12345.0.msi");
        await File.WriteAllBytesAsync(userMsiPath, payload.Bytes, cts.Token);

        var sigVerifier = new FakeSignatureVerifier(result: true);
        var agentLauncher = CreateGuardedLauncher((_, _) => Task.FromResult(new ProcessResult(3010, "MSI staged", "")));
        var ops = new AgentBiosOperations(agentLauncher, sigVerifier, stagingRoot: adminRoot.Path);

        var (server, serverTask, client) = await StartPipeAsync(agentLauncher, ops, cts.Token);
        using (server)
        {
            await using (client)
            {
                var req = new BiosAgentInstallRequest(
                    VendorId: "microsoft",
                    InstallMode: BiosAgentInstallModes.MicrosoftSurfaceMsi,
                    PackagePath: userMsiPath,
                    ExpectedSha256: payload.Sha256,
                    AllowReboot: allowReboot);

                var res = await client.RunBiosInstallerAsync(req, cts.Token);
                Assert.True(res.Executed);
                Assert.True(res.Allowed);
                Assert.Equal(3010, res.ExitCode);
            }

            await serverTask;
        }

        var call = Assert.Single(agentLauncher.Calls);
        Assert.Equal("msiexec.exe", call.BaseName, ignoreCase: true);
        Assert.Equal("/i", call.Arguments[0]);
        AssertPathStrictlyInside(call.Arguments[1], adminRoot.Path);
        Assert.Equal("/qn", call.Arguments[2]);
        if (allowReboot)
        {
            Assert.Equal(3, call.Arguments.Count);
        }
        else
        {
            Assert.Equal(4, call.Arguments.Count);
            Assert.Equal("/norestart", call.Arguments[3]);
        }

        Assert.Empty(Directory.GetFileSystemEntries(adminRoot.Path));
    }

    [Theory]
    [InlineData(false, "-reboot=disable")]
    [InlineData(true, "-reboot=enable")]
    public async Task Pipe_RunBiosInstaller_DellDcuCli_ResolvesAllowlistedRootAndVerifiesSignature(
        bool allowReboot,
        string expectedRebootArg)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var fakeProgramFiles = new TempStagingDir();

        var dcuDir = Path.Combine(fakeProgramFiles.Path, "Dell", "CommandUpdate");
        Directory.CreateDirectory(dcuDir);
        var dcuExe = Path.Combine(dcuDir, "dcu-cli.exe");
        var payload = TestPayload.FromString("dell-command-update-cli-binary");
        await File.WriteAllBytesAsync(dcuExe, payload.Bytes, cts.Token);

        var sigVerifier = new FakeSignatureVerifier(result: true);
        var agentLauncher = CreateGuardedLauncher((_, _) => Task.FromResult(new ProcessResult(1, "Reboot required", "")));
        var ops = new AgentBiosOperations(
            launcher: agentLauncher,
            signatureVerifier: sigVerifier,
            allowedToolRoots: [fakeProgramFiles.Path]);

        var (server, serverTask, client) = await StartPipeAsync(agentLauncher, ops, cts.Token);
        using (server)
        {
            await using (client)
            {
                // Auto-discovery with null PackagePath
                var res1 = await client.RunBiosInstallerAsync(
                    new BiosAgentInstallRequest("dell", BiosAgentInstallModes.DellDcuCli, PackagePath: null, AllowReboot: allowReboot),
                    cts.Token);
                Assert.True(res1.Executed);
                Assert.True(res1.Allowed);
                Assert.Equal(1, res1.ExitCode);

                // Explicit allowlisted path + matching SHA-256
                var res2 = await client.RunBiosInstallerAsync(
                    new BiosAgentInstallRequest("dell", BiosAgentInstallModes.DellDcuCli, PackagePath: dcuExe, ExpectedSha256: payload.Sha256, AllowReboot: allowReboot),
                    cts.Token);
                Assert.True(res2.Executed);
                Assert.True(res2.Allowed);
            }

            await serverTask;
        }

        Assert.Equal(2, agentLauncher.Calls.Count);
        foreach (var call in agentLauncher.Calls)
        {
            Assert.Equal(Path.GetFullPath(dcuExe), Path.GetFullPath(call.FileName));
            Assert.Equal(["/applyUpdates", "-updateType=bios", "-silent", expectedRebootArg], call.Arguments);
        }

        Assert.Equal(2, sigVerifier.CallCount);
    }

    [Fact]
    public async Task Pipe_RunBiosInstaller_FrameworkCabCapsule_ExtractsVerifiesOuterOrCatAndRunsPnpUtil()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var userDir = new TempStagingDir();
        using var adminRoot = new TempStagingDir();

        var cabBytes = TestCabBuilder.CreateUncompressed(new Dictionary<string, byte[]>
        {
            ["firmware.inf"] = Encoding.UTF8.GetBytes("[Version]\nSignature=\"$WINDOWS NT$\""),
            ["sub/custom.inf"] = Encoding.UTF8.GetBytes("[Version]\nSignature=\"$WINDOWS NT$\""),
            ["firmware.cat"] = Encoding.UTF8.GetBytes("signed-whql-catalog"),
            ["firmware.bin"] = Encoding.UTF8.GetBytes("uefi-capsule-payload"),
        });
        var cabPayload = TestPayload.FromBytes(cabBytes);
        var userCabPath = userDir.FilePath("framework-capsule.cab");
        await File.WriteAllBytesAsync(userCabPath, cabPayload.Bytes, cts.Token);

        // Case 1: Outer .cab is unsigned, but SHA-256 matches and inner .cat passes Authenticode.
        var catOnlyVerifier = new FakeSignatureVerifier((p, _) =>
            Task.FromResult(p.EndsWith(".cat", StringComparison.OrdinalIgnoreCase)));
        var agentLauncher = CreateGuardedLauncher((_, _) => Task.FromResult(new ProcessResult(3010, "Driver added.", "")));
        var ops = new AgentBiosOperations(agentLauncher, catOnlyVerifier, stagingRoot: adminRoot.Path);

        var (server, serverTask, client) = await StartPipeAsync(agentLauncher, ops, cts.Token);
        using (server)
        {
            await using (client)
            {
                var res = await client.RunBiosInstallerAsync(
                    new BiosAgentInstallRequest(
                        VendorId: "framework",
                        InstallMode: BiosAgentInstallModes.FrameworkCabCapsule,
                        PackagePath: userCabPath,
                        ExpectedSha256: cabPayload.Sha256,
                        AllowReboot: false,
                        InfRelativePath: "sub/custom.inf"),
                    cts.Token);

                Assert.True(res.Executed);
                Assert.True(res.Allowed);
                Assert.Equal(3010, res.ExitCode);
            }

            await serverTask;
        }

        var call = Assert.Single(agentLauncher.Calls);
        Assert.Equal("pnputil.exe", call.BaseName, ignoreCase: true);
        Assert.Equal(3, call.Arguments.Count);
        Assert.Equal("/add-driver", call.Arguments[0]);
        AssertPathStrictlyInside(call.Arguments[1], adminRoot.Path);
        Assert.EndsWith("custom.inf", call.Arguments[1], StringComparison.OrdinalIgnoreCase);
        Assert.Equal("/install", call.Arguments[2]);
        Assert.Empty(Directory.GetFileSystemEntries(adminRoot.Path));

        // Case 2: Outer .cab signed (no SHA-256 needed), default INF selection.
        var cabSignedVerifier = new FakeSignatureVerifier((p, _) =>
            Task.FromResult(p.EndsWith(".cab", StringComparison.OrdinalIgnoreCase)));
        var launcher2 = CreateGuardedLauncher((_, _) => Task.FromResult(new ProcessResult(0, "OK", "")));
        var ops2 = new AgentBiosOperations(launcher2, cabSignedVerifier, stagingRoot: adminRoot.Path);

        var res2 = await ops2.RunBiosInstallerAsync(
            new BiosAgentInstallRequest("framework", BiosAgentInstallModes.FrameworkCabCapsule, PackagePath: userCabPath),
            cts.Token);
        Assert.True(res2.Executed);
        Assert.True(res2.Allowed);
        Assert.Equal(0, res2.ExitCode);
        Assert.EndsWith(".inf", Assert.Single(launcher2.Calls).Arguments[1], StringComparison.OrdinalIgnoreCase);
        Assert.Empty(Directory.GetFileSystemEntries(adminRoot.Path));

        // Case 3: Neither outer .cab nor inner .cat is signed -> fail closed!
        var unsignedVerifier = new FakeSignatureVerifier(result: false);
        var launcher3 = CreateGuardedLauncher();
        var ops3 = new AgentBiosOperations(launcher3, unsignedVerifier, stagingRoot: adminRoot.Path);

        var res3 = await ops3.RunBiosInstallerAsync(
            new BiosAgentInstallRequest("framework", BiosAgentInstallModes.FrameworkCabCapsule, PackagePath: userCabPath, ExpectedSha256: cabPayload.Sha256),
            cts.Token);
        Assert.False(res3.Executed);
        Assert.False(res3.Allowed);
        Assert.Empty(launcher3.Calls);
        Assert.Empty(Directory.GetFileSystemEntries(adminRoot.Path));
    }

    [Fact]
    public async Task Pipe_InstallBiosWindowsUpdate_ValidGuid_RoutesThroughAgentWindowsUpdateAndMapsOutcome()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var wua = new FakeWuaApi();
        var agentLauncher = CreateGuardedLauncher();
        var ops = new AgentBiosOperations(agentLauncher, wuaApiFactory: () => wua);

        var (server, serverTask, client) = await StartPipeAsync(agentLauncher, ops, cts.Token);
        using (server)
        {
            await using (client)
            {
                // (a) Succeeded + reboot required
                var id1 = Guid.Parse("748279c7-4309-452c-8b30-e02ec52e498f");
                wua.Reset(new FakeWuaUpdate("System Firmware 1.20.0", eula: false), new UpdateInstallOutcome(2, 0, true));
                var r1 = await client.InstallBiosWindowsUpdateAsync(id1, TimeSpan.FromMinutes(2), cts.Token);
                Assert.True(r1.Succeeded);
                Assert.Equal(2, r1.ResultCode);
                Assert.True(r1.RebootRequired);
                Assert.Contains("Reboot required", r1.Message, StringComparison.OrdinalIgnoreCase);

                // (b) Succeeded + no reboot
                var id2 = Guid.Parse("11111111-2222-3333-4444-555555555555");
                wua.Reset(new FakeWuaUpdate("UEFI Capsule 2.0", downloaded: true), new UpdateInstallOutcome(2, 0, false));
                var r2 = await client.InstallBiosWindowsUpdateAsync(id2, ct: cts.Token);
                Assert.True(r2.Succeeded);
                Assert.False(r2.RebootRequired);

                // (c) Not found
                var id3 = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
                wua.Reset(update: null, outcome: new UpdateInstallOutcome(2, 0, false));
                var r3 = await client.InstallBiosWindowsUpdateAsync(id3, ct: cts.Token);
                Assert.False(r3.Succeeded);
                Assert.Contains("no longer offers", r3.Message, StringComparison.OrdinalIgnoreCase);

                // (d) Install failure with HRESULT
                var id4 = Guid.Parse("99999999-8888-7777-6666-555555555555");
                wua.Reset(new FakeWuaUpdate("Broken Firmware", downloaded: true), new UpdateInstallOutcome(4, unchecked((int)0x80070643), false));
                var r4 = await client.InstallBiosWindowsUpdateAsync(id4, ct: cts.Token);
                Assert.False(r4.Succeeded);
                Assert.Equal(4, r4.ResultCode);
                Assert.Contains("0x80070643", r4.Message, StringComparison.OrdinalIgnoreCase);

                // (e) COMException during search
                wua.Reset(update: null, outcome: new UpdateInstallOutcome(4, 0, false));
                wua.SearchError = new COMException("WUA service stopped", unchecked((int)0x8024A000));
                var r5 = await client.InstallBiosWindowsUpdateAsync(id4, ct: cts.Token);
                Assert.False(r5.Succeeded);
                Assert.Contains("0x8024A000", r5.Message, StringComparison.OrdinalIgnoreCase);
            }

            await serverTask;
        }

        Assert.Empty(agentLauncher.Calls);
    }

    // -------------------------------------------------------------------------
    // Group B — Agent-Side Security Boundary Rejections
    // -------------------------------------------------------------------------

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("C")]
    [InlineData("C:\\")]
    [InlineData("CC:")]
    [InlineData("1:")]
    [InlineData(" C:")]
    [InlineData("C: ")]
    [InlineData("C:; calc.exe")]
    [InlineData("C:&whoami")]
    [InlineData("C:|dir")]
    [InlineData("C:\r\nD:")]
    [InlineData("\\\\server\\c$")]
    public async Task AgentSecurity_SuspendBitLocker_RejectsMalformedAndInjectionDrives(string badDrive)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var agentLauncher = CreateGuardedLauncher();
        var ops = new AgentBiosOperations(agentLauncher);

        var (server, serverTask, client) = await StartPipeAsync(agentLauncher, ops, cts.Token);
        using (server)
        {
            await using (client)
            {
                var res = await client.SuspendBitLockerAsync(badDrive, cts.Token);

                Assert.False(res.Suspended);
                Assert.False(res.Allowed);
                Assert.Equal(-1, res.ExitCode);
                Assert.False(string.IsNullOrWhiteSpace(res.Error));
            }

            await serverTask;
        }

        Assert.Empty(agentLauncher.Calls);
    }

    [Fact]
    public async Task AgentSecurity_RunBiosInstaller_RejectsTamperedSha256MalformedSha256AndToctou_DeletesAdminCopy()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var userDir = new TempStagingDir();
        using var adminRoot = new TempStagingDir();

        var cleanPayload = TestPayload.FromString("clean-dell-bios-payload");
        var pkgPath = userDir.FilePath("bios.exe");
        await File.WriteAllBytesAsync(pkgPath, cleanPayload.Bytes, cts.Token);

        var sigVerifier = new FakeSignatureVerifier(result: true);
        var agentLauncher = CreateGuardedLauncher();
        var ops = new AgentBiosOperations(agentLauncher, sigVerifier, stagingRoot: adminRoot.Path);

        var (server, serverTask, client) = await StartPipeAsync(agentLauncher, ops, cts.Token);
        using (server)
        {
            await using (client)
            {
                // (a) Wrong 64-hex SHA-256
                var wrongSha = new string('a', 64);
                var r1 = await client.RunBiosInstallerAsync(
                    new BiosAgentInstallRequest("dell", BiosAgentInstallModes.DellBiosExe, pkgPath, ExpectedSha256: wrongSha),
                    cts.Token);
                Assert.False(r1.Executed);
                Assert.False(r1.Allowed);
                Assert.Contains("SHA-256", r1.Error ?? "", StringComparison.OrdinalIgnoreCase);

                // (b) Malformed / whitespace SHA-256 values all fail closed
                foreach (var badSha in new[] { "abc123", "   ", new string('g', 64), new string('a', 63), new string('a', 65) })
                {
                    var rBad = await client.RunBiosInstallerAsync(
                        new BiosAgentInstallRequest("dell", BiosAgentInstallModes.DellBiosExe, pkgPath, ExpectedSha256: badSha),
                        cts.Token);
                    Assert.False(rBad.Executed);
                    Assert.False(rBad.Allowed);
                }

                // (c) Simulated TOCTOU: source file is tampered AFTER caller computed SHA-256, BEFORE Agent copies it
                await File.WriteAllBytesAsync(pkgPath, Encoding.UTF8.GetBytes("evil-tampered-bytes"), cts.Token);
                var rToctou = await client.RunBiosInstallerAsync(
                    new BiosAgentInstallRequest("dell", BiosAgentInstallModes.DellBiosExe, pkgPath, ExpectedSha256: cleanPayload.Sha256),
                    cts.Token);
                Assert.False(rToctou.Executed);
                Assert.False(rToctou.Allowed);
                Assert.Contains("SHA-256", rToctou.Error ?? "", StringComparison.OrdinalIgnoreCase);
            }

            await serverTask;
        }

        Assert.Empty(agentLauncher.Calls);
        Assert.Empty(Directory.GetFileSystemEntries(adminRoot.Path));

        // (d) Post-copy TOCTOU immunity: if attacker mutates source file during signature verification,
        // Agent still executes its own immutable admin-owned staging copy with the original clean bytes.
        await File.WriteAllBytesAsync(pkgPath, cleanPayload.Bytes, cts.Token);
        string? executedCopyHash = null;
        var raceVerifier = new FakeSignatureVerifier(async (_, token) =>
        {
            await File.WriteAllBytesAsync(pkgPath, Encoding.UTF8.GetBytes("attacker-post-copy-swap"), token);
            return true;
        });
        var raceLauncher = CreateGuardedLauncher(async (call, token) =>
        {
            var (_, actual) = await BiosPackageVerifier.VerifyFileSha256Async(call.FileName, cleanPayload.Sha256, token);
            executedCopyHash = actual;
            return new ProcessResult(0, "ok", "");
        });
        var raceOps = new AgentBiosOperations(raceLauncher, raceVerifier, stagingRoot: adminRoot.Path);

        var raceResult = await raceOps.RunBiosInstallerAsync(
            new BiosAgentInstallRequest("dell", BiosAgentInstallModes.DellBiosExe, pkgPath, ExpectedSha256: cleanPayload.Sha256),
            cts.Token);

        Assert.True(raceResult.Executed);
        Assert.True(raceResult.Allowed);
        Assert.Equal(cleanPayload.Sha256, executedCopyHash);
        Assert.Empty(Directory.GetFileSystemEntries(adminRoot.Path));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\\\\evil-server\\share\\bios.exe")]
    [InlineData("//evil-server/share/bios.exe")]
    [InlineData("\\\\?\\UNC\\evil\\share\\bios.exe")]
    [InlineData("\\\\?\\C:\\bios.exe")]
    [InlineData("\\\\.\\PhysicalDrive0")]
    [InlineData("\\??\\C:\\bios.exe")]
    [InlineData("bios.exe")]
    [InlineData("..\\bios.exe")]
    [InlineData("/tmp/foo/../bios.exe")]
    [InlineData("/tmp/foo/./bios.exe")]
    [InlineData("/tmp/bios.exe;whoami")]
    [InlineData("/tmp/bios.exe&whoami")]
    [InlineData("/tmp/bios.exe|cat")]
    [InlineData("/tmp/bios.exe$(id)")]
    [InlineData("/tmp/bios.exe`id`")]
    [InlineData("/tmp/bios.exe\nbios.exe")]
    [InlineData("/tmp/bios.exe\0.txt")]
    [InlineData(" /tmp/bios.exe")]
    [InlineData("/tmp/bios.exe ")]
    [InlineData("file:///tmp/bios.exe")]
    [InlineData("/tmp/bios.exe:evil")]
    public async Task AgentSecurity_RunBiosInstaller_RejectsUncDeviceTraversalMetacharAndAdsPaths(string badPath)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var adminRoot = new TempStagingDir();
        var agentLauncher = CreateGuardedLauncher();
        var ops = new AgentBiosOperations(agentLauncher, new FakeSignatureVerifier(true), stagingRoot: adminRoot.Path);

        var (server, serverTask, client) = await StartPipeAsync(agentLauncher, ops, cts.Token);
        using (server)
        {
            await using (client)
            {
                var res = await client.RunBiosInstallerAsync(
                    new BiosAgentInstallRequest("dell", BiosAgentInstallModes.DellBiosExe, PackagePath: badPath),
                    cts.Token);

                Assert.False(res.Executed);
                Assert.False(res.Allowed);
            }

            await serverTask;
        }

        Assert.Empty(agentLauncher.Calls);
        Assert.Empty(Directory.GetFileSystemEntries(adminRoot.Path));
    }

    [Fact]
    public async Task AgentSecurity_RunBiosInstaller_RejectsMissingDirectoryEmptyOversizedWrongExtAndSymlinks()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var userDir = new TempStagingDir();
        using var adminRoot = new TempStagingDir();

        var realTarget = userDir.FilePath("real-bios.exe");
        await File.WriteAllBytesAsync(realTarget, Encoding.UTF8.GetBytes("real-bios-bytes"), cts.Token);

        var emptyFile = userDir.FilePath("empty.exe");
        await File.WriteAllBytesAsync(emptyFile, [], cts.Token);

        var wrongExtFile = userDir.FilePath("bios.txt");
        await File.WriteAllBytesAsync(wrongExtFile, Encoding.UTF8.GetBytes("text"), cts.Token);

        var oversizedFile = userDir.FilePath("huge.exe");
        await File.WriteAllBytesAsync(oversizedFile, new byte[2048], cts.Token);

        var dirNamedExe = userDir.FilePath("folder.exe");
        Directory.CreateDirectory(dirNamedExe);

        // Real file symlink
        var fileSymlink = userDir.FilePath("link-bios.exe");
        File.CreateSymbolicLink(fileSymlink, realTarget);

        // Real directory symlink parent
        var realSubDir = userDir.FilePath("real-sub");
        Directory.CreateDirectory(realSubDir);
        var nestedRealExe = Path.Combine(realSubDir, "nested.exe");
        await File.WriteAllBytesAsync(nestedRealExe, Encoding.UTF8.GetBytes("nested-bios"), cts.Token);
        var dirSymlink = userDir.FilePath("link-sub");
        Directory.CreateSymbolicLink(dirSymlink, realSubDir);
        var pathViaSymlinkDir = Path.Combine(dirSymlink, "nested.exe");

        var agentLauncher = CreateGuardedLauncher();
        var ops = new AgentBiosOperations(
            agentLauncher,
            new FakeSignatureVerifier(true),
            stagingRoot: adminRoot.Path,
            maxPackageBytes: 1024);

        var badPaths = new[]
        {
            userDir.FilePath("does-not-exist.exe"),
            dirNamedExe,
            emptyFile,
            wrongExtFile,
            oversizedFile,
            fileSymlink,
            pathViaSymlinkDir,
        };

        foreach (var bad in badPaths)
        {
            var res = await ops.RunBiosInstallerAsync(
                new BiosAgentInstallRequest("dell", BiosAgentInstallModes.DellBiosExe, PackagePath: bad),
                cts.Token);

            Assert.False(res.Executed, $"Path '{bad}' should not execute.");
            Assert.False(res.Allowed, $"Path '{bad}' should not be allowed.");
        }

        Assert.Empty(agentLauncher.Calls);
        Assert.Empty(Directory.GetFileSystemEntries(adminRoot.Path));
    }

    [Fact]
    public async Task AgentSecurity_RunBiosInstaller_RejectsUnsignedBinaryDefaultVerifierAndNonAllowlistedCliTool()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var userDir = new TempStagingDir();
        using var adminRoot = new TempStagingDir();
        using var allowedRoot = new TempStagingDir();
        using var untrustedRoot = new TempStagingDir();

        var payload = TestPayload.FromString("unsigned-bios-binary");
        var exePath = userDir.FilePath("unsigned.exe");
        await File.WriteAllBytesAsync(exePath, payload.Bytes, cts.Token);

        // (a) Unsigned .exe even when SHA-256 matches -> fail closed!
        var launcher1 = CreateGuardedLauncher();
        var ops1 = new AgentBiosOperations(launcher1, new FakeSignatureVerifier(false), stagingRoot: adminRoot.Path);
        var r1 = await ops1.RunBiosInstallerAsync(
            new BiosAgentInstallRequest("hp", BiosAgentInstallModes.HpBiosUpdRec, exePath, ExpectedSha256: payload.Sha256),
            cts.Token);
        Assert.False(r1.Executed);
        Assert.False(r1.Allowed);
        Assert.Contains("Authenticode", r1.Error ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.Empty(launcher1.Calls);
        Assert.Empty(Directory.GetFileSystemEntries(adminRoot.Path));

        // (b) Default WinVerifyTrustSignatureVerifier on unsigned dummy .exe fails closed cleanly
        var launcher2 = CreateGuardedLauncher();
        var ops2 = new AgentBiosOperations(launcher2, signatureVerifier: null, stagingRoot: adminRoot.Path);
        var r2 = await ops2.RunBiosInstallerAsync(
            new BiosAgentInstallRequest("dell", BiosAgentInstallModes.DellBiosExe, exePath, ExpectedSha256: payload.Sha256),
            cts.Token);
        Assert.False(r2.Executed);
        Assert.False(r2.Allowed);
        Assert.Empty(launcher2.Calls);
        Assert.Empty(Directory.GetFileSystemEntries(adminRoot.Path));

        // (c) Dell DCU-CLI outside allowlisted root -> rejected
        var evilDcuDir = Path.Combine(untrustedRoot.Path, "Dell", "CommandUpdate");
        Directory.CreateDirectory(evilDcuDir);
        var evilDcu = Path.Combine(evilDcuDir, "dcu-cli.exe");
        await File.WriteAllBytesAsync(evilDcu, payload.Bytes, cts.Token);

        var launcher3 = CreateGuardedLauncher();
        var ops3 = new AgentBiosOperations(launcher3, new FakeSignatureVerifier(true), allowedToolRoots: [allowedRoot.Path]);
        var r3 = await ops3.RunBiosInstallerAsync(
            new BiosAgentInstallRequest("dell", BiosAgentInstallModes.DellDcuCli, PackagePath: evilDcu),
            cts.Token);
        Assert.False(r3.Executed);
        Assert.False(r3.Allowed);
        Assert.Empty(launcher3.Calls);

        // (d) Dell DCU-CLI symlink inside allowlisted root -> rejected
        var allowedDcuDir = Path.Combine(allowedRoot.Path, "Dell", "CommandUpdate");
        Directory.CreateDirectory(allowedDcuDir);
        var symlinkDcu = Path.Combine(allowedDcuDir, "dcu-cli.exe");
        File.CreateSymbolicLink(symlinkDcu, evilDcu);

        var r4 = await ops3.RunBiosInstallerAsync(
            new BiosAgentInstallRequest("dell", BiosAgentInstallModes.DellDcuCli, PackagePath: symlinkDcu),
            cts.Token);
        Assert.False(r4.Executed);
        Assert.False(r4.Allowed);
        Assert.Empty(launcher3.Calls);

        // (e) Unsigned real dcu-cli.exe inside allowlisted root -> rejected
        File.Delete(symlinkDcu);
        await File.WriteAllBytesAsync(symlinkDcu, payload.Bytes, cts.Token);
        var ops4 = new AgentBiosOperations(launcher3, new FakeSignatureVerifier(false), allowedToolRoots: [allowedRoot.Path]);
        var r5 = await ops4.RunBiosInstallerAsync(
            new BiosAgentInstallRequest("dell", BiosAgentInstallModes.DellDcuCli, PackagePath: symlinkDcu),
            cts.Token);
        Assert.False(r5.Executed);
        Assert.False(r5.Allowed);
        Assert.Empty(launcher3.Calls);
    }

    [Fact]
    public async Task AgentSecurity_RunBiosInstaller_RejectsUnknownModeVendorMismatchAndDisallowedInfPath()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var userDir = new TempStagingDir();
        using var adminRoot = new TempStagingDir();

        var exePath = userDir.FilePath("bios.exe");
        await File.WriteAllBytesAsync(exePath, Encoding.UTF8.GetBytes("payload"), cts.Token);

        var cabBytes = TestCabBuilder.CreateUncompressed(new Dictionary<string, byte[]>
        {
            ["firmware.inf"] = Encoding.UTF8.GetBytes("[Version]"),
        });
        var cabPath = userDir.FilePath("capsule.cab");
        await File.WriteAllBytesAsync(cabPath, cabBytes, cts.Token);

        var agentLauncher = CreateGuardedLauncher();
        var ops = new AgentBiosOperations(agentLauncher, new FakeSignatureVerifier(true), stagingRoot: adminRoot.Path);

        var (server, serverTask, client) = await StartPipeAsync(agentLauncher, ops, cts.Token);
        using (server)
        {
            await using (client)
            {
                var badRequests = new[]
                {
                    new BiosAgentInstallRequest("dell", "", exePath),
                    new BiosAgentInstallRequest("dell", "arbitrary_exec", exePath),
                    new BiosAgentInstallRequest("hp", BiosAgentInstallModes.DellBiosExe, exePath),
                    new BiosAgentInstallRequest("dell", BiosAgentInstallModes.HpBiosUpdRec, exePath),
                    new BiosAgentInstallRequest("asus", BiosAgentInstallModes.DellBiosExe, exePath),
                    new BiosAgentInstallRequest("dell", BiosAgentInstallModes.DellBiosExe, exePath, InfRelativePath: "firmware.inf"),
                    new BiosAgentInstallRequest("framework", BiosAgentInstallModes.FrameworkCabCapsule, cabPath, InfRelativePath: "../escape.inf"),
                    new BiosAgentInstallRequest("framework", BiosAgentInstallModes.FrameworkCabCapsule, cabPath, InfRelativePath: "firmware.exe"),
                };

                foreach (var req in badRequests)
                {
                    var res = await client.RunBiosInstallerAsync(req, cts.Token);
                    Assert.False(res.Executed);
                    Assert.False(res.Allowed);
                }
            }

            await serverTask;
        }

        Assert.Empty(agentLauncher.Calls);
        Assert.Empty(Directory.GetFileSystemEntries(adminRoot.Path));
    }

    [Fact]
    public async Task AgentSecurity_InstallBiosWindowsUpdate_RejectsEmptyAndNonGuidUpdateIdsOverRawPipe()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var wua = new FakeWuaApi();
        var agentLauncher = CreateGuardedLauncher();
        var ops = new AgentBiosOperations(agentLauncher, wuaApiFactory: () => wua);

        var pipeName = $"rpd-bios-raw-{Guid.NewGuid():N}";
        using var server = new AdminPipeServer(
            new AdminPipeServerOptions
            {
                PipeName = pipeName,
                ExpectedClientPid = Environment.ProcessId,
            },
            launcher: agentLauncher,
            biosOperations: ops);

        var serverTask = server.RunSingleSessionAsync(cts.Token);

        await using (var rawPipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous))
        {
            await rawPipe.ConnectAsync(10_000, cts.Token);

            var badIds = new string?[]
            {
                null,
                "",
                "   ",
                "not-a-guid",
                "00000000-0000-0000-0000-000000000000",
                "748279c7-4309-452c-8b30-e02ec52e498f;calc.exe",
            };

            foreach (var badId in badIds)
            {
                await AdminPipeFraming.WriteFrameAsync(
                    rawPipe,
                    new AdminPipeRequest(AdminPipeFraming.OpBiosInstallWua, BiosWuaUpdateId: badId),
                    cts.Token);
                var resp = await AdminPipeFraming.ReadFrameAsync<AdminPipeResponse>(rawPipe, cts.Token);
                Assert.NotNull(resp);
                Assert.False(resp.Ok);
                Assert.False(resp.Allowed);
                Assert.NotNull(resp.BiosWuaOutcome);
                Assert.False(resp.BiosWuaOutcome.Succeeded);
            }

            // Also verify null BiosInstall over raw pipe fails closed.
            await AdminPipeFraming.WriteFrameAsync(
                rawPipe,
                new AdminPipeRequest(AdminPipeFraming.OpBiosRunInstaller, BiosInstall: null),
                cts.Token);
            var nullInstallResp = await AdminPipeFraming.ReadFrameAsync<AdminPipeResponse>(rawPipe, cts.Token);
            Assert.NotNull(nullInstallResp);
            Assert.False(nullInstallResp.Ok);
            Assert.False(nullInstallResp.Allowed);
        }

        await serverTask;

        // Also test AdminPipeClient pre-check for Guid.Empty
        var (server2, serverTask2, client2) = await StartPipeAsync(agentLauncher, ops, cts.Token);
        using (server2)
        {
            await using (client2)
            {
                var emptyRes = await client2.InstallBiosWindowsUpdateAsync(Guid.Empty, ct: cts.Token);
                Assert.False(emptyRes.Succeeded);
                Assert.Contains("non-empty", emptyRes.Message, StringComparison.OrdinalIgnoreCase);
            }

            await serverTask2;
        }

        Assert.Empty(wua.Criteria);
        Assert.Empty(agentLauncher.Calls);
    }

    // -------------------------------------------------------------------------
    // Group C — Elevation Matrix for BiosBitLockerSuspender & BiosInstallerRunner
    // -------------------------------------------------------------------------

    [Fact]
    public async Task BiosBitLockerSuspender_ElevationMatrix_RoutesElevatedBridgeDisconnectedNullAndLegacyCleanly()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var req = CreateSampleInstallRequest(suspendBitLocker: true);

        // 1. Elevated -> runs locally via host launcher, 0 pipe calls.
        var hostLauncher1 = CreateGuardedLauncher((_, _) => Task.FromResult(new ProcessResult(0, "", "")));
        var commands1 = RecordingProcessLauncher.CreateCommandRunner(hostLauncher1, isProcessElevated: true);
        var disconnectedBridge = new DisconnectedBridge();
        var progress1 = new SyncProgress<BiosInstallProgress>();

        var elevatedOutcome = await BiosBitLockerSuspender.SuspendForOneRebootWithResultAsync(
            req, commands1, progress1, null, cts.Token, "C:", bridge: disconnectedBridge, isProcessElevated: () => true);

        Assert.True(elevatedOutcome.Suspended);
        Assert.False(elevatedOutcome.ElevationRequired);
        Assert.Single(hostLauncher1.Calls);
        Assert.Equal("manage-bde.exe", hostLauncher1.Calls[0].BaseName, ignoreCase: true);

        // 2. Un-elevated + Connected live pipe (explicit bridge) -> routes to Agent, 0 Host launcher calls.
        var hostLauncher2 = CreateGuardedLauncher();
        var agentLauncher2 = CreateGuardedLauncher((_, _) => Task.FromResult(new ProcessResult(0, "", "")));
        var ops2 = new AgentBiosOperations(agentLauncher2);
        var progress2 = new SyncProgress<BiosInstallProgress>();

        var (server2, serverTask2, client2) = await StartPipeAsync(agentLauncher2, ops2, cts.Token);
        using (server2)
        {
            await using (client2)
            {
                var commands2 = RecordingProcessLauncher.CreateCommandRunner(hostLauncher2, isProcessElevated: false, elevatedBridge: client2);

                // Also proves automatic routing via commands.ElevatedBridge when explicit bridge/isProcessElevated are omitted!
                var bridgedOutcome = await BiosBitLockerSuspender.SuspendForOneRebootWithResultAsync(
                    req, commands2, progress2, null, cts.Token, "D:");

                Assert.True(bridgedOutcome.Suspended);
                Assert.False(bridgedOutcome.ElevationRequired);
            }

            await serverTask2;
        }

        Assert.Empty(hostLauncher2.Calls);
        var agentCall = Assert.Single(agentLauncher2.Calls);
        Assert.Equal(["-protectors", "-disable", "D:", "-RebootCount", "1"], agentCall.Arguments);
        Assert.Contains(progress2.Reports, p => p.Stage == BiosInstallStage.SuspendingBitLocker && p.Percent == 0);
        Assert.Contains(progress2.Reports, p => p.Stage == BiosInstallStage.SuspendingBitLocker && p.Percent == 100);

        // 3. Un-elevated + Disconnected / null bridge -> 0 Host calls, ElevationRequired == true with Admin Repair Mode hint.
        var hostLauncher3 = CreateGuardedLauncher();
        var commands3 = RecordingProcessLauncher.CreateCommandRunner(hostLauncher3, isProcessElevated: false, elevatedBridge: disconnectedBridge);
        var disconnectedOutcome = await BiosBitLockerSuspender.SuspendForOneRebootWithResultAsync(
            req, commands3, null, null, cts.Token, "C:");
        Assert.False(disconnectedOutcome.Suspended);
        Assert.True(disconnectedOutcome.ElevationRequired);
        Assert.Contains("Admin Repair Mode", disconnectedOutcome.Message ?? "", StringComparison.OrdinalIgnoreCase);

        var nullBridgeBool = await BiosBitLockerSuspender.SuspendForOneRebootIfRequestedAsync(
            req, commands: null, null, null, cts.Token, "C:", bridge: null, isProcessElevated: () => false);
        Assert.False(nullBridgeBool);
        Assert.Empty(hostLauncher3.Calls);

        // 4. Un-elevated + Legacy Agent (biosOperations: null -> Allowed == false) -> 0 Host fallback, LegacyAgentUnsupported == true.
        var hostLauncher4 = CreateGuardedLauncher();
        var agentLauncher4 = CreateGuardedLauncher();
        var (server4, serverTask4, client4) = await StartPipeAsync(agentLauncher4, biosOps: null, cts.Token);
        using (server4)
        {
            await using (client4)
            {
                var commands4 = RecordingProcessLauncher.CreateCommandRunner(hostLauncher4, isProcessElevated: false, elevatedBridge: client4);
                var legacyOutcome = await BiosBitLockerSuspender.SuspendForOneRebootWithResultAsync(
                    req, commands4, null, null, cts.Token, "C:");

                Assert.False(legacyOutcome.Suspended);
                Assert.True(legacyOutcome.ElevationRequired);
                Assert.True(legacyOutcome.LegacyAgentUnsupported);
                Assert.Contains("Update", legacyOutcome.Message ?? "", StringComparison.OrdinalIgnoreCase);
            }

            await serverTask4;
        }

        Assert.Empty(hostLauncher4.Calls);
        Assert.Empty(agentLauncher4.Calls);
    }

    [Fact]
    public async Task BiosInstallerRunner_ElevationMatrix_RoutesElevatedBridgeDisconnectedNullAndLegacyCleanly()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var userDir = new TempStagingDir();
        using var adminRoot = new TempStagingDir();

        var payload = TestPayload.FromString("signed-installer-payload");
        var pkgPath = userDir.FilePath("bios-installer.exe");
        await File.WriteAllBytesAsync(pkgPath, payload.Bytes, cts.Token);

        var installReq = CreateSampleInstallRequest();
        var agentReq = new BiosAgentInstallRequest("dell", BiosAgentInstallModes.DellBiosExe, pkgPath, payload.Sha256, AllowReboot: false);

        // 1. Elevated -> runs locally via Host launcher, 0 pipe calls.
        var hostLauncher1 = CreateGuardedLauncher((_, _) => Task.FromResult(new ProcessResult(3010, "Local staged", "")));
        var commands1 = RecordingProcessLauncher.CreateCommandRunner(hostLauncher1, isProcessElevated: true);
        var elevatedRes = await BiosInstallerRunner.RunInstallerAsync(
            commands1, pkgPath, ["/s"], installReq, bitLockerSuspended: true, RebootCodes, CompletedCodes,
            TimeSpan.FromMinutes(5), null, cts.Token, agentRequest: agentReq, bridge: new DisconnectedBridge(), isProcessElevated: () => true);

        Assert.True(elevatedRes.Succeeded);
        Assert.Equal(BiosInstallStatus.StagedForReboot, elevatedRes.Status);
        Assert.True(elevatedRes.BitLockerSuspended);
        Assert.Single(hostLauncher1.Calls);

        // 2. Un-elevated + Connected live pipe (via commands.ElevatedBridge!) -> 0 Host calls, exit code mapping 3010 / 2 / 1603.
        var nextExitCode = 3010;
        var hostLauncher2 = CreateGuardedLauncher();
        var agentLauncher2 = CreateGuardedLauncher((_, _) => Task.FromResult(new ProcessResult(nextExitCode, $"exit-{nextExitCode}", "")));
        var ops2 = new AgentBiosOperations(agentLauncher2, new FakeSignatureVerifier(true), stagingRoot: adminRoot.Path);

        var (server2, serverTask2, client2) = await StartPipeAsync(agentLauncher2, ops2, cts.Token);
        using (server2)
        {
            await using (client2)
            {
                var commands2 = RecordingProcessLauncher.CreateCommandRunner(hostLauncher2, isProcessElevated: false, elevatedBridge: client2);

                nextExitCode = 3010;
                var stagedRes = await BiosInstallerRunner.RunInstallerAsync(
                    commands2, pkgPath, ["/s"], installReq, bitLockerSuspended: true, RebootCodes, CompletedCodes,
                    TimeSpan.FromMinutes(5), null, cts.Token, agentRequest: agentReq);
                Assert.True(stagedRes.Succeeded);
                Assert.Equal(BiosInstallStatus.StagedForReboot, stagedRes.Status);
                Assert.True(stagedRes.RequiresReboot);
                Assert.True(stagedRes.BitLockerSuspended);
                Assert.Equal(3010, stagedRes.ExitCode);

                nextExitCode = 2;
                var completedRes = await BiosInstallerRunner.RunInstallerAsync(
                    commands2, pkgPath, ["/s"], installReq, bitLockerSuspended: false, RebootCodes, CompletedCodes,
                    TimeSpan.FromMinutes(5), null, cts.Token, agentRequest: agentReq);
                Assert.True(completedRes.Succeeded);
                Assert.Equal(BiosInstallStatus.Completed, completedRes.Status);
                Assert.False(completedRes.RequiresReboot);
                Assert.Equal(2, completedRes.ExitCode);

                nextExitCode = 1603;
                var failedRes = await BiosInstallerRunner.RunInstallerAsync(
                    commands2, pkgPath, ["/s"], installReq, bitLockerSuspended: true, RebootCodes, CompletedCodes,
                    TimeSpan.FromMinutes(5), null, cts.Token, agentRequest: agentReq);
                Assert.False(failedRes.Succeeded);
                Assert.Equal(BiosInstallStatus.Failed, failedRes.Status);
                Assert.True(failedRes.BitLockerSuspended);
                Assert.Equal(1603, failedRes.ExitCode);

                // Un-elevated + connected bridge + null agentRequest -> fails closed, 0 local/agent executions!
                var nullReqRes = await BiosInstallerRunner.RunInstallerAsync(
                    commands2, pkgPath, ["/s"], installReq, bitLockerSuspended: true, RebootCodes, CompletedCodes,
                    TimeSpan.FromMinutes(5), null, cts.Token, agentRequest: null);
                Assert.False(nullReqRes.Succeeded);
                Assert.Equal(BiosInstallStatus.Failed, nullReqRes.Status);
                Assert.True(nullReqRes.BitLockerSuspended);
                Assert.Equal(SystemCommandRunner.AgentFailedExitCode, nullReqRes.ExitCode);
            }

            await serverTask2;
        }

        Assert.Empty(hostLauncher2.Calls);
        Assert.Equal(3, agentLauncher2.Calls.Count);

        // 3. Un-elevated + Disconnected / null bridge -> 0 Host calls, clear elevation error with Admin Repair Mode hint.
        var hostLauncher3 = CreateGuardedLauncher();
        var commands3 = RecordingProcessLauncher.CreateCommandRunner(hostLauncher3, isProcessElevated: false, elevatedBridge: new DisconnectedBridge());
        var discRes = await BiosInstallerRunner.RunInstallerAsync(
            commands3, pkgPath, ["/s"], installReq, bitLockerSuspended: true, RebootCodes, CompletedCodes,
            TimeSpan.FromMinutes(5), null, cts.Token, agentRequest: agentReq);

        Assert.False(discRes.Succeeded);
        Assert.Equal(BiosInstallStatus.Failed, discRes.Status);
        Assert.True(discRes.BitLockerSuspended);
        Assert.Equal(SystemCommandRunner.AgentFailedExitCode, discRes.ExitCode);
        Assert.Contains("Administrator", discRes.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Admin Repair Mode", discRes.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(hostLauncher3.Calls);

        // 4. Un-elevated + Legacy Agent (biosOperations: null) -> 0 Host fallback, clear update message.
        var hostLauncher4 = CreateGuardedLauncher();
        var agentLauncher4 = CreateGuardedLauncher();
        var (server4, serverTask4, client4) = await StartPipeAsync(agentLauncher4, biosOps: null, cts.Token);
        using (server4)
        {
            await using (client4)
            {
                var commands4 = RecordingProcessLauncher.CreateCommandRunner(hostLauncher4, isProcessElevated: false, elevatedBridge: client4);
                var legacyRes = await BiosInstallerRunner.RunInstallerAsync(
                    commands4, pkgPath, ["/s"], installReq, bitLockerSuspended: true, RebootCodes, CompletedCodes,
                    TimeSpan.FromMinutes(5), null, cts.Token, agentRequest: agentReq);

                Assert.False(legacyRes.Succeeded);
                Assert.Equal(BiosInstallStatus.Failed, legacyRes.Status);
                Assert.True(legacyRes.BitLockerSuspended);
                Assert.Equal(SystemCommandRunner.AgentFailedExitCode, legacyRes.ExitCode);
                Assert.Contains("Update", legacyRes.Message, StringComparison.OrdinalIgnoreCase);
            }

            await serverTask4;
        }

        Assert.Empty(hostLauncher4.Calls);
        Assert.Empty(agentLauncher4.Calls);
    }

    [Fact]
    public async Task BiosInstallerRunner_AgentPipe_RedactsSerialNumberFromAgentStdOutStdErrErrorAndLogs()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var userDir = new TempStagingDir();
        using var adminRoot = new TempStagingDir();

        var secret = BiosIdentityFactory.SentinelSerialNumber;
        var mixedCaseSecret = secret.ToLowerInvariant();
        var payload = TestPayload.FromString("bios-payload");
        var pkgPath = userDir.FilePath("bios.exe");
        await File.WriteAllBytesAsync(pkgPath, payload.Bytes, cts.Token);

        var hostLog = new CapturedLog();
        var commandsLog = new CapturedLog();
        var agentLog = new CapturedLog();

        var hostLauncher = CreateGuardedLauncher();
        var exitCode = 3010;
        var agentLauncher = CreateGuardedLauncher((_, _) =>
            Task.FromResult(new ProcessResult(
                exitCode,
                $"Flashing board SN={secret} progress=100%",
                $"Diag note serial={mixedCaseSecret}")));

        var ops = new AgentBiosOperations(agentLauncher, new FakeSignatureVerifier(true), stagingRoot: adminRoot.Path, log: agentLog.Logger);
        var installReq = CreateSampleInstallRequest();
        var agentReq = new BiosAgentInstallRequest("hp", BiosAgentInstallModes.HpBiosUpdRec, pkgPath, payload.Sha256);

        var (server, serverTask, client) = await StartPipeAsync(agentLauncher, ops, cts.Token, agentLog.Logger);
        using (server)
        {
            await using (client)
            {
                var commands = RecordingProcessLauncher.CreateCommandRunner(
                    hostLauncher,
                    log: commandsLog.Logger,
                    isProcessElevated: false,
                    elevatedBridge: client);

                // Success path
                var okRes = await BiosInstallerRunner.RunInstallerAsync(
                    commands, pkgPath, ["-s", "-r"], installReq, true, RebootCodes, CompletedCodes,
                    TimeSpan.FromMinutes(5), hostLog.Logger, cts.Token, agentRequest: agentReq);
                Assert.True(okRes.Succeeded);
                Assert.NotNull(okRes.LogTail);
                Assert.Contains("[REDACTED]", okRes.LogTail);
                Assert.DoesNotContain(secret, okRes.LogTail, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain(secret, okRes.Message, StringComparison.OrdinalIgnoreCase);

                // Failure path
                exitCode = 5;
                var failRes = await BiosInstallerRunner.RunInstallerAsync(
                    commands, pkgPath, ["-s", "-r"], installReq, true, RebootCodes, CompletedCodes,
                    TimeSpan.FromMinutes(5), hostLog.Logger, cts.Token, agentRequest: agentReq);
                Assert.False(failRes.Succeeded);
                Assert.NotNull(failRes.LogTail);
                Assert.Contains("[REDACTED]", failRes.LogTail);
                Assert.DoesNotContain(secret, failRes.LogTail, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain(secret, failRes.Message, StringComparison.OrdinalIgnoreCase);
            }

            await serverTask;
        }

        // Refusal/exception containing secret
        var throwingBridge = new ThrowingBridge(new AdminRequiredException($"Agent error for {secret}"));
        var refusedRes = await BiosInstallerRunner.RunInstallerAsync(
            commands: null, pkgPath, ["-s", "-r"], installReq, true, RebootCodes, CompletedCodes,
            TimeSpan.FromMinutes(5), hostLog.Logger, cts.Token, agentRequest: agentReq, bridge: throwingBridge, isProcessElevated: () => false);
        Assert.False(refusedRes.Succeeded);
        Assert.Contains("[REDACTED]", refusedRes.Message);
        Assert.DoesNotContain(secret, refusedRes.Message, StringComparison.OrdinalIgnoreCase);

        hostLog.AssertDoesNotContainSecret(secret);
        commandsLog.AssertDoesNotContainSecret(secret);
        agentLog.AssertDoesNotContainSecret(secret);
    }

    // -------------------------------------------------------------------------
    // Group D — ElevationService Forwarding, Default Interface Methods & Framing
    // -------------------------------------------------------------------------

    [Fact]
    public async Task ElevationService_ForwardsAllThreeBiosOpsWhenConnectedAndThrowsAdminRequiredWhenDisconnected()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var userDir = new TempStagingDir();
        using var adminRoot = new TempStagingDir();

        var payload = TestPayload.FromString("lenovo-bios-pkg");
        var pkgPath = userDir.FilePath("winuptp.exe");
        await File.WriteAllBytesAsync(pkgPath, payload.Bytes, cts.Token);

        var agentLauncher = CreateGuardedLauncher((_, _) => Task.FromResult(new ProcessResult(0, "ok", "")));
        var wua = new FakeWuaApi();
        var updateId = Guid.Parse("22222222-3333-4444-5555-666666666666");
        wua.Reset(new FakeWuaUpdate("Lenovo System Firmware", downloaded: true), new UpdateInstallOutcome(2, 0, true));

        var ops = new AgentBiosOperations(
            launcher: agentLauncher,
            signatureVerifier: new FakeSignatureVerifier(true),
            wuaApiFactory: () => wua,
            stagingRoot: adminRoot.Path);

        var session = new SessionContext(
            SessionMode.Local,
            null,
            Guid.NewGuid(),
            unattended: false,
            voice: false);
        AdminPipeServer? activeServer = null;
        Task? serverTask = null;

        using var elevation = new ElevationService(
            session,
            isProcessElevated: () => false,
            customConnector: async (req, token) =>
            {
                activeServer = new AdminPipeServer(
                    new AdminPipeServerOptions
                    {
                        PipeName = req.PipeName,
                        ExpectedClientPid = req.ParentPid,
                    },
                    launcher: agentLauncher,
                    biosOperations: ops);
                serverTask = activeServer.RunSingleSessionAsync(token);
                return await AdminPipeClient.ConnectAsync(req.PipeName, TimeSpan.FromSeconds(10), token);
            });

        // Disconnected: all 3 BIOS ops throw AdminRequiredException containing AdminRepairHint.
        var ex1 = await Assert.ThrowsAsync<AdminRequiredException>(() => elevation.SuspendBitLockerAsync("C:", cts.Token));
        Assert.Contains("Admin Repair Mode", ex1.Message, StringComparison.OrdinalIgnoreCase);
        var ex2 = await Assert.ThrowsAsync<AdminRequiredException>(() =>
            elevation.RunBiosInstallerAsync(new BiosAgentInstallRequest("lenovo", BiosAgentInstallModes.LenovoWinUptp, pkgPath, payload.Sha256), cts.Token));
        Assert.Contains("Admin Repair Mode", ex2.Message, StringComparison.OrdinalIgnoreCase);
        var ex3 = await Assert.ThrowsAsync<AdminRequiredException>(() => elevation.InstallBiosWindowsUpdateAsync(updateId, ct: cts.Token));
        Assert.Contains("Admin Repair Mode", ex3.Message, StringComparison.OrdinalIgnoreCase);

        // Connect Admin Repair Mode via ElevationService
        var enableRes = await elevation.EnableAdminModeAsync(cts.Token);
        Assert.True(enableRes.Success);
        Assert.True(elevation.IsAdminHelperConnected);
        Assert.True(elevation.HasAdminCapabilities);

        // Verify DefaultBiosInstallSafetyProbe sees HasElevation == true via ElevationService!
        var safetyProbe = new DefaultBiosInstallSafetyProbe(
            elevation: elevation,
            bitLockerProbe: _ => Task.FromResult<int?>(0));
        var safety = await safetyProbe.ProbeAsync(cts.Token);
        Assert.True(safety.HasElevation);

        // All 3 BIOS ops forward cleanly over the live pipe!
        var blRes = await elevation.SuspendBitLockerAsync("C:", cts.Token);
        Assert.True(blRes.Suspended);

        var instRes = await elevation.RunBiosInstallerAsync(
            new BiosAgentInstallRequest("lenovo", BiosAgentInstallModes.LenovoWinUptp, pkgPath, payload.Sha256),
            cts.Token);
        Assert.True(instRes.Executed);
        Assert.Equal(0, instRes.ExitCode);

        var wuaRes = await elevation.InstallBiosWindowsUpdateAsync(updateId, ct: cts.Token);
        Assert.True(wuaRes.Succeeded);
        Assert.True(wuaRes.RebootRequired);

        // Disconnect and confirm subsequent calls throw AdminRequiredException again.
        elevation.Dispose();
        if (serverTask is not null)
            await serverTask;
        activeServer?.Dispose();

        Assert.False(elevation.IsAdminHelperConnected);
        await Assert.ThrowsAsync<AdminRequiredException>(() => elevation.SuspendBitLockerAsync("C:", cts.Token));
    }

    [Fact]
    public async Task OldBridge_DefaultInterfaceMethods_FailCleanlyWithoutBreakingLegacyDoubles()
    {
        IElevatedCommandBridge bridge = new OldBridge();

        await Assert.ThrowsAsync<AdminRequiredException>(() => bridge.SuspendBitLockerAsync("C:"));
        await Assert.ThrowsAsync<AdminRequiredException>(() =>
            bridge.RunBiosInstallerAsync(new BiosAgentInstallRequest("dell", BiosAgentInstallModes.DellBiosExe, "/tmp/a.exe")));
        await Assert.ThrowsAsync<AdminRequiredException>(() =>
            bridge.InstallBiosWindowsUpdateAsync(Guid.NewGuid()));
    }

    [Fact]
    public async Task AdminPipeFraming_BiosRequestsAndResponses_RoundTripJsonCleanly()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var ms = new MemoryStream();

        var installReq = new BiosAgentInstallRequest(
            VendorId: "framework",
            InstallMode: BiosAgentInstallModes.FrameworkCabCapsule,
            PackagePath: "/tmp/capsule.cab",
            ExpectedSha256: new string('f', 64),
            AllowReboot: false,
            InfRelativePath: "firmware.inf",
            TimeoutMs: 180_000);

        var pipeReq = new AdminPipeRequest(
            Op: AdminPipeFraming.OpBiosRunInstaller,
            TimeoutMs: 180_000,
            BiosSystemDrive: "C:",
            BiosInstall: installReq,
            BiosWuaUpdateId: "748279c7-4309-452c-8b30-e02ec52e498f");

        var pipeResp = new AdminPipeResponse(
            Ok: true,
            Allowed: true,
            Elevated: true,
            HelperPid: 1234,
            ExitCode: 3010,
            BiosBitLocker: new BiosAgentBitLockerResult(true, true, 0, null),
            BiosInstallResult: new BiosAgentInstallResult(true, true, 3010, false, "Staged OK", null),
            BiosWuaOutcome: new BiosWuaInstallOutcome(true, 2, true, "Installed firmware."));

        await AdminPipeFraming.WriteFrameAsync(ms, pipeReq, cts.Token);
        await AdminPipeFraming.WriteFrameAsync(ms, pipeResp, cts.Token);

        // Verify raw wire JSON has no serialNumber or arbitrary commandLine field
        var rawWire = Encoding.UTF8.GetString(ms.ToArray());
        Assert.DoesNotContain("serialNumber", rawWire, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("commandLine", rawWire, StringComparison.OrdinalIgnoreCase);

        ms.Position = 0;
        var decodedReq = await AdminPipeFraming.ReadFrameAsync<AdminPipeRequest>(ms, cts.Token);
        var decodedResp = await AdminPipeFraming.ReadFrameAsync<AdminPipeResponse>(ms, cts.Token);

        Assert.NotNull(decodedReq);
        Assert.Equal(AdminPipeFraming.OpBiosRunInstaller, decodedReq.Op);
        Assert.Equal("C:", decodedReq.BiosSystemDrive);
        Assert.Equal(installReq, decodedReq.BiosInstall);
        Assert.Equal("748279c7-4309-452c-8b30-e02ec52e498f", decodedReq.BiosWuaUpdateId);

        Assert.NotNull(decodedResp);
        Assert.Equal(pipeResp.BiosBitLocker, decodedResp.BiosBitLocker);
        Assert.Equal(pipeResp.BiosInstallResult, decodedResp.BiosInstallResult);
        Assert.Equal(pipeResp.BiosWuaOutcome, decodedResp.BiosWuaOutcome);
    }

    // -------------------------------------------------------------------------
    // Group E — Iteration 2 Security, Protocol, PII & Clamping Regressions
    // -------------------------------------------------------------------------

    [Fact]
    public async Task AgentSecurity_FrameworkCabCapsule_UnsignedWithoutSha256_RejectedBeforeExtraction()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var userDir = new TempStagingDir();
        using var adminRoot = new TempStagingDir();

        // Valid CAB containing both firmware.inf and a .cat that the verifier WOULD approve if extracted.
        var cabBytes = TestCabBuilder.CreateUncompressed(new Dictionary<string, byte[]>
        {
            ["firmware.inf"] = Encoding.UTF8.GetBytes("[Version]\nSignature=\"$WINDOWS NT$\""),
            ["firmware.cat"] = Encoding.UTF8.GetBytes("would-be-signed-cat"),
        });
        var userCabPath = userDir.FilePath("untrusted-capsule.cab");
        await File.WriteAllBytesAsync(userCabPath, cabBytes, cts.Token);

        // Outer .cab fails signature verification; inner .cat would pass if extraction were attempted.
        var catOnlyVerifier = new FakeSignatureVerifier((p, _) =>
            Task.FromResult(p.EndsWith(".cat", StringComparison.OrdinalIgnoreCase)));
        var agentLauncher = CreateGuardedLauncher();
        var ops = new AgentBiosOperations(agentLauncher, catOnlyVerifier, stagingRoot: adminRoot.Path);

        var (server, serverTask, client) = await StartPipeAsync(agentLauncher, ops, cts.Token);
        using (server)
        {
            await using (client)
            {
                var res = await client.RunBiosInstallerAsync(
                    new BiosAgentInstallRequest(
                        VendorId: "framework",
                        InstallMode: BiosAgentInstallModes.FrameworkCabCapsule,
                        PackagePath: userCabPath,
                        ExpectedSha256: null,
                        AllowReboot: false),
                    cts.Token);

                Assert.False(res.Executed);
                Assert.False(res.Allowed);
                Assert.Contains("signature", res.Error ?? "", StringComparison.OrdinalIgnoreCase);
            }

            await serverTask;
        }

        // Only the staged .cab itself may be verified; no .cat verification and zero expand.exe/pnputil.exe invocations.
        var verified = Assert.Single(catOnlyVerifier.VerifiedPaths);
        Assert.EndsWith(".cab", verified, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(agentLauncher.Calls);
        Assert.Empty(Directory.GetFileSystemEntries(adminRoot.Path));
    }

    [Fact]
    public async Task AgentSecurity_DanglingSymlinks_PackageStagingRootAndAncestor_AllRejectedCleanly()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var userDir = new TempStagingDir();
        using var adminRoot = new TempStagingDir();

        var validPkg = userDir.FilePath("valid-bios.exe");
        await File.WriteAllBytesAsync(validPkg, Encoding.UTF8.GetBytes("signed-bios-bytes"), cts.Token);

        var missingTarget = userDir.FilePath("nonexistent-target.exe");
        var danglingPkgLink = userDir.FilePath("dangling-pkg.exe");
        File.CreateSymbolicLink(danglingPkgLink, missingTarget);

        var missingDirTarget = userDir.FilePath("nonexistent-dir");
        var danglingDirLink = userDir.FilePath("dangling-dir");
        Directory.CreateSymbolicLink(danglingDirLink, missingDirTarget);

        var agentLauncher = CreateGuardedLauncher();
        var sigVerifier = new FakeSignatureVerifier(result: true);

        // (a) Dangling symlink package path
        var ops1 = new AgentBiosOperations(agentLauncher, sigVerifier, stagingRoot: adminRoot.Path);
        var r1 = await ops1.RunBiosInstallerAsync(
            new BiosAgentInstallRequest("dell", BiosAgentInstallModes.DellBiosExe, PackagePath: danglingPkgLink),
            cts.Token);
        Assert.False(r1.Executed);
        Assert.False(r1.Allowed);
        Assert.False(File.Exists(missingTarget));

        // (b) Dangling symlink staging root (without and with trailing separator)
        var ops2 = new AgentBiosOperations(agentLauncher, sigVerifier, stagingRoot: danglingDirLink);
        var r2 = await ops2.RunBiosInstallerAsync(
            new BiosAgentInstallRequest("dell", BiosAgentInstallModes.DellBiosExe, PackagePath: validPkg),
            cts.Token);
        Assert.False(r2.Executed);
        Assert.False(r2.Allowed);
        Assert.False(Directory.Exists(missingDirTarget));

        var ops3 = new AgentBiosOperations(agentLauncher, sigVerifier, stagingRoot: danglingDirLink + Path.DirectorySeparatorChar);
        var r3 = await ops3.RunBiosInstallerAsync(
            new BiosAgentInstallRequest("dell", BiosAgentInstallModes.DellBiosExe, PackagePath: validPkg),
            cts.Token);
        Assert.False(r3.Executed);
        Assert.False(r3.Allowed);
        Assert.False(Directory.Exists(missingDirTarget));

        // (c) Non-existent nested staging root under a dangling symlink ancestor
        var nestedUnderDangling = Path.Combine(danglingDirLink, "nested", "child");
        var ops4 = new AgentBiosOperations(agentLauncher, sigVerifier, stagingRoot: nestedUnderDangling);
        var r4 = await ops4.RunBiosInstallerAsync(
            new BiosAgentInstallRequest("dell", BiosAgentInstallModes.DellBiosExe, PackagePath: validPkg),
            cts.Token);
        Assert.False(r4.Executed);
        Assert.False(r4.Allowed);
        Assert.False(Directory.Exists(missingDirTarget));

        Assert.Empty(agentLauncher.Calls);
        Assert.Empty(Directory.GetFileSystemEntries(adminRoot.Path));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task AgentSecurity_FrameworkCabCapsule_FileVsDirectoryCollisionOverLivePipe_RejectsWithoutPathLeak(bool fileBeforeDir)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var userDir = new TempStagingDir();
        using var adminRoot = new TempStagingDir();

        var entries = fileBeforeDir
            ? new Dictionary<string, byte[]>
            {
                ["sub"] = Encoding.UTF8.GetBytes("file-blocking-dir"),
                ["sub/firmware.inf"] = Encoding.UTF8.GetBytes("[Version]\nSignature=\"$WINDOWS NT$\""),
            }
            : new Dictionary<string, byte[]>
            {
                ["sub/firmware.inf"] = Encoding.UTF8.GetBytes("[Version]\nSignature=\"$WINDOWS NT$\""),
                ["sub"] = Encoding.UTF8.GetBytes("file-colliding-with-dir"),
            };

        var cabPayload = TestPayload.FromBytes(TestCabBuilder.CreateUncompressed(entries));
        var cabPath = userDir.FilePath(fileBeforeDir ? "collision-file-first.cab" : "collision-dir-first.cab");
        await File.WriteAllBytesAsync(cabPath, cabPayload.Bytes, cts.Token);

        var agentLauncher = CreateGuardedLauncher();
        var ops = new AgentBiosOperations(agentLauncher, new FakeSignatureVerifier(result: true), stagingRoot: adminRoot.Path);

        var (server, serverTask, client) = await StartPipeAsync(agentLauncher, ops, cts.Token);
        using (server)
        {
            await using (client)
            {
                var res = await client.RunBiosInstallerAsync(
                    new BiosAgentInstallRequest(
                        VendorId: "framework",
                        InstallMode: BiosAgentInstallModes.FrameworkCabCapsule,
                        PackagePath: cabPath,
                        ExpectedSha256: cabPayload.Sha256,
                        AllowReboot: false),
                    cts.Token);

                Assert.False(res.Executed);
                Assert.False(res.Allowed);
                Assert.False(string.IsNullOrWhiteSpace(res.Error));
                Assert.DoesNotContain(adminRoot.Path, res.Error, StringComparison.OrdinalIgnoreCase);
            }

            await serverTask;
        }

        Assert.Empty(agentLauncher.Calls);
        Assert.Empty(Directory.GetFileSystemEntries(adminRoot.Path));
    }

    [Fact]
    public async Task AgentSecurity_RunBiosInstaller_RejectsWhitespaceAndNewlinePaddedSha256FailClosed()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var userDir = new TempStagingDir();
        using var adminRoot = new TempStagingDir();

        var payload = TestPayload.FromString("padded-sha-bios-binary");
        var pkgPath = userDir.FilePath("bios.exe");
        await File.WriteAllBytesAsync(pkgPath, payload.Bytes, cts.Token);

        var agentLauncher = CreateGuardedLauncher();
        var ops = new AgentBiosOperations(agentLauncher, new FakeSignatureVerifier(result: true), stagingRoot: adminRoot.Path);

        var paddedHashes = new[]
        {
            " " + payload.Sha256 + " ",
            " " + payload.Sha256,
            payload.Sha256 + " ",
            "\n" + payload.Sha256 + "\r\n",
            payload.Sha256 + "\n",
            "\t" + payload.Sha256,
        };

        var (server, serverTask, client) = await StartPipeAsync(agentLauncher, ops, cts.Token);
        using (server)
        {
            await using (client)
            {
                foreach (var badSha in paddedHashes)
                {
                    var res = await client.RunBiosInstallerAsync(
                        new BiosAgentInstallRequest(
                            VendorId: "dell",
                            InstallMode: BiosAgentInstallModes.DellBiosExe,
                            PackagePath: pkgPath,
                            ExpectedSha256: badSha),
                        cts.Token);

                    Assert.False(res.Executed);
                    Assert.False(res.Allowed);
                    Assert.Contains("SHA-256", res.Error ?? "", StringComparison.OrdinalIgnoreCase);
                }
            }

            await serverTask;
        }

        Assert.Empty(agentLauncher.Calls);
        Assert.Empty(Directory.GetFileSystemEntries(adminRoot.Path));
    }

    [Theory]
    [InlineData("748279c7-4309-452c-8b30-e02ec52e498f\r\n")]
    [InlineData(" 748279c7-4309-452c-8b30-e02ec52e498f ")]
    [InlineData("{748279c7-4309-452c-8b30-e02ec52e498f}")]
    public async Task AgentSecurity_InstallBiosWindowsUpdate_RejectsNonCanonicalPaddedAndBracedGuidsOverRawPipe(string badGuid)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var wua = new FakeWuaApi();
        wua.Reset(new FakeWuaUpdate("System Firmware", downloaded: true), new UpdateInstallOutcome(2, 0, true));
        var agentLauncher = CreateGuardedLauncher();
        var ops = new AgentBiosOperations(agentLauncher, wuaApiFactory: () => wua);

        var pipeName = $"rpd-bios-guid-{Guid.NewGuid():N}";
        using var server = new AdminPipeServer(
            new AdminPipeServerOptions
            {
                PipeName = pipeName,
                ExpectedClientPid = Environment.ProcessId,
            },
            launcher: agentLauncher,
            biosOperations: ops);

        var serverTask = server.RunSingleSessionAsync(cts.Token);

        await using (var rawPipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous))
        {
            await rawPipe.ConnectAsync(10_000, cts.Token);

            await AdminPipeFraming.WriteFrameAsync(
                rawPipe,
                new AdminPipeRequest(AdminPipeFraming.OpBiosInstallWua, BiosWuaUpdateId: badGuid),
                cts.Token);

            var resp = await AdminPipeFraming.ReadFrameAsync<AdminPipeResponse>(rawPipe, cts.Token);
            Assert.NotNull(resp);
            Assert.False(resp.Ok);
            Assert.False(resp.Allowed);
            Assert.NotNull(resp.BiosWuaOutcome);
            Assert.False(resp.BiosWuaOutcome.Succeeded);
        }

        await serverTask;
        Assert.Empty(wua.Criteria);
        Assert.Empty(agentLauncher.Calls);
    }

    [Fact]
    public async Task AdminPipeClient_MidCallCancellation_PropagatesCancellationAndKeepsThePipeInStep()
    {
        using var testCts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        var agentLauncher = CreateGuardedLauncher(async (_, _) =>
        {
            started.TrySetResult();
            await release.Task.WaitAsync(TimeSpan.FromSeconds(10));
            return new ProcessResult(0, "late-response", "");
        });
        var ops = new AgentBiosOperations(agentLauncher);

        var (server, serverTask, client) = await StartPipeAsync(agentLauncher, ops, testCts.Token);
        using (server)
        {
            await using (client)
            {
                using var callCts = new CancellationTokenSource();
                var inFlight = client.SuspendBitLockerAsync("C:", callCts.Token);

                await started.Task.WaitAsync(testCts.Token);
                callCts.Cancel();

                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => inFlight);

                // The pipe stays open (dropping it would end Admin Repair Mode in the UAC helper). The cancelled request's late
                // answer is read in the background, so the next request gets its own answer, not that stale one.
                Assert.True(client.IsConnected);
                var ping = client.PingAsync(testCts.Token);
                release.TrySetResult();
                await ping;
                Assert.True(client.IsConnected);
            }

            await serverTask;
        }
    }

    [Fact]
    public async Task BiosBitLockerSuspender_RedactsSerialNumberFromAgentRefusalErrorAndExceptionMessages()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var secret = BiosIdentityFactory.SentinelSerialNumber;
        var req = CreateSampleInstallRequest(suspendBitLocker: true);

        // (a) Agent refusal (Allowed: false) containing serial number
        var log1 = new CapturedLog();
        var refusalBridge = new CustomBitLockerBridge(_ => Task.FromResult(
            new BiosAgentBitLockerResult(false, Allowed: false, ExitCode: -1, Error: $"Volume lock failed for {secret}")));
        var out1 = await BiosBitLockerSuspender.SuspendForOneRebootWithResultAsync(
            req, commands: null, progress: null, log1.Logger, cts.Token, "C:",
            bridge: refusalBridge, isProcessElevated: () => false);
        Assert.False(out1.Suspended);
        Assert.True(out1.ElevationRequired);
        Assert.Contains("[REDACTED]", out1.Message ?? "");
        Assert.DoesNotContain(secret, out1.Message ?? "", StringComparison.OrdinalIgnoreCase);
        log1.AssertDoesNotContainSecret(secret);

        // (b) Agent non-zero error (Allowed: true, Suspended: false) containing serial number
        var log2 = new CapturedLog();
        var nonZeroBridge = new CustomBitLockerBridge(_ => Task.FromResult(
            new BiosAgentBitLockerResult(false, Allowed: true, ExitCode: 1, Error: $"BitLocker error on {secret.ToLowerInvariant()}")));
        var out2 = await BiosBitLockerSuspender.SuspendForOneRebootWithResultAsync(
            req, commands: null, progress: null, log2.Logger, cts.Token, "C:",
            bridge: nonZeroBridge, isProcessElevated: () => false);
        Assert.False(out2.Suspended);
        Assert.Contains("[REDACTED]", out2.Message ?? "");
        Assert.DoesNotContain(secret, out2.Message ?? "", StringComparison.OrdinalIgnoreCase);
        log2.AssertDoesNotContainSecret(secret);

        // (c) AdminRequiredException containing serial number
        var log3 = new CapturedLog();
        var adminExBridge = new CustomBitLockerBridge(_ =>
            Task.FromException<BiosAgentBitLockerResult>(new AdminRequiredException($"Unsupported on host {secret}")));
        var out3 = await BiosBitLockerSuspender.SuspendForOneRebootWithResultAsync(
            req, commands: null, progress: null, log3.Logger, cts.Token, "C:",
            bridge: adminExBridge, isProcessElevated: () => false);
        Assert.False(out3.Suspended);
        Assert.True(out3.LegacyAgentUnsupported);
        Assert.Contains("[REDACTED]", out3.Message ?? "");
        Assert.DoesNotContain(secret, out3.Message ?? "", StringComparison.OrdinalIgnoreCase);
        log3.AssertDoesNotContainSecret(secret);

        // (d) Generic bridge exception containing serial number
        var log4 = new CapturedLog();
        var ioExBridge = new CustomBitLockerBridge(_ =>
            Task.FromException<BiosAgentBitLockerResult>(new IOException($"Pipe dropped for {secret}")));
        var out4 = await BiosBitLockerSuspender.SuspendForOneRebootWithResultAsync(
            req, commands: null, progress: null, log4.Logger, cts.Token, "C:",
            bridge: ioExBridge, isProcessElevated: () => false);
        Assert.False(out4.Suspended);
        Assert.Contains("[REDACTED]", out4.Message ?? "");
        Assert.DoesNotContain(secret, out4.Message ?? "", StringComparison.OrdinalIgnoreCase);
        log4.AssertDoesNotContainSecret(secret);

        // (e) Local elevated path exception containing serial number
        var log5 = new CapturedLog();
        var throwingLauncher = CreateGuardedLauncher((_, _) =>
            Task.FromException<ProcessResult>(new InvalidOperationException($"Local manage-bde crash for {secret}")));
        var commands = RecordingProcessLauncher.CreateCommandRunner(throwingLauncher, isProcessElevated: true);
        var out5 = await BiosBitLockerSuspender.SuspendForOneRebootWithResultAsync(
            req, commands, progress: null, log5.Logger, cts.Token, "C:",
            isProcessElevated: () => true);
        Assert.False(out5.Suspended);
        Assert.Contains("[REDACTED]", out5.Message ?? "");
        Assert.DoesNotContain(secret, out5.Message ?? "", StringComparison.OrdinalIgnoreCase);
        log5.AssertDoesNotContainSecret(secret);
    }

    [Fact]
    public async Task AgentSecurity_DellDcuCli_RejectsSiblingPrefixConfusionRoot()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var allowedRoot = new TempStagingDir();

        var siblingEvilRoot = Path.TrimEndingDirectorySeparator(allowedRoot.Path) + "Evil";
        try
        {
            var evilDcuDir = Path.Combine(siblingEvilRoot, "Dell", "CommandUpdate");
            Directory.CreateDirectory(evilDcuDir);
            var evilDcuExe = Path.Combine(evilDcuDir, "dcu-cli.exe");
            await File.WriteAllBytesAsync(evilDcuExe, Encoding.UTF8.GetBytes("evil-dcu-binary"), cts.Token);

            var agentLauncher = CreateGuardedLauncher();
            var ops = new AgentBiosOperations(
                launcher: agentLauncher,
                signatureVerifier: new FakeSignatureVerifier(result: true),
                allowedToolRoots: [allowedRoot.Path]);

            var res = await ops.RunBiosInstallerAsync(
                new BiosAgentInstallRequest("dell", BiosAgentInstallModes.DellDcuCli, PackagePath: evilDcuExe),
                cts.Token);

            Assert.False(res.Executed);
            Assert.False(res.Allowed);
            Assert.Empty(agentLauncher.Calls);
        }
        finally
        {
            try
            {
                if (Directory.Exists(siblingEvilRoot))
                    Directory.Delete(siblingEvilRoot, recursive: true);
            }
            catch
            {
                // Best-effort cleanup.
            }
        }
    }

    [Fact]
    public async Task BiosInstallerRunner_ClampsAgentRequestTimeoutMsBeforeLoggingAndForwarding()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var req = CreateSampleInstallRequest();
        var capturedRequests = new List<BiosAgentInstallRequest>();
        var capturingBridge = new CapturingInstallBridge(agentReq =>
        {
            capturedRequests.Add(agentReq);
            return Task.FromResult(new BiosAgentInstallResult(Executed: true, Allowed: true, ExitCode: 3010));
        });

        var highLog = new CapturedLog();
        var highRes = await BiosInstallerRunner.RunInstallerAsync(
            commands: null,
            executablePath: "/tmp/bios.exe",
            arguments: ["/s"],
            request: req,
            bitLockerSuspended: true,
            rebootSuccessExitCodes: RebootCodes,
            completedSuccessExitCodes: CompletedCodes,
            timeout: TimeSpan.FromMinutes(5),
            log: highLog.Logger,
            ct: cts.Token,
            agentRequest: new BiosAgentInstallRequest("dell", BiosAgentInstallModes.DellBiosExe, "/tmp/bios.exe", TimeoutMs: 9_999_999),
            bridge: capturingBridge,
            isProcessElevated: () => false);

        Assert.True(highRes.Succeeded);
        Assert.Contains("timeout=1800s", highLog.AllText, StringComparison.OrdinalIgnoreCase);

        var lowLog = new CapturedLog();
        var lowRes = await BiosInstallerRunner.RunInstallerAsync(
            commands: null,
            executablePath: "/tmp/bios.exe",
            arguments: ["/s"],
            request: req,
            bitLockerSuspended: true,
            rebootSuccessExitCodes: RebootCodes,
            completedSuccessExitCodes: CompletedCodes,
            timeout: TimeSpan.FromMinutes(5),
            log: lowLog.Logger,
            ct: cts.Token,
            agentRequest: new BiosAgentInstallRequest("dell", BiosAgentInstallModes.DellBiosExe, "/tmp/bios.exe", TimeoutMs: 50),
            bridge: capturingBridge,
            isProcessElevated: () => false);

        Assert.True(lowRes.Succeeded);
        Assert.Contains("timeout=1s", lowLog.AllText, StringComparison.OrdinalIgnoreCase);

        Assert.Equal(2, capturedRequests.Count);
        Assert.Equal(1_800_000, capturedRequests[0].TimeoutMs);
        Assert.Equal(1_000, capturedRequests[1].TimeoutMs);
    }

    // -------------------------------------------------------------------------
    // Helpers & Test Doubles
    // -------------------------------------------------------------------------

    private static RecordingProcessLauncher CreateGuardedLauncher(
        Func<RecordedProcessCall, CancellationToken, Task<ProcessResult>>? inner = null) =>
        new((call, ct) =>
        {
            if (ForbiddenShellBinaries.Contains(call.BaseName))
                throw new InvalidOperationException($"Pure-C# violation: forbidden shell binary '{call.FileName}' was invoked.");

            foreach (var arg in call.Arguments)
            {
                foreach (var ext in ForbiddenScriptExtensions)
                {
                    if (arg.EndsWith(ext, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidOperationException($"Pure-C# violation: forbidden script argument '{arg}' was passed.");
                }
            }

            return inner is not null
                ? inner(call, ct)
                : Task.FromResult(new ProcessResult(0, "", ""));
        });

    private static async Task<(AdminPipeServer Server, Task ServerTask, AdminPipeClient Client)> StartPipeAsync(
        IProcessLauncher agentLauncher,
        IAgentBiosOperations? biosOps,
        CancellationToken ct,
        ILogger? log = null)
    {
        var pipeName = $"rpd-bios-test-{Guid.NewGuid():N}";
        var server = new AdminPipeServer(
            new AdminPipeServerOptions
            {
                PipeName = pipeName,
                ExpectedClientPid = Environment.ProcessId,
            },
            launcher: agentLauncher,
            log: log,
            biosOperations: biosOps);

        var serverTask = server.RunSingleSessionAsync(ct);
        var client = await AdminPipeClient.ConnectAsync(pipeName, TimeSpan.FromSeconds(10), ct);
        return (server, serverTask, client);
    }

    private static void AssertPathStrictlyInside(string candidatePath, string rootDir)
    {
        var fullRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(rootDir)) + Path.DirectorySeparatorChar;
        var fullCandidate = Path.GetFullPath(candidatePath);
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        Assert.StartsWith(fullRoot, fullCandidate, comparison);
    }

    private static BiosInstallRequest CreateSampleInstallRequest(bool suspendBitLocker = true, bool allowReboot = false)
    {
        var system = BiosIdentityFactory.Dell();
        var latest = BiosLatestInfo.UpdateAvailable("dell", "1.15.0", downloadUrl: "https://downloads.dell.com/bios.exe");
        return new BiosInstallRequest(
            System: system,
            Current: system.CurrentBios,
            Target: latest,
            Approved: true,
            ApprovedBy: "operator",
            SuspendBitLocker: suspendBitLocker,
            AllowReboot: allowReboot,
            VerifyHash: true);
    }

    private sealed class FakeWuaUpdate(string title, bool downloaded = false, bool eula = true) : IFoundUpdate
    {
        public string Title => title;
        public bool EulaAccepted { get; private set; } = eula;
        public void AcceptEula() => EulaAccepted = true;
        public bool IsDownloaded { get; set; } = downloaded;
    }

    private sealed class FakeWuaApi : IWindowsUpdateApi
    {
        private readonly List<FakeWuaUpdate> _updates = [];
        public List<string> Criteria { get; } = [];
        public Exception? SearchError;
        public UpdateInstallOutcome Outcome = new(2, 0, false);

        public void Reset(FakeWuaUpdate? update, UpdateInstallOutcome outcome)
        {
            _updates.Clear();
            SearchError = null;
            Outcome = outcome;
            if (update is not null)
                _updates.Add(update);
        }

        public IReadOnlyList<IFoundUpdate> Search(string criteria)
        {
            Criteria.Add(criteria);
            if (SearchError is not null)
                throw SearchError;
            return [.. _updates];
        }

        public int Download(IReadOnlyList<IFoundUpdate> updates)
        {
            foreach (FakeWuaUpdate u in updates)
                u.IsDownloaded = true;
            return 2;
        }

        public UpdateInstallOutcome Install(IReadOnlyList<IFoundUpdate> updates) => Outcome;

        public void StartInteractiveScan() { }
    }

    private sealed class DisconnectedBridge : IElevatedCommandBridge
    {
        public bool IsConnected => false;
        public Task<ProcessResult?> RunElevatedAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct, Action<string>? outputLine = null) =>
            Task.FromResult<ProcessResult?>(null);
        public Task<SensorSnapshot?> ReadSensorsAsync(CancellationToken ct = default) => Task.FromResult<SensorSnapshot?>(null);
        public Task<IReadOnlyList<DriveHealth>?> ReadDrivesAsync(CancellationToken ct = default) => Task.FromResult<IReadOnlyList<DriveHealth>?>(null);
    }

    private sealed class ThrowingBridge(Exception ex) : IElevatedCommandBridge
    {
        public bool IsConnected => true;
        public Task<ProcessResult?> RunElevatedAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct, Action<string>? outputLine = null) =>
            Task.FromException<ProcessResult?>(ex);
        public Task<SensorSnapshot?> ReadSensorsAsync(CancellationToken ct = default) => Task.FromResult<SensorSnapshot?>(null);
        public Task<IReadOnlyList<DriveHealth>?> ReadDrivesAsync(CancellationToken ct = default) => Task.FromResult<IReadOnlyList<DriveHealth>?>(null);
        public Task<BiosAgentInstallResult> RunBiosInstallerAsync(BiosAgentInstallRequest request, CancellationToken ct = default) =>
            Task.FromException<BiosAgentInstallResult>(ex);
    }

    private sealed class OldBridge : IElevatedCommandBridge
    {
        public bool IsConnected => true;
        public Task<ProcessResult?> RunElevatedAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct, Action<string>? outputLine = null) =>
            Task.FromResult<ProcessResult?>(null);
        public Task<SensorSnapshot?> ReadSensorsAsync(CancellationToken ct = default) => Task.FromResult<SensorSnapshot?>(null);
        public Task<IReadOnlyList<DriveHealth>?> ReadDrivesAsync(CancellationToken ct = default) => Task.FromResult<IReadOnlyList<DriveHealth>?>(null);
    }

    private sealed class CustomBitLockerBridge(Func<string, Task<BiosAgentBitLockerResult>> handler) : IElevatedCommandBridge
    {
        public bool IsConnected => true;
        public Task<ProcessResult?> RunElevatedAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct, Action<string>? outputLine = null) =>
            Task.FromResult<ProcessResult?>(null);
        public Task<SensorSnapshot?> ReadSensorsAsync(CancellationToken ct = default) => Task.FromResult<SensorSnapshot?>(null);
        public Task<IReadOnlyList<DriveHealth>?> ReadDrivesAsync(CancellationToken ct = default) => Task.FromResult<IReadOnlyList<DriveHealth>?>(null);
        public Task<BiosAgentBitLockerResult> SuspendBitLockerAsync(string systemDrive, CancellationToken ct = default) =>
            handler(systemDrive);
    }

    private sealed class CapturingInstallBridge(Func<BiosAgentInstallRequest, Task<BiosAgentInstallResult>> handler) : IElevatedCommandBridge
    {
        public bool IsConnected => true;
        public Task<ProcessResult?> RunElevatedAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct, Action<string>? outputLine = null) =>
            Task.FromResult<ProcessResult?>(null);
        public Task<SensorSnapshot?> ReadSensorsAsync(CancellationToken ct = default) => Task.FromResult<SensorSnapshot?>(null);
        public Task<IReadOnlyList<DriveHealth>?> ReadDrivesAsync(CancellationToken ct = default) => Task.FromResult<IReadOnlyList<DriveHealth>?>(null);
        public Task<BiosAgentInstallResult> RunBiosInstallerAsync(BiosAgentInstallRequest request, CancellationToken ct = default) =>
            handler(request);
    }
}
