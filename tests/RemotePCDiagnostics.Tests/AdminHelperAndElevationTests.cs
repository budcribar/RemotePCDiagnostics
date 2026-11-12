using System.Diagnostics;
using System.IO.Pipes;
using System.Xml.Linq;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Tests;

public sealed class AdminHelperAndElevationTests
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

    private sealed class RecordingLauncher(Func<string, IReadOnlyList<string>, ProcessResult>? handler = null) : IProcessLauncher
    {
        public List<(string FileName, IReadOnlyList<string> Arguments)> Calls { get; } = [];

        public Task<ProcessResult> RunAsync(
            string fileName,
            IReadOnlyList<string> arguments,
            TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            Calls.Add((fileName, arguments.ToArray()));
            var result = handler is not null
                ? handler(fileName, arguments)
                : new ProcessResult(0, "ok", "");
            return Task.FromResult(result);
        }
    }

    private sealed class FakeBridge(bool connected, Func<string, IReadOnlyList<string>, ProcessResult?> handler) : IElevatedCommandBridge
    {
        public bool IsConnected { get; set; } = connected;
        public List<(string FileName, IReadOnlyList<string> Arguments)> Calls { get; } = [];

        public Task<ProcessResult?> RunElevatedAsync(
            string fileName,
            IReadOnlyList<string> arguments,
            TimeSpan timeout,
            CancellationToken ct,
            Action<string>? outputLine = null)
        {
            Calls.Add((fileName, arguments.ToArray()));
            var result = handler(fileName, arguments);
            if (result is not null && outputLine is not null && !string.IsNullOrEmpty(result.StdOut))
            {
                foreach (var line in result.StdOut.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
                    outputLine(line);
            }
            return Task.FromResult(result);
        }
    }

    [Fact]
    public async Task AdminPipeFraming_RoundTripsJsonAndHandlesEofAndOversizedPayloads()
    {
        using var ms = new MemoryStream();
        var req = new AdminPipeRequest(AdminPipeFraming.OpRunCommand, "sfc.exe", ["/scannow"], 45_000);
        await AdminPipeFraming.WriteFrameAsync(ms, req, CancellationToken.None);

        ms.Position = 0;
        var decoded = await AdminPipeFraming.ReadFrameAsync<AdminPipeRequest>(ms, CancellationToken.None);
        Assert.NotNull(decoded);
        Assert.Equal(AdminPipeFraming.OpRunCommand, decoded!.Op);
        Assert.Equal("sfc.exe", decoded.FileName);
        Assert.Equal(["/scannow"], decoded.Arguments);
        Assert.Equal(45_000, decoded.TimeoutMs);

        // Clean EOF returns null without throwing.
        var eof = await AdminPipeFraming.ReadFrameAsync<AdminPipeRequest>(ms, CancellationToken.None);
        Assert.Null(eof);

        // Oversized length prefix throws InvalidDataException.
        using var bad = new MemoryStream();
        var badHeader = new byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(badHeader, AdminPipeFraming.MaxFrameBytes + 1);
        bad.Write(badHeader);
        bad.Position = 0;
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            AdminPipeFraming.ReadFrameAsync<AdminPipeRequest>(bad, CancellationToken.None));
    }

    [Fact]
    public void AdminCommandAllowlist_AllowsSystemRepairToolsAndRejectsSpoofedOrArbitraryBinaries()
    {
        Assert.True(AdminCommandAllowlist.TryResolveSystemTool("sfc.exe", out var sfc));
        Assert.EndsWith("sfc.exe", sfc, StringComparison.OrdinalIgnoreCase);

        Assert.True(AdminCommandAllowlist.TryResolveSystemTool("DISM.exe", out var dism));
        Assert.EndsWith("DISM.exe", dism, StringComparison.OrdinalIgnoreCase);

        Assert.True(AdminCommandAllowlist.TryResolveSystemTool(SystemCommandRunner.PowerShell, out var ps));
        Assert.EndsWith("powershell.exe", ps, StringComparison.OrdinalIgnoreCase);

        // Rejects non-allowlisted tools even in System32.
        Assert.False(AdminCommandAllowlist.TryResolveSystemTool("cmd.exe", out _));
        Assert.False(AdminCommandAllowlist.TryResolveSystemTool("calc.exe", out _));
        Assert.False(AdminCommandAllowlist.TryResolveSystemTool("", out _));

        // Rejects spoofed paths outside Environment.SystemDirectory when SystemDirectory is populated.
        if (!string.IsNullOrEmpty(Environment.SystemDirectory))
        {
            var spoofed = Path.Combine(Path.GetTempPath(), "sfc.exe");
            Assert.False(AdminCommandAllowlist.TryResolveSystemTool(spoofed, out _));
        }
    }

    [Fact]
    public async Task AdminPipeServerAndClient_ExecuteAllowlistedCommandsAndRejectDisallowedOnes()
    {
        var pipeName = $"rpd-test-{Guid.NewGuid():N}";
        var launcher = new RecordingLauncher((exe, args) =>
            new ProcessResult(0, $"ran:{Path.GetFileName(exe)} {string.Join(' ', args)}", ""));

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var server = new AdminPipeServer(
            new AdminPipeServerOptions
            {
                PipeName = pipeName,
                ExpectedClientPid = Environment.ProcessId,
            },
            launcher);

        var serverTask = server.RunSingleSessionAsync(cts.Token);

        await using (var client = await AdminPipeClient.ConnectAsync(pipeName, TimeSpan.FromSeconds(10), cts.Token))
        {
            Assert.True(client.IsConnected);
            Assert.Equal(Environment.ProcessId, client.HelperPid);

            var allowed = await client.RunCommandAsync("ipconfig.exe", ["/flushdns"], TimeSpan.FromSeconds(10), cts.Token);
            Assert.True(allowed.Ok);
            Assert.True(allowed.Allowed);
            Assert.Equal(0, allowed.ExitCode);
            Assert.Contains("ipconfig.exe /flushdns", allowed.StdOut, StringComparison.OrdinalIgnoreCase);
            Assert.Single(launcher.Calls);

            var denied = await client.RunCommandAsync("notepad.exe", [], TimeSpan.FromSeconds(10), cts.Token);
            Assert.False(denied.Ok);
            Assert.False(denied.Allowed);
            Assert.Single(launcher.Calls);
        }

        await serverTask;
    }

    [Fact]
    public async Task AdminPipeServer_RejectsUnverifiedClientProcessImmediately()
    {
        var pipeName = $"rpd-reject-{Guid.NewGuid():N}";
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var server = new AdminPipeServer(
            new AdminPipeServerOptions
            {
                PipeName = pipeName,
                CustomClientVerifier = _ => (false, "spoofed client"),
            },
            new RecordingLauncher());

        var serverTask = server.RunSingleSessionAsync(cts.Token);

        await Assert.ThrowsAnyAsync<IOException>(() =>
            AdminPipeClient.ConnectAsync(pipeName, TimeSpan.FromSeconds(5), cts.Token));

        await serverTask;
    }

    [Fact]
    public async Task SystemCommandRunner_RoutesThroughElevatedBridgeOnlyWhenUnelevatedAndConnected()
    {
        var local = new RecordingLauncher((_, _) => new ProcessResult(0, "local", ""));
        var lines = new List<string>();
        var bridge = new FakeBridge(connected: true, (_, _) => new ProcessResult(0, "elevated-line-1\nelevated-line-2", ""));

        var unElevatedRunner = new SystemCommandRunner(
            launcher: local,
            elevatedBridge: bridge,
            isProcessElevated: () => false);

        var res = await unElevatedRunner.RunPowerShellAsync("Write-Output 'ok'", TimeSpan.FromSeconds(10), CancellationToken.None, lines.Add);
        Assert.NotNull(res);
        Assert.Contains("elevated-line-1", res!.StdOut);
        Assert.Equal(["elevated-line-1", "elevated-line-2"], lines);
        Assert.Single(bridge.Calls);
        Assert.Empty(local.Calls);

        // When already elevated, runs directly without crossing the bridge.
        var elevatedRunner = new SystemCommandRunner(
            launcher: local,
            elevatedBridge: bridge,
            isProcessElevated: () => true);

        var directRes = await elevatedRunner.RunPowerShellAsync("Write-Output 'direct'", CancellationToken.None);
        Assert.NotNull(directRes);
        Assert.Equal("local", directRes!.StdOut);
        Assert.Single(bridge.Calls);
        Assert.Single(local.Calls);

        // When bridge disconnects, falls back cleanly to local launcher.
        bridge.IsConnected = false;
        var fallbackRes = await unElevatedRunner.RunPowerShellAsync("Write-Output 'fallback'", CancellationToken.None);
        Assert.NotNull(fallbackRes);
        Assert.Equal("local", fallbackRes!.StdOut);
        Assert.Equal(2, local.Calls.Count);
    }

    [Fact]
    public async Task ElevationService_ManagesHelperConnectionStateAndPreservesRemoteRelaunchFlags()
    {
        var sessionId = Guid.Parse("a8f5e2c1-4b3d-4e9f-8a1c-2d3e4f5a6b7c");
        var session = new SessionContext(
            SessionMode.Remote,
            new Uri("https://remoteblazorwebview.com:34544/"),
            sessionId,
            unattended: true,
            voice: true,
            group: "Acme-PC");

        var relaunchArgs = ElevationService.BuildRelaunchArguments(session);
        Assert.Equal(
            [
                "-u=https://remoteblazorwebview.com:34544",
                $"-i={sessionId:D}",
                "-g=acme-pc",
                "--unattended",
                "--voice",
                "--restarted",
            ],
            relaunchArgs);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        AdminPipeServer? activeServer = null;
        Task? serverTask = null;
        IReadOnlyList<string>? capturedRelaunch = null;

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
                    new RecordingLauncher());
                serverTask = activeServer.RunSingleSessionAsync(token);
                return await AdminPipeClient.ConnectAsync(req.PipeName, TimeSpan.FromSeconds(10), token);
            },
            customRelauncher: (args, _) =>
            {
                capturedRelaunch = args;
                return Task.FromResult(new ElevationResult(true, false, "Relaunched"));
            });

        var changedCount = 0;
        elevation.Changed += () => Interlocked.Increment(ref changedCount);

        Assert.False(elevation.IsProcessElevated);
        Assert.False(elevation.IsAdminHelperConnected);
        Assert.False(elevation.HasAdminCapabilities);

        var enableRes = await elevation.EnableAdminModeAsync(cts.Token);
        Assert.True(enableRes.Success);
        Assert.False(enableRes.Cancelled);
        Assert.True(elevation.IsAdminHelperConnected);
        Assert.True(elevation.HasAdminCapabilities);
        Assert.True(changedCount >= 1);

        var relaunchRes = await elevation.RelaunchElevatedAsync(cts.Token);
        Assert.True(relaunchRes.Success);
        Assert.Equal(relaunchArgs, capturedRelaunch);

        elevation.Dispose();
        if (serverTask is not null)
            await serverTask;
        activeServer?.Dispose();
    }

    [Fact]
    public void AdminHelperCli_ParsesValidFlagsAndRejectsInvalidArguments()
    {
        Assert.True(RemotePCDiagnostics.Admin.Program.TryParseArguments(
            ["--mode=helper", "--parent-pid=4321", "--pipe=rpd-admin-123", "--client-sid=S-1-5-18"],
            out var pid1,
            out var pipe1,
            out var sid1));
        Assert.Equal(4321, pid1);
        Assert.Equal("rpd-admin-123", pipe1);
        Assert.Equal("S-1-5-18", sid1);

        Assert.True(RemotePCDiagnostics.Admin.Program.TryParseArguments(
            ["--mode", "helper", "--parent-pid", "99", "--pipe", "rpd-admin-abc"],
            out var pid2,
            out var pipe2,
            out var sid2));
        Assert.Equal(99, pid2);
        Assert.Equal("rpd-admin-abc", pipe2);
        Assert.Null(sid2);

        Assert.False(RemotePCDiagnostics.Admin.Program.TryParseArguments(["--mode=service", "--parent-pid=99", "--pipe=ok"], out _, out _, out _));
        Assert.False(RemotePCDiagnostics.Admin.Program.TryParseArguments(["--mode=helper", "--parent-pid=0", "--pipe=ok"], out _, out _, out _));
        Assert.False(RemotePCDiagnostics.Admin.Program.TryParseArguments(["--mode=helper", "--parent-pid=99", @"--pipe=..\evil"], out _, out _, out _));
    }

    [Fact]
    public async Task RealAdminHelperProcess_ConnectsAnswersPingAndExitsCleanlyWhenPipeCloses()
    {
        var adminExe = Path.Combine(AppContext.BaseDirectory, "RemotePCDiagnostics.Admin.exe");
        var adminDll = Path.Combine(AppContext.BaseDirectory, "RemotePCDiagnostics.Admin.dll");

        ProcessStartInfo BuildPsi(params string[] args)
        {
            ProcessStartInfo psi;
            if (File.Exists(adminExe))
            {
                psi = new ProcessStartInfo(adminExe);
                foreach (var a in args) psi.ArgumentList.Add(a);
            }
            else
            {
                Assert.True(File.Exists(adminDll), $"Neither {adminExe} nor {adminDll} was found in test output.");
                psi = new ProcessStartInfo("dotnet");
                psi.ArgumentList.Add(adminDll);
                foreach (var a in args) psi.ArgumentList.Add(a);
            }
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.Environment["RPD_ADMIN_ALLOW_TEST_PARENT"] = "1";
            return psi;
        }

        using (var selfCheck = Process.Start(BuildPsi("--self-check"))!)
        {
            Assert.True(selfCheck.WaitForExit(15_000));
            Assert.Equal(0, selfCheck.ExitCode);
        }

        var pipeName = $"rpd-live-{Guid.NewGuid():N}";
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(25));
        using var helper = Process.Start(BuildPsi(
            "--mode=helper",
            $"--parent-pid={Environment.ProcessId}",
            $"--pipe={pipeName}"))!;

        try
        {
            await using (var client = await AdminPipeClient.ConnectAsync(pipeName, TimeSpan.FromSeconds(15), cts.Token))
            {
                Assert.True(client.IsConnected);
                Assert.Equal(helper.Id, client.HelperPid);

                var ping = await client.PingAsync(cts.Token);
                Assert.True(ping.Ok);
                Assert.Equal(helper.Id, ping.HelperPid);
            }

            // Disposing the client closes the named pipe; the helper must exit promptly without lingering.
            using var exitCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await helper.WaitForExitAsync(exitCts.Token);
            Assert.Equal(0, helper.ExitCode);
        }
        finally
        {
            if (!helper.HasExited)
            {
                try { helper.Kill(entireProcessTree: true); } catch { }
            }
        }
    }

    [Fact]
    public void StorePolicy10_2_9_ManifestsMsixAssetsAndBuildScript_AreValidAndAsciiClean()
    {
        var root = FindRepoRoot();

        // Both Host and Admin manifests must launch asInvoker (Microsoft Store Policy 10.2.9).
        foreach (var rel in new[]
        {
            Path.Combine("src", "RemotePCDiagnostics.Host", "app.manifest"),
            Path.Combine("src", "RemotePCDiagnostics.Admin", "app.manifest"),
        })
        {
            var full = Path.Combine(root, rel);
            Assert.True(File.Exists(full), $"Missing manifest: {full}");
            var text = File.ReadAllText(full);
            Assert.Contains("level=\"asInvoker\"", text);
            Assert.DoesNotContain("requireAdministrator", text);
        }

        // AppxManifest template declares Windows.FullTrustApplication + runFullTrust + allowElevation.
        var appxPath = Path.Combine(root, "msix", "AppxManifest.template.xml");
        Assert.True(File.Exists(appxPath), $"Missing AppxManifest template: {appxPath}");
        var appxRaw = File.ReadAllText(appxPath);
        var appxDoc = XDocument.Load(appxPath);
        Assert.NotNull(appxDoc.Root);
        Assert.Contains("Windows.FullTrustApplication", appxRaw);
        Assert.Contains("RemotePCDiagnostics.Host.exe", appxRaw);
        Assert.Contains("Name=\"runFullTrust\"", appxRaw);
        Assert.Contains("Name=\"allowElevation\"", appxRaw);

        // Visual PNG assets exist with valid PNG signatures and exact pixel dimensions.
        var expectedPngs = new (string Name, int Width, int Height)[]
        {
            ("Square44x44Logo.png", 44, 44),
            ("StoreLogo.png", 50, 50),
            ("Square150x150Logo.png", 150, 150),
            ("Wide310x150Logo.png", 310, 150),
        };
        foreach (var (name, expectedW, expectedH) in expectedPngs)
        {
            var pngPath = Path.Combine(root, "msix", "Assets", name);
            Assert.True(File.Exists(pngPath), $"Missing MSIX PNG asset: {pngPath}");
            var bytes = File.ReadAllBytes(pngPath);
            Assert.True(bytes.Length > 24);
            Assert.Equal(new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }, bytes[..8]);
            var actualW = (bytes[16] << 24) | (bytes[17] << 16) | (bytes[18] << 8) | bytes[19];
            var actualH = (bytes[20] << 24) | (bytes[21] << 16) | (bytes[22] << 8) | bytes[23];
            Assert.Equal((expectedW, expectedH), (actualW, actualH));
        }

        // Build-Msix.ps1 must enforce zero .sys drivers, invoke MakeAppx, and remain strictly 7-bit ASCII (no BOM).
        var buildMsixPath = Path.Combine(root, "msix", "Build-Msix.ps1");
        Assert.True(File.Exists(buildMsixPath), $"Missing MSIX build script: {buildMsixPath}");
        var scriptBytes = File.ReadAllBytes(buildMsixPath);
        Assert.DoesNotContain(scriptBytes, b => b > 127);
        var scriptText = File.ReadAllText(buildMsixPath);
        Assert.Contains("*.sys", scriptText);
        Assert.Contains("makeappx", scriptText, StringComparison.OrdinalIgnoreCase);
    }
}
