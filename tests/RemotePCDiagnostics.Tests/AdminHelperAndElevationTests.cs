using System.Diagnostics;
using System.IO.Pipes;
using System.Xml.Linq;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Sensors;
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
        public List<AdminPipeScript> Scripts { get; } = [];
        public bool ScriptThrows { get; set; }

        public Task<ProcessResult> RunAgentScriptAsync(AdminPipeScript script, TimeSpan timeout, CancellationToken ct, Action<string>? outputLine = null)
        {
            if (ScriptThrows) throw new IOException("pipe is broken");
            Scripts.Add(script);
            return Task.FromResult(new ProcessResult(0, "done", ""));
        }

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

        public Task<SensorSnapshot?> ReadSensorsAsync(CancellationToken ct = default)
        {
            return Task.FromResult<SensorSnapshot?>(null);
        }

        public Task<IReadOnlyList<DriveHealth>?> ReadDrivesAsync(CancellationToken ct = default)
        {
            return Task.FromResult<IReadOnlyList<DriveHealth>?>(null);
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

        // Not PowerShell: the Agent runs only its own scripts (agent_script), never one the app sends.
        Assert.False(AdminCommandAllowlist.TryResolveSystemTool(SystemCommandRunner.PowerShell, out _));

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

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AgentServicePipe_GivesStandardUsersOnlyReadOps(bool clientIsAdmin)
    {
        var pipeName = $"rpd-svc-{Guid.NewGuid():N}";
        var launcher = new RecordingLauncher((exe, args) => new ProcessResult(0, "ran", ""));
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var server = new AdminPipeServer(
            new AdminPipeServerOptions
            {
                PipeName = pipeName,
                RestrictStandardUsers = true,
                ClientIsAdministrator = _ => clientIsAdmin,
            },
            launcher,
            changeJournal: () => new RemotePCDiagnostics.Core.Changes.FileChangeJournal(Path.Combine(Path.GetTempPath(), $"{pipeName}.json"), null));

        var serverTask = server.RunSingleSessionAsync(cts.Token);

        await using (var client = await AdminPipeClient.ConnectAsync(pipeName, TimeSpan.FromSeconds(10), cts.Token))
        {
            Assert.Equal(!clientIsAdmin, client.Restricted);

            var run = await client.RunCommandAsync("ipconfig.exe", ["/flushdns"], TimeSpan.FromSeconds(10), cts.Token);
            Assert.Equal(clientIsAdmin, run.Ok);
            Assert.Equal(clientIsAdmin ? 1 : 0, launcher.Calls.Count);
            if (!clientIsAdmin)
            {
                Assert.False(run.Allowed);
                Assert.Contains("administrator", run.Error, StringComparison.OrdinalIgnoreCase);
            }

            // Reads still work for everyone.
            Assert.NotNull(await client.ReadChangeJournalAsync(cts.Token));
        }

        await serverTask;
    }

    [Fact]
    public void AgentServicePipe_ReadOnlyOpsChangeNothing()
    {
        string[] changing =
        [
            AdminPipeFraming.OpRunCommand, AdminPipeFraming.OpSelfUpdate, AdminPipeFraming.OpUpdateRpcd, AdminPipeFraming.OpSecurityAudit,
            AdminPipeFraming.OpModuleHost, AdminPipeFraming.OpPrepareMachine, AdminPipeFraming.OpSystemSetting, AdminPipeFraming.OpRemoveAppx,
            AdminPipeFraming.OpRunUninstaller, AdminPipeFraming.OpSetScheduledTask, AdminPipeFraming.OpJournalRemove, AdminPipeFraming.OpJournalAdd,
            AdminPipeFraming.OpMachineTweak, AdminPipeFraming.OpAgentScript, AdminPipeFraming.OpStateWrite, AdminPipeFraming.OpBiosSuspendBitLocker,
            AdminPipeFraming.OpBiosRunInstaller, AdminPipeFraming.OpBiosInstallWua, AdminPipeFraming.OpBiosJobStatus, AdminPipeFraming.OpCommandJobStatus,
            AdminPipeFraming.OpCommandJobCancel,
        ];
        foreach (var op in changing)
            Assert.False(AdminPipeServer.ReadOnlyOps.Contains(op), op);

        // Exhaustive allowlist check so no new op is accidentally added without review.
        string[] expectedReadOnly =
        [
            AdminPipeFraming.OpPing, AdminPipeFraming.OpCancel, AdminPipeFraming.OpReadSensors, AdminPipeFraming.OpReadDrives,
            AdminPipeFraming.OpWmiQuery, AdminPipeFraming.OpStateRead, AdminPipeFraming.OpJournalList,
            AdminPipeFraming.OpUpdateRpcdStatus, AdminPipeFraming.OpAgentEnrollment,
        ];
        Assert.Equal(expectedReadOnly.OrderBy(x => x, StringComparer.OrdinalIgnoreCase),
            AdminPipeServer.ReadOnlyOps.OrderBy(x => x, StringComparer.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData(AdminPipeClient.LocalSystemSidValue, 4200u, 4200u, null, true)]                                   // SYSTEM pipe + matching Agent service PID
    [InlineData(AdminPipeClient.BuiltinAdministratorsSidValue, 4200u, 4200u, null, true)]                         // Admins pipe + matching Agent service PID
    [InlineData(AdminPipeClient.LocalSystemSidValue, 4200u, null, AdminPipeClient.LocalSystemSidValue, true)]     // SYSTEM pipe + server process running as LocalSystem
    [InlineData("S-1-5-21-1000-2000-3000-1001", 4200u, 4200u, AdminPipeClient.LocalSystemSidValue, false)]        // User-owned pipe (squatter)
    [InlineData(null, 4200u, 4200u, AdminPipeClient.LocalSystemSidValue, false)]                                  // Missing pipe owner
    [InlineData(AdminPipeClient.LocalSystemSidValue, null, 4200u, null, false)]                                   // Server PID lookup failed
    [InlineData(AdminPipeClient.LocalSystemSidValue, 0u, 4200u, null, false)]                                     // Zero server PID
    [InlineData(AdminPipeClient.BuiltinAdministratorsSidValue, 9999u, 4200u, "S-1-5-21-1000-2000-3000-1001", false)] // Non-SYSTEM user process squatting
    [InlineData(AdminPipeClient.LocalSystemSidValue, 9999u, 4200u, null, false)]                                  // Server PID != service PID and token unreadable (fail closed)
    public void AdminPipeClient_VerifyPipeServerIdentity_BlocksPipeSquatting(
        string? ownerSid,
        uint? serverPid,
        uint? servicePid,
        string? serverUserSid,
        bool expectedAllowed)
    {
        var problem = AdminPipeClient.VerifyPipeServerIdentity(
            ElevationService.ServiceAdminPipeName,
            ownerSid,
            serverPid,
            servicePid,
            serverUserSid);
        if (expectedAllowed)
            Assert.Null(problem);
        else
            Assert.NotNull(problem);
    }

    [Fact]
    public async Task AdminPipeClient_ConnectAsync_RejectsSquattedSystemPipeBeforePing()
    {
        var pipeName = $"rpd-squat-{Guid.NewGuid():N}";
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var server = new AdminPipeServer(
            new AdminPipeServerOptions { PipeName = pipeName },
            new RecordingLauncher());

        var serverTask = server.RunSingleSessionAsync(cts.Token);

        var ex = await Assert.ThrowsAsync<IOException>(() =>
            AdminPipeClient.ConnectAsync(
                pipeName,
                TimeSpan.FromSeconds(10),
                cts.Token,
                requireSystemOwnedPipe: true,
                pipeServerVerifier: _ => "The pipe is hosted by an untrusted process."));
        Assert.Contains("untrusted process", ex.Message, StringComparison.OrdinalIgnoreCase);

        await serverTask;
    }

    [Fact]
    public async Task AdminPipeClient_ConnectAsync_AcceptsVerifiedSystemPipe()
    {
        var pipeName = $"rpd-verified-{Guid.NewGuid():N}";
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var server = new AdminPipeServer(
            new AdminPipeServerOptions { PipeName = pipeName },
            new RecordingLauncher());

        var serverTask = server.RunSingleSessionAsync(cts.Token);

        await using (var client = await AdminPipeClient.ConnectAsync(
            pipeName,
            TimeSpan.FromSeconds(10),
            cts.Token,
            requireSystemOwnedPipe: true,
            pipeServerVerifier: _ => null))
        {
            Assert.True(client.IsConnected);
            Assert.True((await client.PingAsync(cts.Token)).Ok);
        }

        await serverTask;
    }

    [Theory]
    [InlineData(1u, 1u, true)]                                                       // Active console user
    [InlineData(2u, 2u, true)]                                                       // Switched console user
    [InlineData(1u, 2u, false)]                                                      // Disconnected / background session
    [InlineData(1u, AdminPipeServer.NoActiveConsoleSessionId, false)]                // No console user logged on (boot)
    [InlineData(1u, null, false)]                                                    // Console session unknown
    [InlineData(0u, 0u, false)]                                                      // Session 0 is never an interactive desktop user
    [InlineData(null, 1u, false)]                                                    // Client session lookup failed
    public void AdminPipeServer_VerifyActiveConsoleSession_ChecksSessionMatch(
        uint? clientSessionId,
        uint? activeConsoleSessionId,
        bool expectedAllowed)
    {
        var (allowed, reason) = AdminPipeServer.VerifyActiveConsoleSession(clientSessionId, activeConsoleSessionId);
        Assert.Equal(expectedAllowed, allowed);
        if (!expectedAllowed)
            Assert.False(string.IsNullOrWhiteSpace(reason));
    }

    [Fact]
    public async Task AdminPipeServer_RequireActiveConsoleSession_BlocksBackgroundSessionsAndHandlesUserSwitch()
    {
        var pipeName = $"rpd-session-{Guid.NewGuid():N}";
        uint clientSession = 1;
        uint activeConsoleSession = 2; // Initially a background session (1 != 2)

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        await using var server = new AdminPipeServer(
            new AdminPipeServerOptions
            {
                PipeName = pipeName,
                RequireActiveConsoleSession = true,
                SessionIdProvider = _ => (Volatile.Read(ref clientSession), Volatile.Read(ref activeConsoleSession)),
            },
            new RecordingLauncher());

        var serverTask = server.RunUntilCancelledAsync(cts.Token);

        // 1. Background session (1 != 2) is rejected immediately on connect.
        await Assert.ThrowsAnyAsync<IOException>(() =>
            AdminPipeClient.ConnectAsync(pipeName, TimeSpan.FromSeconds(10), cts.Token));

        // 2. Active console user (session 2 == 2) connects and succeeds.
        Volatile.Write(ref clientSession, 2u);
        await using (var activeClient = await AdminPipeClient.ConnectAsync(pipeName, TimeSpan.FromSeconds(10), cts.Token))
        {
            Assert.True((await activeClient.PingAsync(cts.Token)).Ok);

            // 3. Console switches to session 3 while session 2 is still connected: next request is dropped.
            Volatile.Write(ref activeConsoleSession, 3u);
            await Assert.ThrowsAnyAsync<IOException>(() => activeClient.PingAsync(cts.Token));
        }

        // 4. New active console user (session 3 == 3) connects cleanly with zero restart.
        Volatile.Write(ref clientSession, 3u);
        await using (var switchedClient = await AdminPipeClient.ConnectAsync(pipeName, TimeSpan.FromSeconds(10), cts.Token))
        {
            Assert.True((await switchedClient.PingAsync(cts.Token)).Ok);
        }

        cts.Cancel();
        await serverTask;
    }

    [Theory]
    [InlineData(true, AdminPipeServer.TokenElevationTypeFull, null, true)]      // Elevated admin
    [InlineData(true, AdminPipeServer.TokenElevationTypeDefault, null, true)]   // Admin with UAC off
    [InlineData(false, AdminPipeServer.TokenElevationTypeLimited, true, true)]  // Un-elevated UAC split-token admin
    [InlineData(false, AdminPipeServer.TokenElevationTypeLimited, false, false)] // Split-token non-admin (e.g. Backup Operator)
    [InlineData(false, AdminPipeServer.TokenElevationTypeFull, null, false)]    // Elevated split-token non-admin
    [InlineData(false, AdminPipeServer.TokenElevationTypeLimited, null, false)] // Split-token linked lookup failed (fail closed)
    [InlineData(false, AdminPipeServer.TokenElevationTypeDefault, null, false)] // Standard user
    [InlineData(false, null, null, false)]                                      // Elevation type query failed (fail closed)
    public void AdminPipeServer_EvaluateTokenIsAdministrator_HandlesUacSplitTokens(
        bool currentTokenHasEnabledAdmin,
        int? elevationType,
        bool? linkedTokenHasEnabledAdmin,
        bool expectedIsAdmin)
    {
        Assert.Equal(expectedIsAdmin,
            AdminPipeServer.EvaluateTokenIsAdministrator(currentTokenHasEnabledAdmin, elevationType, linkedTokenHasEnabledAdmin));
    }

    [Fact]
    public void ElevationService_RestrictedAgentClientIsNotAdminCapable()
    {
        // HasAdminCapabilities needs an Agent that does repairs for this user, never the app's own elevation.
        using var elevation = new ElevationService(new SessionContext(SessionMode.Local), isProcessElevated: () => true,
            customConnector: (_, _) => throw new IOException("none"));
        Assert.False(elevation.HasAdminCapabilities);
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
        var sfc = SystemCommandRunner.SystemTool("sfc.exe");

        var unElevatedRunner = new SystemCommandRunner(
            launcher: local,
            elevatedBridge: bridge,
            isProcessElevated: () => false);

        var res = await unElevatedRunner.RunAsync(sfc, ["/verifyonly"], TimeSpan.FromSeconds(10), CancellationToken.None, lines.Add);
        Assert.NotNull(res);
        Assert.Contains("elevated-line-1", res!.StdOut);
        Assert.Equal(["elevated-line-1", "elevated-line-2"], lines);
        Assert.Single(bridge.Calls);
        Assert.Empty(local.Calls);

        // PowerShell is never sent to the Agent: it runs with the app's own rights.
        var ps = await unElevatedRunner.RunPowerShellAsync("Write-Output 'ok'", CancellationToken.None);
        Assert.Equal("local", ps!.StdOut);
        Assert.Single(bridge.Calls);
        Assert.Single(local.Calls);

        // When already elevated, runs directly without crossing the bridge.
        var elevatedRunner = new SystemCommandRunner(
            launcher: local,
            elevatedBridge: bridge,
            isProcessElevated: () => true);

        var directRes = await elevatedRunner.RunAsync(sfc, ["/verifyonly"], CancellationToken.None);
        Assert.NotNull(directRes);
        Assert.Equal("local", directRes!.StdOut);
        Assert.Single(bridge.Calls);
        Assert.Equal(2, local.Calls.Count);

        // Without the Agent the tool runs with the app's own rights (and Windows refuses what needs more).
        bridge.IsConnected = false;
        var notConnected = await unElevatedRunner.RunAsync(sfc, ["/verifyonly"], CancellationToken.None);
        Assert.Equal("local", notConnected!.StdOut);
        Assert.Equal(3, local.Calls.Count);
    }

    [Theory]
    [InlineData(true)]   // the pipe broke
    [InlineData(false)]  // the Agent refused it (an older Agent, or arguments it doesn't allow)
    public async Task SystemCommandRunner_WhenTheAgentCallFails_DoesNotRunTheToolItself_AndSaysToTurnOnAdminRepairMode(bool throws)
    {
        var local = new RecordingLauncher((_, _) => new ProcessResult(0, "local", ""));
        var bridge = new FakeBridge(connected: true, (_, _) => throws ? throw new IOException("pipe is broken") : null);
        var runner = new SystemCommandRunner(launcher: local, elevatedBridge: bridge, isProcessElevated: () => false);

        var res = await runner.RunAsync(SystemCommandRunner.SystemTool("dism.exe"), ["/Online", "/Cleanup-Image", "/ScanHealth"], CancellationToken.None);

        Assert.Empty(local.Calls);
        Assert.NotNull(res);
        Assert.NotEqual(0, res!.ExitCode);
        var why = SystemCommandRunner.AgentFailure(res);
        Assert.NotNull(why);
        if (throws) Assert.Contains(ElevationService.AdminRepairHint, why);
        Assert.Null(SystemCommandRunner.AgentFailure(new ProcessResult(1, "", "")));
    }

    [Fact]
    public async Task SystemCommandRunner_AgentScript_GoesToTheAgentByName_AndFailsWithTheHintWhenThePipeBreaks()
    {
        var local = new RecordingLauncher((_, _) => new ProcessResult(0, "local", ""));
        var bridge = new FakeBridge(connected: true, (_, _) => null);
        var runner = new SystemCommandRunner(launcher: local, elevatedBridge: bridge, isProcessElevated: () => false);

        var ok = await runner.RunAgentScriptAsync(AgentScripts.Of(AgentScripts.CleanTemp), null, CancellationToken.None);
        Assert.Equal(0, ok!.ExitCode);
        Assert.Equal(AgentScripts.CleanTemp, Assert.Single(bridge.Scripts).Name);
        Assert.Empty(local.Calls);
        Assert.Empty(bridge.Calls);

        bridge.ScriptThrows = true;
        var broken = await runner.RunAgentScriptAsync(AgentScripts.Of(AgentScripts.CleanTemp), null, CancellationToken.None);
        Assert.Contains(ElevationService.AdminRepairHint, SystemCommandRunner.AgentFailure(broken));
        Assert.Empty(local.Calls);
    }

    [Fact]
    public async Task ElevationService_ManagesHelperConnectionState()
    {
        var sessionId = Guid.Parse("a8f5e2c1-4b3d-4e9f-8a1c-2d3e4f5a6b7c");
        var session = new SessionContext(
            SessionMode.Remote,
            new Uri("https://remoteblazorwebview.com:34544/"),
            sessionId,
            unattended: true,
            voice: true,
            group: "Acme-PC");

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
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
                    new RecordingLauncher());
                serverTask = activeServer.RunSingleSessionAsync(token);
                return await AdminPipeClient.ConnectAsync(req.PipeName, TimeSpan.FromSeconds(10), token);
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

        elevation.Dispose();
        if (serverTask is not null)
            await serverTask;
        activeServer?.Dispose();
    }

    [Fact]
    public void AdminHelperCli_ParsesValidFlagsAndRejectsInvalidArguments()
    {
        Assert.True(RemotePCDiagnostics.Agent.Core.AgentCommandLine.TryParseHelperArguments(
            ["--mode=helper", "--parent-pid=4321", "--pipe=rpd-admin-123", "--client-sid=S-1-5-18"],
            out var pid1,
            out var pipe1,
            out var sid1));
        Assert.Equal(4321, pid1);
        Assert.Equal("rpd-admin-123", pipe1);
        Assert.Equal("S-1-5-18", sid1);

        Assert.True(RemotePCDiagnostics.Agent.Core.AgentCommandLine.TryParseHelperArguments(
            ["--mode", "helper", "--parent-pid", "99", "--pipe", "rpd-admin-abc"],
            out var pid2,
            out var pipe2,
            out var sid2));
        Assert.Equal(99, pid2);
        Assert.Equal("rpd-admin-abc", pipe2);
        Assert.Null(sid2);

        Assert.False(RemotePCDiagnostics.Agent.Core.AgentCommandLine.TryParseHelperArguments(["--mode=service", "--parent-pid=99", "--pipe=ok"], out _, out _, out _));
        Assert.False(RemotePCDiagnostics.Agent.Core.AgentCommandLine.TryParseHelperArguments(["--mode=helper", "--parent-pid=0", "--pipe=ok"], out _, out _, out _));
        Assert.False(RemotePCDiagnostics.Agent.Core.AgentCommandLine.TryParseHelperArguments(["--mode=helper", "--parent-pid=99", @"--pipe=..\evil"], out _, out _, out _));
    }

    [Fact]
    public async Task RealAdminHelperProcess_AnswersOnlyItsHostAndExitsCleanlyWhenPipeCloses()
    {
        var adminExe = Path.Combine(AppContext.BaseDirectory, "RemotePCDiagnostics.Agent.exe");
        var adminDll = Path.Combine(AppContext.BaseDirectory, "RemotePCDiagnostics.Agent.dll");

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
#if DEBUG
            // Debug builds honour RPD_ADMIN_ALLOW_TEST_PARENT, so the helper accepts this test process as its client.
            await using (var client = await AdminPipeClient.ConnectAsync(pipeName, TimeSpan.FromSeconds(15), cts.Token))
            {
                Assert.True(client.IsConnected);
                Assert.Equal(helper.Id, client.HelperPid);

                var ping = await client.PingAsync(cts.Token);
                Assert.True(ping.Ok);
                Assert.Equal(helper.Id, ping.HelperPid);
            }
#else
            // Release builds ignore RPD_ADMIN_ALLOW_TEST_PARENT: only RemotePCDiagnostics.Host.exe next to the helper may connect,
            // so the helper must drop this test process before answering anything.
            await Assert.ThrowsAnyAsync<IOException>(async () =>
            {
                await using var client = await AdminPipeClient.ConnectAsync(pipeName, TimeSpan.FromSeconds(15), cts.Token);
            });
#endif

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

        // Both Host and Agent manifests must launch asInvoker (Microsoft Store Policy 10.2.9).
        foreach (var rel in new[]
        {
            Path.Combine("src", "RemotePCDiagnostics.Host", "app.manifest"),
            Path.Combine("src", "RemotePCDiagnostics.Agent", "app.manifest"),
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
        Assert.Contains("no custom uninstall action", scriptText);
    }

    // The agent service starts the app with --admin-pipe=<name> on its command line (AgentHubSession.StartHostProcess).
    // Missing it made every Admin "Start Diagnostics" start the helper with a UAC prompt instead of using the service's pipe.
    [Fact]
    public async Task AdminPipeServer_ListensAgainAfterTheClientDrops()
    {
        var pipeName = $"rpd-again-{Guid.NewGuid():N}";
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        await using var server = new AdminPipeServer(
            new AdminPipeServerOptions { PipeName = pipeName, ExpectedClientPid = Environment.ProcessId },
            new RecordingLauncher());
        var serverTask = server.RunUntilCancelledAsync(cts.Token);

        await using (var first = await AdminPipeClient.ConnectAsync(pipeName, TimeSpan.FromSeconds(10), cts.Token))
        {
            Assert.True((await first.PingAsync(cts.Token)).Ok);
        }

        await using var second = await AdminPipeClient.ConnectAsync(pipeName, TimeSpan.FromSeconds(10), cts.Token);
        Assert.True((await second.PingAsync(cts.Token)).Ok);

        cts.Cancel();
        await serverTask;
    }

    [Fact]
    public async Task ElevationService_ReconnectsWhenTheAdminPipeComesBack()
    {
        var pipeName = $"rpd-rejoin-{Guid.NewGuid():N}";
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(25));

        await using var firstServer = new AdminPipeServer(
            new AdminPipeServerOptions { PipeName = pipeName, ExpectedClientPid = Environment.ProcessId },
            new RecordingLauncher());
        var firstTask = firstServer.RunSingleSessionAsync(cts.Token);

        using var elevation = new ElevationService(new SessionContext(SessionMode.Local), initialPipeName: pipeName);
        Assert.True(await WaitUntilAsync(() => elevation.IsAdminHelperConnected, TimeSpan.FromSeconds(10)));

        await firstServer.DisposeAsync();
        try { await firstTask; } catch { }
        try { await elevation.ReadAgentEnrollmentAsync(cts.Token); } catch { }
        Assert.False(elevation.IsAdminHelperConnected);

        await using var secondServer = new AdminPipeServer(
            new AdminPipeServerOptions { PipeName = pipeName, ExpectedClientPid = Environment.ProcessId },
            new RecordingLauncher());
        var secondTask = secondServer.RunSingleSessionAsync(CancellationToken.None);
        Assert.True(await WaitUntilAsync(() => elevation.IsAdminHelperConnected, TimeSpan.FromSeconds(12)));

        cts.Cancel();
        secondServer.Dispose();
        try { await secondTask; } catch { }
    }

    [Fact]
    public async Task ElevationService_LeavesAdminRepairModeWhenTheAgentPipeComesBack()
    {
        // VH1, Nov 28: the app started while an update was replacing the Agent service, fell back to the UAC helper and never left it.
        var keptPipe = $"rpd-back-{Guid.NewGuid():N}";
        var previousEvery = ElevationService.ReturnToPipeEveryLoops;
        ElevationService.ReturnToPipeEveryLoops = 1;
        AdminPipeServer? helperServer = null;
        Task? helperTask = null;
        try
        {
            using var elevation = new ElevationService(
                new SessionContext(SessionMode.Local),
                isProcessElevated: () => false,
                initialPipeName: keptPipe,
                customConnector: async (req, token) =>
                {
                    helperServer = new AdminPipeServer(
                        new AdminPipeServerOptions { PipeName = req.PipeName, ExpectedClientPid = req.ParentPid },
                        new RecordingLauncher());
                    helperTask = helperServer.RunSingleSessionAsync(CancellationToken.None);
                    return await AdminPipeClient.ConnectAsync(req.PipeName, TimeSpan.FromSeconds(10), token);
                });

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            Assert.True((await elevation.EnableAdminModeAsync(cts.Token)).Success);
            Assert.StartsWith("rpd-admin-", elevation.ConnectedPipeName);

            await using var agentServer = new AdminPipeServer(
                new AdminPipeServerOptions { PipeName = keptPipe, ExpectedClientPid = Environment.ProcessId },
                new RecordingLauncher());
            var agentTask = agentServer.RunSingleSessionAsync(CancellationToken.None);

            Assert.True(await WaitUntilAsync(() => elevation.ConnectedPipeName == keptPipe, TimeSpan.FromSeconds(15)));
            Assert.True(elevation.HasAdminCapabilities);
            // The helper's session ends once nothing runs on it, which is what ends a real helper process.
            Assert.True(await WaitUntilAsync(() => helperTask!.IsCompleted, TimeSpan.FromSeconds(10)));

            elevation.Dispose();
            agentServer.Dispose();
            try { await agentTask; } catch { }
        }
        finally
        {
            ElevationService.ReturnToPipeEveryLoops = previousEvery;
            helperServer?.Dispose();
        }
    }

    [Fact]
    public void A_command_that_cannot_start_names_the_windows_error()
    {
        var message = AdminPipeServer.LaunchError(@"C:\Windows\System32\wevtutil.exe", new System.ComponentModel.Win32Exception(50));
        Assert.Contains("Windows error 50", message);
        Assert.Contains("wevtutil.exe", message);
        Assert.Equal("boom", AdminPipeServer.LaunchError("x.exe", new InvalidOperationException("boom")));
    }

    private static async Task<bool> WaitUntilAsync(Func<bool> ready, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            if (ready())
                return true;
            await Task.Delay(100);
        }
        return ready();
    }

    [Fact]
    public void Initial_pipe_name_comes_from_the_admin_pipe_argument()
    {
        string[] args = ["RemotePCDiagnostics.Host.exe", "-u=https://relay.example:34544", "--unattended", ElevationService.AdminPipeArgPrefix + "rpd-admin-0123abcd"];
        Assert.Equal("rpd-admin-0123abcd", ElevationService.TryResolveInitialPipeName(args));
    }

    [Fact]
    public void Initial_pipe_name_ignores_an_empty_admin_pipe_argument()
    {
        string[] args = ["RemotePCDiagnostics.Host.exe", ElevationService.AdminPipeArgPrefix, ElevationService.AdminPipeArgPrefix + " rpd-admin-second "];
        Assert.Equal("rpd-admin-second", ElevationService.TryResolveInitialPipeName(args));
    }

    [Fact]
    public void Initial_pipe_name_with_no_args_reads_this_process_command_line()
    {
        // The test runner has no --admin-pipe argument, so the answer is whatever the environment variable says.
        var expected = Environment.GetEnvironmentVariable(ElevationService.AdminPipeEnvVar)?.Trim();
        Assert.Equal(string.IsNullOrEmpty(expected) ? null : expected, ElevationService.TryResolveInitialPipeName());
        Assert.DoesNotContain(Environment.GetCommandLineArgs(), a => a.StartsWith(ElevationService.AdminPipeArgPrefix, StringComparison.OrdinalIgnoreCase));
    }
}
