using System.Runtime.InteropServices;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Bios;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;
using Xunit;

namespace RemotePCDiagnostics.Tests.Bios;

public sealed class WindowsUpdateBiosProviderTests
{
    private static readonly Guid SampleUpdateId = Guid.Parse("11112222-3333-4444-5555-666677778888");
    private static readonly Guid SecondUpdateId = Guid.Parse("aaaa1111-bbbb-2222-cccc-333344445555");

    private static readonly HashSet<string> ForbiddenShellBinaries = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell", "powershell.exe", "pwsh", "pwsh.exe",
        "cmd", "cmd.exe", "sh", "bash", "zsh",
    };

    private static readonly string[] ForbiddenScriptExtensions = [".ps1", ".bat", ".cmd", ".sh"];

    private static RecordingProcessLauncher CreateGuardedLauncher(
        Func<RecordedProcessCall, CancellationToken, Task<ProcessResult>>? inner = null) =>
        new((call, ct) =>
        {
            if (ForbiddenShellBinaries.Contains(call.BaseName))
                throw new InvalidOperationException($"Pure-C# violation: forbidden shell binary '{call.FileName}' invoked.");

            foreach (var arg in call.Arguments)
            {
                foreach (var ext in ForbiddenScriptExtensions)
                {
                    if (arg.EndsWith(ext, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidOperationException($"Pure-C# violation: forbidden script argument '{arg}' passed.");
                }
            }

            return inner is not null ? inner(call, ct) : Task.FromResult(new ProcessResult(0, "", ""));
        });

    private static async Task<(AdminPipeServer Server, Task ServerTask, AdminPipeClient Client)> StartPipeAsync(
        IProcessLauncher agentLauncher,
        IAgentBiosOperations? biosOps,
        CancellationToken ct,
        ILogger? log = null)
    {
        var pipeName = $"rpd-bios-wua-{Guid.NewGuid():N}";
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

    private static BiosInstallRequest CreateWuaInstallRequest(
        BiosSystemIdentity? system = null,
        string? packageId = null,
        string targetVersion = "1.24.0.0",
        bool suspendBitLocker = true,
        bool allowReboot = false)
    {
        var id = system ?? BiosIdentityFactory.GenericUefi();
        var target = BiosLatestInfo.UpdateAvailable(
            providerId: WindowsUpdateBiosProvider.ProviderVendorId,
            latestVersion: targetVersion,
            packageId: packageId,
            downloadUrl: null);

        return new BiosInstallRequest(
            System: id,
            Current: id.CurrentBios,
            Target: target,
            Approved: true,
            ApprovedBy: "operator@contoso.com",
            SuspendBitLocker: suspendBitLocker,
            AllowReboot: allowReboot,
            VerifyHash: true);
    }

    // -------------------------------------------------------------------------
    // Metadata, Capabilities & CanHandle
    // -------------------------------------------------------------------------

    [Fact]
    public void Metadata_And_Capabilities_Match_Contract()
    {
        var provider = new WindowsUpdateBiosProvider();

        Assert.Equal("windows-update", provider.VendorId);
        Assert.Equal("Windows Update", provider.DisplayName);
        Assert.Equal(10, provider.Priority);
        Assert.True(provider.Capabilities.CanCheckLatest);
        Assert.True(provider.Capabilities.CanInstall);
        Assert.True(provider.Capabilities.SupportsSilentInstall);
        Assert.True(provider.Capabilities.RequiresReboot);
        Assert.True(provider.Capabilities.RequiresElevation);
        Assert.True(provider.Capabilities.RequiresInternet);
    }

    [Fact]
    public void Single_Public_Constructor_Is_DiFriendly()
    {
        var ctors = typeof(WindowsUpdateBiosProvider).GetConstructors();
        Assert.Single(ctors);
        Assert.All(ctors[0].GetParameters(), p => Assert.True(p.HasDefaultValue));
    }

    [Fact]
    public void CanHandle_UefiOnly_RejectsLegacyUnknownAndNull()
    {
        var provider = new WindowsUpdateBiosProvider();

        Assert.True(provider.CanHandle(BiosIdentityFactory.GenericUefi()));
        Assert.True(provider.CanHandle(BiosIdentityFactory.Hp()));
        Assert.True(provider.CanHandle(BiosIdentityFactory.MicrosoftSurface()));

        Assert.False(provider.CanHandle(BiosIdentityFactory.Legacy()));
        Assert.False(provider.CanHandle(BiosIdentityFactory.Unknown()));
        Assert.False(provider.CanHandle(null!));
    }

    // -------------------------------------------------------------------------
    // GetLatestVersionAsync — Firmware Filtering, Version/Date Logic, SWO & Errors
    // -------------------------------------------------------------------------

    [Fact]
    public async Task GetLatestVersionAsync_NonUefi_ReturnsUnsupportedHardware_ZeroWuaCalls()
    {
        var called = false;
        var wua = new FakeWindowsUpdateClient
        {
            SearchHandler = _ =>
            {
                called = true;
                return Task.FromResult<IReadOnlyList<BiosWuaFirmwareUpdate>>([]);
            },
        };

        var provider = new WindowsUpdateBiosProvider(wuaClient: wua);
        var legacy = BiosIdentityFactory.Legacy();

        var latest = await provider.GetLatestVersionAsync(legacy, legacy.CurrentBios);

        Assert.Equal(BiosCheckStatus.UnsupportedHardware, latest.Status);
        Assert.False(called);
    }

    [Fact]
    public async Task GetLatestVersionAsync_FiltersOutNonBiosDrivers_IntelMe_Peripherals_OsUpdates_And_InvalidGuids()
    {
        var wua = new FakeWindowsUpdateClient
        {
            SearchHandler = _ => Task.FromResult<IReadOnlyList<BiosWuaFirmwareUpdate>>(
            [
                // Rejected: Intel ME / CSME
                new(Guid.NewGuid().ToString("D"), "Intel Corporation - Firmware - Intel ME Firmware 16.1.30", "16.1.30", new DateOnly(2025, 1, 1), 1000, BiosUpdateSeverity.Critical, true, "Firmware", "Intel ME"),
                new(Guid.NewGuid().ToString("D"), "Intel(R) Management Engine Interface - 2405.5.0.0", "2405.5.0.0", new DateOnly(2025, 1, 1), 1000, BiosUpdateSeverity.Critical, true, "System", "CSME"),
                // Rejected: Graphics / Audio / Network / Storage / Dock / Thunderbolt / OS
                new(Guid.NewGuid().ToString("D"), "NVIDIA - Display - 32.0.15.6094", "32.0.15.6094", new DateOnly(2025, 1, 1), 1000, BiosUpdateSeverity.Recommended, false, "Display"),
                new(Guid.NewGuid().ToString("D"), "Realtek Semiconductor Corp. - Media - Audio Firmware", "6.0.9500", new DateOnly(2025, 1, 1), 1000, BiosUpdateSeverity.Recommended, false, "Media"),
                new(Guid.NewGuid().ToString("D"), "Intel - Net - Wi-Fi 6E AX211", "23.40.0", new DateOnly(2025, 1, 1), 1000, BiosUpdateSeverity.Recommended, false, "Net"),
                new(Guid.NewGuid().ToString("D"), "Samsung NVMe SSD Firmware Update", "4.0.0", new DateOnly(2025, 1, 1), 1000, BiosUpdateSeverity.Recommended, true, "Firmware"),
                new(Guid.NewGuid().ToString("D"), "Dell Thunderbolt Dock Firmware", "1.0.9", new DateOnly(2025, 1, 1), 1000, BiosUpdateSeverity.Recommended, false, "Firmware"),
                new(Guid.NewGuid().ToString("D"), "2024-06 Cumulative Update for Windows 11", "22631.3737", new DateOnly(2025, 1, 1), 1000, BiosUpdateSeverity.Critical, true),
                // Rejected: DriverClass="System" alone without Firmware/UEFI/BIOS keyword
                new(Guid.NewGuid().ToString("D"), "Intel - System - 10.1.45.4", "10.1.45.4", new DateOnly(2025, 1, 1), 1000, BiosUpdateSeverity.Recommended, false, "System", "PCI Express Root Port"),
                // Rejected: Invalid / braced / empty GUIDs
                new($"{{{Guid.NewGuid():D}}}", "Contoso System Firmware - 9.9.9", "9.9.9", new DateOnly(2025, 1, 1), 1000, BiosUpdateSeverity.Critical, true, "Firmware"),
                new(Guid.Empty.ToString("D"), "Contoso System Firmware - 9.9.8", "9.9.8", new DateOnly(2025, 1, 1), 1000, BiosUpdateSeverity.Critical, true, "Firmware"),
                new("not-a-guid", "Contoso System Firmware - 9.9.7", "9.9.7", new DateOnly(2025, 1, 1), 1000, BiosUpdateSeverity.Critical, true, "Firmware"),
                // Accepted: Genuine UEFI System Firmware update!
                new(SampleUpdateId.ToString("D").ToUpperInvariant(), "Contoso Corporation - Firmware - 1.24.0.0", null, new DateOnly(2024, 5, 10), 12_500_000, BiosUpdateSeverity.Critical, true, "Firmware", "System Firmware", ["Drivers"]),
            ]),
        };

        var log = new CapturedLog();
        var provider = new WindowsUpdateBiosProvider(wuaClient: wua, log: log.Logger);
        var sys = BiosIdentityFactory.GenericUefi(); // CurrentBios = 1.0.0

        var latest = await provider.GetLatestVersionAsync(sys, sys.CurrentBios);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal("windows-update", latest.ProviderId);
        Assert.Equal("1.24.0.0", latest.LatestVersion);
        Assert.Equal(SampleUpdateId.ToString("D"), latest.PackageId); // Canonical lowercase "D"
        Assert.Null(latest.DownloadUrl);
        Assert.Equal(BiosUpdateSeverity.Critical, latest.Severity);
        Assert.Equal(12_500_000, latest.SizeBytes);
        Assert.True(latest.RequiresReboot);
        log.AssertDoesNotContainSecret();
    }

    [Fact]
    public async Task GetLatestVersionAsync_NoPendingFirmware_And_Downgrade_ReturnUpToDate()
    {
        var sys = BiosIdentityFactory.GenericUefi() with
        {
            CurrentBios = new BiosCurrentInfo("AMI", "2.0.0", new DateOnly(2024, 6, 1), "20240601", "3.2", BiosFirmwareMode.Uefi),
        };

        // 1. Empty WUA result -> UpToDate
        var emptyWua = new FakeWindowsUpdateClient { SearchHandler = _ => Task.FromResult<IReadOnlyList<BiosWuaFirmwareUpdate>>([]) };
        var rEmpty = await new WindowsUpdateBiosProvider(emptyWua).GetLatestVersionAsync(sys, sys.CurrentBios);
        Assert.Equal(BiosCheckStatus.UpToDate, rEmpty.Status);

        // 2. Older / equal version -> UpToDate (downgrade protection)
        var olderWua = new FakeWindowsUpdateClient
        {
            SearchHandler = _ => Task.FromResult<IReadOnlyList<BiosWuaFirmwareUpdate>>(
            [
                new(SampleUpdateId.ToString("D"), "Contoso System Firmware - 1.9.0", "1.9.0", new DateOnly(2024, 1, 1), 1000, BiosUpdateSeverity.Recommended, true, "Firmware"),
            ]),
        };
        var rOlder = await new WindowsUpdateBiosProvider(olderWua).GetLatestVersionAsync(sys, sys.CurrentBios);
        Assert.Equal(BiosCheckStatus.UpToDate, rOlder.Status);
        Assert.Null(rOlder.PackageId);
    }

    [Fact]
    public async Task GetLatestVersionAsync_VersionlessPendingCapsule_ReturnsUpdateAvailable()
    {
        var wua = new FakeWindowsUpdateClient
        {
            SearchHandler = _ => Task.FromResult<IReadOnlyList<BiosWuaFirmwareUpdate>>(
            [
                new(SampleUpdateId.ToString("D"), "Contoso System Firmware Capsule", null, null, 8_000_000, BiosUpdateSeverity.Unknown, true, "Firmware"),
            ]),
        };

        var sys = BiosIdentityFactory.GenericUefi();
        var latest = await new WindowsUpdateBiosProvider(wua).GetLatestVersionAsync(sys, sys.CurrentBios);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal(SampleUpdateId.ToString("D"), latest.PackageId);
        Assert.Equal(BiosUpdateSeverity.Recommended, latest.Severity);
    }

    [Fact]
    public async Task GetLatestVersionAsync_Exceptions_And_PlatformNotSupported_MappedCleanly()
    {
        var sys = BiosIdentityFactory.GenericUefi();

        // PlatformNotSupportedException -> ProviderUnavailable (E2E-T2-VER-07)
        var pnsWua = new FakeWindowsUpdateClient
        {
            SearchHandler = _ => Task.FromException<IReadOnlyList<BiosWuaFirmwareUpdate>>(
                new PlatformNotSupportedException("Windows Update Agent is only available on Windows.")),
        };
        Assert.Equal(BiosCheckStatus.ProviderUnavailable,
            (await new WindowsUpdateBiosProvider(pnsWua).GetLatestVersionAsync(sys, sys.CurrentBios)).Status);

        // Offline WUA COM HRESULT (0x8024402C) -> Offline
        var offlineWua = new FakeWindowsUpdateClient
        {
            SearchHandler = _ => Task.FromException<IReadOnlyList<BiosWuaFirmwareUpdate>>(
                new COMException("Name not resolved", unchecked((int)0x8024402C))),
        };
        Assert.Equal(BiosCheckStatus.Offline,
            (await new WindowsUpdateBiosProvider(offlineWua).GetLatestVersionAsync(sys, sys.CurrentBios)).Status);

        // Generic COM error -> ProviderUnavailable
        var comWua = new FakeWindowsUpdateClient
        {
            SearchHandler = _ => Task.FromException<IReadOnlyList<BiosWuaFirmwareUpdate>>(
                new COMException("Service disabled", unchecked((int)0x8024001E))),
        };
        Assert.Equal(BiosCheckStatus.ProviderUnavailable,
            (await new WindowsUpdateBiosProvider(comWua).GetLatestVersionAsync(sys, sys.CurrentBios)).Status);

        // Timeout -> Offline
        var timeoutWua = new FakeWindowsUpdateClient
        {
            SearchHandler = _ => Task.FromException<IReadOnlyList<BiosWuaFirmwareUpdate>>(new TimeoutException("timed out")),
        };
        Assert.Equal(BiosCheckStatus.Offline,
            (await new WindowsUpdateBiosProvider(timeoutWua).GetLatestVersionAsync(sys, sys.CurrentBios)).Status);

        // Caller cancellation -> throws OperationCanceledException
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            new WindowsUpdateBiosProvider(pnsWua).GetLatestVersionAsync(sys, sys.CurrentBios, cts.Token));
    }

    [Fact]
    public async Task DefaultComClient_OnNonWindows_ReturnsProviderUnavailable_And_InstallFailed_WithoutThrowing()
    {
        if (OperatingSystem.IsWindows())
            return;

        // Default constructor uses internal WindowsUpdateAgentBiosClient (wuaClient: null).
        var provider = new WindowsUpdateBiosProvider(isProcessElevated: () => true);
        var sys = BiosIdentityFactory.GenericUefi();

        var latest = await provider.GetLatestVersionAsync(sys, sys.CurrentBios);
        Assert.Equal(BiosCheckStatus.ProviderUnavailable, latest.Status);

        var installRes = await provider.InstallAsync(
            CreateWuaInstallRequest(sys, packageId: SampleUpdateId.ToString("D"), suspendBitLocker: false));
        Assert.False(installRes.Succeeded);
        Assert.Equal(BiosInstallStatus.Failed, installRes.Status);
    }

    [Fact]
    public async Task GetLatestVersionAsync_SwoComparator_IsPermutationInvariant()
    {
        var items = new BiosWuaFirmwareUpdate[]
        {
            new(SampleUpdateId.ToString("D"), "Contoso System Firmware - 1.10", "1.10", new DateOnly(2024, 2, 1), 100, BiosUpdateSeverity.Recommended, true, "Firmware"),
            new(SecondUpdateId.ToString("D"), "Contoso System Firmware - 1.24", "1.24", new DateOnly(2024, 5, 1), 100, BiosUpdateSeverity.Critical, true, "Firmware"),
            new("11111111-1111-1111-1111-111111111111", "Contoso System Firmware - R#9-2", "R#9-2", new DateOnly(2024, 3, 1), 100, BiosUpdateSeverity.Optional, true, "Firmware"),
            new("22222222-2222-2222-2222-222222222222", "Contoso System Firmware - 0.9", "0.9", new DateOnly(2024, 6, 1), 100, BiosUpdateSeverity.Critical, true, "Firmware"),
        };

        var sys = BiosIdentityFactory.GenericUefi(); // CurrentBios = 1.0.0
        var rng = new Random(554433);

        for (var trial = 0; trial < 20; trial++)
        {
            var shuffled = trial == 0 ? items : items.OrderBy(_ => rng.Next()).ToArray();
            var wua = new FakeWindowsUpdateClient
            {
                SearchHandler = _ => Task.FromResult<IReadOnlyList<BiosWuaFirmwareUpdate>>(shuffled),
            };

            var latest = await new WindowsUpdateBiosProvider(wua).GetLatestVersionAsync(sys, sys.CurrentBios);

            Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
            Assert.Equal("1.24", latest.LatestVersion);
            Assert.Equal(SecondUpdateId.ToString("D"), latest.PackageId);
        }
    }

    // -------------------------------------------------------------------------
    // InstallAsync — Strict GUID, Elevated Local, BitLocker, Live Agent Pipe
    // -------------------------------------------------------------------------

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("00000000-0000-0000-0000-000000000000")]
    [InlineData("{11112222-3333-4444-5555-666677778888}")]
    [InlineData(" 11112222-3333-4444-5555-666677778888 ")]
    [InlineData("11112222-3333-4444-5555-666677778888\n")]
    [InlineData("11112222-3333-4444-5555-666677778888;calc.exe")]
    [InlineData("../evil")]
    public async Task InstallAsync_InvalidPackageId_FailsImmediately_ZeroBitLockerAndZeroWuaCalls(string? badPackageId)
    {
        var wua = new FakeWindowsUpdateClient();
        var launcher = CreateGuardedLauncher();
        var commands = RecordingProcessLauncher.CreateCommandRunner(launcher, isProcessElevated: true);
        var provider = new WindowsUpdateBiosProvider(wuaClient: wua, commands: commands, isProcessElevated: () => true);

        var res = await provider.InstallAsync(CreateWuaInstallRequest(packageId: badPackageId, suspendBitLocker: true));

        Assert.False(res.Succeeded);
        Assert.Equal(BiosInstallStatus.Failed, res.Status);
        Assert.Empty(launcher.Calls);
        Assert.Empty(wua.InstalledUpdateIds);
    }

    [Theory]
    [InlineData(true, BiosInstallStatus.StagedForReboot)]
    [InlineData(false, BiosInstallStatus.Completed)]
    public async Task InstallAsync_Elevated_ExecutesLocalWuaClient_And_SuspendsBitLocker(
        bool rebootRequired,
        BiosInstallStatus expectedStatus)
    {
        var wua = new FakeWindowsUpdateClient
        {
            InstallHandler = (id, _) => Task.FromResult(new BiosWuaInstallOutcome(
                Succeeded: true,
                ResultCode: AgentWindowsUpdate.SucceededCode,
                RebootRequired: rebootRequired,
                Message: $"Installed {id:D}")),
        };
        var launcher = CreateGuardedLauncher();
        var log = new CapturedLog();
        var commands = RecordingProcessLauncher.CreateCommandRunner(launcher, log: log.Logger, isProcessElevated: true);
        var progress = new SyncProgress<BiosInstallProgress>();

        var provider = new WindowsUpdateBiosProvider(
            wuaClient: wua,
            commands: commands,
            elevatedBridge: null,
            isProcessElevated: () => true,
            log: log.Logger);

        var res = await provider.InstallAsync(
            CreateWuaInstallRequest(packageId: SampleUpdateId.ToString("D"), suspendBitLocker: true),
            progress);

        Assert.True(res.Succeeded);
        Assert.Equal(expectedStatus, res.Status);
        Assert.Equal(rebootRequired, res.RequiresReboot);
        Assert.True(res.BitLockerSuspended);
        Assert.Equal([SampleUpdateId], wua.InstalledUpdateIds);
        Assert.Single(launcher.Calls);
        Assert.Equal("manage-bde.exe", launcher.Calls[0].BaseName);

        Assert.Contains(progress.Reports, r => r.Stage == BiosInstallStage.SuspendingBitLocker);
        Assert.Contains(progress.Reports, r => r.Stage == BiosInstallStage.Installing);
        Assert.Contains(progress.Reports, r => r.Stage == (rebootRequired ? BiosInstallStage.RebootRequired : BiosInstallStage.Completed) && r.Percent == 100);
        log.AssertDoesNotContainSecret();
    }

    [Theory]
    [InlineData(true, BiosInstallStatus.StagedForReboot)]
    [InlineData(false, BiosInstallStatus.Completed)]
    public async Task InstallAsync_UnElevated_LiveNamedPipe_RoutesBitLockerAndWuaThroughAgent(
        bool rebootRequired,
        BiosInstallStatus expectedStatus)
    {
        var fakeWuaApi = new FakeWuaApi
        {
            FoundUpdates = [new FakeWuaUpdate("Contoso System Firmware - 1.24.0.0", eulaAccepted: false, isDownloaded: false)],
            InstallOutcome = new UpdateInstallOutcome(AgentWindowsUpdate.SucceededCode, 0, rebootRequired),
        };

        var localWua = new FakeWindowsUpdateClient();
        var localLauncher = CreateGuardedLauncher();
        var agentLauncher = CreateGuardedLauncher();

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var ops = new AgentBiosOperations(agentLauncher, wuaApiFactory: () => fakeWuaApi);

        var (server, serverTask, client) = await StartPipeAsync(agentLauncher, ops, cts.Token);
        using (server)
        {
            await using (client)
            {
                var log = new CapturedLog();
                var provider = new WindowsUpdateBiosProvider(
                    wuaClient: localWua,
                    commands: RecordingProcessLauncher.CreateCommandRunner(localLauncher, log: log.Logger, isProcessElevated: false),
                    elevatedBridge: client,
                    isProcessElevated: () => false,
                    log: log.Logger);

                var res = await provider.InstallAsync(
                    CreateWuaInstallRequest(packageId: SampleUpdateId.ToString("D"), suspendBitLocker: true),
                    ct: cts.Token);

                Assert.True(res.Succeeded);
                Assert.Equal(expectedStatus, res.Status);
                Assert.Equal(rebootRequired, res.RequiresReboot);
                Assert.True(res.BitLockerSuspended);

                // Zero local WUA or local process calls!
                Assert.Empty(localWua.InstalledUpdateIds);
                Assert.Empty(localLauncher.Calls);

                // Agent ran manage-bde.exe and searched WUA for exact UpdateID.
                Assert.Single(agentLauncher.Calls);
                Assert.Equal("manage-bde.exe", agentLauncher.Calls[0].BaseName);
                Assert.Contains($"IsInstalled=0 and UpdateID='{SampleUpdateId:D}'", fakeWuaApi.SearchCriteria);
                log.AssertDoesNotContainSecret();
            }

            await serverTask;
        }
    }

    [Fact]
    public async Task InstallAsync_UnElevated_LiveNamedPipe_WuaFailureAndComException_PreserveBitLockerSuspended()
    {
        var agentLauncher = CreateGuardedLauncher();
        var localWua = new FakeWindowsUpdateClient();

        // Case 1: WUA update not found after BitLocker was suspended -> BitLockerSuspended MUST stay true!
        {
            var notFoundApi = new FakeWuaApi { FoundUpdates = [] };
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            var ops = new AgentBiosOperations(agentLauncher, wuaApiFactory: () => notFoundApi);
            var (server, serverTask, client) = await StartPipeAsync(agentLauncher, ops, cts.Token);
            using (server)
            {
                await using (client)
                {
                    var provider = new WindowsUpdateBiosProvider(
                        wuaClient: localWua,
                        elevatedBridge: client,
                        isProcessElevated: () => false);

                    var res = await provider.InstallAsync(
                        CreateWuaInstallRequest(packageId: SampleUpdateId.ToString("D"), suspendBitLocker: true),
                        ct: cts.Token);

                    Assert.False(res.Succeeded);
                    Assert.Equal(BiosInstallStatus.Failed, res.Status);
                    Assert.True(res.BitLockerSuspended);
                    Assert.Empty(localWua.InstalledUpdateIds);
                }

                await serverTask;
            }
        }

        // Case 2: WUA COMException (0x8024A000) -> Failed with hex HRESULT and BitLockerSuspended preserved!
        {
            var comFailApi = new FakeWuaApi
            {
                SearchException = new COMException($"WUA error on {BiosIdentityFactory.SentinelSerialNumber}", unchecked((int)0x8024A000)),
            };
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            var ops = new AgentBiosOperations(agentLauncher, wuaApiFactory: () => comFailApi);
            var (server, serverTask, client) = await StartPipeAsync(agentLauncher, ops, cts.Token);
            using (server)
            {
                await using (client)
                {
                    var log = new CapturedLog();
                    var provider = new WindowsUpdateBiosProvider(
                        wuaClient: localWua,
                        elevatedBridge: client,
                        isProcessElevated: () => false,
                        log: log.Logger);

                    var res = await provider.InstallAsync(
                        CreateWuaInstallRequest(packageId: SampleUpdateId.ToString("D"), suspendBitLocker: true),
                        ct: cts.Token);

                    Assert.False(res.Succeeded);
                    Assert.Equal(BiosInstallStatus.Failed, res.Status);
                    Assert.True(res.BitLockerSuspended);
                    Assert.Contains("0x8024A000", res.Message, StringComparison.OrdinalIgnoreCase);
                    Assert.DoesNotContain(BiosIdentityFactory.SentinelSerialNumber, res.Message, StringComparison.OrdinalIgnoreCase);
                    log.AssertDoesNotContainSecret();
                }

                await serverTask;
            }
        }
    }

    [Fact]
    public async Task InstallAsync_UnElevated_LegacyAgent_And_DisconnectedBridge_FailClosed_NeverFallBackLocally()
    {
        var localWua = new FakeWindowsUpdateClient();
        var localLauncher = CreateGuardedLauncher();
        var commands = RecordingProcessLauncher.CreateCommandRunner(localLauncher, isProcessElevated: false);

        // 1. Disconnected / null bridge (both SuspendBitLocker = true and false)
        var noBridgeProvider = new WindowsUpdateBiosProvider(
            wuaClient: localWua,
            commands: commands,
            elevatedBridge: null,
            isProcessElevated: () => false);

        foreach (var suspendBl in new[] { true, false })
        {
            var r = await noBridgeProvider.InstallAsync(
                CreateWuaInstallRequest(packageId: SampleUpdateId.ToString("D"), suspendBitLocker: suspendBl));
            Assert.False(r.Succeeded);
            Assert.Equal(SystemCommandRunner.AgentFailedExitCode, r.ExitCode);
            Assert.Contains(ElevationService.AdminRepairHint, r.Message);
        }

        Assert.Empty(localLauncher.Calls);
        Assert.Empty(localWua.InstalledUpdateIds);

        // 2. Legacy Agent (biosOperations: null) -> throws AdminRequiredException -> fails closed, ZERO local WUA fallback!
        var agentLauncher = CreateGuardedLauncher();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var (server, serverTask, client) = await StartPipeAsync(agentLauncher, biosOps: null, cts.Token);
        using (server)
        {
            await using (client)
            {
                var legacyProvider = new WindowsUpdateBiosProvider(
                    wuaClient: localWua,
                    commands: commands,
                    elevatedBridge: client,
                    isProcessElevated: () => false);

                var res = await legacyProvider.InstallAsync(
                    CreateWuaInstallRequest(packageId: SampleUpdateId.ToString("D"), suspendBitLocker: false),
                    ct: cts.Token);

                Assert.False(res.Succeeded);
                Assert.Equal(SystemCommandRunner.AgentFailedExitCode, res.ExitCode);
                Assert.Empty(localWua.InstalledUpdateIds);
                Assert.Empty(localLauncher.Calls);
            }

            await serverTask;
        }
    }

    [Fact]
    public async Task GetCurrentAndLatest_RedactsSerialNumber_And_HandlesIncomparableVersionDateFallback()
    {
        var serial = BiosIdentityFactory.SentinelSerialNumber;
        var sys = BiosIdentityFactory.GenericUefi(serialNumber: serial) with
        {
            CurrentBios = new BiosCurrentInfo(
                "AMI",
                $"A10-{serial}",
                new DateOnly(2023, 6, 1),
                "20230601",
                $"Fam-{serial}",
                BiosFirmwareMode.Uefi,
                Metadata: new Dictionary<string, string> { ["k"] = $"v-{serial}" }),
        };

        var cur = await new WindowsUpdateBiosProvider().GetCurrentVersionAsync(sys);
        Assert.DoesNotContain(serial, cur.Version, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(serial, cur.Family, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(serial, cur.Metadata?["k"] ?? "", StringComparison.OrdinalIgnoreCase);

        // Incomparable version ("A10" vs "1.24.0") -> falls back to ReleaseDate comparison!
        var wua = new FakeWindowsUpdateClient
        {
            SearchHandler = _ => Task.FromResult<IReadOnlyList<BiosWuaFirmwareUpdate>>(
            [
                new(SampleUpdateId.ToString("D"), $"Contoso System Firmware - 1.24.0 ({serial})", "1.24.0", new DateOnly(2024, 5, 1), 1000, BiosUpdateSeverity.Recommended, true, "Firmware"),
            ]),
        };

        var log = new CapturedLog();
        var cleanSys = sys with { CurrentBios = sys.CurrentBios with { Version = "A10" } };
        var latest = await new WindowsUpdateBiosProvider(wua, log: log.Logger).GetLatestVersionAsync(cleanSys, cleanSys.CurrentBios);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.DoesNotContain(serial, latest.ReleaseSummary ?? "", StringComparison.OrdinalIgnoreCase);
        log.AssertDoesNotContainSecret();

        // Older date with incomparable version -> UpToDate
        var olderWua = new FakeWindowsUpdateClient
        {
            SearchHandler = _ => Task.FromResult<IReadOnlyList<BiosWuaFirmwareUpdate>>(
            [
                new(SampleUpdateId.ToString("D"), "Contoso System Firmware - 1.24.0", "1.24.0", new DateOnly(2022, 1, 1), 1000, BiosUpdateSeverity.Recommended, true, "Firmware"),
            ]),
        };
        var upToDate = await new WindowsUpdateBiosProvider(olderWua).GetLatestVersionAsync(cleanSys, cleanSys.CurrentBios);
        Assert.Equal(BiosCheckStatus.UpToDate, upToDate.Status);
    }

    [Fact]
    public async Task InstallAsync_Elevated_NonEncryptedDriveProceeds_And_LocalExceptionPreservesBitLockerSuspended()
    {
        // 1. Non-encrypted drive (manage-bde exit 1) proceeds cleanly with BitLockerSuspended = false
        var wuaOk = new FakeWindowsUpdateClient();
        var launcherUnenc = CreateGuardedLauncher((_, _) => Task.FromResult(new ProcessResult(1, "", "Not encrypted.")));
        var p1 = new WindowsUpdateBiosProvider(
            wuaClient: wuaOk,
            commands: RecordingProcessLauncher.CreateCommandRunner(launcherUnenc, isProcessElevated: true),
            isProcessElevated: () => true);

        var r1 = await p1.InstallAsync(CreateWuaInstallRequest(packageId: SampleUpdateId.ToString("D"), suspendBitLocker: true) with { BitLockerKnownOff = true });
        Assert.True(r1.Succeeded);
        Assert.False(r1.BitLockerSuspended);

        // 2. Local WUA exception after BitLocker succeeded -> BitLockerSuspended MUST stay true & SerialNumber redacted!
        var wuaThrow = new FakeWindowsUpdateClient
        {
            InstallHandler = (_, _) => Task.FromException<BiosWuaInstallOutcome>(
                new COMException($"Boom on {BiosIdentityFactory.SentinelSerialNumber}", unchecked((int)0x80240022))),
        };
        var launcherEnc = CreateGuardedLauncher();
        var log = new CapturedLog();
        var p2 = new WindowsUpdateBiosProvider(
            wuaClient: wuaThrow,
            commands: RecordingProcessLauncher.CreateCommandRunner(launcherEnc, log: log.Logger, isProcessElevated: true),
            isProcessElevated: () => true,
            log: log.Logger);

        var r2 = await p2.InstallAsync(CreateWuaInstallRequest(packageId: SampleUpdateId.ToString("D"), suspendBitLocker: true));
        Assert.False(r2.Succeeded);
        Assert.Equal(BiosInstallStatus.Failed, r2.Status);
        Assert.True(r2.BitLockerSuspended);
        Assert.DoesNotContain(BiosIdentityFactory.SentinelSerialNumber, r2.Message, StringComparison.OrdinalIgnoreCase);
        log.AssertDoesNotContainSecret();
    }

    // -------------------------------------------------------------------------
    // Lightweight Fake IWindowsUpdateApi for live AdminPipeServer round-trips
    // -------------------------------------------------------------------------

    private sealed class FakeWuaUpdate(string title, bool eulaAccepted, bool isDownloaded) : IFoundUpdate
    {
        public string Title { get; } = title;
        public bool EulaAccepted { get; private set; } = eulaAccepted;
        public bool IsDownloaded { get; set; } = isDownloaded;
        public void AcceptEula() => EulaAccepted = true;
    }

    private sealed class FakeWuaApi : IWindowsUpdateApi
    {
        public List<string> SearchCriteria { get; } = [];
        public IReadOnlyList<FakeWuaUpdate> FoundUpdates { get; set; } = [];
        public Exception? SearchException { get; set; }
        public int DownloadResult { get; set; } = AgentWindowsUpdate.SucceededCode;
        public UpdateInstallOutcome InstallOutcome { get; set; } = new(AgentWindowsUpdate.SucceededCode, 0, true);

        public IReadOnlyList<IFoundUpdate> Search(string criteria)
        {
            SearchCriteria.Add(criteria);
            if (SearchException is not null)
                throw SearchException;
            return FoundUpdates;
        }

        public int Download(IReadOnlyList<IFoundUpdate> updates)
        {
            foreach (var u in updates.OfType<FakeWuaUpdate>())
                u.IsDownloaded = DownloadResult is AgentWindowsUpdate.SucceededCode or AgentWindowsUpdate.SucceededWithErrorsCode;
            return DownloadResult;
        }

        public UpdateInstallOutcome Install(IReadOnlyList<IFoundUpdate> updates) => InstallOutcome;

        public void StartInteractiveScan() { }
    }

    // -------------------------------------------------------------------------
    // M4 Iteration 2 Regression Tests
    // -------------------------------------------------------------------------

    [Fact]
    public async Task GetLatestVersionAsync_DuplicateGuids_IsCompletelyOrderIndependentAndDeterministic()
    {
        var sys = BiosIdentityFactory.GenericUefi() with
        {
            CurrentBios = new BiosCurrentInfo("AMI", "1.10.0", new DateOnly(2024, 6, 1), "20240601", "3.4", BiosFirmwareMode.Uefi),
        };

        var dupGuidLower = SampleUpdateId.ToString("D");
        var dupGuidUpper = dupGuidLower.ToUpperInvariant();

        var olderEntry = new BiosWuaFirmwareUpdate(
            UpdateId: dupGuidLower,
            Title: "Contoso System Firmware - 1.05.0",
            Version: "1.05.0",
            ReleaseDate: new DateOnly(2023, 1, 1),
            SizeBytes: 5_000_000,
            Severity: BiosUpdateSeverity.Optional,
            RebootRequired: true,
            DriverClass: "Firmware",
            DriverModel: "System Firmware");

        var newerEntry = new BiosWuaFirmwareUpdate(
            UpdateId: dupGuidUpper,
            Title: "Contoso System Firmware - 2.00.0",
            Version: "2.00.0",
            ReleaseDate: new DateOnly(2025, 5, 1),
            SizeBytes: 8_000_000,
            Severity: BiosUpdateSeverity.Critical,
            RebootRequired: true,
            DriverClass: "Firmware",
            DriverModel: "System Firmware");

        var wuaAB = new FakeWindowsUpdateClient
        {
            SearchHandler = _ => Task.FromResult<IReadOnlyList<BiosWuaFirmwareUpdate>>([olderEntry, newerEntry]),
        };
        var wuaBA = new FakeWindowsUpdateClient
        {
            SearchHandler = _ => Task.FromResult<IReadOnlyList<BiosWuaFirmwareUpdate>>([newerEntry, olderEntry]),
        };

        var resAB = await new WindowsUpdateBiosProvider(wuaClient: wuaAB).GetLatestVersionAsync(sys, sys.CurrentBios);
        var resBA = await new WindowsUpdateBiosProvider(wuaClient: wuaBA).GetLatestVersionAsync(sys, sys.CurrentBios);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, resAB.Status);
        Assert.Equal("2.00.0", resAB.LatestVersion);
        Assert.Equal(dupGuidLower, resAB.PackageId);
        Assert.Equal(resAB.Status, resBA.Status);
        Assert.Equal(resAB.LatestVersion, resBA.LatestVersion);
        Assert.Equal(resAB.PackageId, resBA.PackageId);
        Assert.Equal(resAB.Severity, resBA.Severity);
    }

    [Theory]
    [InlineData("BIOS Setup Utility - 2.5.0", null)]
    [InlineData("BIOS Setup Utility - 2.5.0", "System")]
    [InlineData("USB Hub Firmware Update - 2.0.0", "System")]
    [InlineData("HP BIOS Configuration Utility - 4.0.0", "System")]
    [InlineData("HP PC Hardware Diagnostics UEFI Tool - 2.0.0", null)]
    [InlineData("Lenovo Firmware Update Utility - 3.0.0", null)]
    [InlineData("Intel(R) MEI Firmware - 16.0.0", "Firmware")]
    public async Task GetLatestVersionAsync_RejectsUtilitiesMeiAndUsbHubFirmware(string title, string? driverClass)
    {
        var wua = new FakeWindowsUpdateClient
        {
            SearchHandler = _ => Task.FromResult<IReadOnlyList<BiosWuaFirmwareUpdate>>(
            [
                new(SampleUpdateId.ToString("D"), title, "9.9.9", new DateOnly(2025, 1, 1), 1_000_000, BiosUpdateSeverity.Recommended, true, driverClass),
            ]),
        };

        var sys = BiosIdentityFactory.GenericUefi();
        var latest = await new WindowsUpdateBiosProvider(wuaClient: wua).GetLatestVersionAsync(sys, sys.CurrentBios);

        Assert.Equal(BiosCheckStatus.UpToDate, latest.Status);
        Assert.Null(latest.PackageId);
    }

    [Theory]
    [InlineData("Dell Inc. - Firmware - 1.24.0", "Firmware")]
    [InlineData("Microsoft Surface UEFI - 18.101.143", "Firmware")]
    [InlineData("Lenovo System Firmware - 1.42.0", "Firmware")]
    [InlineData("HP Inc. - System Firmware - 01.18.00", "Firmware")]
    public async Task GetLatestVersionAsync_AcceptsGenuineSystemFirmwareCapsules(string title, string driverClass)
    {
        var wua = new FakeWindowsUpdateClient
        {
            SearchHandler = _ => Task.FromResult<IReadOnlyList<BiosWuaFirmwareUpdate>>(
            [
                new(SampleUpdateId.ToString("D"), title, null, new DateOnly(2025, 1, 1), 10_000_000, BiosUpdateSeverity.Recommended, true, driverClass, "System Firmware"),
            ]),
        };

        var sys = BiosIdentityFactory.GenericUefi();
        var latest = await new WindowsUpdateBiosProvider(wuaClient: wua).GetLatestVersionAsync(sys, sys.CurrentBios);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal(SampleUpdateId.ToString("D"), latest.PackageId);
    }

    [Fact]
    public async Task SerialNumberRedaction_CoversGetCurrentAndEncodedBitLockerLogsAndProgress()
    {
        const string spaceSlashSerial = "SN WUA/999";
        var encodedSerial = Uri.EscapeDataString(spaceSlashSerial); // SN%20WUA%2F999

        var sys = BiosIdentityFactory.GenericUefi(serialNumber: spaceSlashSerial) with
        {
            CurrentBios = new BiosCurrentInfo(
                Vendor: $"AMI {spaceSlashSerial}",
                Version: $"1.0.0-{spaceSlashSerial}",
                ReleaseDate: new DateOnly(2023, 1, 1),
                ReleaseDateRaw: $"20230101-{spaceSlashSerial}",
                SmbiosRevision: $"3.2-{spaceSlashSerial}",
                FirmwareMode: BiosFirmwareMode.Uefi,
                Family: $"BIOS-{spaceSlashSerial}"),
        };

        // 1. GetCurrentVersionAsync redacts Vendor, ReleaseDateRaw, SmbiosRevision, Version, Family.
        var cur = await new WindowsUpdateBiosProvider().GetCurrentVersionAsync(sys);
        Assert.Equal("windows-update", cur.ProviderId);
        Assert.DoesNotContain(spaceSlashSerial, cur.Vendor, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(spaceSlashSerial, cur.Version, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(spaceSlashSerial, cur.ReleaseDateRaw, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(spaceSlashSerial, cur.SmbiosRevision, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(spaceSlashSerial, cur.Family, StringComparison.OrdinalIgnoreCase);

        // 2. InstallAsync redacts both raw and URL-encoded SerialNumber from BitLocker refusal logs, progress, and result over live pipe.
        var log = new CapturedLog();
        var progress = new SyncProgress<BiosInstallProgress>();

        var agentLauncher = CreateGuardedLauncher();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var refusingOps = new RefusingBitLockerBiosOps($"Refused for {encodedSerial} and {spaceSlashSerial}");
        var (server, serverTask, client) = await StartPipeAsync(agentLauncher, refusingOps, cts.Token);
        using (server)
        {
            await using (client)
            {
                var provider = new WindowsUpdateBiosProvider(
                    wuaClient: new FakeWindowsUpdateClient(),
                    elevatedBridge: client,
                    isProcessElevated: () => false,
                    log: log.Logger);

                var res = await provider.InstallAsync(
                    CreateWuaInstallRequest(system: sys, packageId: SampleUpdateId.ToString("D"), targetVersion: $"2.0.0-{spaceSlashSerial}", suspendBitLocker: true),
                    progress: progress,
                    ct: cts.Token);

                Assert.False(res.Succeeded);
                Assert.DoesNotContain(spaceSlashSerial, res.Message, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain(encodedSerial, res.Message, StringComparison.OrdinalIgnoreCase);
                log.AssertDoesNotContainSecret(spaceSlashSerial);
                log.AssertDoesNotContainSecret(encodedSerial);
                Assert.NotEmpty(progress.Reports);
                Assert.All(progress.Reports, ev =>
                {
                    Assert.DoesNotContain(spaceSlashSerial, ev.Detail ?? "", StringComparison.OrdinalIgnoreCase);
                    Assert.DoesNotContain(encodedSerial, ev.Detail ?? "", StringComparison.OrdinalIgnoreCase);
                });
            }

            await serverTask;
        }
    }

    private sealed class RefusingBitLockerBiosOps(string refusalMessage) : IAgentBiosOperations
    {
        public Task<BiosAgentBitLockerResult> SuspendBitLockerAsync(string systemDrive, CancellationToken ct = default) =>
            Task.FromResult(new BiosAgentBitLockerResult(Allowed: false, Suspended: false, Error: refusalMessage));

        public Task<BiosAgentInstallResult> RunBiosInstallerAsync(BiosAgentInstallRequest request, CancellationToken ct = default) =>
            throw new NotSupportedException();

        public Task<BiosWuaInstallOutcome> InstallWindowsUpdateAsync(Guid updateId, TimeSpan timeout, CancellationToken ct = default) =>
            throw new NotSupportedException();
    }
}
