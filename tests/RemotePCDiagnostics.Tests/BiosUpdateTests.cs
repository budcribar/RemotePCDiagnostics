using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Core.Bios;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Tests;

public sealed class BiosUpdateTests
{
    private static BiosSystemIdentity SampleIdentity(string manufacturer = "HP", string version = "F.10", string dateRaw = "01/15/2024") =>
        new(
            Manufacturer: manufacturer,
            Model: "HP EliteBook 840 G10",
            SystemSku: "8B41",
            BoardManufacturer: manufacturer,
            BoardProduct: "8B41",
            BoardVersion: "KBC Version 42.10",
            SerialNumber: "5CG1234567",
            OsVersion: "Microsoft Windows 11 Pro 10.0.26100",
            Architecture: "X64",
            CurrentBios: new BiosCurrentInfo(
                Vendor: manufacturer,
                Version: version,
                ReleaseDate: BiosVersionComparer.TryParseReleaseDate(dateRaw),
                ReleaseDateRaw: dateRaw,
                SmbiosRevision: "3.4",
                FirmwareMode: BiosFirmwareMode.Uefi));

    private static BiosSafetySnapshot SafeSnapshot() =>
        new(
            OnAcPower: true,
            HasBattery: true,
            BatteryPercent: 85,
            BitLockerActive: false,
            BitLockerSuspended: false,
            HasElevation: true,
            PendingReboot: false);

    private static BiosLatestInfo SampleUpdate(
        string providerId = "hp",
        string latestVersion = "F.24",
        string? downloadUrl = "https://ftp.hp.com/pub/softpaq/sp150000.exe",
        string? sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef") =>
        BiosLatestInfo.UpdateAvailable(
            providerId: providerId,
            latestVersion: latestVersion,
            releaseDate: new DateOnly(2025, 11, 10),
            severity: BiosUpdateSeverity.Recommended,
            packageId: "sp150000",
            releaseSummary: "Security and stability fixes",
            downloadUrl: downloadUrl,
            sha256: sha256,
            sizeBytes: 32_000_000);

    // --- Provider selection & priority ---

    [Fact]
    public void ResolveProvider_PrefersHigherPriorityThenVendorId()
    {
        var generic = new FakeBiosProvider("windows-update", "Windows Update", priority: 10, canHandle: _ => true);
        var oemB = new FakeBiosProvider("oem-b", "OEM B", priority: 100, canHandle: _ => true);
        var oemA = new FakeBiosProvider("oem-a", "OEM A", priority: 100, canHandle: _ => true);

        var service = new BiosUpdateService(
            new FakeSystemProbe(SampleIdentity()),
            new FakeSafetyProbe(SafeSnapshot()),
            [generic, oemB, oemA]);

        Assert.Equal(["oem-a", "oem-b", "windows-update"], service.Providers.Select(p => p.VendorId).ToArray());
        Assert.Same(oemA, service.ResolveProvider(SampleIdentity()));
    }

    [Fact]
    public void ResolveProvider_IsolatesThrowingCanHandle()
    {
        var broken = new FakeBiosProvider("broken", "Broken", priority: 200, canHandle: _ => throw new InvalidOperationException("boom"));
        var fallback = new FakeBiosProvider("fallback", "Fallback", priority: 10, canHandle: _ => true);

        var service = new BiosUpdateService(
            new FakeSystemProbe(SampleIdentity()),
            new FakeSafetyProbe(SafeSnapshot()),
            [broken, fallback]);

        Assert.Same(fallback, service.ResolveProvider(SampleIdentity()));
    }

    // --- GetCurrentVersionAsync ---

    [Fact]
    public async Task GetCurrentVersionAsync_UsesProviderOverrideAndFallsBackToSmbiosOnError()
    {
        var system = SampleIdentity("HP", "F.10");
        var customCurrent = system.CurrentBios with { Version = "01.10.00", Family = "U70", ProviderId = "hp" };
        var provider = new FakeBiosProvider("hp", "HP", canHandle: _ => true, getCurrent: (_, _) => Task.FromResult(customCurrent));

        var service = new BiosUpdateService(new FakeSystemProbe(system), new FakeSafetyProbe(SafeSnapshot()), [provider]);
        var result = await service.GetCurrentVersionAsync();

        Assert.Equal("01.10.00", result.Version);
        Assert.Equal("U70", result.Family);
        Assert.Equal("hp", result.ProviderId);

        var throwing = new FakeBiosProvider("hp", "HP", canHandle: _ => true, getCurrent: (_, _) => throw new IOException("probe failed"));
        var fallbackService = new BiosUpdateService(new FakeSystemProbe(system), new FakeSafetyProbe(SafeSnapshot()), [throwing]);
        var fallback = await fallbackService.GetCurrentVersionAsync();

        Assert.Equal("F.10", fallback.Version);
        Assert.Equal("hp", fallback.ProviderId);
    }

    [Fact]
    public async Task GetCurrentVersionAsync_ReturnsSmbiosWhenNoProviderMatches()
    {
        var system = SampleIdentity("CustomOEM", "1.02");
        var service = new BiosUpdateService(new FakeSystemProbe(system), new FakeSafetyProbe(SafeSnapshot()), []);

        var result = await service.GetCurrentVersionAsync();
        Assert.Equal("1.02", result.Version);
        Assert.Equal("", result.ProviderId);
    }

    // --- CheckForUpdateAsync ---

    [Fact]
    public async Task CheckForUpdateAsync_ReturnsUnsupportedWhenNoProviderMatches()
    {
        var system = SampleIdentity("MysteryVendor", "1.0");
        var service = new BiosUpdateService(new FakeSystemProbe(system), new FakeSafetyProbe(SafeSnapshot()), []);

        var outcome = await service.CheckForUpdateAsync();

        Assert.Null(outcome.ProviderId);
        Assert.Equal(BiosCheckStatus.UnsupportedHardware, outcome.Latest.Status);
        Assert.Contains("MysteryVendor", outcome.Latest.Message);
    }

    [Fact]
    public async Task CheckForUpdateAsync_ReturnsUpdateAvailableAndUpToDate()
    {
        var system = SampleIdentity("HP", "F.10");
        var update = SampleUpdate("hp", "F.24");
        var provider = new FakeBiosProvider("hp", "HP", canHandle: _ => true, getLatest: (_, _, _) => Task.FromResult(update));
        var service = new BiosUpdateService(new FakeSystemProbe(system), new FakeSafetyProbe(SafeSnapshot()), [provider]);

        var outcome = await service.CheckForUpdateAsync();

        Assert.Equal("hp", outcome.ProviderId);
        Assert.Equal("HP", outcome.ProviderDisplayName);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, outcome.Latest.Status);
        Assert.Equal("F.24", outcome.Latest.LatestVersion);

        var upToDateProvider = new FakeBiosProvider("hp", "HP", canHandle: _ => true,
            getLatest: (_, cur, _) => Task.FromResult(BiosLatestInfo.UpToDate("hp", cur.Version)));
        var upToDateService = new BiosUpdateService(new FakeSystemProbe(system), new FakeSafetyProbe(SafeSnapshot()), [upToDateProvider]);

        var upToDate = await upToDateService.CheckForUpdateAsync();
        Assert.Equal(BiosCheckStatus.UpToDate, upToDate.Latest.Status);
    }

    [Fact]
    public async Task CheckForUpdateAsync_RespectsCanCheckLatestAndCatchesProviderExceptions()
    {
        var system = SampleIdentity("Dell", "1.5.0");
        var noCheck = new FakeBiosProvider("dell", "Dell", canHandle: _ => true,
            capabilities: new BiosProviderCapabilities(CanCheckLatest: false));
        var s1 = new BiosUpdateService(new FakeSystemProbe(system), new FakeSafetyProbe(SafeSnapshot()), [noCheck]);

        var o1 = await s1.CheckForUpdateAsync();
        Assert.Equal(BiosCheckStatus.UnsupportedHardware, o1.Latest.Status);

        var throwing = new FakeBiosProvider("dell", "Dell", canHandle: _ => true,
            getLatest: (_, _, _) => throw new HttpRequestException("catalog 503"));
        var s2 = new BiosUpdateService(new FakeSystemProbe(system), new FakeSafetyProbe(SafeSnapshot()), [throwing]);

        var o2 = await s2.CheckForUpdateAsync();
        Assert.Equal(BiosCheckStatus.Failed, o2.Latest.Status);
        Assert.Contains("catalog 503", o2.Latest.Message);
    }

    // --- Install safety gates & orchestration ---

    [Fact]
    public async Task InstallUpdateAsync_RefusesWithoutApprovalOrWhenAlreadyUpToDate()
    {
        var system = SampleIdentity("HP", "F.10");
        var provider = new FakeBiosProvider("hp", "HP", canHandle: _ => true,
            capabilities: new BiosProviderCapabilities(CanCheckLatest: true, CanInstall: true));
        var service = new BiosUpdateService(new FakeSystemProbe(system), new FakeSafetyProbe(SafeSnapshot()), [provider]);

        var unapproved = new BiosInstallRequest(system, system.CurrentBios, SampleUpdate(), Approved: false);
        var r1 = await service.InstallUpdateAsync(unapproved);
        Assert.False(r1.Succeeded);
        Assert.Equal(BiosInstallStatus.Refused, r1.Status);
        Assert.Equal(0, provider.InstallCalls);

        var alreadyCurrent = new BiosInstallRequest(system, system.CurrentBios, BiosLatestInfo.UpToDate("hp", "F.10"), Approved: true);
        var r2 = await service.InstallUpdateAsync(alreadyCurrent);
        Assert.True(r2.Succeeded);
        Assert.Equal(BiosInstallStatus.AlreadyUpToDate, r2.Status);
        Assert.Equal(0, provider.InstallCalls);
    }

    [Fact]
    public async Task InstallUpdateAsync_ReturnsUnsupportedWhenProviderCannotInstall()
    {
        var system = SampleIdentity("HP", "F.10");
        var readOnlyProvider = new FakeBiosProvider("hp", "HP", canHandle: _ => true,
            capabilities: new BiosProviderCapabilities(CanCheckLatest: true, CanInstall: false));
        var service = new BiosUpdateService(new FakeSystemProbe(system), new FakeSafetyProbe(SafeSnapshot()), [readOnlyProvider]);

        var req = new BiosInstallRequest(system, system.CurrentBios, SampleUpdate(), Approved: true, ApprovedBy: "tech");
        var result = await service.InstallUpdateAsync(req);

        Assert.False(result.Succeeded);
        Assert.Equal(BiosInstallStatus.Unsupported, result.Status);
    }

    [Fact]
    public async Task InstallUpdateAsync_BlocksOnUnsafePrerequisites()
    {
        var system = SampleIdentity("HP", "F.10");
        var provider = new FakeBiosProvider("hp", "HP", canHandle: _ => true,
            capabilities: new BiosProviderCapabilities(CanCheckLatest: true, CanInstall: true, RequiresElevation: true));

        var unsafeSnapshot = new BiosSafetySnapshot(
            OnAcPower: false,
            HasBattery: true,
            BatteryPercent: 18,
            BitLockerActive: true,
            BitLockerSuspended: false,
            HasElevation: false,
            PendingReboot: true);

        var service = new BiosUpdateService(new FakeSystemProbe(system), new FakeSafetyProbe(unsafeSnapshot), [provider]);
        var req = new BiosInstallRequest(
            system,
            system.CurrentBios,
            SampleUpdate(downloadUrl: "http://insecure.example.com/bios.exe"),
            Approved: true,
            ApprovedBy: "tech",
            SuspendBitLocker: false);

        var eval = await service.EvaluateInstallSafetyAsync(req);
        Assert.False(eval.Passed);
        Assert.Equal(6, eval.BlockingReasons.Count);

        var install = await service.InstallUpdateAsync(req);
        Assert.False(install.Succeeded);
        Assert.Equal(BiosInstallStatus.BlockedByPrerequisites, install.Status);
        Assert.Equal(0, provider.InstallCalls);
    }

    [Fact]
    public void SafetyEvaluator_AllowsDesktopWithoutBatteryAndWarnsWhenHashMissing()
    {
        var system = SampleIdentity("ASUS", "1204");
        var desktopSnapshot = new BiosSafetySnapshot(
            OnAcPower: true,
            HasBattery: false,
            BatteryPercent: null,
            BitLockerActive: false,
            BitLockerSuspended: false,
            HasElevation: true,
            PendingReboot: false);

        var req = new BiosInstallRequest(
            system,
            system.CurrentBios,
            SampleUpdate("asus", "1401", sha256: null),
            Approved: true,
            VerifyHash: true);

        var result = BiosInstallSafetyEvaluator.Evaluate(desktopSnapshot, req, new BiosProviderCapabilities(CanInstall: true));

        Assert.True(result.Passed);
        Assert.Empty(result.BlockingReasons);
        Assert.Single(result.Warnings);
    }

    [Fact]
    public async Task InstallUpdateAsync_SucceedsAndReportsProgressWhenPrerequisitesPass()
    {
        var system = SampleIdentity("HP", "F.10");
        var stages = new List<BiosInstallStage>();
        var provider = new FakeBiosProvider(
            "hp",
            "HP",
            canHandle: _ => true,
            capabilities: new BiosProviderCapabilities(CanCheckLatest: true, CanInstall: true, SupportsSilentInstall: true),
            install: (req, progress, _) =>
            {
                progress?.Report(new BiosInstallProgress(BiosInstallStage.Downloading, 30, "Downloading…"));
                progress?.Report(new BiosInstallProgress(BiosInstallStage.Verifying, 60, "Verifying SHA-256…"));
                progress?.Report(new BiosInstallProgress(BiosInstallStage.Staging, 90, "Staging update…"));
                progress?.Report(new BiosInstallProgress(BiosInstallStage.RebootRequired, 100, "Ready to restart."));
                return Task.FromResult(BiosInstallResult.StagedForReboot(req.Current.Version, req.Target.LatestVersion, bitLockerSuspended: true));
            });

        var service = new BiosUpdateService(new FakeSystemProbe(system), new FakeSafetyProbe(SafeSnapshot()), [provider]);
        var req = new BiosInstallRequest(system, system.CurrentBios, SampleUpdate(), Approved: true, ApprovedBy: "bud");
        var progress = new SyncProgress<BiosInstallProgress>(p => stages.Add(p.Stage));

        var result = await service.InstallUpdateAsync(req, progress);

        Assert.True(result.Succeeded);
        Assert.Equal(BiosInstallStatus.StagedForReboot, result.Status);
        Assert.True(result.RequiresReboot);
        Assert.True(result.BitLockerSuspended);
        Assert.Equal(1, provider.InstallCalls);
        Assert.Equal(
            [
                BiosInstallStage.CheckingPrerequisites,
                BiosInstallStage.Downloading,
                BiosInstallStage.Verifying,
                BiosInstallStage.Staging,
                BiosInstallStage.RebootRequired,
            ],
            stages);
    }

    [Fact]
    public async Task InstallUpdateAsync_CatchesProviderExceptions()
    {
        var system = SampleIdentity("HP", "F.10");
        var provider = new FakeBiosProvider(
            "hp",
            "HP",
            canHandle: _ => true,
            capabilities: new BiosProviderCapabilities(CanCheckLatest: true, CanInstall: true),
            install: (_, _, _) => throw new InvalidOperationException("flash utility crashed"));

        var service = new BiosUpdateService(new FakeSystemProbe(system), new FakeSafetyProbe(SafeSnapshot()), [provider]);
        var req = new BiosInstallRequest(system, system.CurrentBios, SampleUpdate(), Approved: true);

        var result = await service.InstallUpdateAsync(req);

        Assert.False(result.Succeeded);
        Assert.Equal(BiosInstallStatus.Failed, result.Status);
        Assert.Contains("flash utility crashed", result.Message);
    }

    // --- Version comparison ---

    [Theory]
    [InlineData("1.9", "1.14.0", true)]
    [InlineData("01.09.00", "01.14.00", true)]
    [InlineData("1.14.0", "1.14", false)]
    [InlineData("F.8", "F.24", true)]
    [InlineData("F.24", "F.8", false)]
    [InlineData("A09", "A12", true)]
    [InlineData("Rev. 1.2", "v1.10", true)]
    [InlineData("N32ET89W", "N32ET91W", true)]
    [InlineData("N32ET91W", "N32ET89W", false)]
    public void BiosVersionComparer_IsNewer_HandlesCommonVendorFormats(string current, string latest, bool expected)
    {
        Assert.Equal(expected, BiosVersionComparer.IsNewer(current, latest));
    }

    [Fact]
    public void BiosVersionComparer_DifferentFamiliesReturnNullAndFallBackToReleaseDate()
    {
        Assert.Null(BiosVersionComparer.Compare("F.10", "P.20"));
        Assert.True(BiosVersionComparer.IsNewer("F.10", "P.20", new DateOnly(2024, 1, 1), new DateOnly(2025, 6, 1)));
        Assert.False(BiosVersionComparer.IsNewer("F.10", "P.20", new DateOnly(2025, 6, 1), new DateOnly(2024, 1, 1)));
    }

    [Theory]
    [InlineData("2025-11-10", 2025, 11, 10)]
    [InlineData("01/15/2024", 2024, 1, 15)]
    [InlineData("20240305", 2024, 3, 5)]
    public void BiosVersionComparer_TryParseReleaseDate_ParsesCommonFormats(string raw, int y, int m, int d)
    {
        Assert.Equal(new DateOnly(y, m, d), BiosVersionComparer.TryParseReleaseDate(raw));
    }

    // --- Package verifier ---

    [Theory]
    [InlineData("https://ftp.hp.com/pub/softpaq/sp150000.exe", new[] { "hp.com" }, true)]
    [InlineData("https://hp.com/bios.exe", new[] { "hp.com" }, true)]
    [InlineData("https://evilhp.com/bios.exe", new[] { "hp.com" }, false)]
    [InlineData("http://ftp.hp.com/pub/softpaq/sp150000.exe", new[] { "hp.com" }, false)]
    [InlineData("file:///C:/temp/bios.exe", null, false)]
    [InlineData("", null, false)]
    public void BiosPackageVerifier_IsSafeDownloadUrl_ValidatesSchemeAndHostSuffix(string url, string[]? suffixes, bool expected)
    {
        Assert.Equal(expected, BiosPackageVerifier.IsSafeDownloadUrl(url, suffixes));
    }

    [Fact]
    public async Task BiosPackageVerifier_VerifyFileSha256Async_MatchesAndRejectsMismatch()
    {
        var tempFile = Path.Combine(Path.GetTempPath(), $"bios-test-{Guid.NewGuid():N}.bin");
        try
        {
            var payload = "sample-bios-firmware-payload"u8.ToArray();
            await File.WriteAllBytesAsync(tempFile, payload);
            var expected = Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant();

            var ok = await BiosPackageVerifier.VerifyFileSha256Async(tempFile, expected.ToUpperInvariant());
            Assert.True(ok.Valid);
            Assert.Equal(expected, ok.ActualSha256);

            var bad = await BiosPackageVerifier.VerifyFileSha256Async(tempFile, new string('0', 64));
            Assert.False(bad.Valid);
            Assert.Equal(expected, bad.ActualSha256);

            var shortHash = await BiosPackageVerifier.VerifyFileSha256Async(tempFile, "abcd");
            Assert.False(shortHash.Valid);
        }
        finally
        {
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    // --- Default probes & DI wiring ---

    [Fact]
    public async Task DefaultBiosSystemProbe_ReadsOsqueryAndFiltersOemFiller()
    {
        var launcher = new FakeLauncher(sql =>
        {
            if (sql.Contains("system_info", StringComparison.OrdinalIgnoreCase))
            {
                return """
                    [{"hostname":"PC1","computer_name":"PC1","uuid":"u","hardware_vendor":"Dell Inc.","hardware_model":"Latitude 7440","hardware_version":"To Be Filled By O.E.M.","hardware_serial":"ABC123","board_vendor":"Dell Inc.","board_model":"0ABCD1","board_version":"A00","board_serial":"BSN","cpu_brand":"Intel","cpu_type":"x64","cpu_physical_cores":"8","cpu_logical_cores":"16","cpu_sockets":"1","physical_memory":"17179869184"}]
                    """;
            }
            if (sql.Contains("platform_info", StringComparison.OrdinalIgnoreCase))
            {
                return """
                    [{"vendor":"Dell Inc.","version":"1.12.0","date":"02/20/2025","revision":"3.5"}]
                    """;
            }
            return "[]";
        });

        var osquery = new OsqueryRunner(baseDirectory: Path.GetTempPath(), launcher: launcher, fileExists: _ => true);
        var probe = new DefaultBiosSystemProbe(osquery, readWindowsRegistry: false);

        var identity = await probe.ProbeAsync();

        Assert.Equal("Dell Inc.", identity.Manufacturer);
        Assert.Equal("Latitude 7440", identity.Model);
        Assert.Equal("0ABCD1", identity.BoardProduct);
        Assert.Equal("ABC123", identity.SerialNumber);
        Assert.Equal("1.12.0", identity.CurrentBios.Version);
        Assert.Equal(new DateOnly(2025, 2, 20), identity.CurrentBios.ReleaseDate);
        Assert.Equal("3.5", identity.CurrentBios.SmbiosRevision);
    }

    [Theory]
    [InlineData("1", true, false)]
    [InlineData("3", true, false)]
    [InlineData("6", true, false)]
    [InlineData("5", true, true)]
    [InlineData("0", false, false)]
    [InlineData("2", false, false)]
    [InlineData("8", false, false)]
    [InlineData("", null, null)]
    [InlineData("not-a-number", null, null)]
    public void DefaultBiosInstallSafetyProbe_ParsesBitLockerProtectionCodes(string raw, bool? expectedActive, bool? expectedSuspended)
    {
        var (active, suspended) = DefaultBiosInstallSafetyProbe.ParseBitLockerProtectionCode(raw);
        Assert.Equal(expectedActive, active);
        Assert.Equal(expectedSuspended, suspended);
    }

    [Fact]
    public async Task AddBiosUpdates_WiresServiceAndPluggableProvidersInDi()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IBiosSystemProbe>(new FakeSystemProbe(SampleIdentity("Lenovo", "N32ET89W")));
        services.AddSingleton<IBiosInstallSafetyProbe>(new FakeSafetyProbe(SafeSnapshot()));
        services.AddBiosUpdates();
        services.AddBiosUpdateProvider<SampleLenovoProvider>();

        using var sp = services.BuildServiceProvider(new ServiceProviderOptions { ValidateOnBuild = true });
        var bios = sp.GetRequiredService<IBiosUpdateService>();

        Assert.Single(bios.Providers);
        var outcome = await bios.CheckForUpdateAsync();
        Assert.Equal("lenovo", outcome.ProviderId);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, outcome.Latest.Status);
        Assert.Equal("N32ET91W", outcome.Latest.LatestVersion);
    }

    [Fact]
    public async Task InstallUpdate_SurvivesAThrowingCanHandleOnTheTargetsProvider_AndSafetyCheckUsesTheSameProvider()
    {
        var system = SampleIdentity("HP");
        var installCaps = new BiosProviderCapabilities(CanCheckLatest: true, CanInstall: true, RequiresElevation: false);
        var hp = new FakeBiosProvider("hp", "HP", capabilities: installCaps, canHandle: _ => true,
            install: (r, _, _) => Task.FromResult(new BiosInstallResult(true, BiosInstallStatus.StagedForReboot)));
        var wu = new FakeBiosProvider("windowsupdate", "Windows Update", priority: 10, capabilities: installCaps,
            canHandle: _ => throw new InvalidOperationException("probe failed"));
        var service = new BiosUpdateService(new FakeSystemProbe(system), new FakeSafetyProbe(SafeSnapshot()), [hp, wu]);

        // The target names the Windows Update provider, whose CanHandle throws: that must not escape InstallUpdateAsync.
        var wuTarget = BiosLatestInfo.UpdateAvailable("windowsupdate", "F.12");
        var request = new BiosInstallRequest(system, system.CurrentBios, wuTarget, Approved: true);
        var result = await service.InstallUpdateAsync(request);

        Assert.True(result.Succeeded, result.Message);
        Assert.Equal(1, hp.InstallCalls);
        Assert.Equal(0, wu.InstallCalls);
        Assert.True((await service.EvaluateInstallSafetyAsync(request)).Passed);
    }

    // --- Test doubles ---

    private sealed class SampleLenovoProvider : IBiosUpdateProvider
    {
        public string VendorId => "lenovo";
        public string DisplayName => "Lenovo";
        public BiosProviderCapabilities Capabilities { get; } = new(CanCheckLatest: true, CanInstall: false);
        public bool CanHandle(BiosSystemIdentity system) => system.Manufacturer.Contains("Lenovo", StringComparison.OrdinalIgnoreCase);
        public Task<BiosLatestInfo> GetLatestVersionAsync(BiosSystemIdentity system, BiosCurrentInfo current, CancellationToken ct = default) =>
            Task.FromResult(BiosLatestInfo.UpdateAvailable(VendorId, "N32ET91W"));
    }

    private sealed class FakeSystemProbe(BiosSystemIdentity identity) : IBiosSystemProbe
    {
        public Task<BiosSystemIdentity> ProbeAsync(CancellationToken ct = default) => Task.FromResult(identity);
    }

    private sealed class FakeSafetyProbe(BiosSafetySnapshot snapshot) : IBiosInstallSafetyProbe
    {
        public Task<BiosSafetySnapshot> ProbeAsync(CancellationToken ct = default) => Task.FromResult(snapshot);
    }

    private sealed class SyncProgress<T>(Action<T> onReport) : IProgress<T>
    {
        public void Report(T value) => onReport(value);
    }

    private sealed class FakeBiosProvider(
        string vendorId,
        string displayName,
        int priority = 100,
        BiosProviderCapabilities? capabilities = null,
        Func<BiosSystemIdentity, bool>? canHandle = null,
        Func<BiosSystemIdentity, CancellationToken, Task<BiosCurrentInfo>>? getCurrent = null,
        Func<BiosSystemIdentity, BiosCurrentInfo, CancellationToken, Task<BiosLatestInfo>>? getLatest = null,
        Func<BiosInstallRequest, IProgress<BiosInstallProgress>?, CancellationToken, Task<BiosInstallResult>>? install = null)
        : IBiosUpdateProvider
    {
        public int InstallCalls { get; private set; }
        public string VendorId => vendorId;
        public string DisplayName => displayName;
        public int Priority => priority;
        public BiosProviderCapabilities Capabilities => capabilities ?? new BiosProviderCapabilities();
        public bool CanHandle(BiosSystemIdentity system) => canHandle?.Invoke(system) ?? false;

        public Task<BiosCurrentInfo> GetCurrentVersionAsync(BiosSystemIdentity system, CancellationToken ct = default) =>
            getCurrent is not null ? getCurrent(system, ct) : Task.FromResult(system.CurrentBios with { ProviderId = VendorId });

        public Task<BiosLatestInfo> GetLatestVersionAsync(BiosSystemIdentity system, BiosCurrentInfo current, CancellationToken ct = default) =>
            getLatest is not null ? getLatest(system, current, ct) : Task.FromResult(BiosLatestInfo.UpToDate(VendorId, current.Version));

        public Task<BiosInstallResult> InstallAsync(BiosInstallRequest request, IProgress<BiosInstallProgress>? progress = null, CancellationToken ct = default)
        {
            InstallCalls++;
            return install is not null
                ? install(request, progress, ct)
                : Task.FromResult(BiosInstallResult.Unsupported("not supported", request.Current.Version, request.Target.LatestVersion));
        }
    }

    private sealed class FakeLauncher(Func<string, string> sqlToJson) : IProcessLauncher
    {
        public Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct)
        {
            var sql = arguments.LastOrDefault() ?? "";
            return Task.FromResult(new ProcessResult(0, sqlToJson(sql), "", TimedOut: false));
        }
    }
}
