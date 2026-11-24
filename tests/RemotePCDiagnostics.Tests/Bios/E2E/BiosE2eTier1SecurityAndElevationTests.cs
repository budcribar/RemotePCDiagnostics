using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Core.Bios;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Tests.Bios.E2E;

/// <summary>
/// Tier 1 E2E Feature Coverage (Areas 1.5–1.9: Safety Evaluation, Version Comparison,
/// Transport/Package Security, Pure-C# Compliance, and Agent Elevation Span) — 29 test IDs.
/// </summary>
[Trait("Tier", "1")]
public sealed class BiosE2eTier1SecurityAndElevationTests
{
    // =========================================================================
    // Area 1.5: Pre-Flash Safety Evaluation & Pure-C# BitLocker Probe (E2E-T1-SAF-01..06)
    // =========================================================================

    [Theory]
    [InlineData("1", true, false)]
    [InlineData("3", true, false)]
    [InlineData("6", true, false)]
    [InlineData("5", true, true)]
    [InlineData("0", false, false)]
    [InlineData("2", false, false)]
    [InlineData("4", false, false)]
    [InlineData("7", false, false)]
    [InlineData("8", false, false)]
    public void E2E_T1_SAF_01_PureCSharpBitLockerProtectionCodeEquivalence(
        string code, bool expectedActive, bool expectedSuspended)
    {
        var (active, suspended) = DefaultBiosInstallSafetyProbe.ParseBitLockerProtectionCode(code);
        Assert.Equal(expectedActive, active);
        Assert.Equal(expectedSuspended, suspended);
    }

    [Fact]
    public async Task E2E_T1_SAF_02_PureCSharpSafetyProbeNonThrowingAndInjectableDelegate()
    {
        var elevation = new StubElevationContext(isProcessElevated: false, isAdminHelperConnected: true);
        var probeCalled = false;
        var probe = new DefaultBiosInstallSafetyProbe(
            elevation: elevation,
            bitLockerProbe: _ =>
            {
                probeCalled = true;
                return Task.FromResult<int?>(5); // active + suspended
            });

        var snapshot = await probe.ProbeAsync();

        Assert.True(probeCalled);
        Assert.True(snapshot.HasElevation);
        Assert.True(snapshot.BitLockerActive);
        Assert.True(snapshot.BitLockerSuspended);

        // Toggle elevation off and verify HasElevation tracks IElevationContext cleanly without throwing
        elevation.IsAdminHelperConnected = false;
        var snapshotNoAdmin = await probe.ProbeAsync();
        Assert.False(snapshotNoAdmin.HasElevation);
    }

    [Fact]
    public async Task E2E_T1_SAF_03_EvaluateInstallSafetyPassesSafeLaptopAndDesktopSnapshots()
    {
        var identity = E2eIdentities.HpEliteBook();
        var (_, sha256) = E2ePayloads.BuildDummyBinary("safe-check");
        var target = BiosLatestInfo.UpdateAvailable("hp", "01.14.00",
            downloadUrl: "https://ftp.hp.com/pub/softpaq/sp151234.exe", sha256: sha256);
        var request = new BiosInstallRequest(identity, identity.CurrentBios, target, Approved: true, SuspendBitLocker: true, AllowReboot: false, VerifyHash: true);

        await using var laptopHost = BiosE2eTestHost.CreateElevated(identity, StubSafetyProbe.SafeLaptop(bitLockerActive: true));
        var laptopRes = await laptopHost.Service.EvaluateInstallSafetyAsync(request);
        Assert.True(laptopRes.Passed);
        Assert.Empty(laptopRes.BlockingReasons);

        await using var desktopHost = BiosE2eTestHost.CreateElevated(identity, StubSafetyProbe.SafeDesktop(bitLockerActive: false));
        var desktopRes = await desktopHost.Service.EvaluateInstallSafetyAsync(request);
        Assert.True(desktopRes.Passed);
        Assert.Empty(desktopRes.BlockingReasons);
    }

    [Fact]
    public async Task E2E_T1_SAF_04_InstallUpdateRefusesUnapprovedAndNonInstallableTargets()
    {
        var identity = E2eIdentities.HpEliteBook();
        await using var host = BiosE2eTestHost.CreateElevated(identity);

        // Unapproved UpdateAvailable -> Refused
        var availTarget = BiosLatestInfo.UpdateAvailable("hp", "01.14.00", downloadUrl: "https://ftp.hp.com/pub/softpaq/sp151234.exe");
        var unapproved = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(identity, identity.CurrentBios, availTarget, Approved: false));
        Assert.False(unapproved.Succeeded);
        Assert.Equal(BiosInstallStatus.Refused, unapproved.Status);

        // Non-installable statuses -> Refused
        var nonInstallableTargets = new[]
        {
            BiosLatestInfo.Failed("hp", "Catalog failed"),
            BiosLatestInfo.Offline("hp"),
            BiosLatestInfo.Unavailable("hp", "503"),
            BiosLatestInfo.Unsupported("hp", "Unsupported")
        };
        foreach (var target in nonInstallableTargets)
        {
            var res = await host.Service.InstallUpdateAsync(
                new BiosInstallRequest(identity, identity.CurrentBios, target, Approved: true));
            Assert.False(res.Succeeded);
            Assert.Equal(BiosInstallStatus.Refused, res.Status);
        }

        // UpToDate -> AlreadyUpToDate (Succeeded == true)
        var upToDateTarget = BiosLatestInfo.UpToDate("hp", "01.10.00");
        var already = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(identity, identity.CurrentBios, upToDateTarget, Approved: true));
        Assert.True(already.Succeeded);
        Assert.Equal(BiosInstallStatus.AlreadyUpToDate, already.Status);

        Assert.Equal(0, host.SafetyProbe.ProbeCount);
        Assert.Empty(host.HttpHandler.Requests);
        Assert.Empty(host.HostProcessLauncher.Calls);
    }

    public static TheoryData<string, BiosSafetySnapshot, bool, string> SafetyBlockerCases => new()
    {
        { "MissingElevation", new BiosSafetySnapshot(true, true, 80, false, false, HasElevation: false, PendingReboot: false), true, "https://ftp.hp.com/sp.exe" },
        { "OffAcPower", new BiosSafetySnapshot(OnAcPower: false, HasBattery: true, BatteryPercent: 80, false, false, HasElevation: true, PendingReboot: false), true, "https://ftp.hp.com/sp.exe" },
        { "LowBattery20", new BiosSafetySnapshot(OnAcPower: true, HasBattery: true, BatteryPercent: 20, false, false, HasElevation: true, PendingReboot: false), true, "https://ftp.hp.com/sp.exe" },
        { "BitLockerBlocked", new BiosSafetySnapshot(true, true, 80, BitLockerActive: true, BitLockerSuspended: false, HasElevation: true, PendingReboot: false), false, "https://ftp.hp.com/sp.exe" },
        { "PendingReboot", new BiosSafetySnapshot(true, true, 80, false, false, HasElevation: true, PendingReboot: true), true, "https://ftp.hp.com/sp.exe" },
        { "NonHttpsUrl", new BiosSafetySnapshot(true, true, 80, false, false, HasElevation: true, PendingReboot: false), true, "http://ftp.hp.com/sp.exe" }
    };

    [Theory]
    [MemberData(nameof(SafetyBlockerCases))]
    public async Task E2E_T1_SAF_05_InstallUpdateBlocksOnSafetyPrerequisiteViolations(
        string scenario, BiosSafetySnapshot snapshot, bool suspendBitLocker, string downloadUrl)
    {
        Assert.False(string.IsNullOrWhiteSpace(scenario));
        var identity = E2eIdentities.HpEliteBook();
        await using var host = BiosE2eTestHost.CreateElevated(identity, snapshot);

        var target = BiosLatestInfo.UpdateAvailable("hp", "01.14.00", downloadUrl: downloadUrl);
        var progress = new SyncProgress<BiosInstallProgress>();

        var result = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(identity, identity.CurrentBios, target, Approved: true, SuspendBitLocker: suspendBitLocker),
            progress);

        Assert.False(result.Succeeded);
        Assert.Equal(BiosInstallStatus.BlockedByPrerequisites, result.Status);
        Assert.Equal([BiosInstallStage.CheckingPrerequisites, BiosInstallStage.Failed],
            progress.Reports.Select(r => r.Stage).ToArray());
        Assert.Empty(host.HttpHandler.Requests);
        Assert.Empty(host.HostProcessLauncher.Calls);
        host.AssertNoSerialNumberLeaked(result: result);
    }

    [Fact]
    public async Task E2E_T1_SAF_06_ActiveBitLockerPassesSafetyGateWhenSuspendBitLockerEnabled()
    {
        var identity = E2eIdentities.HpEliteBook();
        var (pkgBytes, sha256) = E2ePayloads.BuildDummyBinary("hp-bitlocker-pass");
        const string url = "https://ftp.hp.com/pub/softpaq/sp151234.exe";

        await using var host = BiosE2eTestHost.CreateElevated(
            identity,
            StubSafetyProbe.SafeLaptop(bitLockerActive: true, bitLockerSuspended: false));
        host.HttpHandler.MapBytes(url, pkgBytes);

        var target = BiosLatestInfo.UpdateAvailable("hp", "01.14.00", downloadUrl: url, sha256: sha256);
        var request = new BiosInstallRequest(identity, identity.CurrentBios, target, Approved: true, SuspendBitLocker: true, AllowReboot: false, VerifyHash: true, StagingDirectory: host.StagingDir.Path);

        var safety = await host.Service.EvaluateInstallSafetyAsync(request);
        Assert.True(safety.Passed);
        Assert.Empty(safety.BlockingReasons);

        var result = await host.Service.InstallUpdateAsync(request);
        Assert.True(result.Succeeded);
        Assert.True(result.BitLockerSuspended);

        var bde = Assert.Single(host.HostProcessLauncher.Calls, c => c.ToolName.Equals("manage-bde.exe", StringComparison.OrdinalIgnoreCase));
        Assert.Equal("-protectors", bde.Arguments[0]);
        Assert.Equal("-disable", bde.Arguments[1]);
        Assert.Matches(@"^[A-Za-z]:$", bde.Arguments[2]);
        Assert.Equal("-RebootCount", bde.Arguments[3]);
        Assert.Equal("1", bde.Arguments[4]);
    }

    // =========================================================================
    // Area 1.6: Version Comparison & Release Date Resolution (E2E-T1-VER-01..05)
    // =========================================================================

    [Fact]
    public void E2E_T1_VER_01_PureDottedNumericComparison()
    {
        Assert.True(BiosVersionComparer.Compare("01.09.00", "01.14.00") < 0);
        Assert.True(BiosVersionComparer.Compare("1.2.3", "1.10.0") < 0);
        Assert.Equal(0, BiosVersionComparer.Compare("1.14", "1.14.0"));
        Assert.True(BiosVersionComparer.IsNewer("01.09.00", "01.14.00"));
        Assert.False(BiosVersionComparer.IsNewer("1.14", "1.14.0"));
    }

    [Fact]
    public void E2E_T1_VER_02_PrefixNumericComparisonWithNormalization()
    {
        Assert.True(BiosVersionComparer.Compare("Rev. F.8", "F.24") < 0);
        Assert.True(BiosVersionComparer.Compare("v1.2.0", "V1.3.0") < 0);
        Assert.True(BiosVersionComparer.Compare("A09", "A12") < 0);
        Assert.True(BiosVersionComparer.IsNewer("Rev. F.8", "F.24"));
        Assert.True(BiosVersionComparer.IsNewer("v1.2.0", "V1.3.0"));
        Assert.True(BiosVersionComparer.IsNewer("A09", "A12"));
    }

    [Fact]
    public void E2E_T1_VER_03_SkeletonPatternComparisonLenovoOem()
    {
        Assert.True(BiosVersionComparer.Compare("N32ET89W", "N32ET91W") < 0);
        Assert.True(BiosVersionComparer.Compare("N3XET48W", "N3XET52W") < 0);
        Assert.Equal(0, BiosVersionComparer.Compare("N3XET52W", "n3xet52w"));
        Assert.True(BiosVersionComparer.IsNewer("N3XET48W", "N3XET52W"));
    }

    [Theory]
    [InlineData("2025-02-15", 2025, 2, 15)]
    [InlineData("02/15/2025", 2025, 2, 15)]
    [InlineData("2/5/2025", 2025, 2, 5)]
    [InlineData("2025/02/15", 2025, 2, 15)]
    [InlineData("20250215", 2025, 2, 15)]
    [InlineData("25/04/2024", 2024, 4, 25)]
    public void E2E_T1_VER_04_ReleaseDateParsingFormats(string raw, int year, int month, int day)
    {
        var parsed = BiosVersionComparer.TryParseReleaseDate(raw);
        Assert.Equal(new DateOnly(year, month, day), parsed);
    }

    [Fact]
    public void E2E_T1_VER_05_DateFallbackWhenVersionsIncomparable()
    {
        Assert.Null(BiosVersionComparer.Compare("F.10", "P.20"));
        Assert.True(BiosVersionComparer.IsNewer("F.10", "P.20", new DateOnly(2024, 1, 1), new DateOnly(2024, 6, 1)));
        Assert.False(BiosVersionComparer.IsNewer("F.10", "P.20", new DateOnly(2024, 6, 1), new DateOnly(2024, 1, 1)));
        Assert.False(BiosVersionComparer.IsNewer("F.10", "P.20", null, null));
    }

    // =========================================================================
    // Area 1.7: Transport Security, Package Verification, Archive/XML & BitLocker (E2E-T1-SEC-01..07)
    // =========================================================================

    [Fact]
    public async Task E2E_T1_SEC_01_AllowedHostHttpsDownloadAndValidSha256()
    {
        var identity = E2eIdentities.DellLatitude();
        var (pkgBytes, sha256) = E2ePayloads.BuildDummyBinary("dell-sec01");
        const string pkgUrl = "https://downloads.dell.com/FOLDER12345M/1/Latitude_1.18.0.exe";

        await using var host = BiosE2eTestHost.CreateElevated(identity);
        host.HttpHandler.MapBytes(pkgUrl, pkgBytes);

        var target = BiosLatestInfo.UpdateAvailable("dell", "1.18.0", downloadUrl: pkgUrl, sha256: sha256);
        var result = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(identity, identity.CurrentBios, target, Approved: true, SuspendBitLocker: false, AllowReboot: false, VerifyHash: true, StagingDirectory: host.StagingDir.Path));

        Assert.True(result.Succeeded);
        Assert.Equal(BiosInstallStatus.StagedForReboot, result.Status);
        var call = Assert.Single(host.HostProcessLauncher.Calls);
        Assert.Equal("Latitude_1.18.0.exe", call.ToolName);
        Assert.True(File.Exists(call.FileName) || call.FileName.StartsWith(host.StagingDir.Path, StringComparison.OrdinalIgnoreCase));
        host.AssertNoSerialNumberLeaked(result: result);
    }

    [Fact]
    public async Task E2E_T1_SEC_02_ValidMultiHopHttpsRedirectWithinAllowedDomain()
    {
        var identity = E2eIdentities.HpEliteBook();
        var (pkgBytes, sha256) = E2ePayloads.BuildDummyBinary("hp-redirect-ok");
        const string startUrl = "https://ftp.hp.com/pub/softpaq/sp151234.exe";
        const string finalUrl = "https://downloads.hpcloud.hp.com/softpaq/sp151234.exe";

        await using var host = BiosE2eTestHost.CreateElevated(identity);
        host.HttpHandler.MapRedirect(startUrl, finalUrl, HttpStatusCode.Found);
        host.HttpHandler.MapBytes(finalUrl, pkgBytes);

        var target = BiosLatestInfo.UpdateAvailable("hp", "01.14.00", downloadUrl: startUrl, sha256: sha256);
        var result = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(identity, identity.CurrentBios, target, Approved: true, SuspendBitLocker: false, AllowReboot: false, VerifyHash: true, StagingDirectory: host.StagingDir.Path));

        Assert.True(result.Succeeded);
        Assert.Equal(BiosInstallStatus.StagedForReboot, result.Status);
        Assert.Equal(2, host.HttpHandler.Requests.Count);
        Assert.Equal(startUrl, host.HttpHandler.Requests[0].RequestUri.AbsoluteUri);
        Assert.Equal(finalUrl, host.HttpHandler.Requests[1].RequestUri.AbsoluteUri);
    }

    [Fact]
    public async Task E2E_T1_SEC_03_MissingSha256FallsBackToPureCSharpSignatureVerifierValidSignature()
    {
        var identity = E2eIdentities.HpEliteBook();
        var (pkgBytes, _) = E2ePayloads.BuildDummyBinary("hp-signed-no-hash");
        const string url = "https://ftp.hp.com/pub/softpaq/sp151234.exe";

        await using var host = BiosE2eTestHost.CreateElevated(identity);
        host.SignatureVerifier.Predicate = _ => true;
        host.HttpHandler.MapBytes(url, pkgBytes);

        var target = BiosLatestInfo.UpdateAvailable("hp", "01.14.00", downloadUrl: url, sha256: null);
        var result = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(identity, identity.CurrentBios, target, Approved: true, SuspendBitLocker: false, AllowReboot: false, VerifyHash: true, StagingDirectory: host.StagingDir.Path));

        Assert.True(result.Succeeded);
        Assert.Equal(BiosInstallStatus.StagedForReboot, result.Status);
        Assert.Single(host.SignatureVerifier.VerifiedFilePaths);
        Assert.Equal(2, host.HostProcessLauncher.Calls.Count);
    }

    [Fact]
    public async Task E2E_T1_SEC_04_Sha256ComputationAndConstantTimeVerificationContract()
    {
        using var dir = new IsolatedStagingDir("sha256");
        var filePath = Path.Combine(dir.Path, "firmware.bin");
        var (bytes, expectedLower) = E2ePayloads.BuildDummyBinary("sha-contract");
        await File.WriteAllBytesAsync(filePath, bytes);

        var computed = await BiosPackageVerifier.ComputeSha256HexAsync(filePath);
        Assert.Equal(expectedLower, computed);

        // Case-insensitive valid 64-char hex passes
        var (validUpper, actualUpper) = await BiosPackageVerifier.VerifyFileSha256Async(filePath, expectedLower.ToUpperInvariant());
        Assert.True(validUpper);
        Assert.Equal(expectedLower, actualUpper);

        // Modified content fails
        bytes[^1] ^= 0x01;
        await File.WriteAllBytesAsync(filePath, bytes);
        var (validModified, actualModified) = await BiosPackageVerifier.VerifyFileSha256Async(filePath, expectedLower);
        Assert.False(validModified);
        Assert.NotEqual(expectedLower, actualModified);
    }

    [Theory]
    [InlineData("https://hp.com/a.exe", true)]
    [InlineData("https://ftp.hp.com/a.exe", true)]
    [InlineData("https://FTP.HP.COM/a.exe", true)]
    [InlineData("https://downloads.hpcloud.hp.com/a.exe", true)]
    [InlineData("http://ftp.hp.com/a.exe", false)]
    [InlineData("https://evilhp.com/a.exe", false)]
    [InlineData("https://hp.com.evil.org/a.exe", false)]
    public void E2E_T1_SEC_05_IsSafeDownloadUrlOfficialSuffixMatching(string url, bool expected)
    {
        var actual = BiosPackageVerifier.IsSafeDownloadUrl(url, ["hp.com", "hpcloud.hp.com"]);
        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task E2E_T1_SEC_06_PureCSharpMsCabUncompressedAndMsZipCatalogExtractionViaProvider(bool mszip)
    {
        var identity = E2eIdentities.DellLatitude(systemSku: "0A1B", biosVersion: "1.12.0");
        await using var host = BiosE2eTestHost.CreateElevated(identity);

        var cabBytes = E2ePayloads.DellCatalogCab(systemId: "0A1B", version: "1.19.0", mszip: mszip);
        host.HttpHandler.MapBytes("https://downloads.dell.com/catalog/CatalogPC.cab", cabBytes);

        var outcome = await host.Service.CheckForUpdateAsync();
        Assert.Equal("dell", outcome.ProviderId);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, outcome.Latest.Status);
        Assert.Equal("1.19.0", outcome.Latest.LatestVersion);
        // Pure-C# extraction must launch ZERO external processes (no expand.exe, no shell)
        Assert.Empty(host.HostProcessLauncher.Calls);
    }

    [Fact]
    public async Task E2E_T1_SEC_07_SuspendBitLockerFalseSkipsManageBdeCompletely()
    {
        var identity = E2eIdentities.HpEliteBook();
        var (pkgBytes, sha256) = E2ePayloads.BuildDummyBinary("hp-no-bitlocker");
        const string url = "https://ftp.hp.com/pub/softpaq/sp151234.exe";

        await using var host = BiosE2eTestHost.CreateElevated(identity, StubSafetyProbe.SafeLaptop(bitLockerActive: false));
        host.HttpHandler.MapBytes(url, pkgBytes);

        var target = BiosLatestInfo.UpdateAvailable("hp", "01.14.00", downloadUrl: url, sha256: sha256);
        var result = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(identity, identity.CurrentBios, target, Approved: true, SuspendBitLocker: false, AllowReboot: false, VerifyHash: true, StagingDirectory: host.StagingDir.Path));

        Assert.True(result.Succeeded);
        Assert.False(result.BitLockerSuspended);
        Assert.DoesNotContain(host.HostProcessLauncher.Calls, c => c.ToolName.Equals("manage-bde.exe", StringComparison.OrdinalIgnoreCase));
    }

    // =========================================================================
    // Area 1.8: Pure-C# Compliance & Contract Static Verification (E2E-T1-PCS-01..05)
    // =========================================================================

    [Fact]
    public void E2E_T1_PCS_01_ZeroScriptFilesUnderBiosHostAndAgentPaths()
    {
        var repoRoot = E2ePayloads.FindRepoRoot();
        var scanDirs = new[]
        {
            Path.Combine(repoRoot, "src", "RemotePCDiagnostics.Core", "Bios"),
            Path.Combine(repoRoot, "src", "RemotePCDiagnostics.Core", "Session"),
            Path.Combine(repoRoot, "src", "RemotePCDiagnostics.Agent")
        };

        var forbiddenExts = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".ps1", ".bat", ".cmd", ".sh" };
        var found = new List<string>();
        foreach (var dir in scanDirs)
        {
            Assert.True(Directory.Exists(dir), $"Expected directory '{dir}' to exist.");
            foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
            {
                if (forbiddenExts.Contains(Path.GetExtension(file)))
                    found.Add(file);
            }
        }

        Assert.Empty(found);
    }

    [Fact]
    public void E2E_T1_PCS_02_ZeroPowerShellOrShellInvocationsInBiosHostAndAgentCSharpCode()
    {
        var repoRoot = E2ePayloads.FindRepoRoot();
        var filesToScan = new List<string>();
        filesToScan.AddRange(Directory.EnumerateFiles(
            Path.Combine(repoRoot, "src", "RemotePCDiagnostics.Core", "Bios"), "*.cs", SearchOption.AllDirectories));
        filesToScan.Add(Path.Combine(repoRoot, "src", "RemotePCDiagnostics.Core", "Session", "AgentBiosOperations.cs"));
        filesToScan.Add(Path.Combine(repoRoot, "src", "RemotePCDiagnostics.Core", "Session", "AgentWindowsUpdate.cs"));
        filesToScan.Add(Path.Combine(repoRoot, "src", "RemotePCDiagnostics.Agent", "AgentHubSession.cs"));
        filesToScan.Add(Path.Combine(repoRoot, "src", "RemotePCDiagnostics.Agent", "AgentAdminHost.cs"));

        var forbiddenRegex = new Regex(
            @"(?:powershell\.exe|\bpwsh\b|RunPowerShellAsync|PowerShellArgs|BitLockerProbeScript|cmd\.exe|/bin/sh|\bbash\b|\.ps1\b|\.bat\b|\.cmd\b|\.sh\b)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        // Self-check StripCSharpComments: string/verbatim/raw/char literals containing "//" or "/*"
        // MUST preserve subsequent code so forbidden tokens are caught, while real comments are stripped.
        Assert.Matches(forbiddenRegex, StripCSharpComments("var u = \"https://hp.com/bios\"; RunPowerShellAsync(\"x.ps1\");"));
        Assert.Matches(forbiddenRegex, StripCSharpComments("var s = \"/*\"; var p = \"powershell.exe\";"));
        Assert.Matches(forbiddenRegex, StripCSharpComments("var v = @\"https://hp.com/a\" + \"cmd.exe\";"));
        Assert.Matches(forbiddenRegex, StripCSharpComments("var r = \"\"\"https://hp.com/a /*\"\"\"; var q = \"pwsh\";"));
        Assert.Matches(forbiddenRegex, StripCSharpComments("char c = '\"'; var u = \"https://a//b\"; var p = \"powershell.exe\";"));
        Assert.DoesNotMatch(forbiddenRegex, StripCSharpComments("// powershell.exe\n/* cmd.exe \n bash */ var ok = 1;"));

        var violations = new List<string>();
        foreach (var file in filesToScan)
        {
            Assert.True(File.Exists(file), $"Expected source file '{file}' to exist.");
            var codeOnly = StripCSharpComments(File.ReadAllText(file));
            foreach (Match m in forbiddenRegex.Matches(codeOnly))
                violations.Add($"{Path.GetFileName(file)}: '{m.Value}'");
        }

        // Also scan the BIOS dispatch and AdminPipeClient BIOS sections of AdminPipeProtocol.cs
        var pipePath = Path.Combine(repoRoot, "src", "RemotePCDiagnostics.Core", "Session", "AdminPipeProtocol.cs");
        var pipeSource = File.ReadAllText(pipePath);

        var biosHandlerIdx = pipeSource.IndexOf("HandleBiosOperationAsync", StringComparison.Ordinal);
        Assert.True(biosHandlerIdx > 0, "HandleBiosOperationAsync not found in AdminPipeProtocol.cs.");
        var biosHandlerEnd = pipeSource.IndexOf("private AdminPipeResponse PrepareMachine", biosHandlerIdx, StringComparison.Ordinal);
        Assert.True(biosHandlerEnd > biosHandlerIdx, "Could not locate end of HandleBiosOperationAsync.");
        var biosHandlerCode = StripCSharpComments(pipeSource[biosHandlerIdx..biosHandlerEnd]);
        foreach (Match m in forbiddenRegex.Matches(biosHandlerCode))
            violations.Add($"AdminPipeProtocol.cs(HandleBiosOperationAsync): '{m.Value}'");

        var pipeClientBiosStart = pipeSource.IndexOf("public async Task<BiosAgentBitLockerResult> SuspendBitLockerAsync", StringComparison.Ordinal);
        Assert.True(pipeClientBiosStart > 0, "AdminPipeClient BIOS methods not found in AdminPipeProtocol.cs.");
        var pipeClientBiosEnd = pipeSource.IndexOf("private static void ThrowIfRefused", pipeClientBiosStart, StringComparison.Ordinal);
        Assert.True(pipeClientBiosEnd > pipeClientBiosStart, "Could not locate end of AdminPipeClient BIOS methods.");
        var pipeClientBiosSlice = pipeSource[pipeClientBiosStart..pipeClientBiosEnd];
        Assert.Contains("RunBiosInstallerAsync", pipeClientBiosSlice, StringComparison.Ordinal);
        Assert.Contains("InstallBiosWindowsUpdateAsync", pipeClientBiosSlice, StringComparison.Ordinal);
        foreach (Match m in forbiddenRegex.Matches(StripCSharpComments(pipeClientBiosSlice)))
            violations.Add($"AdminPipeProtocol.cs(AdminPipeClient BIOS): '{m.Value}'");

        // Also scan ElevationContext.cs BIOS bridge forwarding methods
        var elevPath = Path.Combine(repoRoot, "src", "RemotePCDiagnostics.Core", "Session", "ElevationContext.cs");
        var elevSource = File.ReadAllText(elevPath);
        var elevBiosStart = elevSource.IndexOf("public Task<BiosAgentBitLockerResult> SuspendBitLockerAsync", StringComparison.Ordinal);
        Assert.True(elevBiosStart > 0, "ElevationContext BIOS methods not found in ElevationContext.cs.");
        var elevBiosEnd = elevSource.IndexOf("private AdminPipeClient? ConnectedOrNull", elevBiosStart, StringComparison.Ordinal);
        Assert.True(elevBiosEnd > elevBiosStart, "Could not locate end of ElevationContext BIOS methods.");
        var elevBiosSlice = elevSource[elevBiosStart..elevBiosEnd];
        Assert.Contains("RunBiosInstallerAsync", elevBiosSlice, StringComparison.Ordinal);
        Assert.Contains("InstallBiosWindowsUpdateAsync", elevBiosSlice, StringComparison.Ordinal);
        foreach (Match m in forbiddenRegex.Matches(StripCSharpComments(elevBiosSlice)))
            violations.Add($"ElevationContext.cs(BIOS bridge): '{m.Value}'");

        Assert.Empty(violations);
    }

    [Fact]
    public async Task E2E_T1_PCS_03_ZeroShellProcessesLaunchedAtRuntimeAcrossAllNineProvidersAndAgentPipe()
    {
        var (pkgBytes, sha256) = E2ePayloads.BuildDummyBinary("pcs03-pkg");
        var (cabBytes, cabSha) = E2ePayloads.FrameworkCabCapsule();
        var wuaGuid = Guid.NewGuid();

        // Exercise all 9 providers (check + install where supported) under BOTH elevated Host and live Agent Pipe
        foreach (var elevated in new[] { true, false })
        {
            await using var host = await BiosE2eTestHost.CreateAsync(new BiosE2eHostOptions
            {
                InitialIdentity = E2eIdentities.HpEliteBook(),
                IsProcessElevated = elevated,
                UseLiveAgentPipe = !elevated,
                UseHermeticRealSafetyProbe = !elevated
            });

            host.HttpHandler.MapText("https://hpia.hpcloud.hp.com/ref/8b41/8b41_64_11.0.cab", E2ePayloads.HpCatalogXml(sha256: sha256));
            host.HttpHandler.MapBytes("https://ftp.hp.com/pub/softpaq/sp151001-151500/sp151234.exe", pkgBytes);
            host.HttpHandler.MapBytes("https://downloads.dell.com/catalog/CatalogPC.cab", E2ePayloads.DellCatalogCab(sha256: sha256));
            host.HttpHandler.MapBytes("https://downloads.dell.com/FOLDER12345M/1/Latitude_5430_1.18.0.exe", pkgBytes);
            host.HttpHandler.MapText("https://download.lenovo.com/catalog/21HM_Win11.xml", E2ePayloads.LenovoIndexXml());
            host.HttpHandler.MapText("https://download.lenovo.com/pccbbs/mobiles/n3xuj12w_2_.xml", E2ePayloads.LenovoDescriptorXml(sha256: sha256));
            host.HttpHandler.MapBytes("https://download.lenovo.com/pccbbs/mobiles/winuptp.exe", pkgBytes);
            host.HttpHandler.MapPrefixText("https://www.asus.com/support/api/product.asmx/GetPDBIOS", E2ePayloads.AsusBiosJson());
            host.HttpHandler.MapPrefixText("https://www.acer.com/us-en/support/api/product/bios", E2ePayloads.AcerBiosJson());
            host.HttpHandler.MapPrefixText("https://www.msi.com/api/v1/product/support/panel", E2ePayloads.MsiBiosJson());
            host.HttpHandler.MapPrefixText("https://www.microsoft.com/surface/api/firmware", E2ePayloads.SurfaceFirmwareJson(sha256: sha256));
            host.HttpHandler.MapBytes("https://download.microsoft.com/download/surface/SurfacePro9_Win11_22631_25.021.12345.0.msi", pkgBytes);
            host.HttpHandler.MapBytes("https://cdn.fwupd.org/downloads/firmware.xml.gz", E2ePayloads.FrameworkLvfsXmlGz(sha256: cabSha), "application/gzip");
            host.HttpHandler.MapBytes("https://cdn.fwupd.org/downloads/framework-laptop13-amd7040-3.05.cab", cabBytes);

            host.WindowsUpdateClient.PendingUpdates =
            [
                new BiosWuaFirmwareUpdate(wuaGuid.ToString("D"), "System Firmware 2.0", "2.0", new DateOnly(2025, 3, 1), 1024, BiosUpdateSeverity.Critical, true, "Firmware")
            ];

            var identities = new[]
            {
                E2eIdentities.HpEliteBook(),
                E2eIdentities.DellLatitude(),
                E2eIdentities.LenovoThinkPad(),
                E2eIdentities.AsusRog(),
                E2eIdentities.AcerPredator(),
                E2eIdentities.MsiMag(),
                E2eIdentities.SurfacePro9(),
                E2eIdentities.FrameworkLaptop13(),
                E2eIdentities.GenericPc(firmwareMode: BiosFirmwareMode.Uefi)
            };

            foreach (var id in identities)
            {
                host.SystemProbe.Identity = id;
                var check = await host.Service.CheckForUpdateAsync();
                Assert.Equal(BiosCheckStatus.UpdateAvailable, check.Latest.Status);

                var res = await host.Service.InstallUpdateAsync(
                    new BiosInstallRequest(check.System, check.Current, check.Latest, Approved: true, SuspendBitLocker: true, AllowReboot: false, VerifyHash: true, StagingDirectory: host.StagingDir.Path));

                var provider = host.Service.ResolveProvider(id)!;
                if (provider.Capabilities.CanInstall)
                    Assert.True(res.Succeeded, $"Expected install to succeed for {provider.VendorId} (elevated={elevated}), got: {res.Status} - {res.Message}");
                else
                    Assert.Equal(BiosInstallStatus.Unsupported, res.Status);
            }

            host.AssertZeroShellInvocations();
            host.AssertNoSerialNumberLeaked();
        }
    }

    [Fact]
    public async Task E2E_T1_PCS_04_DefaultWinVerifyTrustVerifierFailsClosedOpaqueBoxThroughDi()
    {
        var identity = E2eIdentities.HpEliteBook();
        var (unsignedBytes, _) = E2ePayloads.BuildDummyBinary("unsigned-payload");
        const string url = "https://ftp.hp.com/pub/softpaq/sp151234.exe";

        // Intentionally DO NOT register StubSignatureVerifier so DI wires the real WinVerifyTrust verifier
        await using var host = BiosE2eTestHost.CreateElevated(identity, registerSignatureVerifier: false);
        host.HttpHandler.MapBytes(url, unsignedBytes);

        var target = BiosLatestInfo.UpdateAvailable("hp", "01.14.00", downloadUrl: url, sha256: null);
        var result = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(identity, identity.CurrentBios, target, Approved: true, SuspendBitLocker: true, AllowReboot: false, VerifyHash: true, StagingDirectory: host.StagingDir.Path));

        Assert.False(result.Succeeded);
        Assert.Equal(BiosInstallStatus.Failed, result.Status);
        Assert.Single(host.HttpHandler.Requests);
        Assert.Contains("Authenticode", result.Message ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.Empty(host.HostProcessLauncher.Calls);
        host.StagingDir.AssertEmpty();
        host.AssertNoSerialNumberLeaked(result: result);
    }

    [Fact]
    public async Task E2E_T1_PCS_05_BiosProviderContractDocDocumentsPureCSharpAndAgentElevationMandates()
    {
        var repoRoot = E2ePayloads.FindRepoRoot();
        var docPath = Path.Combine(repoRoot, "docs", "bios-provider-contract.md");
        var doc = await File.ReadAllTextAsync(docPath);

        Assert.Contains("Pure C# Only", doc, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("No PowerShell or Shell Scripts", doc, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Agent Elevation Span", doc, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("IElevatedCommandBridge", doc, StringComparison.Ordinal);
        Assert.DoesNotContain("RunPowerShellAsync(", doc, StringComparison.Ordinal);
    }

    // =========================================================================
    // Area 1.9: Agent Elevation Span & Typed Admin-Pipe Operations (E2E-T1-ELV-01..06)
    // =========================================================================

    [Fact]
    public async Task E2E_T1_ELV_01_UnElevatedHostWithConnectedBridgeRoutesBitLockerSuspendThroughAgent()
    {
        var identity = E2eIdentities.HpEliteBook();
        var (pkgBytes, sha256) = E2ePayloads.BuildDummyBinary("elv01-hp");
        const string url = "https://ftp.hp.com/pub/softpaq/sp151234.exe";

        await using var host = await BiosE2eTestHost.CreateAsync(new BiosE2eHostOptions
        {
            InitialIdentity = identity,
            IsProcessElevated = false,
            UseLiveAgentPipe = true,
            UseHermeticRealSafetyProbe = true,
            HermeticBitLockerActive = true
        });
        host.HttpHandler.MapBytes(url, pkgBytes);

        var target = BiosLatestInfo.UpdateAvailable("hp", "01.14.00", downloadUrl: url, sha256: sha256);
        var result = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(identity, identity.CurrentBios, target, Approved: true, SuspendBitLocker: true, AllowReboot: false, VerifyHash: true, StagingDirectory: host.StagingDir.Path));

        Assert.True(result.Succeeded, result.Message);
        Assert.Equal(BiosInstallStatus.StagedForReboot, result.Status);
        Assert.True(result.BitLockerSuspended);

        // Real DefaultBiosInstallSafetyProbe observed HasElevation == true via IElevationContext.HasAdminCapabilities
        Assert.NotNull(host.HermeticSafetyProbe?.LastRealSnapshot);
        Assert.True(host.HermeticSafetyProbe!.LastRealSnapshot!.HasElevation);

        // Host ran 0 manage-bde.exe and 0 installers; Agent ran BOTH
        Assert.Empty(host.HostProcessLauncher.Calls);
        Assert.Contains(host.LivePipe!.AgentProcessLauncher.Calls, c => c.ToolName.Equals("manage-bde.exe", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(host.LivePipe!.AgentProcessLauncher.Calls, c => c.ToolName.Equals("sp151234.exe", StringComparison.OrdinalIgnoreCase));
        host.AssertNoSerialNumberLeaked(result: result);
    }

    public static TheoryData<string, BiosSystemIdentity, string, string, string[]> AgentBridgedOemInstallCases => new()
    {
        { "hp", E2eIdentities.HpEliteBook(), "https://ftp.hp.com/pub/softpaq/sp151234.exe", "sp151234.exe", ["-s", "-r"] },
        { "dell", E2eIdentities.DellLatitude(), "https://downloads.dell.com/FOLDER12345M/1/Latitude_5430_1.18.0.exe", "Latitude_5430_1.18.0.exe", ["/s"] },
        { "lenovo", E2eIdentities.LenovoThinkPad(), "https://download.lenovo.com/pccbbs/mobiles/winuptp.exe", "winuptp.exe", ["-s"] },
        { "microsoft", E2eIdentities.SurfacePro9(), "https://download.microsoft.com/download/surface/SurfacePro9.msi", "msiexec.exe", ["/i", "/qn", "/norestart"] },
        { "framework", E2eIdentities.FrameworkLaptop13(), "https://cdn.fwupd.org/downloads/framework-laptop13-3.05.cab", "pnputil.exe", ["/add-driver", "/install"] }
    };

    [Theory]
    [MemberData(nameof(AgentBridgedOemInstallCases))]
    public async Task E2E_T1_ELV_02_UnElevatedHostWithConnectedBridgeRoutesVerifiedOemStagingThroughAgent(
        string vendorId, BiosSystemIdentity identity, string downloadUrl, string expectedAgentTool, string[] expectedArgTokens)
    {
        var (pkgBytes, sha256) = vendorId == "framework"
            ? E2ePayloads.FrameworkCabCapsule()
            : E2ePayloads.BuildDummyBinary($"elv02-{vendorId}");

        await using var host = await BiosE2eTestHost.CreateAsync(new BiosE2eHostOptions
        {
            InitialIdentity = identity,
            IsProcessElevated = false,
            UseLiveAgentPipe = true,
            UseHermeticRealSafetyProbe = true
        });
        host.HttpHandler.MapBytes(downloadUrl, pkgBytes);

        var target = BiosLatestInfo.UpdateAvailable(vendorId, "9.99.0", downloadUrl: downloadUrl, sha256: sha256);
        var result = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(identity, identity.CurrentBios, target, Approved: true, SuspendBitLocker: true, AllowReboot: false, VerifyHash: true, StagingDirectory: host.StagingDir.Path));

        Assert.True(result.Succeeded, $"Vendor {vendorId} failed: {result.Message}");
        Assert.Equal(BiosInstallStatus.StagedForReboot, result.Status);
        Assert.True(result.BitLockerSuspended);

        // ZERO local executions on un-elevated Host
        Assert.Empty(host.HostProcessLauncher.Calls);

        // Agent re-verified signature and executed expected tool with allowlisted no-reboot flags
        Assert.NotEmpty(host.LivePipe!.AgentSignatureVerifier.VerifiedFilePaths);
        var matchingCalls = host.LivePipe.AgentProcessLauncher.Calls
            .Where(c => c.ToolName.Equals(expectedAgentTool, StringComparison.OrdinalIgnoreCase))
            .ToList();
        Assert.NotEmpty(matchingCalls);
        var installerCall = matchingCalls[^1];
        var isHpSoftPaq = vendorId == "hp" && AgentBiosOperations.IsHpSoftPaqExecutable(expectedAgentTool);
        foreach (var token in expectedArgTokens)
        {
            if (isHpSoftPaq && token == "-r") continue;
            Assert.Contains(token, installerCall.Arguments, StringComparer.OrdinalIgnoreCase);
        }

        // Explicitly enforce provider-specific reboot suppression polarity for AllowReboot == false
        switch (vendorId)
        {
            case "hp":
                if (isHpSoftPaq)
                    Assert.DoesNotContain("-r", installerCall.Arguments, StringComparer.OrdinalIgnoreCase);
                else
                    Assert.Contains("-r", installerCall.Arguments, StringComparer.OrdinalIgnoreCase);
                break;
            case "dell":
                Assert.DoesNotContain("/r", installerCall.Arguments, StringComparer.OrdinalIgnoreCase);
                break;
            case "lenovo":
                Assert.DoesNotContain("-r", installerCall.Arguments, StringComparer.OrdinalIgnoreCase);
                break;
            case "microsoft":
                Assert.Contains("/norestart", installerCall.Arguments, StringComparer.OrdinalIgnoreCase);
                break;
            case "framework":
                Assert.Contains("/add-driver", installerCall.Arguments, StringComparer.OrdinalIgnoreCase);
                break;
        }

        // Agent cleaned up its admin staging copy after execution
        host.LivePipe.AgentStagingDir.AssertEmpty();
        host.AssertNoSerialNumberLeaked(result: result);
        host.AssertZeroShellInvocations();
    }

    [Fact]
    public async Task E2E_T1_ELV_03_UnElevatedHostWithConnectedBridgeRoutesWindowsUpdateCapsuleThroughAgent()
    {
        var identity = E2eIdentities.GenericPc(firmwareMode: BiosFirmwareMode.Uefi);
        var updateGuid = Guid.NewGuid();

        await using var host = await BiosE2eTestHost.CreateAsync(new BiosE2eHostOptions
        {
            InitialIdentity = identity,
            IsProcessElevated = false,
            UseLiveAgentPipe = true,
            UseHermeticRealSafetyProbe = true
        });
        host.LivePipe!.AgentWuaApi.NextInstallOutcome = new UpdateInstallOutcome(AgentWindowsUpdate.SucceededCode, 0, RebootRequired: true);

        var target = BiosLatestInfo.UpdateAvailable("windows-update", "2.5.0", packageId: updateGuid.ToString("D"));
        var result = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(identity, identity.CurrentBios, target, Approved: true, SuspendBitLocker: true, AllowReboot: false));

        Assert.True(result.Succeeded, result.Message);
        Assert.Equal(BiosInstallStatus.StagedForReboot, result.Status);
        Assert.True(result.RequiresReboot);
        Assert.True(result.BitLockerSuspended);

        // Host ran 0 local WUA installs and 0 local manage-bde.exe calls
        Assert.Empty(host.WindowsUpdateClient.InstalledUpdateIds);
        Assert.Empty(host.HostProcessLauncher.Calls);

        // Agent executed WUA search/download/install with the exact GUID and suspended BitLocker
        Assert.Contains(host.LivePipe.AgentWuaApi.SearchQueries, q => q.Contains(updateGuid.ToString("D"), StringComparison.OrdinalIgnoreCase));
        Assert.Equal(1, host.LivePipe.AgentWuaApi.InstalledCount);
        Assert.Contains(host.LivePipe.AgentProcessLauncher.Calls, c => c.ToolName.Equals("manage-bde.exe", StringComparison.OrdinalIgnoreCase));
        host.AssertZeroShellInvocations();
        host.AssertNoSerialNumberLeaked(result: result);
    }

    [Fact]
    public async Task E2E_T1_ELV_04_ElevatedHostRunsDirectlyWithoutRequiringAgentPipe()
    {
        var (pkgBytes, sha256) = E2ePayloads.BuildDummyBinary("elv04-direct");
        var (cabBytes, cabSha) = E2ePayloads.FrameworkCabCapsule();
        var wuaGuid = Guid.NewGuid();

        await using var host = await BiosE2eTestHost.CreateAsync(new BiosE2eHostOptions
        {
            InitialIdentity = E2eIdentities.HpEliteBook(),
            IsProcessElevated = true,
            IsAdminHelperConnected = false,
            UseDisconnectedBridge = true
        });

        host.HttpHandler.MapBytes("https://ftp.hp.com/pub/softpaq/sp151234.exe", pkgBytes);
        host.HttpHandler.MapBytes("https://downloads.dell.com/FOLDER1/dell.exe", pkgBytes);
        host.HttpHandler.MapBytes("https://download.lenovo.com/pccbbs/winuptp.exe", pkgBytes);
        host.HttpHandler.MapBytes("https://download.microsoft.com/surface/SurfacePro9.msi", pkgBytes);
        host.HttpHandler.MapBytes("https://cdn.fwupd.org/downloads/fw.cab", cabBytes);

        var targets = new (BiosSystemIdentity Id, BiosLatestInfo Target)[]
        {
            (E2eIdentities.HpEliteBook(), BiosLatestInfo.UpdateAvailable("hp", "01.14.00", downloadUrl: "https://ftp.hp.com/pub/softpaq/sp151234.exe", sha256: sha256)),
            (E2eIdentities.DellLatitude(), BiosLatestInfo.UpdateAvailable("dell", "1.18.0", downloadUrl: "https://downloads.dell.com/FOLDER1/dell.exe", sha256: sha256)),
            (E2eIdentities.LenovoThinkPad(), BiosLatestInfo.UpdateAvailable("lenovo", "N3XET52W", downloadUrl: "https://download.lenovo.com/pccbbs/winuptp.exe", sha256: sha256)),
            (E2eIdentities.SurfacePro9(), BiosLatestInfo.UpdateAvailable("microsoft", "15.102.143", downloadUrl: "https://download.microsoft.com/surface/SurfacePro9.msi", sha256: sha256)),
            (E2eIdentities.FrameworkLaptop13(), BiosLatestInfo.UpdateAvailable("framework", "3.05", downloadUrl: "https://cdn.fwupd.org/downloads/fw.cab", sha256: cabSha)),
            (E2eIdentities.GenericPc(firmwareMode: BiosFirmwareMode.Uefi), BiosLatestInfo.UpdateAvailable("windows-update", "2.0", packageId: wuaGuid.ToString("D")))
        };

        foreach (var (id, target) in targets)
        {
            host.SystemProbe.Identity = id;
            var res = await host.Service.InstallUpdateAsync(
                new BiosInstallRequest(id, id.CurrentBios, target, Approved: true, SuspendBitLocker: true, AllowReboot: false, VerifyHash: true, StagingDirectory: host.StagingDir.Path));
            Assert.True(res.Succeeded, $"Elevated direct install failed for {target.ProviderId}: {res.Message}");
        }

        Assert.True(host.HostProcessLauncher.Calls.Count >= 11); // 6 manage-bde + 5 OEM installers
        Assert.Equal([wuaGuid], host.WindowsUpdateClient.InstalledUpdateIds);
        host.AssertZeroShellInvocations();
    }

    [Fact]
    public async Task E2E_T1_ELV_05_CrossPlatformAdminPipeTypedBiosRoundTrips()
    {
        await using var pipe = await LiveAgentPipeFixture.StartAsync();
        using var dir = new IsolatedStagingDir("elv05");

        // 1. Typed BitLocker suspend round-trip
        var bdeRes = await pipe.Client!.SuspendBitLockerAsync("C:");
        Assert.True(bdeRes.Allowed);
        Assert.True(bdeRes.Suspended);
        Assert.Equal(0, bdeRes.ExitCode);

        // 2. Typed verified BIOS installer round-trip
        var pkgPath = Path.Combine(dir.Path, "Latitude_1.18.0.exe");
        var (pkgBytes, sha256) = E2ePayloads.BuildDummyBinary("elv05-dell");
        await File.WriteAllBytesAsync(pkgPath, pkgBytes);

        var installRes = await pipe.Client.RunBiosInstallerAsync(new BiosAgentInstallRequest(
            VendorId: "dell",
            InstallMode: BiosAgentInstallModes.DellBiosExe,
            PackagePath: pkgPath,
            ExpectedSha256: sha256,
            AllowReboot: false));

        Assert.True(installRes.Allowed);
        Assert.True(installRes.Executed);
        Assert.Equal(0, installRes.ExitCode);
        pipe.AgentStagingDir.AssertEmpty();

        // 3. Typed WUA GUID install round-trip
        var wuaGuid = Guid.NewGuid();
        var wuaRes = await pipe.Client.InstallBiosWindowsUpdateAsync(wuaGuid);
        Assert.True(wuaRes.Succeeded);
        Assert.Equal(AgentWindowsUpdate.SucceededCode, wuaRes.ResultCode);
        Assert.True(wuaRes.RebootRequired);
    }

    [Fact]
    public void E2E_T1_ELV_06_DiCompatibilityWithAndWithoutElevationContextAndBridge()
    {
        // Case A: WITH IElevationContext + IElevatedCommandBridge registered (HostServices parity)
        var withElevation = new ServiceCollection();
        withElevation.AddSingleton<IElevationContext>(new StubElevationContext(false, false));
        withElevation.AddSingleton<IElevatedCommandBridge>(new DisconnectedBridgeStub());
        withElevation.AddBiosUpdates();
        withElevation.AddBuiltInBiosUpdateProviders();
        using (var sp = withElevation.BuildServiceProvider(new ServiceProviderOptions { ValidateOnBuild = true, ValidateScopes = true }))
        {
            var svc = sp.GetRequiredService<IBiosUpdateService>();
            Assert.Equal(9, svc.Providers.Count);
        }

        // Case B: WITHOUT IElevationContext or IElevatedCommandBridge registered
        var withoutElevation = new ServiceCollection();
        withoutElevation.AddBiosUpdates();
        withoutElevation.AddBuiltInBiosUpdateProviders();
        using (var sp = withoutElevation.BuildServiceProvider(new ServiceProviderOptions { ValidateOnBuild = true, ValidateScopes = true }))
        {
            var svc = sp.GetRequiredService<IBiosUpdateService>();
            Assert.Equal(9, svc.Providers.Count);
        }
    }

    private static string StripCSharpComments(string source)
    {
        var sb = new StringBuilder(source.Length);
        int i = 0;
        StripCSharpCommentsCore(source, ref i, sb, stopAtCloseBrace: false);
        return sb.ToString();
    }

    private static void StripCSharpCommentsCore(string source, ref int i, StringBuilder sb, bool stopAtCloseBrace)
    {
        int braceDepth = stopAtCloseBrace ? 1 : 0;

        while (i < source.Length)
        {
            // 1. Block comments /* ... */ (preserve newlines)
            if (i + 1 < source.Length && source[i] == '/' && source[i + 1] == '*')
            {
                i += 2;
                while (i < source.Length)
                {
                    if (i + 1 < source.Length && source[i] == '*' && source[i + 1] == '/')
                    {
                        i += 2;
                        break;
                    }
                    if (source[i] == '\n')
                        sb.Append('\n');
                    i++;
                }
                continue;
            }

            // 2. Single-line comments // ...
            if (i + 1 < source.Length && source[i] == '/' && source[i + 1] == '/')
            {
                i += 2;
                while (i < source.Length && source[i] != '\n')
                    i++;
                continue;
            }

            // 3. Raw string literals: optional one or more '$' followed by 3+ '"'
            if (source[i] == '$' || source[i] == '"')
            {
                int k = i;
                while (k < source.Length && source[k] == '$')
                    k++;
                int q = k;
                while (q < source.Length && source[q] == '"')
                    q++;
                int quoteCount = q - k;
                if (quoteCount >= 3)
                {
                    // Emit prefix ($*) and opening quotes
                    sb.Append(source, i, q - i);
                    i = q;
                    while (i < source.Length)
                    {
                        if (source[i] == '"')
                        {
                            int closeStart = i;
                            while (i < source.Length && source[i] == '"')
                                i++;
                            sb.Append(source, closeStart, i - closeStart);
                            if (i - closeStart >= quoteCount)
                                break;
                        }
                        else
                        {
                            sb.Append(source[i++]);
                        }
                    }
                    continue;
                }
            }

            // 4. Verbatim & verbatim-interpolated strings: @"...", $@"...", @$"..."
            bool isVerbatimInterpolated =
                i + 2 < source.Length
                && ((source[i] == '$' && source[i + 1] == '@' && source[i + 2] == '"')
                    || (source[i] == '@' && source[i + 1] == '$' && source[i + 2] == '"'));
            bool isVerbatim = i + 1 < source.Length && source[i] == '@' && source[i + 1] == '"';
            if (isVerbatimInterpolated || isVerbatim)
            {
                int prefixLen = isVerbatimInterpolated ? 3 : 2;
                sb.Append(source, i, prefixLen);
                i += prefixLen;
                while (i < source.Length)
                {
                    if (source[i] == '"')
                    {
                        if (i + 1 < source.Length && source[i + 1] == '"')
                        {
                            sb.Append("\"\"");
                            i += 2;
                        }
                        else
                        {
                            sb.Append('"');
                            i++;
                            break;
                        }
                    }
                    else if (isVerbatimInterpolated && source[i] == '{')
                    {
                        if (i + 1 < source.Length && source[i + 1] == '{')
                        {
                            sb.Append("{{");
                            i += 2;
                        }
                        else
                        {
                            sb.Append('{');
                            i++;
                            StripCSharpCommentsCore(source, ref i, sb, stopAtCloseBrace: true);
                        }
                    }
                    else
                    {
                        sb.Append(source[i++]);
                    }
                }
                continue;
            }

            // 5. Normal & interpolated strings: "...", $"..."
            bool isInterpolated = i + 1 < source.Length && source[i] == '$' && source[i + 1] == '"';
            if (isInterpolated || source[i] == '"')
            {
                int prefixLen = isInterpolated ? 2 : 1;
                sb.Append(source, i, prefixLen);
                i += prefixLen;
                while (i < source.Length)
                {
                    if (source[i] == '\\' && i + 1 < source.Length)
                    {
                        sb.Append(source[i]);
                        sb.Append(source[i + 1]);
                        i += 2;
                    }
                    else if (source[i] == '"')
                    {
                        sb.Append('"');
                        i++;
                        break;
                    }
                    else if (isInterpolated && source[i] == '{')
                    {
                        if (i + 1 < source.Length && source[i + 1] == '{')
                        {
                            sb.Append("{{");
                            i += 2;
                        }
                        else
                        {
                            sb.Append('{');
                            i++;
                            StripCSharpCommentsCore(source, ref i, sb, stopAtCloseBrace: true);
                        }
                    }
                    else
                    {
                        sb.Append(source[i++]);
                    }
                }
                continue;
            }

            // 6. Character literals: '...'
            if (source[i] == '\'')
            {
                sb.Append(source[i++]);
                while (i < source.Length)
                {
                    if (source[i] == '\\' && i + 1 < source.Length)
                    {
                        sb.Append(source[i]);
                        sb.Append(source[i + 1]);
                        i += 2;
                    }
                    else if (source[i] == '\'')
                    {
                        sb.Append('\'');
                        i++;
                        break;
                    }
                    else
                    {
                        sb.Append(source[i++]);
                    }
                }
                continue;
            }

            if (stopAtCloseBrace)
            {
                if (source[i] == '{')
                {
                    braceDepth++;
                    sb.Append(source[i++]);
                    continue;
                }
                if (source[i] == '}')
                {
                    braceDepth--;
                    sb.Append(source[i++]);
                    if (braceDepth == 0)
                        return;
                    continue;
                }
            }

            sb.Append(source[i++]);
        }
    }
}
