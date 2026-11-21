using System.Net;
using System.Net.Sockets;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Bios;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Sensors;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Tests.Bios;

public sealed class LenovoBiosUpdateProviderTests
{
    private static readonly HashSet<string> ForbiddenShellBinaries = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell", "powershell.exe", "pwsh", "pwsh.exe",
        "cmd", "cmd.exe", "sh", "bash", "zsh",
    };

    private static readonly string[] ForbiddenScriptExtensions = [".ps1", ".bat", ".cmd", ".sh"];

    private const string SampleSha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    private const string SampleIndexXml = """
        <?xml version="1.0" encoding="utf-8"?>
        <packages count="2">
          <package>
            <category>Display and Video Graphics</category>
            <location>https://download.lenovo.com/pccbbs/mobiles/gfx01.xml</location>
            <version>31.0.101.5186</version>
          </package>
          <package>
            <category>BIOS/UEFI</category>
            <location>https://download.lenovo.com/pccbbs/mobiles/n32uj20w_2_.xml</location>
            <version>1.68</version>
            <BiosVersion>N32ET92W</BiosVersion>
            <release>2024-06-15</release>
          </package>
        </packages>
        """;

    private const string SampleDescriptorXml = """
        <?xml version="1.0" encoding="utf-8"?>
        <Package id="n32uj20w" version="N32ET92W (1.68 )">
          <Title><Desc id="EN">ThinkPad BIOS Update Utility</Desc></Title>
          <Summary><Desc id="EN">Security and stability UEFI BIOS update.</Desc></Summary>
          <ReleaseDate>2024-06-15</ReleaseDate>
          <Severity type="1" />
          <Reboot type="3" />
          <Install>
            <Cmdline id="EN">winuptp.exe -s</Cmdline>
          </Install>
          <Files>
            <Installer>
              <File>
                <Name>n32uj20w.exe</Name>
                <CRC>0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF</CRC>
                <Size>24117248</Size>
              </File>
            </Installer>
            <Readme>
              <File>
                <Name>n32uj20w.txt</Name>
              </File>
            </Readme>
          </Files>
        </Package>
        """;

    // -------------------------------------------------------------------------
    // L1 — Metadata & Capabilities
    // -------------------------------------------------------------------------

    [Fact]
    public void Metadata_MatchesContract()
    {
        var provider = new LenovoBiosUpdateProvider();

        Assert.Equal("lenovo", provider.VendorId);
        Assert.Equal("Lenovo", provider.DisplayName);
        Assert.Equal(100, provider.Priority);
        Assert.True(provider.Capabilities.CanCheckLatest);
        Assert.True(provider.Capabilities.CanInstall);
        Assert.True(provider.Capabilities.SupportsSilentInstall);
        Assert.True(provider.Capabilities.RequiresReboot);
        Assert.True(provider.Capabilities.RequiresElevation);
        Assert.True(provider.Capabilities.RequiresInternet);
    }

    // -------------------------------------------------------------------------
    // L2 — CanHandle Positive & Negative
    // -------------------------------------------------------------------------

    [Theory]
    [InlineData("LENOVO", "")]
    [InlineData("Lenovo", "")]
    [InlineData("Lenovo Group Limited", "")]
    [InlineData("Generic OEM", "LENOVO")]
    public void CanHandle_LenovoManufacturers_ReturnsTrue(string manufacturer, string boardManufacturer)
    {
        var provider = new LenovoBiosUpdateProvider();
        var identity = BiosIdentityFactory.Lenovo(manufacturer: manufacturer) with
        {
            BoardManufacturer = boardManufacturer,
        };

        Assert.True(provider.CanHandle(identity));
    }

    [Theory]
    [InlineData("HP")]
    [InlineData("Dell Inc.")]
    [InlineData("MyLenovoish Corp")]
    [InlineData("ASUSTeK COMPUTER INC.")]
    public void CanHandle_NonLenovo_ReturnsFalse(string manufacturer)
    {
        var provider = new LenovoBiosUpdateProvider();
        Assert.False(provider.CanHandle(BiosIdentityFactory.GenericUefi(manufacturer)));
    }

    [Fact]
    public void CanHandle_UnknownAndNull_ReturnsFalseWithoutThrowing()
    {
        var provider = new LenovoBiosUpdateProvider();
        Assert.False(provider.CanHandle(BiosIdentityFactory.Unknown()));
        Assert.False(provider.CanHandle(null!));
    }

    // -------------------------------------------------------------------------
    // L3 — GetCurrentVersionAsync SMBIOS Normalization Matrix
    // -------------------------------------------------------------------------

    [Theory]
    [InlineData("N32ET89W (1.65 )", "N32ET89W", "N32ET", "1.65")]
    [InlineData("R1YET42W (1.19)", "R1YET42W", "R1YET", "1.19")]
    [InlineData("N3XET48W (1.23 )", "N3XET48W", "N3XET", "1.23")]
    [InlineData("N32ET89W", "N32ET89W", "N32ET", null)]
    [InlineData("J2CN57WW", "J2CN57WW", "J2CN", null)]
    [InlineData("1.65", "1.65", "", "1.65")]
    [InlineData("", "", "", null)]
    public async Task GetCurrentVersionAsync_NormalizesLenovoVersionsAndNeverExposesSerialNumber(
        string rawVersion,
        string expectedVersion,
        string expectedFamily,
        string? expectedNumeric)
    {
        var log = new CapturedLog();
        var provider = new LenovoBiosUpdateProvider(log: log.Logger);
        var identity = BiosIdentityFactory.Lenovo(biosVersion: rawVersion);

        var current = await provider.GetCurrentVersionAsync(identity);

        Assert.Equal("lenovo", current.ProviderId);
        Assert.Equal(expectedVersion, current.Version);
        Assert.Equal(expectedFamily, current.Family);
        Assert.NotNull(current.Metadata);
        Assert.Equal("20XW", current.Metadata["mtm"]);

        if (expectedNumeric is not null)
            Assert.Equal(expectedNumeric, current.Metadata["numericVersion"]);
        else
            Assert.False(current.Metadata.ContainsKey("numericVersion"));

        foreach (var kvp in current.Metadata)
        {
            Assert.DoesNotContain(BiosIdentityFactory.SentinelSerialNumber, kvp.Key, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(BiosIdentityFactory.SentinelSerialNumber, kvp.Value, StringComparison.OrdinalIgnoreCase);
        }

        log.AssertDoesNotContainSecret();
    }

    // -------------------------------------------------------------------------
    // L4 — Win11 Primary, Win11->Win10 Fallback, Win10 Direct & Both 404
    // -------------------------------------------------------------------------

    [Fact]
    public async Task GetLatestVersionAsync_Win11Primary_ParsesIndexAndDescriptor()
    {
        var handler = new FakeBiosHttpHandler()
            .MapText("https://download.lenovo.com/catalog/20XW_Win11.xml", SampleIndexXml, "application/xml")
            .MapText("https://download.lenovo.com/pccbbs/mobiles/n32uj20w_2_.xml", SampleDescriptorXml, "application/xml");

        var log = new CapturedLog();
        var provider = LenovoBiosUpdateProvider.CreateWithHandler(handler, log: log.Logger);
        var identity = BiosIdentityFactory.Lenovo();
        var current = await provider.GetCurrentVersionAsync(identity);

        var latest = await provider.GetLatestVersionAsync(identity, current);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal("lenovo", latest.ProviderId);
        Assert.Equal("N32ET92W", latest.LatestVersion);
        Assert.Equal("n32uj20w", latest.PackageId);
        Assert.Equal(new DateOnly(2024, 6, 15), latest.ReleaseDate);
        Assert.Equal(BiosUpdateSeverity.Critical, latest.Severity);
        Assert.Equal("Security and stability UEFI BIOS update.", latest.ReleaseSummary);
        Assert.Equal("https://download.lenovo.com/pccbbs/mobiles/n32uj20w.exe", latest.DownloadUrl);
        Assert.Equal("https://download.lenovo.com/pccbbs/mobiles/n32uj20w.txt", latest.ReleaseNotesUrl);
        Assert.Equal(SampleSha256, latest.Sha256);
        Assert.Equal(24117248, latest.SizeBytes);
        Assert.True(latest.RequiresReboot);
        Assert.Equal("Win11", latest.Metadata?["catalogOs"]);
        Assert.Equal("20XW", latest.Metadata?["mtm"]);
        Assert.Equal(BiosAgentInstallModes.LenovoWinUptp, latest.Metadata?["installMode"]);
        log.AssertDoesNotContainSecret();
    }

    [Fact]
    public async Task GetLatestVersionAsync_Win11404_FallsBackToWin10()
    {
        var handler = new FakeBiosHttpHandler()
            .MapStatus("https://download.lenovo.com/catalog/20XW_Win11.xml", HttpStatusCode.NotFound)
            .MapText("https://download.lenovo.com/catalog/20XW_Win10.xml", SampleIndexXml, "application/xml")
            .MapText("https://download.lenovo.com/pccbbs/mobiles/n32uj20w_2_.xml", SampleDescriptorXml, "application/xml");

        var provider = LenovoBiosUpdateProvider.CreateWithHandler(handler);
        var identity = BiosIdentityFactory.Lenovo(osVersion: "Microsoft Windows 11 Pro 10.0.22631");
        var current = await provider.GetCurrentVersionAsync(identity);

        var latest = await provider.GetLatestVersionAsync(identity, current);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal("Win10", latest.Metadata?["catalogOs"]);
        Assert.Equal(3, handler.Requests.Count);
        Assert.EndsWith("20XW_Win11.xml", handler.Requests[0].RequestUri!.AbsoluteUri);
        Assert.EndsWith("20XW_Win10.xml", handler.Requests[1].RequestUri!.AbsoluteUri);
    }

    [Fact]
    public async Task GetLatestVersionAsync_Win10Direct_NeverRequestsWin11_AndBoth404ReturnsUnsupported()
    {
        var win10Handler = new FakeBiosHttpHandler()
            .MapText("https://download.lenovo.com/catalog/20XW_Win10.xml", SampleIndexXml, "application/xml")
            .MapText("https://download.lenovo.com/pccbbs/mobiles/n32uj20w_2_.xml", SampleDescriptorXml, "application/xml");

        var win10Provider = LenovoBiosUpdateProvider.CreateWithHandler(win10Handler);
        var win10Id = BiosIdentityFactory.Lenovo(osVersion: "Microsoft Windows 10 Pro 10.0.19045");
        var latest = await win10Provider.GetLatestVersionAsync(win10Id, await win10Provider.GetCurrentVersionAsync(win10Id));

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.DoesNotContain(win10Handler.Requests, r => r.RequestUri!.AbsoluteUri.Contains("_Win11.xml", StringComparison.OrdinalIgnoreCase));

        var notFoundHandler = new FakeBiosHttpHandler(); // unmatched -> 404
        var notFoundProvider = LenovoBiosUpdateProvider.CreateWithHandler(notFoundHandler);
        var win11Id = BiosIdentityFactory.Lenovo();
        var unsupported = await notFoundProvider.GetLatestVersionAsync(win11Id, win11Id.CurrentBios);
        Assert.Equal(BiosCheckStatus.UnsupportedHardware, unsupported.Status);
        Assert.Equal(2, notFoundHandler.Requests.Count);
    }

    // -------------------------------------------------------------------------
    // L5 — Symbolic vs Numeric & Cross-Family Version Comparison
    // -------------------------------------------------------------------------

    [Theory]
    [InlineData("1.68", BiosCheckStatus.UpdateAvailable)]
    [InlineData("1.65", BiosCheckStatus.UpToDate)]
    [InlineData("1.68/1.22", BiosCheckStatus.UpdateAvailable)]
    [InlineData("N32ET89W", BiosCheckStatus.UpToDate)]
    [InlineData("N32ET92W", BiosCheckStatus.UpdateAvailable)]
    public async Task GetLatestVersionAsync_SymbolicNumericAndSlashPairComparison(
        string descriptorVersion,
        BiosCheckStatus expectedStatus)
    {
        var descXml = $"""
            <Package id="n32uj20w" version="{descriptorVersion}">
              <ReleaseDate>2024-06-15</ReleaseDate>
              <Files><Installer><File><Name>n32uj20w.exe</Name></File></Installer></Files>
            </Package>
            """;

        var handler = new FakeBiosHttpHandler()
            .MapText("https://download.lenovo.com/catalog/20XW_Win11.xml", SampleIndexXml, "application/xml")
            .MapText("https://download.lenovo.com/pccbbs/mobiles/n32uj20w_2_.xml", descXml, "application/xml");

        var provider = LenovoBiosUpdateProvider.CreateWithHandler(handler);
        var identity = BiosIdentityFactory.Lenovo(biosVersion: "N32ET89W (1.65 )");
        var current = await provider.GetCurrentVersionAsync(identity);

        var latest = await provider.GetLatestVersionAsync(identity, current);

        Assert.Equal(expectedStatus, latest.Status);
    }

    [Fact]
    public async Task GetLatestVersionAsync_MultipleFamilies_PrefersMatchingFamilyAndRejectsCrossFamilyOnly()
    {
        const string multiIndex = """
            <packages>
              <package>
                <category>BIOS/UEFI</category>
                <location>https://download.lenovo.com/pccbbs/mobiles/n33uj99w.xml</location>
                <BiosVersion>N33ET99W</BiosVersion>
              </package>
              <package>
                <category>BIOS/UEFI</category>
                <location>https://download.lenovo.com/pccbbs/mobiles/n32uj20w.xml</location>
                <BiosVersion>N32ET92W</BiosVersion>
              </package>
            </packages>
            """;

        const string n33Desc = """
            <Package id="n33uj99w" version="N33ET99W">
              <Files><Installer><File><Name>n33uj99w.exe</Name></File></Installer></Files>
            </Package>
            """;

        const string n32Desc = """
            <Package id="n32uj20w" version="N32ET92W">
              <Files><Installer><File><Name>n32uj20w.exe</Name></File></Installer></Files>
            </Package>
            """;

        var handler = new FakeBiosHttpHandler()
            .MapText("https://download.lenovo.com/catalog/20XW_Win11.xml", multiIndex, "application/xml")
            .MapText("https://download.lenovo.com/pccbbs/mobiles/n33uj99w.xml", n33Desc, "application/xml")
            .MapText("https://download.lenovo.com/pccbbs/mobiles/n32uj20w.xml", n32Desc, "application/xml");

        var provider = LenovoBiosUpdateProvider.CreateWithHandler(handler);
        var identity = BiosIdentityFactory.Lenovo(biosVersion: "N32ET89W (1.65 )");
        var current = await provider.GetCurrentVersionAsync(identity);

        var latest = await provider.GetLatestVersionAsync(identity, current);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal("N32ET92W", latest.LatestVersion);

        // Standalone mismatched family must NOT be treated as UpdateAvailable.
        const string wrongFamilyOnlyIndex = """
            <packages>
              <package>
                <category>BIOS/UEFI</category>
                <location>https://download.lenovo.com/pccbbs/mobiles/n33uj99w.xml</location>
                <BiosVersion>N33ET99W</BiosVersion>
              </package>
            </packages>
            """;

        var wrongHandler = new FakeBiosHttpHandler()
            .MapText("https://download.lenovo.com/catalog/20XW_Win11.xml", wrongFamilyOnlyIndex, "application/xml")
            .MapText("https://download.lenovo.com/pccbbs/mobiles/n33uj99w.xml", n33Desc, "application/xml");

        var wrongProvider = LenovoBiosUpdateProvider.CreateWithHandler(wrongHandler);
        var wrongLatest = await wrongProvider.GetLatestVersionAsync(identity, current);
        Assert.Equal(BiosCheckStatus.UnsupportedHardware, wrongLatest.Status);
    }

    // -------------------------------------------------------------------------
    // L6 — <CRC> Handling (64-hex SHA-256 vs CRC32/SHA-1)
    // -------------------------------------------------------------------------

    [Theory]
    [InlineData("DEADBEEF", null)]
    [InlineData("0123456789abcdef0123456789abcdef01234567", null)]
    [InlineData("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF", SampleSha256)]
    public async Task GetLatestVersionAsync_CrcField_OnlyAcceptsValid64HexSha256(string crcValue, string? expectedSha256)
    {
        var descXml = $"""
            <Package id="n32uj20w" version="N32ET92W">
              <Files><Installer><File><Name>n32uj20w.exe</Name><CRC>{crcValue}</CRC></File></Installer></Files>
            </Package>
            """;

        var handler = new FakeBiosHttpHandler()
            .MapText("https://download.lenovo.com/catalog/20XW_Win11.xml", SampleIndexXml, "application/xml")
            .MapText("https://download.lenovo.com/pccbbs/mobiles/n32uj20w_2_.xml", descXml, "application/xml");

        var provider = LenovoBiosUpdateProvider.CreateWithHandler(handler);
        var identity = BiosIdentityFactory.Lenovo();
        var latest = await provider.GetLatestVersionAsync(identity, await provider.GetCurrentVersionAsync(identity));

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal(expectedSha256, latest.Sha256);
    }

    // -------------------------------------------------------------------------
    // L7 — Invalid / Malicious MTM (0 HTTP Calls)
    // -------------------------------------------------------------------------

    [Theory]
    [InlineData("", "")]
    [InlineData("AB", "")]
    [InlineData("!!@@", "")]
    [InlineData("ABCD", "")]
    [InlineData("21HM;rm -rf /", "")]
    [InlineData("../../etc", "")]
    public async Task GetLatestVersionAsync_InvalidOrMaliciousMtm_ReturnsUnsupportedWithZeroHttpCalls(string badModel, string badSku)
    {
        var handler = new FakeBiosHttpHandler();
        var provider = LenovoBiosUpdateProvider.CreateWithHandler(handler);
        var identity = BiosIdentityFactory.Lenovo(model: badModel, systemSku: badSku);

        var latest = await provider.GetLatestVersionAsync(identity, identity.CurrentBios);

        Assert.Equal(BiosCheckStatus.UnsupportedHardware, latest.Status);
        Assert.Empty(handler.Requests);
    }

    // -------------------------------------------------------------------------
    // L8 — Security: XXE, Disallowed Descriptor URL, Path Traversal / External <Name>, HTTP/Network
    // -------------------------------------------------------------------------

    [Fact]
    public async Task GetLatestVersionAsync_XxeInIndexOrDescriptor_ReturnsFailed()
    {
        const string xxe = """
            <?xml version="1.0"?>
            <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/hosts"> ]>
            <packages><package><category>BIOS</category><location>&xxe;</location></package></packages>
            """;

        var idxHandler = new FakeBiosHttpHandler()
            .MapText("https://download.lenovo.com/catalog/20XW_Win11.xml", xxe, "application/xml");
        var identity = BiosIdentityFactory.Lenovo();

        var idxRes = await LenovoBiosUpdateProvider.CreateWithHandler(idxHandler)
            .GetLatestVersionAsync(identity, identity.CurrentBios);
        Assert.Equal(BiosCheckStatus.Failed, idxRes.Status);

        var descHandler = new FakeBiosHttpHandler()
            .MapText("https://download.lenovo.com/catalog/20XW_Win11.xml", SampleIndexXml, "application/xml")
            .MapText("https://download.lenovo.com/pccbbs/mobiles/n32uj20w_2_.xml", xxe, "application/xml");
        var descRes = await LenovoBiosUpdateProvider.CreateWithHandler(descHandler)
            .GetLatestVersionAsync(identity, identity.CurrentBios);
        Assert.Equal(BiosCheckStatus.Failed, descRes.Status);
    }

    [Theory]
    [InlineData("http://download.lenovo.com/pccbbs/mobiles/n32uj20w.xml")]
    [InlineData("https://evil.com/pccbbs/mobiles/n32uj20w.xml")]
    public async Task GetLatestVersionAsync_DisallowedDescriptorLocation_ReturnsFailedWithoutContactingBadHost(string badLocation)
    {
        var indexXml = $"""
            <packages>
              <package>
                <category>BIOS/UEFI</category>
                <location>{badLocation}</location>
              </package>
            </packages>
            """;

        var handler = new FakeBiosHttpHandler()
            .MapText("https://download.lenovo.com/catalog/20XW_Win11.xml", indexXml, "application/xml");
        var provider = LenovoBiosUpdateProvider.CreateWithHandler(handler);
        var identity = BiosIdentityFactory.Lenovo();

        var latest = await provider.GetLatestVersionAsync(identity, identity.CurrentBios);

        Assert.Equal(BiosCheckStatus.Failed, latest.Status);
        Assert.Single(handler.Requests);
    }

    [Theory]
    [InlineData("../escape.exe")]
    [InlineData("/abs.exe")]
    [InlineData("https://evil.com/bad.exe")]
    [InlineData(@"\\evil\share.exe")]
    [InlineData("sub/../../escape.exe")]
    public async Task GetLatestVersionAsync_UnsafeInstallerFileNameInDescriptor_ReturnsFailed(string badName)
    {
        var descXml = $"""
            <Package id="n32uj20w" version="N32ET92W">
              <Files><Installer><File><Name>{badName}</Name></File></Installer></Files>
            </Package>
            """;

        var handler = new FakeBiosHttpHandler()
            .MapText("https://download.lenovo.com/catalog/20XW_Win11.xml", SampleIndexXml, "application/xml")
            .MapText("https://download.lenovo.com/pccbbs/mobiles/n32uj20w_2_.xml", descXml, "application/xml");

        var provider = LenovoBiosUpdateProvider.CreateWithHandler(handler);
        var identity = BiosIdentityFactory.Lenovo();
        var latest = await provider.GetLatestVersionAsync(identity, await provider.GetCurrentVersionAsync(identity));

        Assert.Equal(BiosCheckStatus.Failed, latest.Status);
    }

    [Fact]
    public async Task GetLatestVersionAsync_NonBiosOnlyAndHttpErrorsAndCancel()
    {
        var identity = BiosIdentityFactory.Lenovo();

        const string nonBiosIndex = "<packages><package><category>Networking</category><location>https://download.lenovo.com/p/net.xml</location></package></packages>";
        var nonBiosHandler = new FakeBiosHttpHandler().MapText("https://download.lenovo.com/catalog/20XW_Win11.xml", nonBiosIndex, "application/xml");
        Assert.Equal(BiosCheckStatus.UnsupportedHardware,
            (await LenovoBiosUpdateProvider.CreateWithHandler(nonBiosHandler).GetLatestVersionAsync(identity, identity.CurrentBios)).Status);

        var err503Handler = new FakeBiosHttpHandler().MapStatus("https://download.lenovo.com/catalog/20XW_Win11.xml", HttpStatusCode.ServiceUnavailable);
        Assert.Equal(BiosCheckStatus.ProviderUnavailable,
            (await LenovoBiosUpdateProvider.CreateWithHandler(err503Handler).GetLatestVersionAsync(identity, identity.CurrentBios)).Status);

        var offlineHandler = new FakeBiosHttpHandler()
            .MapException("https://download.lenovo.com/catalog/20XW_Win11.xml", () => new HttpRequestException("offline", new SocketException()));
        var offlineProvider = LenovoBiosUpdateProvider.CreateWithHandler(offlineHandler);
        Assert.Equal(BiosCheckStatus.Offline, (await offlineProvider.GetLatestVersionAsync(identity, identity.CurrentBios)).Status);

        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => offlineProvider.GetLatestVersionAsync(identity, identity.CurrentBios, cts.Token));
    }

    // -------------------------------------------------------------------------
    // L9 — InstallAsync Elevated Local Happy Path (LenovoWinUptp & LenovoPackageSilent)
    // -------------------------------------------------------------------------

    [Theory]
    [InlineData(BiosAgentInstallModes.LenovoWinUptp, false, 0, new[] { "-s" })]
    [InlineData(BiosAgentInstallModes.LenovoWinUptp, false, 1, new[] { "-s" })]
    [InlineData(BiosAgentInstallModes.LenovoWinUptp, true, 3010, new[] { "-s", "-r" })]
    [InlineData(BiosAgentInstallModes.LenovoPackageSilent, false, 0, new[] { "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART" })]
    [InlineData(BiosAgentInstallModes.LenovoPackageSilent, true, 3010, new[] { "/VERYSILENT", "/SUPPRESSMSGBOXES" })]
    public async Task InstallAsync_ElevatedHappyPath_EnforcesStandardPolarityAndCleansAutoStaging(
        string installMode,
        bool allowReboot,
        int exitCode,
        string[] expectedArgs)
    {
        const string url = "https://download.lenovo.com/pccbbs/mobiles/n32uj20w.exe";
        var payload = TestPayload.FromString($"lenovo-bios-{installMode}-{allowReboot}");
        var handler = new FakeBiosHttpHandler().MapBytes(url, payload.Bytes);

        string? observedAutoDir = null;
        var launcher = CreateGuardedLauncher((call, _) =>
        {
            if (call.BaseName.Equals("manage-bde.exe", StringComparison.OrdinalIgnoreCase))
                return Task.FromResult(new ProcessResult(0, "Suspended", ""));

            observedAutoDir = Path.GetDirectoryName(call.FileName);
            return Task.FromResult(new ProcessResult(exitCode, "Lenovo staged OK", ""));
        });

        var commands = RecordingProcessLauncher.CreateCommandRunner(launcher, isProcessElevated: true);
        var progress = new SyncProgress<BiosInstallProgress>();
        var log = new CapturedLog();
        var provider = LenovoBiosUpdateProvider.CreateWithHandler(handler, commands: commands, log: log.Logger);

        var request = CreateLenovoInstallRequest(url, payload.Sha256, installMode: installMode, allowReboot: allowReboot);
        var result = await provider.InstallAsync(request, progress);

        Assert.True(result.Succeeded);
        Assert.Equal(BiosInstallStatus.StagedForReboot, result.Status);
        Assert.True(result.RequiresReboot);
        Assert.True(result.BitLockerSuspended);
        Assert.Equal(exitCode, result.ExitCode);

        Assert.Equal(2, launcher.Calls.Count);
        Assert.Equal("manage-bde.exe", launcher.Calls[0].BaseName, ignoreCase: true);
        Assert.Equal(expectedArgs, launcher.Calls[1].Arguments);

        Assert.NotNull(observedAutoDir);
        Assert.False(Directory.Exists(observedAutoDir!));
        Assert.Equal(BiosInstallStage.RebootRequired, progress.Reports[^1].Stage);
        log.AssertDoesNotContainSecret();
    }

    [Fact]
    public async Task GetLatestVersionAsync_InnoSetupCmdline_ClassifiesAsLenovoPackageSilent()
    {
        const string silentDesc = """
            <Package id="n32uj20w" version="N32ET92W">
              <Install><Cmdline id="EN">n32uj20w.exe /VERYSILENT /NORESTART</Cmdline></Install>
              <Files><Installer><File><Name>n32uj20w.exe</Name></File></Installer></Files>
            </Package>
            """;

        var handler = new FakeBiosHttpHandler()
            .MapText("https://download.lenovo.com/catalog/20XW_Win11.xml", SampleIndexXml, "application/xml")
            .MapText("https://download.lenovo.com/pccbbs/mobiles/n32uj20w_2_.xml", silentDesc, "application/xml");

        var provider = LenovoBiosUpdateProvider.CreateWithHandler(handler);
        var identity = BiosIdentityFactory.Lenovo();
        var latest = await provider.GetLatestVersionAsync(identity, await provider.GetCurrentVersionAsync(identity));

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal(BiosAgentInstallModes.LenovoPackageSilent, latest.Metadata?["installMode"]);
    }

    // -------------------------------------------------------------------------
    // L10 — Verification Security, SuspendBitLocker=false & SerialNumber Redaction
    // -------------------------------------------------------------------------

    [Fact]
    public async Task InstallAsync_VerificationFailuresAndSerialNumberRedaction()
    {
        using var staging = new TempStagingDir();
        const string url = "https://download.lenovo.com/pccbbs/mobiles/n32uj20w.exe";
        var payload = TestPayload.FromString("lenovo-binary");
        var handler = new FakeBiosHttpHandler().MapBytes(url, payload.Bytes);
        var launcher = CreateGuardedLauncher();
        var commands = RecordingProcessLauncher.CreateCommandRunner(launcher, isProcessElevated: true);
        var provider = LenovoBiosUpdateProvider.CreateWithHandler(handler, commands: commands);

        // Unsafe URL
        var unsafeRes = await provider.InstallAsync(CreateLenovoInstallRequest("https://evil.com/n32uj20w.exe", payload.Sha256));
        Assert.False(unsafeRes.Succeeded);
        Assert.Empty(launcher.Calls);

        // SHA-256 mismatch deletes file and never runs
        var mismatchRes = await provider.InstallAsync(CreateLenovoInstallRequest(url, new string('b', 64), stagingDir: staging.Path));
        Assert.False(mismatchRes.Succeeded);
        Assert.Empty(launcher.Calls);
        Assert.Empty(Directory.GetFiles(staging.Path));

        // No SHA-256 + Authenticode false deletes file and never runs
        var unsignedProvider = LenovoBiosUpdateProvider.CreateWithHandler(
            handler,
            commands: commands,
            signatureVerifier: new FakeSignatureVerifier(false));
        var unsignedRes = await unsignedProvider.InstallAsync(CreateLenovoInstallRequest(url, sha256: null, stagingDir: staging.Path));
        Assert.False(unsignedRes.Succeeded);
        Assert.Empty(launcher.Calls);
        Assert.Empty(Directory.GetFiles(staging.Path));

        // Non-zero exit code with SerialNumber redaction + SuspendBitLocker = false
        var failLauncher = CreateGuardedLauncher((_, _) =>
            Task.FromResult(new ProcessResult(2, "", $"Lenovo flash failed SN={BiosIdentityFactory.SentinelSerialNumber}")));
        var log = new CapturedLog();
        var failProvider = LenovoBiosUpdateProvider.CreateWithHandler(
            handler,
            commands: RecordingProcessLauncher.CreateCommandRunner(failLauncher, isProcessElevated: true),
            log: log.Logger);

        var failRes = await failProvider.InstallAsync(
            CreateLenovoInstallRequest(url, payload.Sha256, suspendBitLocker: false, stagingDir: staging.Path));

        Assert.False(failRes.Succeeded);
        Assert.Equal(2, failRes.ExitCode);
        Assert.Single(failLauncher.Calls);
        Assert.Contains("[REDACTED]", failRes.LogTail ?? "");
        Assert.DoesNotContain(BiosIdentityFactory.SentinelSerialNumber, failRes.LogTail ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(BiosIdentityFactory.SentinelSerialNumber, failRes.Message, StringComparison.OrdinalIgnoreCase);
        log.AssertDoesNotContainSecret();
        Assert.True(Directory.Exists(staging.Path));
    }

    // -------------------------------------------------------------------------
    // L11 — Un-Elevated Agent Bridge (Mock Bridge, Live Named Pipe, Disconnected)
    // -------------------------------------------------------------------------

    [Theory]
    [InlineData(BiosAgentInstallModes.LenovoWinUptp, false)]
    [InlineData(BiosAgentInstallModes.LenovoPackageSilent, true)]
    public async Task InstallAsync_UnElevatedConnectedBridge_RoutesThroughBridgeWithPinnedSha256(
        string installMode,
        bool allowReboot)
    {
        const string url = "https://download.lenovo.com/pccbbs/mobiles/n32uj20w.exe";
        var payload = TestPayload.FromString($"lenovo-bridge-{installMode}-{allowReboot}");
        var handler = new FakeBiosHttpHandler().MapBytes(url, payload.Bytes);
        var localLauncher = CreateGuardedLauncher();
        var bridge = new RecordingBiosBridge();

        var provider = LenovoBiosUpdateProvider.CreateWithHandler(
            handler,
            commands: RecordingProcessLauncher.CreateCommandRunner(localLauncher, isProcessElevated: false, elevatedBridge: bridge),
            signatureVerifier: new FakeSignatureVerifier(true));

        var request = CreateLenovoInstallRequest(url, sha256: null, installMode: installMode, allowReboot: allowReboot);
        var result = await provider.InstallAsync(request);

        Assert.True(result.Succeeded);
        Assert.Equal(BiosInstallStatus.StagedForReboot, result.Status);
        Assert.True(result.BitLockerSuspended);
        Assert.Empty(localLauncher.Calls);
        Assert.Single(bridge.BitLockerDrives);

        var agentReq = Assert.Single(bridge.InstallRequests);
        Assert.Equal("lenovo", agentReq.VendorId);
        Assert.Equal(installMode, agentReq.InstallMode);
        Assert.Equal(payload.Sha256, agentReq.ExpectedSha256);
        Assert.Equal(allowReboot, agentReq.AllowReboot);
    }

    [Fact]
    public async Task InstallAsync_UnElevatedLiveNamedPipe_RoundTripsThroughAgentBiosOperations()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var adminRoot = new TempStagingDir();

        const string url = "https://download.lenovo.com/pccbbs/mobiles/winuptp64.exe";
        var payload = TestPayload.FromString("lenovo-live-pipe-payload");
        var handler = new FakeBiosHttpHandler().MapBytes(url, payload.Bytes);

        var localLauncher = CreateGuardedLauncher();
        var agentLauncher = CreateGuardedLauncher((call, _) =>
        {
            if (call.BaseName.Equals("manage-bde.exe", StringComparison.OrdinalIgnoreCase))
                return Task.FromResult(new ProcessResult(0, "Protectors disabled.", ""));

            return Task.FromResult(new ProcessResult(1, "Lenovo WinUPTP staged OK", ""));
        });

        var ops = new AgentBiosOperations(agentLauncher, new FakeSignatureVerifier(true), stagingRoot: adminRoot.Path);
        var (server, serverTask, client) = await StartPipeAsync(agentLauncher, ops, cts.Token);
        using (server)
        {
            await using (client)
            {
                var provider = LenovoBiosUpdateProvider.CreateWithHandler(
                    handler,
                    commands: RecordingProcessLauncher.CreateCommandRunner(localLauncher, isProcessElevated: false),
                    elevatedBridge: client,
                    isProcessElevated: () => false);

                var result = await provider.InstallAsync(
                    CreateLenovoInstallRequest(url, payload.Sha256, allowReboot: false),
                    ct: cts.Token);

                Assert.True(result.Succeeded);
                Assert.Equal(BiosInstallStatus.StagedForReboot, result.Status);
                Assert.True(result.BitLockerSuspended);
                Assert.Equal(1, result.ExitCode);
            }

            await serverTask;
        }

        Assert.Empty(localLauncher.Calls);
        Assert.Equal(2, agentLauncher.Calls.Count);
        Assert.Equal("manage-bde.exe", agentLauncher.Calls[0].BaseName, ignoreCase: true);
        Assert.Equal(["-s"], agentLauncher.Calls[1].Arguments);
        Assert.Empty(Directory.GetFileSystemEntries(adminRoot.Path));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task InstallAsync_UnElevatedDisconnectedBridge_FailsClosed(bool suspendBitLocker)
    {
        const string url = "https://download.lenovo.com/pccbbs/mobiles/n32uj20w.exe";
        var payload = TestPayload.FromString("lenovo-disconnected");
        var handler = new FakeBiosHttpHandler().MapBytes(url, payload.Bytes);
        var localLauncher = CreateGuardedLauncher();
        var disconnected = new RecordingBiosBridge(isConnected: false);

        var provider = LenovoBiosUpdateProvider.CreateWithHandler(
            handler,
            commands: RecordingProcessLauncher.CreateCommandRunner(localLauncher, isProcessElevated: false, elevatedBridge: disconnected));

        var result = await provider.InstallAsync(CreateLenovoInstallRequest(url, payload.Sha256, suspendBitLocker: suspendBitLocker));

        Assert.False(result.Succeeded);
        Assert.Equal(BiosInstallStatus.Failed, result.Status);
        Assert.Equal(SystemCommandRunner.AgentFailedExitCode, result.ExitCode);
        Assert.Empty(localLauncher.Calls);
        Assert.Empty(disconnected.InstallRequests);
    }

    // -------------------------------------------------------------------------
    // L12 — Iteration 2 Hardening Regressions (Cross-Family, Traversal, Non-.exe, Malformed Descriptor Resilience, SHA256/CRC)
    // -------------------------------------------------------------------------

    [Theory]
    [InlineData("J2CN57WW", "J3CN100WW")]
    [InlineData("8MCN58WW", "9MCN10WW")]
    [InlineData("N32ET89WW", "N33ET10WW")]
    [InlineData("7KCN32WW", "8KCN40WW")]
    public async Task GetLatestVersionAsync_CrossFamily4CharDigitLeadingAnd5CharWW_NeverReturnsUpdateAvailable(
        string currentVersion,
        string candidateVersion)
    {
        var indexXml = $"""
            <packages>
              <package>
                <category>BIOS/UEFI</category>
                <location>https://download.lenovo.com/pccbbs/mobiles/crossfam.xml</location>
                <BiosVersion>{candidateVersion}</BiosVersion>
              </package>
            </packages>
            """;
        var descXml = $"""
            <Package id="crossfam" version="{candidateVersion}">
              <Files><Installer><File><Name>crossfam.exe</Name></File></Installer></Files>
            </Package>
            """;

        var handler = new FakeBiosHttpHandler()
            .MapText("https://download.lenovo.com/catalog/20XW_Win11.xml", indexXml, "application/xml")
            .MapText("https://download.lenovo.com/pccbbs/mobiles/crossfam.xml", descXml, "application/xml");

        var provider = LenovoBiosUpdateProvider.CreateWithHandler(handler);
        var identity = BiosIdentityFactory.Lenovo(biosVersion: currentVersion);
        var current = await provider.GetCurrentVersionAsync(identity);

        var latest = await provider.GetLatestVersionAsync(identity, current);

        Assert.NotEqual(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal(BiosCheckStatus.UnsupportedHardware, latest.Status);
    }

    [Theory]
    [InlineData("J2CN57WW", "J2CN100WW", "J2CN")]
    [InlineData("8MCN58WW", "8MCN60WW", "8MCN")]
    [InlineData("N32ET89WW", "N32ET90WW", "N32ET")]
    public async Task GetLatestVersionAsync_SameFamily4CharDigitLeadingAnd5CharWW_ReturnsUpdateAvailable(
        string currentVersion,
        string candidateVersion,
        string expectedFamily)
    {
        var indexXml = $"""
            <packages>
              <package>
                <category>BIOS/UEFI</category>
                <location>https://download.lenovo.com/pccbbs/mobiles/samefam.xml</location>
                <BiosVersion>{candidateVersion}</BiosVersion>
              </package>
            </packages>
            """;
        var descXml = $"""
            <Package id="samefam" version="{candidateVersion}">
              <Files><Installer><File><Name>samefam.exe</Name></File></Installer></Files>
            </Package>
            """;

        var handler = new FakeBiosHttpHandler()
            .MapText("https://download.lenovo.com/catalog/20XW_Win11.xml", indexXml, "application/xml")
            .MapText("https://download.lenovo.com/pccbbs/mobiles/samefam.xml", descXml, "application/xml");

        var provider = LenovoBiosUpdateProvider.CreateWithHandler(handler);
        var identity = BiosIdentityFactory.Lenovo(biosVersion: currentVersion);
        var current = await provider.GetCurrentVersionAsync(identity);

        Assert.Equal(expectedFamily, current.Family);
        var latest = await provider.GetLatestVersionAsync(identity, current);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal(candidateVersion, latest.LatestVersion);
        Assert.Equal(expectedFamily, latest.Metadata?["biosFamily"]);
    }

    [Fact]
    public async Task GetLatestVersionAsync_KnownFamilyWithUnknownSymbolicCandidate_DoesNotFallThroughToUpdateAvailable()
    {
        const string descXml = """
            <Package id="unknownsym" version="N99ZZ999ZZZ">
              <Files><Installer><File><Name>unknownsym.exe</Name></File></Installer></Files>
            </Package>
            """;

        var handler = new FakeBiosHttpHandler()
            .MapText("https://download.lenovo.com/catalog/20XW_Win11.xml", SampleIndexXml, "application/xml")
            .MapText("https://download.lenovo.com/pccbbs/mobiles/n32uj20w_2_.xml", descXml, "application/xml");

        var provider = LenovoBiosUpdateProvider.CreateWithHandler(handler);
        var identity = BiosIdentityFactory.Lenovo(biosVersion: "N32ET89W (1.65 )");
        var current = await provider.GetCurrentVersionAsync(identity);

        var latest = await provider.GetLatestVersionAsync(identity, current);

        Assert.NotEqual(BiosCheckStatus.UpdateAvailable, latest.Status);
    }

    [Theory]
    [InlineData("..%2fother/evil.exe")]
    [InlineData("%2e%2e%2fother%2fevil.exe")]
    [InlineData("%2e%2e/evil.exe")]
    [InlineData("%2e%2e%5cother%5cevil.exe")]
    [InlineData("foo%5cbar.exe")]
    [InlineData("%252e%252e/evil.exe")]
    [InlineData("n32uj31w.ps1")]
    [InlineData("n32uj31w.bat")]
    [InlineData("n32uj31w.cmd")]
    public async Task GetLatestVersionAsync_PercentEncodedTraversalOrNonExeFileName_ReturnsFailed(string badName)
    {
        var descXml = $"""
            <Package id="n32uj20w" version="N32ET92W">
              <Files><Installer><File><Name>{badName}</Name></File></Installer></Files>
            </Package>
            """;

        var handler = new FakeBiosHttpHandler()
            .MapText("https://download.lenovo.com/catalog/20XW_Win11.xml", SampleIndexXml, "application/xml")
            .MapText("https://download.lenovo.com/pccbbs/mobiles/n32uj20w_2_.xml", descXml, "application/xml");

        var provider = LenovoBiosUpdateProvider.CreateWithHandler(handler);
        var identity = BiosIdentityFactory.Lenovo();
        var current = await provider.GetCurrentVersionAsync(identity);

        var latest = await provider.GetLatestVersionAsync(identity, current);

        Assert.Equal(BiosCheckStatus.Failed, latest.Status);
    }

    [Theory]
    [InlineData("..%2fother/desc.xml")]
    [InlineData("%2e%2e%2fother/desc.xml")]
    [InlineData("%2e%2e%5cother%5cdesc.xml")]
    [InlineData("foo%5cbar.xml")]
    [InlineData("https://download.lenovo.com/catalog/%2e%2e/other/desc.xml")]
    [InlineData("https://download.lenovo.com/catalog/..%2fother/desc.xml")]
    public async Task GetLatestVersionAsync_PercentEncodedTraversalInDescriptorLocation_ReturnsFailedWithZeroDescriptorFetches(
        string badLocation)
    {
        var indexXml = $"""
            <packages>
              <package>
                <category>BIOS/UEFI</category>
                <location>{badLocation}</location>
              </package>
            </packages>
            """;

        var handler = new FakeBiosHttpHandler()
            .MapText("https://download.lenovo.com/catalog/20XW_Win11.xml", indexXml, "application/xml");

        var provider = LenovoBiosUpdateProvider.CreateWithHandler(handler);
        var identity = BiosIdentityFactory.Lenovo();

        var latest = await provider.GetLatestVersionAsync(identity, identity.CurrentBios);

        Assert.Equal(BiosCheckStatus.Failed, latest.Status);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task GetLatestVersionAsync_SingleMalformedDescriptor_FallsThroughToNextValidDescriptor_AndAllMalformedReturnsFailed()
    {
        const string twoBiosIndex = """
            <packages>
              <package>
                <category>BIOS/UEFI</category>
                <location>https://download.lenovo.com/pccbbs/mobiles/bios_broken.xml</location>
                <version>1.70</version>
              </package>
              <package>
                <category>BIOS/UEFI</category>
                <location>https://download.lenovo.com/pccbbs/mobiles/bios_good.xml</location>
                <version>1.68</version>
              </package>
            </packages>
            """;

        var handler = new FakeBiosHttpHandler()
            .MapText("https://download.lenovo.com/catalog/20XW_Win11.xml", twoBiosIndex, "application/xml")
            .MapText("https://download.lenovo.com/pccbbs/mobiles/bios_broken.xml", "<Package><unclosed", "application/xml")
            .MapText("https://download.lenovo.com/pccbbs/mobiles/bios_good.xml", SampleDescriptorXml, "application/xml");

        var provider = LenovoBiosUpdateProvider.CreateWithHandler(handler);
        var identity = BiosIdentityFactory.Lenovo();
        var current = await provider.GetCurrentVersionAsync(identity);

        var latest = await provider.GetLatestVersionAsync(identity, current);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal("N32ET92W", latest.LatestVersion);

        // When ALL descriptors are malformed (even echoing SerialNumber), return Failed with SerialNumber redacted.
        var brokenWithSecret = $"<Package><{BiosIdentityFactory.SentinelSerialNumber}>";
        var allBadHandler = new FakeBiosHttpHandler()
            .MapText("https://download.lenovo.com/catalog/20XW_Win11.xml", twoBiosIndex, "application/xml")
            .MapText("https://download.lenovo.com/pccbbs/mobiles/bios_broken.xml", brokenWithSecret, "application/xml")
            .MapText("https://download.lenovo.com/pccbbs/mobiles/bios_good.xml", brokenWithSecret, "application/xml");

        var allBadLatest = await LenovoBiosUpdateProvider.CreateWithHandler(allBadHandler)
            .GetLatestVersionAsync(identity, current);

        Assert.Equal(BiosCheckStatus.Failed, allBadLatest.Status);
        Assert.DoesNotContain(BiosIdentityFactory.SentinelSerialNumber, allBadLatest.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task GetLatestVersionAsync_InvalidSha256Placeholder_FallsBackToValidCrcSha256()
    {
        var descXml = $"""
            <Package id="n32uj20w" version="N32ET92W">
              <Files>
                <Installer>
                  <File>
                    <Name>n32uj20w.exe</Name>
                    <SHA256>N/A</SHA256>
                    <CRC>{SampleSha256}</CRC>
                  </File>
                </Installer>
              </Files>
            </Package>
            """;

        var handler = new FakeBiosHttpHandler()
            .MapText("https://download.lenovo.com/catalog/20XW_Win11.xml", SampleIndexXml, "application/xml")
            .MapText("https://download.lenovo.com/pccbbs/mobiles/n32uj20w_2_.xml", descXml, "application/xml");

        var provider = LenovoBiosUpdateProvider.CreateWithHandler(handler);
        var identity = BiosIdentityFactory.Lenovo();
        var latest = await provider.GetLatestVersionAsync(identity, await provider.GetCurrentVersionAsync(identity));

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal(SampleSha256, latest.Sha256);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static BiosInstallRequest CreateLenovoInstallRequest(
        string downloadUrl,
        string? sha256,
        string? installMode = null,
        bool suspendBitLocker = true,
        bool allowReboot = false,
        string? stagingDir = null)
    {
        var system = BiosIdentityFactory.Lenovo();
        IReadOnlyDictionary<string, string>? metadata = installMode is null
            ? null
            : new Dictionary<string, string> { ["installMode"] = installMode };

        var target = BiosLatestInfo.UpdateAvailable(
            providerId: "lenovo",
            latestVersion: "N32ET92W",
            downloadUrl: downloadUrl,
            sha256: sha256,
            metadata: metadata);

        return new BiosInstallRequest(
            System: system,
            Current: system.CurrentBios,
            Target: target,
            Approved: true,
            ApprovedBy: "operator@contoso.com",
            SuspendBitLocker: suspendBitLocker,
            AllowReboot: allowReboot,
            VerifyHash: true,
            StagingDirectory: stagingDir);
    }

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
        IAgentBiosOperations biosOps,
        CancellationToken ct)
    {
        var pipeName = $"rpd-bios-lenovo-test-{Guid.NewGuid():N}";
        var server = new AdminPipeServer(
            new AdminPipeServerOptions
            {
                PipeName = pipeName,
                ExpectedClientPid = Environment.ProcessId,
            },
            launcher: agentLauncher,
            biosOperations: biosOps);

        var serverTask = server.RunSingleSessionAsync(ct);
        var client = await AdminPipeClient.ConnectAsync(pipeName, TimeSpan.FromSeconds(10), ct);
        return (server, serverTask, client);
    }

    private sealed class RecordingBiosBridge(bool isConnected = true) : IElevatedCommandBridge
    {
        public bool IsConnected => isConnected;
        public List<string> BitLockerDrives { get; } = [];
        public List<BiosAgentInstallRequest> InstallRequests { get; } = [];

        public Task<ProcessResult?> RunElevatedAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct, Action<string>? outputLine = null) =>
            Task.FromResult<ProcessResult?>(null);

        public Task<SensorSnapshot?> ReadSensorsAsync(CancellationToken ct = default) => Task.FromResult<SensorSnapshot?>(null);
        public Task<IReadOnlyList<DriveHealth>?> ReadDrivesAsync(CancellationToken ct = default) => Task.FromResult<IReadOnlyList<DriveHealth>?>(null);

        public Task<BiosAgentBitLockerResult> SuspendBitLockerAsync(string systemDrive, CancellationToken ct = default)
        {
            BitLockerDrives.Add(systemDrive);
            return Task.FromResult(new BiosAgentBitLockerResult(Suspended: true, Allowed: true, ExitCode: 0));
        }

        public Task<BiosAgentInstallResult> RunBiosInstallerAsync(BiosAgentInstallRequest request, CancellationToken ct = default)
        {
            InstallRequests.Add(request);
            return Task.FromResult(new BiosAgentInstallResult(Executed: true, Allowed: true, ExitCode: 1, TimedOut: false, LogTail: "Agent Lenovo OK"));
        }
    }
}
