using System.Net;
using System.Net.Sockets;
using System.Text;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Bios;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Sensors;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Tests.Bios;

public sealed class HpBiosUpdateProviderTests
{
    private static readonly HashSet<string> ForbiddenShellBinaries = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell", "powershell.exe", "pwsh", "pwsh.exe",
        "cmd", "cmd.exe", "sh", "bash", "zsh",
    };

    private static readonly string[] ForbiddenScriptExtensions = [".ps1", ".bat", ".cmd", ".sh"];

    private const string SampleHpCatalogXml = """
        <?xml version="1.0" encoding="utf-8"?>
        <ImagePal>
          <Solutions>
            <UpdateInfo>
              <Id>sp149999</Id>
              <Category>Driver - Graphics</Category>
              <Name>Intel UHD Graphics Driver</Name>
              <Version>31.0.101.5186</Version>
              <DateReleased>2024-02-01</DateReleased>
              <Url>https://ftp.hp.com/pub/softpaq/sp149999.exe</Url>
            </UpdateInfo>
            <UpdateInfo>
              <Id>sp150500</Id>
              <Category>Firmware</Category>
              <Name>HP Thunderbolt Dock G4 Firmware Update</Name>
              <Version>1.5.20.0</Version>
              <DateReleased>2024-06-01</DateReleased>
              <Url>https://ftp.hp.com/pub/softpaq/sp150500.exe</Url>
            </UpdateInfo>
            <UpdateInfo>
              <Id>sp151234</Id>
              <Category>BIOS</Category>
              <Name>HP Notebook System BIOS Update (T76)</Name>
              <Version>01.15.00 Rev.A</Version>
              <DateReleased>2024-05-10</DateReleased>
              <Severity>Critical</Severity>
              <Size>31457280</Size>
              <SHA256>0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF</SHA256>
              <Url>ftp.hp.com/pub/softpaq/sp151234.exe</Url>
              <CvaUrl>https://ftp.hp.com/pub/softpaq/sp151234.cva</CvaUrl>
              <Description>Critical security and UEFI stability update for T76 family.</Description>
            </UpdateInfo>
          </Solutions>
        </ImagePal>
        """;

    // -------------------------------------------------------------------------
    // H1 — Metadata & Capabilities
    // -------------------------------------------------------------------------

    [Fact]
    public void Metadata_MatchesContract()
    {
        var provider = new HpBiosUpdateProvider();

        Assert.Equal("hp", provider.VendorId);
        Assert.Equal("HP", provider.DisplayName);
        Assert.Equal(100, provider.Priority);
        Assert.True(provider.Capabilities.CanCheckLatest);
        Assert.True(provider.Capabilities.CanInstall);
        Assert.True(provider.Capabilities.SupportsSilentInstall);
        Assert.True(provider.Capabilities.RequiresReboot);
        Assert.True(provider.Capabilities.RequiresElevation);
        Assert.True(provider.Capabilities.RequiresInternet);
    }

    // -------------------------------------------------------------------------
    // H2 & H3 — CanHandle Positive & Negative Word-Boundary Matching
    // -------------------------------------------------------------------------

    [Theory]
    [InlineData("HP", "")]
    [InlineData("HP Inc.", "")]
    [InlineData("Hewlett-Packard", "")]
    [InlineData("Hewlett Packard Enterprise", "")]
    [InlineData("Generic OEM", "HP")]
    [InlineData("", "Hewlett-Packard")]
    public void CanHandle_HpManufacturers_ReturnsTrue(string manufacturer, string boardManufacturer)
    {
        var provider = new HpBiosUpdateProvider();
        var identity = BiosIdentityFactory.Hp(manufacturer: manufacturer) with
        {
            BoardManufacturer = boardManufacturer,
        };

        Assert.True(provider.CanHandle(identity));
    }

    [Theory]
    [InlineData("Ship")]
    [InlineData("Shop Corp")]
    [InlineData("MyHP Systems")]
    [InlineData("PHP Hardware")]
    [InlineData("Dell Inc.")]
    [InlineData("LENOVO")]
    [InlineData("ASUSTeK COMPUTER INC.")]
    public void CanHandle_NonHpOrSubstringManufacturers_ReturnsFalse(string manufacturer)
    {
        var provider = new HpBiosUpdateProvider();
        var identity = BiosIdentityFactory.GenericUefi(manufacturer: manufacturer);

        Assert.False(provider.CanHandle(identity));
    }

    [Fact]
    public void CanHandle_UnknownAndNull_ReturnsFalseWithoutThrowing()
    {
        var provider = new HpBiosUpdateProvider();

        Assert.False(provider.CanHandle(BiosIdentityFactory.Unknown()));
        Assert.False(provider.CanHandle(null!));
    }

    // -------------------------------------------------------------------------
    // H4 — GetCurrentVersionAsync Normalization & Zero SerialNumber Leakage
    // -------------------------------------------------------------------------

    [Theory]
    [InlineData("U70 Ver. 01.14.00", "U70", "01.14.00")]
    [InlineData("T76 Ver. 01.12.00", "T76", "01.12.00")]
    [InlineData("M70 Ver. 01.45.00 Rev.A", "M70", "01.45.00")]
    [InlineData("F.24 Rev.A", "F", "F.24")]
    [InlineData("F.24", "F", "F.24")]
    [InlineData("01.10.00", "", "01.10.00")]
    [InlineData("", "", "")]
    public async Task GetCurrentVersionAsync_NormalizesHpVersions_AndNeverExposesSerialNumber(
        string rawVersion,
        string expectedFamily,
        string expectedVersion)
    {
        var log = new CapturedLog();
        var provider = new HpBiosUpdateProvider(log: log.Logger);
        var identity = BiosIdentityFactory.Hp(boardProduct: "0x880d", biosVersion: rawVersion);

        var current = await provider.GetCurrentVersionAsync(identity);

        Assert.Equal("hp", current.ProviderId);
        Assert.Equal(expectedFamily, current.Family);
        Assert.Equal(expectedVersion, current.Version);
        Assert.NotNull(current.Metadata);
        Assert.Equal("880D", current.Metadata["systemId"]);

        foreach (var kvp in current.Metadata)
        {
            Assert.DoesNotContain(BiosIdentityFactory.SentinelSerialNumber, kvp.Key, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(BiosIdentityFactory.SentinelSerialNumber, kvp.Value, StringComparison.OrdinalIgnoreCase);
        }

        log.AssertDoesNotContainSecret();
    }

    [Fact]
    public async Task GetCurrentVersionAsync_FallsBackToSystemSkuOnlyWhenBoardProductIsBlank()
    {
        var provider = new HpBiosUpdateProvider();
        var blankBoard = BiosIdentityFactory.Hp(boardProduct: "   ") with { SystemSku = "8a1b" };

        var current = await provider.GetCurrentVersionAsync(blankBoard);

        Assert.NotNull(current.Metadata);
        Assert.Equal("8A1B", current.Metadata["systemId"]);
    }

    // -------------------------------------------------------------------------
    // H5 — GetLatestVersionAsync Plain XML & MS-CAB (Uncompressed & MSZIP)
    // -------------------------------------------------------------------------

    [Theory]
    [InlineData("plain")]
    [InlineData("cab-none")]
    [InlineData("cab-mszip")]
    public async Task GetLatestVersionAsync_PlainAndCabCatalogs_ReturnsUpdateAvailable(string encoding)
    {
        var xmlBytes = Encoding.UTF8.GetBytes(SampleHpCatalogXml);
        byte[] payload = encoding switch
        {
            "plain" => xmlBytes,
            "cab-none" => TestCabBuilder.CreateUncompressed(new Dictionary<string, byte[]> { ["880d_64_11.0.xml"] = xmlBytes }),
            "cab-mszip" => TestCabBuilder.CreateMsZip(new Dictionary<string, byte[]> { ["880d_64_11.0.xml"] = xmlBytes }),
            _ => throw new ArgumentOutOfRangeException(nameof(encoding)),
        };

        var handler = new FakeBiosHttpHandler()
            .MapBytes("https://hpia.hpcloud.hp.com/ref/880d/880d_64_11.0.cab", payload);

        var log = new CapturedLog();
        var provider = HpBiosUpdateProvider.CreateWithHandler(handler, log: log.Logger);
        var identity = BiosIdentityFactory.Hp(boardProduct: "880D", biosVersion: "T76 Ver. 01.12.00");
        var current = await provider.GetCurrentVersionAsync(identity);

        var latest = await provider.GetLatestVersionAsync(identity, current);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal("hp", latest.ProviderId);
        Assert.Equal("01.15.00", latest.LatestVersion);
        Assert.Equal(new DateOnly(2024, 5, 10), latest.ReleaseDate);
        Assert.Equal(BiosUpdateSeverity.Critical, latest.Severity);
        Assert.Equal("sp151234", latest.PackageId);
        Assert.Equal("https://ftp.hp.com/pub/softpaq/sp151234.exe", latest.DownloadUrl);
        Assert.Equal("https://ftp.hp.com/pub/softpaq/sp151234.cva", latest.ReleaseNotesUrl);
        Assert.Equal("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", latest.Sha256);
        Assert.Equal(31457280, latest.SizeBytes);
        Assert.True(latest.RequiresReboot);
        Assert.Single(handler.Requests);
        log.AssertDoesNotContainSecret();
    }

    [Fact]
    public async Task GetLatestVersionAsync_Win11404_FallsBackToWin10Catalog()
    {
        var handler = new FakeBiosHttpHandler()
            .MapStatus("https://hpia.hpcloud.hp.com/ref/880d/880d_64_11.0.cab", HttpStatusCode.NotFound)
            .MapText("https://hpia.hpcloud.hp.com/ref/880d/880d_64_10.0.cab", SampleHpCatalogXml, "application/xml");

        var provider = HpBiosUpdateProvider.CreateWithHandler(handler);
        var identity = BiosIdentityFactory.Hp(osVersion: "Microsoft Windows 11 Pro 10.0.22631");
        var current = await provider.GetCurrentVersionAsync(identity);

        var latest = await provider.GetLatestVersionAsync(identity, current);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal("01.15.00", latest.LatestVersion);
        Assert.Equal("10.0", latest.Metadata?["osVersion"]);
        Assert.Equal(2, handler.Requests.Count);
        Assert.EndsWith("880d_64_11.0.cab", handler.Requests[0].RequestUri!.AbsoluteUri, StringComparison.OrdinalIgnoreCase);
        Assert.EndsWith("880d_64_10.0.cab", handler.Requests[1].RequestUri!.AbsoluteUri, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task GetLatestVersionAsync_Win10_RequestsWin10Directly()
    {
        var handler = new FakeBiosHttpHandler()
            .MapText("https://hpia.hpcloud.hp.com/ref/880d/880d_64_10.0.cab", SampleHpCatalogXml, "application/xml");

        var provider = HpBiosUpdateProvider.CreateWithHandler(handler);
        var identity = BiosIdentityFactory.Hp(osVersion: "Microsoft Windows 10 Pro 10.0.19045");
        var current = await provider.GetCurrentVersionAsync(identity);

        var latest = await provider.GetLatestVersionAsync(identity, current);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Single(handler.Requests);
        Assert.EndsWith("880d_64_10.0.cab", handler.Requests[0].RequestUri!.AbsoluteUri, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task GetLatestVersionAsync_Arm64VersionedCatalog_Resolves8cbeOmniBookX()
    {
        const string xml = """
            <ImagePal>
              <UpdateInfo>
                <Id>sp160001</Id>
                <Category>BIOS</Category>
                <Name>HP Consumer Notebook System BIOS Update (ARM64)</Name>
                <Version>F.36</Version>
                <DateReleased>2026-09-15</DateReleased>
                <Url>https://ftp.hp.com/pub/softpaq/sp160001-160500/sp160001.exe</Url>
              </UpdateInfo>
            </ImagePal>
            """;

        var handler = new FakeBiosHttpHandler()
            .MapText("https://hpia.hpcloud.hp.com/ref/8cbe/8cbe_arm64_11.0.24h2.cab", xml, "application/xml");

        var provider = HpBiosUpdateProvider.CreateWithHandler(handler);
        var identity = BiosIdentityFactory.Hp(
            model: "HP OmniBook X Laptop 14-fe0xxx",
            boardProduct: "8CBE",
            biosVersion: "F.34",
            osVersion: "Microsoft Windows 11 Home 10.0.26100") with { Architecture = "ARM64" };
        var current = await provider.GetCurrentVersionAsync(identity);

        var latest = await provider.GetLatestVersionAsync(identity, current);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal("F.36", latest.LatestVersion);
        Assert.Equal("11.0.24h2", latest.Metadata?["osVersion"]);
        Assert.Equal(2, handler.Requests.Count);
        Assert.EndsWith("8cbe_arm64_11.0.25h2.cab", handler.Requests[0].RequestUri!.AbsoluteUri, StringComparison.Ordinal);
        Assert.EndsWith("8cbe_arm64_11.0.24h2.cab", handler.Requests[1].RequestUri!.AbsoluteUri, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetLatestVersionAsync_X64Emulation_FallsBackToArm64VersionedCatalog()
    {
        const string xml = """
            <ImagePal>
              <UpdateInfo>
                <Id>sp160001</Id>
                <Category>BIOS</Category>
                <Name>HP Consumer Notebook System BIOS Update (ARM64)</Name>
                <Version>F.36</Version>
                <Url>https://ftp.hp.com/pub/softpaq/sp160001-160500/sp160001.exe</Url>
              </UpdateInfo>
            </ImagePal>
            """;

        var handler = new FakeBiosHttpHandler()
            .MapText("https://hpia.hpcloud.hp.com/ref/8cbe/8cbe_arm64_11.0.24h2.cab", xml, "application/xml");

        var provider = HpBiosUpdateProvider.CreateWithHandler(handler);
        var identity = BiosIdentityFactory.Hp(
            model: "HP OmniBook X Laptop 14-fe0xxx",
            boardProduct: "8CBE",
            biosVersion: "F.34",
            osVersion: "Microsoft Windows 11 Home 10.0.26100");
        var current = await provider.GetCurrentVersionAsync(identity);

        var latest = await provider.GetLatestVersionAsync(identity, current);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal("F.36", latest.LatestVersion);
        Assert.Equal("11.0.24h2", latest.Metadata?["osVersion"]);
    }

    [Fact]
    public async Task GetLatestVersionAsync_Win11FeatureReleaseFallback_ResolvesLowercase25h2()
    {
        var handler = new FakeBiosHttpHandler()
            .MapText("https://hpia.hpcloud.hp.com/ref/880d/880d_64_11.0.25h2.cab", SampleHpCatalogXml, "application/xml");

        var provider = HpBiosUpdateProvider.CreateWithHandler(handler);
        var identity = BiosIdentityFactory.Hp(osVersion: "Microsoft Windows 11 Pro 10.0.26100");
        var current = await provider.GetCurrentVersionAsync(identity);

        var latest = await provider.GetLatestVersionAsync(identity, current);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal("01.15.00", latest.LatestVersion);
        Assert.Equal("11.0.25h2", latest.Metadata?["osVersion"]);
    }

    [Fact]
    public async Task GetLatestVersionAsync_Md5ChecksumInCatalog_IsIgnoredNotTreatedAsSha256()
    {
        const string xml = """
            <ImagePal>
              <UpdateInfo>
                <Id>sp151235</Id>
                <Category>BIOS</Category>
                <Name>HP System BIOS (T76)</Name>
                <Version>01.16.00</Version>
                <Checksum>d41d8cd98f00b204e9800998ecf8427e</Checksum>
                <Url>https://ftp.hp.com/pub/softpaq/sp151235.exe</Url>
              </UpdateInfo>
            </ImagePal>
            """;

        var handler = new FakeBiosHttpHandler()
            .MapText("https://hpia.hpcloud.hp.com/ref/880d/880d_64_11.0.cab", xml, "application/xml");

        var provider = HpBiosUpdateProvider.CreateWithHandler(handler);
        var identity = BiosIdentityFactory.Hp();
        var current = await provider.GetCurrentVersionAsync(identity);

        var latest = await provider.GetLatestVersionAsync(identity, current);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Null(latest.Sha256);
    }

    // -------------------------------------------------------------------------
    // H6 — UpToDate & Multi-Entry Family Filtering
    // -------------------------------------------------------------------------

    [Fact]
    public async Task GetLatestVersionAsync_CurrentEqualsLatest_ReturnsUpToDate()
    {
        var handler = new FakeBiosHttpHandler()
            .MapText("https://hpia.hpcloud.hp.com/ref/880d/880d_64_11.0.cab", SampleHpCatalogXml, "application/xml");

        var provider = HpBiosUpdateProvider.CreateWithHandler(handler);
        var identity = BiosIdentityFactory.Hp(biosVersion: "T76 Ver. 01.15.00");
        var current = await provider.GetCurrentVersionAsync(identity);

        var latest = await provider.GetLatestVersionAsync(identity, current);

        Assert.Equal(BiosCheckStatus.UpToDate, latest.Status);
        Assert.Equal("01.15.00", latest.LatestVersion);
    }

    [Fact]
    public async Task GetLatestVersionAsync_MultipleFamiliesAndVersions_FiltersByFamilyAndPicksNewest()
    {
        const string xml = """
            <ImagePal>
              <UpdateInfo>
                <Id>sp150001</Id>
                <Category>BIOS</Category>
                <Name>HP System BIOS (U70)</Name>
                <Version>01.99.00</Version>
                <Url>https://ftp.hp.com/pub/softpaq/sp150001.exe</Url>
              </UpdateInfo>
              <UpdateInfo>
                <Id>sp150002</Id>
                <Category>BIOS</Category>
                <Name>HP System BIOS (T76)</Name>
                <Version>01.14.00</Version>
                <Url>https://ftp.hp.com/pub/softpaq/sp150002.exe</Url>
              </UpdateInfo>
              <UpdateInfo>
                <Id>sp150003</Id>
                <Category>BIOS</Category>
                <Name>HP System BIOS (T76)</Name>
                <Version>01.16.00</Version>
                <Url>https://ftp.hp.com/pub/softpaq/sp150003.exe</Url>
              </UpdateInfo>
            </ImagePal>
            """;

        var handler = new FakeBiosHttpHandler()
            .MapText("https://hpia.hpcloud.hp.com/ref/880d/880d_64_11.0.cab", xml, "application/xml");

        var provider = HpBiosUpdateProvider.CreateWithHandler(handler);
        var identity = BiosIdentityFactory.Hp(biosVersion: "T76 Ver. 01.12.00");
        var current = await provider.GetCurrentVersionAsync(identity);

        var latest = await provider.GetLatestVersionAsync(identity, current);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal("01.16.00", latest.LatestVersion);
        Assert.Equal("sp150003", latest.PackageId);
        Assert.Equal("T76", latest.Metadata?["family"]);
    }

    // -------------------------------------------------------------------------
    // H7 — Invalid / Malicious SystemId (0 HTTP calls)
    // -------------------------------------------------------------------------

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("ZZZ1")]
    [InlineData("123")]
    [InlineData("12345")]
    [InlineData("880D; powershell -c calc")]
    [InlineData("../../etc")]
    public async Task GetLatestVersionAsync_InvalidOrMaliciousSystemId_ReturnsUnsupportedWithZeroHttpCalls(string badBoardProduct)
    {
        var handler = new FakeBiosHttpHandler();
        var provider = HpBiosUpdateProvider.CreateWithHandler(handler);
        var identity = BiosIdentityFactory.Hp(boardProduct: badBoardProduct) with { SystemSku = "INVALID" };

        var latest = await provider.GetLatestVersionAsync(identity, identity.CurrentBios);

        Assert.Equal(BiosCheckStatus.UnsupportedHardware, latest.Status);
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task GetLatestVersionAsync_MaliciousBoardProductDoesNotFallBackToValidSystemSku()
    {
        var handler = new FakeBiosHttpHandler();
        var provider = HpBiosUpdateProvider.CreateWithHandler(handler);
        var identity = BiosIdentityFactory.Hp(boardProduct: "880D;calc.exe") with { SystemSku = "880D" };

        var latest = await provider.GetLatestVersionAsync(identity, identity.CurrentBios);

        Assert.Equal(BiosCheckStatus.UnsupportedHardware, latest.Status);
        Assert.Empty(handler.Requests);
    }

    // -------------------------------------------------------------------------
    // H8 — HTTP Status, Network, Redirect, XXE & Unsafe Package URLs
    // -------------------------------------------------------------------------

    [Theory]
    [InlineData(HttpStatusCode.NotFound, BiosCheckStatus.UnsupportedHardware)]
    [InlineData(HttpStatusCode.TooManyRequests, BiosCheckStatus.ProviderUnavailable)]
    [InlineData(HttpStatusCode.ServiceUnavailable, BiosCheckStatus.ProviderUnavailable)]
    [InlineData(HttpStatusCode.InternalServerError, BiosCheckStatus.ProviderUnavailable)]
    public async Task GetLatestVersionAsync_HttpStatusMapping(HttpStatusCode status, BiosCheckStatus expected)
    {
        var handler = new FakeBiosHttpHandler()
            .MapStatus("https://hpia.hpcloud.hp.com/ref/880d/880d_64_10.0.cab", status);

        var provider = HpBiosUpdateProvider.CreateWithHandler(handler);
        var identity = BiosIdentityFactory.Hp(osVersion: "Microsoft Windows 10 Pro 10.0.19045");

        var latest = await provider.GetLatestVersionAsync(identity, identity.CurrentBios);

        Assert.Equal(expected, latest.Status);
    }

    [Fact]
    public async Task GetLatestVersionAsync_NetworkAndTimeout_ReturnOffline_AndCallerCancellationRethrows()
    {
        var netHandler = new FakeBiosHttpHandler()
            .MapException("https://hpia.hpcloud.hp.com/ref/880d/880d_64_11.0.cab", () => new HttpRequestException("offline", new SocketException()));

        var provider = HpBiosUpdateProvider.CreateWithHandler(netHandler);
        var identity = BiosIdentityFactory.Hp();

        var offline = await provider.GetLatestVersionAsync(identity, identity.CurrentBios);
        Assert.Equal(BiosCheckStatus.Offline, offline.Status);

        var timeoutHandler = new FakeBiosHttpHandler()
            .MapException("https://hpia.hpcloud.hp.com/ref/880d/880d_64_11.0.cab", () => new TaskCanceledException("timeout"));
        var timeoutProvider = HpBiosUpdateProvider.CreateWithHandler(timeoutHandler);
        var timedOut = await timeoutProvider.GetLatestVersionAsync(identity, identity.CurrentBios);
        Assert.Equal(BiosCheckStatus.Offline, timedOut.Status);

        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => provider.GetLatestVersionAsync(identity, identity.CurrentBios, cts.Token));
    }

    [Fact]
    public async Task GetLatestVersionAsync_XxePayload_ReturnsFailed()
    {
        const string xxeXml = """
            <?xml version="1.0"?>
            <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
            <ImagePal><UpdateInfo><Category>BIOS</Category><Version>&xxe;</Version></UpdateInfo></ImagePal>
            """;

        var handler = new FakeBiosHttpHandler()
            .MapText("https://hpia.hpcloud.hp.com/ref/880d/880d_64_11.0.cab", xxeXml, "application/xml");

        var provider = HpBiosUpdateProvider.CreateWithHandler(handler);
        var latest = await provider.GetLatestVersionAsync(BiosIdentityFactory.Hp(), BiosIdentityFactory.Hp().CurrentBios);

        Assert.Equal(BiosCheckStatus.Failed, latest.Status);
    }

    [Theory]
    [InlineData("http://ftp.hp.com/pub/softpaq/sp151234.exe")]
    [InlineData("https://evil.com/sp151234.exe")]
    [InlineData("https://hp.com.evil.com/sp151234.exe")]
    [InlineData("file:///C:/Windows/System32/calc.exe")]
    public async Task GetLatestVersionAsync_DisallowedPackageUrlInCatalog_ReturnsFailed(string badUrl)
    {
        var xml = $"""
            <ImagePal>
              <UpdateInfo>
                <Id>sp151234</Id>
                <Category>BIOS</Category>
                <Name>HP System BIOS (T76)</Name>
                <Version>01.16.00</Version>
                <Url>{badUrl}</Url>
              </UpdateInfo>
            </ImagePal>
            """;

        var handler = new FakeBiosHttpHandler()
            .MapText("https://hpia.hpcloud.hp.com/ref/880d/880d_64_11.0.cab", xml, "application/xml");

        var provider = HpBiosUpdateProvider.CreateWithHandler(handler);
        var identity = BiosIdentityFactory.Hp();
        var current = await provider.GetCurrentVersionAsync(identity);

        var latest = await provider.GetLatestVersionAsync(identity, current);

        Assert.Equal(BiosCheckStatus.Failed, latest.Status);
    }

    [Fact]
    public async Task GetLatestVersionAsync_OffDomainRedirect_ReturnsFailed()
    {
        var handler = new FakeBiosHttpHandler()
            .MapRedirect("https://hpia.hpcloud.hp.com/ref/880d/880d_64_11.0.cab", "https://evil.com/catalog.cab");

        var provider = HpBiosUpdateProvider.CreateWithHandler(handler);
        var identity = BiosIdentityFactory.Hp();

        var latest = await provider.GetLatestVersionAsync(identity, identity.CurrentBios);

        Assert.Equal(BiosCheckStatus.Failed, latest.Status);
        Assert.Single(handler.Requests);
    }

    // -------------------------------------------------------------------------
    // H9 — InstallAsync Elevated Local Happy Path & Inverted HP -r Polarity
    // -------------------------------------------------------------------------

    [Theory]
    [InlineData("https://ftp.hp.com/pub/softpaq/sp151234.exe", false, 0, new[] { "-s", "-r" })]
    [InlineData("https://ftp.hp.com/pub/softpaq/sp151234.exe", true, 3010, new[] { "-s" })]
    [InlineData("https://ftp.hp.com/pub/softpaq/HPBIOSUPDREC64.exe", false, 3010, new[] { "-s", "-r" })]
    [InlineData("https://ftp.hp.com/pub/softpaq/HPBIOSUPDREC64.exe", true, 0, new[] { "-s" })]
    public async Task InstallAsync_ElevatedHappyPath_EnforcesInvertedHpRebootFlagAndCleansAutoStaging(
        string url,
        bool allowReboot,
        int installerExitCode,
        string[] expectedArgs)
    {
        var payload = TestPayload.FromString($"hp-bios-binary-{allowReboot}-{installerExitCode}");
        var handler = new FakeBiosHttpHandler().MapBytes(url, payload.Bytes);

        string? observedAutoDir = null;
        var launcher = CreateGuardedLauncher((call, _) =>
        {
            if (call.BaseName.Equals("manage-bde.exe", StringComparison.OrdinalIgnoreCase))
                return Task.FromResult(new ProcessResult(0, "BitLocker suspended", ""));

            observedAutoDir = Path.GetDirectoryName(call.FileName);
            Assert.True(File.Exists(call.FileName));
            return Task.FromResult(new ProcessResult(installerExitCode, "HP BIOS staged", ""));
        });

        var commands = RecordingProcessLauncher.CreateCommandRunner(launcher, isProcessElevated: true);
        var log = new CapturedLog();
        var progress = new SyncProgress<BiosInstallProgress>();
        var provider = HpBiosUpdateProvider.CreateWithHandler(handler, commands: commands, log: log.Logger);

        var request = BiosIdentityFactory.CreateInstallRequest(
            system: BiosIdentityFactory.Hp(),
            downloadUrl: url,
            sha256: payload.Sha256,
            targetVersion: "01.15.00",
            suspendBitLocker: true,
            allowReboot: allowReboot,
            stagingDirectory: null);

        var result = await provider.InstallAsync(request, progress);

        Assert.True(result.Succeeded);
        Assert.Equal(BiosInstallStatus.StagedForReboot, result.Status);
        Assert.True(result.RequiresReboot);
        Assert.True(result.BitLockerSuspended);
        Assert.Equal(installerExitCode, result.ExitCode);

        Assert.Equal(2, launcher.Calls.Count);
        Assert.Equal("manage-bde.exe", launcher.Calls[0].BaseName, ignoreCase: true);
        Assert.Equal("-protectors", launcher.Calls[0].Arguments[0]);
        Assert.Equal("-disable", launcher.Calls[0].Arguments[1]);
        Assert.Equal("-RebootCount", launcher.Calls[0].Arguments[3]);
        Assert.Equal("1", launcher.Calls[0].Arguments[4]);

        Assert.Equal(expectedArgs, launcher.Calls[1].Arguments);

        Assert.NotNull(observedAutoDir);
        Assert.False(Directory.Exists(observedAutoDir!));

        var stages = progress.Reports.Select(r => r.Stage).ToList();
        Assert.Contains(BiosInstallStage.Downloading, stages);
        Assert.Contains(BiosInstallStage.Verifying, stages);
        Assert.Contains(BiosInstallStage.SuspendingBitLocker, stages);
        Assert.Contains(BiosInstallStage.Staging, stages);
        Assert.Equal(BiosInstallStage.RebootRequired, stages[^1]);
        log.AssertDoesNotContainSecret();
    }

    // -------------------------------------------------------------------------
    // H10 — SuspendBitLocker = false & Non-Encrypted Volume
    // -------------------------------------------------------------------------

    [Fact]
    public async Task InstallAsync_SuspendBitLockerFalse_AndCallerStagingPreserved()
    {
        using var staging = new TempStagingDir();
        const string url = "https://ftp.hp.com/pub/softpaq/sp151234.exe";
        var payload = TestPayload.FromString("hp-bios-no-bitlocker");
        var handler = new FakeBiosHttpHandler().MapBytes(url, payload.Bytes);

        var launcher = CreateGuardedLauncher((_, _) => Task.FromResult(new ProcessResult(0, "OK", "")));
        var commands = RecordingProcessLauncher.CreateCommandRunner(launcher, isProcessElevated: true);
        var provider = HpBiosUpdateProvider.CreateWithHandler(handler, commands: commands);

        var request = BiosIdentityFactory.CreateInstallRequest(
            system: BiosIdentityFactory.Hp(),
            downloadUrl: url,
            sha256: payload.Sha256,
            suspendBitLocker: false,
            allowReboot: false,
            stagingDirectory: staging.Path);

        var result = await provider.InstallAsync(request);

        Assert.True(result.Succeeded);
        Assert.Equal(BiosInstallStatus.StagedForReboot, result.Status);
        Assert.False(result.BitLockerSuspended);
        var call = Assert.Single(launcher.Calls);
        Assert.Equal(["-s", "-r"], call.Arguments);
        Assert.True(Directory.Exists(staging.Path));
    }

    [Fact]
    public async Task InstallAsync_NonEncryptedVolume_ContinuesWithBitLockerSuspendedFalse()
    {
        const string url = "https://ftp.hp.com/pub/softpaq/sp151234.exe";
        var payload = TestPayload.FromString("hp-bios-unencrypted");
        var handler = new FakeBiosHttpHandler().MapBytes(url, payload.Bytes);

        var launcher = CreateGuardedLauncher((call, _) =>
        {
            if (call.BaseName.Equals("manage-bde.exe", StringComparison.OrdinalIgnoreCase))
                return Task.FromResult(new ProcessResult(1, "", "Volume C: is not encrypted."));
            return Task.FromResult(new ProcessResult(3010, "Staged", ""));
        });
        var commands = RecordingProcessLauncher.CreateCommandRunner(launcher, isProcessElevated: true);
        var provider = HpBiosUpdateProvider.CreateWithHandler(handler, commands: commands);

        var request = BiosIdentityFactory.CreateInstallRequest(
            system: BiosIdentityFactory.Hp(),
            downloadUrl: url,
            sha256: payload.Sha256,
            suspendBitLocker: true,
            allowReboot: false) with { BitLockerKnownOff = true };

        var result = await provider.InstallAsync(request);

        Assert.True(result.Succeeded);
        Assert.Equal(BiosInstallStatus.StagedForReboot, result.Status);
        Assert.False(result.BitLockerSuspended);
        Assert.Equal(2, launcher.Calls.Count);

        // The same manage-bde failure, when BitLocker isn't known to be off, stops the flash.
        var before = launcher.Calls.Count;
        var blocked = await provider.InstallAsync(request with { BitLockerKnownOff = false });
        Assert.False(blocked.Succeeded);
        Assert.Contains("BitLocker", blocked.Message);
        Assert.DoesNotContain(launcher.Calls.Skip(before), c => !c.BaseName.Equals("manage-bde.exe", StringComparison.OrdinalIgnoreCase));
    }

    // -------------------------------------------------------------------------
    // H11 — Verification Security (URL, Redirect, SHA-256, Authenticode)
    // -------------------------------------------------------------------------

    [Theory]
    [InlineData("http://ftp.hp.com/pub/softpaq/sp151234.exe")]
    [InlineData("https://evil.com/sp151234.exe")]
    public async Task InstallAsync_UnsafeUrl_FailsWithZeroProcessCalls(string badUrl)
    {
        var handler = new FakeBiosHttpHandler();
        var launcher = CreateGuardedLauncher();
        var commands = RecordingProcessLauncher.CreateCommandRunner(launcher, isProcessElevated: true);
        var provider = HpBiosUpdateProvider.CreateWithHandler(handler, commands: commands);

        var request = BiosIdentityFactory.CreateInstallRequest(downloadUrl: badUrl);
        var result = await provider.InstallAsync(request);

        Assert.False(result.Succeeded);
        Assert.Equal(BiosInstallStatus.Failed, result.Status);
        Assert.Empty(launcher.Calls);
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task InstallAsync_Sha256Mismatch_DeletesFileAndNeverExecutes()
    {
        using var staging = new TempStagingDir();
        const string url = "https://ftp.hp.com/pub/softpaq/sp151234.exe";
        var payload = TestPayload.FromString("tampered-hp-binary");
        var handler = new FakeBiosHttpHandler().MapBytes(url, payload.Bytes);
        var launcher = CreateGuardedLauncher();
        var commands = RecordingProcessLauncher.CreateCommandRunner(launcher, isProcessElevated: true);
        var provider = HpBiosUpdateProvider.CreateWithHandler(handler, commands: commands);

        var request = BiosIdentityFactory.CreateInstallRequest(
            downloadUrl: url,
            sha256: new string('a', 64),
            stagingDirectory: staging.Path);

        var result = await provider.InstallAsync(request);

        Assert.False(result.Succeeded);
        Assert.Equal(BiosInstallStatus.Failed, result.Status);
        Assert.Empty(launcher.Calls);
        Assert.Empty(Directory.GetFiles(staging.Path));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task InstallAsync_NoSha256_FallsBackToAuthenticodeVerifier(bool signatureValid)
    {
        using var staging = new TempStagingDir();
        const string url = "https://ftp.hp.com/pub/softpaq/sp151234.exe";
        var payload = TestPayload.FromString("hp-signed-or-unsigned");
        var handler = new FakeBiosHttpHandler().MapBytes(url, payload.Bytes);
        var sigVerifier = new FakeSignatureVerifier(signatureValid);
        var launcher = CreateGuardedLauncher((_, _) => Task.FromResult(new ProcessResult(0, "OK", "")));
        var commands = RecordingProcessLauncher.CreateCommandRunner(launcher, isProcessElevated: true);
        var provider = HpBiosUpdateProvider.CreateWithHandler(handler, commands: commands, signatureVerifier: sigVerifier);

        var request = BiosIdentityFactory.CreateInstallRequest(
            downloadUrl: url,
            sha256: null,
            suspendBitLocker: false,
            stagingDirectory: staging.Path);

        var result = await provider.InstallAsync(request);

        Assert.Equal(1, sigVerifier.CallCount);
        if (signatureValid)
        {
            Assert.True(result.Succeeded);
            Assert.Single(launcher.Calls);
        }
        else
        {
            Assert.False(result.Succeeded);
            Assert.Empty(launcher.Calls);
            Assert.Empty(Directory.GetFiles(staging.Path));
        }
    }

    // -------------------------------------------------------------------------
    // H12 — Non-Zero Exit Code & SerialNumber Redaction
    // -------------------------------------------------------------------------

    [Fact]
    public async Task InstallAsync_NonZeroExitCode_RedactsSerialNumberInLogTailAndLogs()
    {
        const string url = "https://ftp.hp.com/pub/softpaq/sp151234.exe";
        var payload = TestPayload.FromString("hp-failing-installer");
        var handler = new FakeBiosHttpHandler().MapBytes(url, payload.Bytes);
        var launcher = CreateGuardedLauncher((_, _) =>
            Task.FromResult(new ProcessResult(
                1603,
                $"Flashing SN={BiosIdentityFactory.SentinelSerialNumber}",
                $"Fatal error on {BiosIdentityFactory.SentinelSerialNumber}")));

        var commands = RecordingProcessLauncher.CreateCommandRunner(launcher, isProcessElevated: true);
        var log = new CapturedLog();
        var provider = HpBiosUpdateProvider.CreateWithHandler(handler, commands: commands, log: log.Logger);

        var request = BiosIdentityFactory.CreateInstallRequest(
            system: BiosIdentityFactory.Hp(),
            downloadUrl: url,
            sha256: payload.Sha256,
            suspendBitLocker: false);

        var result = await provider.InstallAsync(request);

        Assert.False(result.Succeeded);
        Assert.Equal(BiosInstallStatus.Failed, result.Status);
        Assert.Equal(1603, result.ExitCode);
        Assert.NotNull(result.LogTail);
        Assert.Contains("[REDACTED]", result.LogTail);
        Assert.DoesNotContain(BiosIdentityFactory.SentinelSerialNumber, result.LogTail, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(BiosIdentityFactory.SentinelSerialNumber, result.Message, StringComparison.OrdinalIgnoreCase);
        log.AssertDoesNotContainSecret();
    }

    // -------------------------------------------------------------------------
    // H13 — Un-Elevated Agent Elevation Span (Mock Bridge, Live Pipe, Disconnected)
    // -------------------------------------------------------------------------

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task InstallAsync_UnElevatedConnectedBridge_RoutesBitLockerAndInstallerWithPinnedSha256(bool allowReboot)
    {
        const string url = "https://ftp.hp.com/pub/softpaq/sp151234.exe";
        var payload = TestPayload.FromString($"hp-agent-routed-{allowReboot}");
        var handler = new FakeBiosHttpHandler().MapBytes(url, payload.Bytes);
        var sigVerifier = new FakeSignatureVerifier(true);
        var localLauncher = CreateGuardedLauncher();
        var bridge = new RecordingBiosBridge();

        var commands = RecordingProcessLauncher.CreateCommandRunner(
            localLauncher,
            isProcessElevated: false,
            elevatedBridge: bridge);

        var provider = HpBiosUpdateProvider.CreateWithHandler(
            handler,
            commands: commands,
            signatureVerifier: sigVerifier);

        // Deliberately omit Sha256 on Target so Authenticode runs and provider still pins SHA-256 for Agent TOCTOU safety.
        var request = BiosIdentityFactory.CreateInstallRequest(
            system: BiosIdentityFactory.Hp(),
            downloadUrl: url,
            sha256: null,
            suspendBitLocker: true,
            allowReboot: allowReboot);

        var result = await provider.InstallAsync(request);

        Assert.True(result.Succeeded);
        Assert.Equal(BiosInstallStatus.StagedForReboot, result.Status);
        Assert.True(result.BitLockerSuspended);
        Assert.Empty(localLauncher.Calls);
        Assert.Single(bridge.BitLockerDrives);

        var agentReq = Assert.Single(bridge.InstallRequests);
        Assert.Equal("hp", agentReq.VendorId);
        Assert.Equal(BiosAgentInstallModes.HpSoftPaq, agentReq.InstallMode);
        Assert.Equal(payload.Sha256, agentReq.ExpectedSha256);
        Assert.Equal(allowReboot, agentReq.AllowReboot);
    }

    [Fact]
    public async Task InstallAsync_UnElevatedLiveNamedPipe_RoundTripsThroughAgentBiosOperations()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var adminRoot = new TempStagingDir();

        const string url = "https://ftp.hp.com/pub/softpaq/HPBIOSUPDREC64.exe";
        var payload = TestPayload.FromString("hp-live-pipe-payload");
        var handler = new FakeBiosHttpHandler().MapBytes(url, payload.Bytes);

        var localLauncher = CreateGuardedLauncher();
        var agentLauncher = CreateGuardedLauncher((call, _) =>
        {
            if (call.BaseName.Equals("manage-bde.exe", StringComparison.OrdinalIgnoreCase))
                return Task.FromResult(new ProcessResult(0, "Protectors disabled.", ""));

            return Task.FromResult(new ProcessResult(3010, "HPBIOSUPDREC staged OK", ""));
        });

        var agentSigVerifier = new FakeSignatureVerifier(true);
        var ops = new AgentBiosOperations(agentLauncher, agentSigVerifier, stagingRoot: adminRoot.Path);

        var (server, serverTask, client) = await StartPipeAsync(agentLauncher, ops, cts.Token);
        using (server)
        {
            await using (client)
            {
                var provider = HpBiosUpdateProvider.CreateWithHandler(
                    handler,
                    commands: RecordingProcessLauncher.CreateCommandRunner(localLauncher, isProcessElevated: false),
                    elevatedBridge: client,
                    isProcessElevated: () => false);

                var request = BiosIdentityFactory.CreateInstallRequest(
                    system: BiosIdentityFactory.Hp(),
                    downloadUrl: url,
                    sha256: payload.Sha256,
                    suspendBitLocker: true,
                    allowReboot: false);

                var result = await provider.InstallAsync(request, ct: cts.Token);

                Assert.True(result.Succeeded);
                Assert.Equal(BiosInstallStatus.StagedForReboot, result.Status);
                Assert.True(result.BitLockerSuspended);
                Assert.Equal(3010, result.ExitCode);
            }

            await serverTask;
        }

        Assert.Empty(localLauncher.Calls);
        Assert.Equal(2, agentLauncher.Calls.Count);
        Assert.Equal("manage-bde.exe", agentLauncher.Calls[0].BaseName, ignoreCase: true);
        Assert.Equal(["-s", "-r"], agentLauncher.Calls[1].Arguments);
        Assert.Empty(Directory.GetFileSystemEntries(adminRoot.Path));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task InstallAsync_UnElevatedDisconnectedBridge_FailsClosedWithZeroLocalCalls(bool suspendBitLocker)
    {
        const string url = "https://ftp.hp.com/pub/softpaq/sp151234.exe";
        var payload = TestPayload.FromString("hp-disconnected-bridge");
        var handler = new FakeBiosHttpHandler().MapBytes(url, payload.Bytes);
        var localLauncher = CreateGuardedLauncher();
        var disconnected = new RecordingBiosBridge(isConnected: false);

        var provider = HpBiosUpdateProvider.CreateWithHandler(
            handler,
            commands: RecordingProcessLauncher.CreateCommandRunner(localLauncher, isProcessElevated: false, elevatedBridge: disconnected));

        var request = BiosIdentityFactory.CreateInstallRequest(
            downloadUrl: url,
            sha256: payload.Sha256,
            suspendBitLocker: suspendBitLocker);

        var result = await provider.InstallAsync(request);

        Assert.False(result.Succeeded);
        Assert.Equal(BiosInstallStatus.Failed, result.Status);
        Assert.Equal(SystemCommandRunner.AgentFailedExitCode, result.ExitCode);
        Assert.Empty(localLauncher.Calls);
        Assert.Empty(disconnected.InstallRequests);
    }

    // -------------------------------------------------------------------------
    // H14 — Iteration 2 Hardening Regressions (Peripherals/ME, Non-.exe, Traversal, Redaction, Digit-Leading Family)
    // -------------------------------------------------------------------------

    [Theory]
    [InlineData("BIOS", "HP Thunderbolt Firmware Update")]
    [InlineData("BIOS", "HP Dock Firmware")]
    [InlineData("BIOS", "NVMe SSD Firmware")]
    [InlineData("BIOS - System Firmware", "Intel Management Engine Firmware")]
    [InlineData("Firmware", "Intel Management Engine System Firmware")]
    [InlineData("BIOS", "HP BIOS Configuration Utility")]
    [InlineData("BIOS", "Intel CSME Firmware Update")]
    [InlineData("BIOS", "Intel AMT Firmware Update")]
    [InlineData("BIOS", "Intel ME Firmware")]
    [InlineData("BIOS", "Intel(R) ME Firmware")]
    public async Task GetLatestVersionAsync_PeripheralOrIntelMeFirmware_IsExcludedEvenUnderBiosCategory(
        string category,
        string name)
    {
        var xml = $"""
            <ImagePal>
              <UpdateInfo>
                <Id>sp160001</Id>
                <Category>{category}</Category>
                <Name>{name}</Name>
                <Version>16.1.30</Version>
                <Url>https://ftp.hp.com/pub/softpaq/sp160001.exe</Url>
              </UpdateInfo>
            </ImagePal>
            """;

        var handler = new FakeBiosHttpHandler()
            .MapText("https://hpia.hpcloud.hp.com/ref/880d/880d_64_11.0.cab", xml, "application/xml");

        var provider = HpBiosUpdateProvider.CreateWithHandler(handler);
        var identity = BiosIdentityFactory.Hp(biosVersion: "T76 Ver. 01.12.00");
        var current = await provider.GetCurrentVersionAsync(identity);

        var latest = await provider.GetLatestVersionAsync(identity, current);

        Assert.Equal(BiosCheckStatus.UnsupportedHardware, latest.Status);
    }

    [Theory]
    [InlineData("https://ftp.hp.com/pub/softpaq/sp151234.ps1")]
    [InlineData("https://ftp.hp.com/pub/softpaq/sp151234.bat")]
    [InlineData("https://ftp.hp.com/pub/softpaq/sp151234.cmd")]
    [InlineData("https://ftp.hp.com/pub/..%2fother/sp151234.exe")]
    [InlineData("https://ftp.hp.com/pub/%2e%2e/other/sp151234.exe")]
    [InlineData("ftp.hp.com/pub/%2e%2e%5cother/sp151234.exe")]
    [InlineData("https://ftp.hp.com/pub/%252e%252e/other/sp151234.exe")]
    [InlineData("https://ftp.hp.com/pub/sp151234%00.exe")]
    public async Task GetLatestVersionAsync_NonExeOrPercentEncodedTraversalUrl_ReturnsFailed(string badUrl)
    {
        var xml = $"""
            <ImagePal>
              <UpdateInfo>
                <Id>sp151234</Id>
                <Category>BIOS</Category>
                <Name>HP System BIOS (T76)</Name>
                <Version>01.16.00</Version>
                <Url>{badUrl}</Url>
              </UpdateInfo>
            </ImagePal>
            """;

        var handler = new FakeBiosHttpHandler()
            .MapText("https://hpia.hpcloud.hp.com/ref/880d/880d_64_11.0.cab", xml, "application/xml");

        var provider = HpBiosUpdateProvider.CreateWithHandler(handler);
        var identity = BiosIdentityFactory.Hp();
        var current = await provider.GetCurrentVersionAsync(identity);

        var latest = await provider.GetLatestVersionAsync(identity, current);

        Assert.Equal(BiosCheckStatus.Failed, latest.Status);
    }

    [Fact]
    public async Task GetLatestVersionAsync_MalformedCatalogWithSerialNumber_RedactsSerialNumberFromMessage()
    {
        var malformedXml = $"<ImagePal><{BiosIdentityFactory.SentinelSerialNumber}></ImagePal>";
        var handler = new FakeBiosHttpHandler()
            .MapText("https://hpia.hpcloud.hp.com/ref/880d/880d_64_11.0.cab", malformedXml, "application/xml");

        var provider = HpBiosUpdateProvider.CreateWithHandler(handler);
        var identity = BiosIdentityFactory.Hp();

        var latest = await provider.GetLatestVersionAsync(identity, identity.CurrentBios);

        Assert.Equal(BiosCheckStatus.Failed, latest.Status);
        Assert.DoesNotContain(BiosIdentityFactory.SentinelSerialNumber, latest.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task GetLatestVersionAsync_DigitLeadingFamilyInTitle_MatchesCorrectFamilyAndIgnoresYear()
    {
        const string xml = """
            <ImagePal>
              <UpdateInfo>
                <Id>sp170001</Id>
                <Category>BIOS</Category>
                <Name>HP System BIOS (2025) (786G2)</Name>
                <Version>01.99.00</Version>
                <Url>https://ftp.hp.com/pub/softpaq/sp170001.exe</Url>
              </UpdateInfo>
              <UpdateInfo>
                <Id>sp170002</Id>
                <Category>BIOS</Category>
                <Name>HP System BIOS (2025) (786G1)</Name>
                <Version>01.10.00</Version>
                <Url>https://ftp.hp.com/pub/softpaq/sp170002.exe</Url>
              </UpdateInfo>
            </ImagePal>
            """;

        var handler = new FakeBiosHttpHandler()
            .MapText("https://hpia.hpcloud.hp.com/ref/880d/880d_64_11.0.cab", xml, "application/xml");

        var provider = HpBiosUpdateProvider.CreateWithHandler(handler);
        var identity = BiosIdentityFactory.Hp(biosVersion: "786G1 Ver. 01.02.00");
        var current = await provider.GetCurrentVersionAsync(identity);

        var latest = await provider.GetLatestVersionAsync(identity, current);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal("01.10.00", latest.LatestVersion);
        Assert.Equal("sp170002", latest.PackageId);
        Assert.Equal("786G1", latest.Metadata?["family"]);
    }

    [Fact]
    public async Task GetLatestVersionAsync_IntelMeteorLakeSystemBiosTitle_IsAcceptedAndMatchesFamily()
    {
        const string xml = """
            <ImagePal>
              <UpdateInfo>
                <Id>sp175001</Id>
                <Category>BIOS - System Firmware</Category>
                <Name>HP EliteBook Intel Meteor Lake System BIOS Update (U70)</Name>
                <Version>01.16.00</Version>
                <Url>https://ftp.hp.com/pub/softpaq/sp175001.exe</Url>
              </UpdateInfo>
            </ImagePal>
            """;

        var handler = new FakeBiosHttpHandler()
            .MapText("https://hpia.hpcloud.hp.com/ref/880d/880d_64_11.0.cab", xml, "application/xml");

        var provider = HpBiosUpdateProvider.CreateWithHandler(handler);
        var identity = BiosIdentityFactory.Hp(biosVersion: "U70 Ver. 01.12.00");
        var current = await provider.GetCurrentVersionAsync(identity);

        var latest = await provider.GetLatestVersionAsync(identity, current);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal("01.16.00", latest.LatestVersion);
        Assert.Equal("sp175001", latest.PackageId);
        Assert.Equal("U70", latest.Metadata?["family"]);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

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
        var pipeName = $"rpd-bios-hp-test-{Guid.NewGuid():N}";
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
            return Task.FromResult(new BiosAgentInstallResult(Executed: true, Allowed: true, ExitCode: 3010, TimedOut: false, LogTail: "Agent HP OK"));
        }
    }
}
