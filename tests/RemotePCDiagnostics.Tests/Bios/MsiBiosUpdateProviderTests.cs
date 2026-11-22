using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Core.Bios;

namespace RemotePCDiagnostics.Tests.Bios;

public sealed class MsiBiosUpdateProviderTests
{
    private const string ValidSha256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    // =========================================================================
    // M1 — Metadata & Capabilities
    // =========================================================================

    [Fact]
    public void Metadata_MatchesContract()
    {
        var provider = new MsiBiosUpdateProvider();

        Assert.Equal("msi", provider.VendorId);
        Assert.Equal("MSI", provider.DisplayName);
        Assert.Equal(100, provider.Priority);
        Assert.Equal(["msi.com"], MsiBiosUpdateProvider.AllowedHostSuffixes);
        Assert.True(provider.Capabilities.CanCheckLatest);
        Assert.False(provider.Capabilities.CanInstall);
        Assert.False(provider.Capabilities.SupportsSilentInstall);
        Assert.False(provider.Capabilities.RequiresReboot);
        Assert.False(provider.Capabilities.RequiresElevation);
        Assert.True(provider.Capabilities.RequiresInternet);
    }

    // =========================================================================
    // M2 — CanHandle Positive & Negative Matrix
    // =========================================================================

    [Theory]
    [InlineData("MSI", "")]
    [InlineData("Micro-Star International Co., Ltd.", "")]
    [InlineData("Micro-Star International", "")]
    [InlineData("Micro Star International", "")]
    [InlineData("Generic OEM", "MSI")]
    [InlineData("", "Micro-Star International Co., Ltd.")]
    public void CanHandle_MsiManufacturers_ReturnsTrue(string manufacturer, string boardManufacturer)
    {
        var provider = new MsiBiosUpdateProvider();
        var identity = BiosIdentityFactory.Msi(manufacturer: manufacturer) with
        {
            BoardManufacturer = boardManufacturer,
        };

        Assert.True(provider.CanHandle(identity));
    }

    [Theory]
    [InlineData("CustomSI")]
    [InlineData("CustomSI Ltd")]
    [InlineData("Comsi")]
    [InlineData("MSInc")]
    [InlineData("RMSI Corp")]
    [InlineData("Micro-Stardom")]
    [InlineData("HP")]
    [InlineData("Dell Inc.")]
    [InlineData("LENOVO")]
    [InlineData("ASUSTeK COMPUTER INC.")]
    [InlineData("Acer")]
    public void CanHandle_NonMsiOrSubstringManufacturers_ReturnsFalse(string manufacturer)
    {
        var provider = new MsiBiosUpdateProvider();
        var identity = BiosIdentityFactory.GenericUefi(manufacturer);

        Assert.False(provider.CanHandle(identity));
    }

    [Fact]
    public void CanHandle_EmptyWhitespaceLargeAndNull_ReturnsFalseWithoutThrowing()
    {
        var provider = new MsiBiosUpdateProvider();

        Assert.False(provider.CanHandle(BiosIdentityFactory.Unknown()));
        Assert.False(provider.CanHandle(null!));
        Assert.False(provider.CanHandle(BiosIdentityFactory.GenericUefi("   ")));
        Assert.False(provider.CanHandle(BiosIdentityFactory.GenericUefi(new string('M', 4096))));
    }

    // =========================================================================
    // M3 — GetCurrentVersionAsync Normalization & Redaction
    // =========================================================================

    [Theory]
    [InlineData("A.E0", "A.E0", "7D25", "A")]
    [InlineData("1.A0", "1.A0", "7D25", "1")]
    [InlineData("E7D25IMS.AE0", "A.E0", "7D25", "A")]
    [InlineData("E7D75AMS.1A0", "1.A0", "7D75", "1")]
    [InlineData("7D25vAE", "A.E0", "7D25", "A")]
    [InlineData("E16R5IMS.10C", "1.0C", "16R5", "1")]
    [InlineData("", "", "7D25", "")]
    public async Task GetCurrentVersionAsync_SetsProviderIdNormalizesMsiVersionAndBoardCode_RedactsSerial(
        string rawVersion,
        string expectedVersion,
        string expectedBoardCode,
        string expectedMajor)
    {
        var log = new CapturedLog();
        var provider = new MsiBiosUpdateProvider(log: log.Logger);
        var identity = BiosIdentityFactory.Msi(biosVersion: rawVersion);

        var current = await provider.GetCurrentVersionAsync(identity);

        Assert.Equal("msi", current.ProviderId);
        Assert.Equal(expectedVersion, current.Version);
        Assert.NotNull(current.Metadata);
        Assert.Equal(expectedBoardCode, current.Metadata["boardCode"]);
        if (!string.IsNullOrEmpty(expectedMajor))
            Assert.Equal(expectedMajor, current.Metadata["msiMajor"]);

        log.AssertDoesNotContainSecret();
        foreach (var kv in current.Metadata)
            Assert.DoesNotContain(BiosIdentityFactory.SentinelSerialNumber, kv.Value, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task GetCurrentVersionAsync_NullAndCancelled_Throws()
    {
        var provider = new MsiBiosUpdateProvider();
        await Assert.ThrowsAsync<ArgumentNullException>(() => provider.GetCurrentVersionAsync(null!));

        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => provider.GetCurrentVersionAsync(BiosIdentityFactory.Msi(), cts.Token));
    }

    // =========================================================================
    // M4 — GetLatestVersionAsync Happy Path, UpToDate, Downgrade & BoardCode Extraction
    // =========================================================================

    [Fact]
    public async Task GetLatestVersionAsync_ValidSupportPanelCatalog_ReturnsUpdateAvailable()
    {
        var handler = new FakeBiosHttpHandler();
        var log = new CapturedLog();
        var system = BiosIdentityFactory.Msi(
            model: "MAG B650 TOMAHAWK WIFI",
            boardProduct: "MAG B650 TOMAHAWK WIFI (MS-7D75)",
            biosVersion: "1.A0");

        var json = $$"""
        {
          "result": {
            "downloads": {
              "Utility": [
                {
                  "download_version": "9.99",
                  "download_title": "MSI Center",
                  "download_release": "2025-01-01",
                  "download_url": "https://download.msi.com/uti_exe/mb/MSI_Center.zip"
                }
              ],
              "AMI BIOS": [
                {
                  "download_id": "msi-7d75-1g",
                  "download_title": "7D75v1G",
                  "download_version": "7D75v1G",
                  "download_release": "2024-06-20",
                  "download_size": "13.25 MB",
                  "download_sha256": "{{ValidSha256.ToUpperInvariant()}}",
                  "download_description": "- AGESA ComboPI 1.2.0.0a updated.<br/>- Security patch applied.",
                  "release_notes_url": "https://www.msi.com/Motherboard/MAG-B650-TOMAHAWK-WIFI/support",
                  "download_url": "https://download.msi.com/bos_exe/mb/7D75v1G.zip"
                },
                {
                  "download_id": "msi-7d75-1h1-beta",
                  "download_title": "7D75v1H1(Beta version)",
                  "download_version": "7D75v1H1(Beta version)",
                  "download_release": "2024-07-01",
                  "download_url": "https://download.msi.com/bos_exe/mb/7D75v1H1.zip"
                }
              ]
            }
          }
        }
        """;

        handler.MapJson(BuildDefaultMsiUrl("MS-7D75"), json);
        var provider = MsiBiosUpdateProvider.CreateWithHandler(handler, log.Logger);

        var latest = await provider.GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal("msi", latest.ProviderId);
        Assert.Equal("7D75v1G", latest.LatestVersion);
        Assert.Equal(new DateOnly(2024, 6, 20), latest.ReleaseDate);
        Assert.Equal("msi-7d75-1g", latest.PackageId);
        Assert.Equal("https://download.msi.com/bos_exe/mb/7D75v1G.zip", latest.DownloadUrl);
        Assert.Equal("https://www.msi.com/Motherboard/MAG-B650-TOMAHAWK-WIFI/support", latest.ReleaseNotesUrl);
        Assert.Equal(ValidSha256, latest.Sha256);
        Assert.Equal((long)Math.Round(13.25 * 1024 * 1024, MidpointRounding.AwayFromZero), latest.SizeBytes);
        Assert.True(latest.RequiresReboot);
        Assert.NotNull(latest.ReleaseSummary);
        Assert.DoesNotContain("<br", latest.ReleaseSummary, StringComparison.OrdinalIgnoreCase);
        Assert.Single(handler.Requests);
        Assert.DoesNotContain(BiosIdentityFactory.SentinelSerialNumber, handler.Requests[0].RequestUri!.AbsoluteUri, StringComparison.OrdinalIgnoreCase);
        log.AssertDoesNotContainSecret();
    }

    [Theory]
    [InlineData("A.E0", "A.E0")]
    [InlineData("A.E0", "7D25vAE")]
    [InlineData("E7D25IMS.AE0", "7D25vAE")]
    [InlineData("1.A0", "E7D25IMS.1A0")]
    [InlineData("1.G0", "1.G0")]
    [InlineData("1.H0", "1.G0")]
    [InlineData("A.G0", "A.E0")]
    public async Task GetLatestVersionAsync_CurrentEqualsOrExceedsLatest_ReturnsUpToDate(
        string currentVersion,
        string catalogVersion)
    {
        var handler = new FakeBiosHttpHandler();
        var system = BiosIdentityFactory.Msi(biosVersion: currentVersion);
        handler.MapJson(BuildDefaultMsiUrl("MS-7D25"), BuildSingleMsiCatalog(catalogVersion, "2025-04-01"));

        var latest = await MsiBiosUpdateProvider.CreateWithHandler(handler).GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.UpToDate, latest.Status);
        Assert.Null(latest.DownloadUrl);
    }

    [Theory]
    [InlineData("PRO Z690-A WIFI (MS-7D25)", "Default string", "MS-7D25")]
    [InlineData("MS-7D75", "MAG B650 TOMAHAWK WIFI", "MS-7D75")]
    [InlineData("MS-17S1", "Raider GE78 HX 13VH", "MS-17S1")]
    [InlineData("To Be Filled By O.E.M.", "MS-7D25", "MS-7D25")]
    [InlineData("Default string", "Raider GE78 HX 13VH", "Raider GE78 HX 13VH")]
    public async Task GetLatestVersionAsync_BoardProductAndModelCodeExtraction(
        string boardProduct,
        string model,
        string expectedQueryToken)
    {
        var handler = new FakeBiosHttpHandler();
        handler.MapJson(BuildDefaultMsiUrl(expectedQueryToken), BuildSingleMsiCatalog("A.G0", "2024-06-20"));

        var system = BiosIdentityFactory.Msi(model: model, boardProduct: boardProduct, biosVersion: "A.E0");
        var latest = await MsiBiosUpdateProvider.CreateWithHandler(handler).GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Single(handler.Requests);
        Assert.Contains(Uri.EscapeDataString(expectedQueryToken), handler.Requests[0].RequestUri!.AbsoluteUri, StringComparison.Ordinal);
    }

    // =========================================================================
    // M5 — MSI Alphanumeric/Base-36 Version Matrix, Beta, Laptop, Cross-Branch & Wrong-Board Guards
    // =========================================================================

    [Theory]
    [InlineData("1.90", "1.A0", BiosCheckStatus.UpdateAvailable)]
    [InlineData("1.A0", "1.G0", BiosCheckStatus.UpdateAvailable)]
    [InlineData("1.G0", "1.H0", BiosCheckStatus.UpdateAvailable)]
    [InlineData("1.A0", "7D25v1G", BiosCheckStatus.UpdateAvailable)]
    [InlineData("E7D25IMS.190", "7D25v1A", BiosCheckStatus.UpdateAvailable)]
    [InlineData("E7D25IMS.1A0", "E7D25IMS.1G0", BiosCheckStatus.UpdateAvailable)]
    [InlineData("A.90", "A.A0", BiosCheckStatus.UpdateAvailable)]
    [InlineData("A.E0", "A.F0", BiosCheckStatus.UpdateAvailable)]
    [InlineData("A.E0", "A.G0", BiosCheckStatus.UpdateAvailable)]
    [InlineData("E7D25IMS.AE0", "7D25vAG", BiosCheckStatus.UpdateAvailable)]
    [InlineData("7D25v19", "7D25v1A", BiosCheckStatus.UpdateAvailable)]
    [InlineData("7D25v1A1(Beta version)", "7D25v1A", BiosCheckStatus.UpdateAvailable)]
    [InlineData("7D25v1G", "7D25v1A", BiosCheckStatus.UpToDate)]
    [InlineData("1.G0", "1.90", BiosCheckStatus.UpToDate)]
    [InlineData("E7D25IMS.1G0", "7D25v1G", BiosCheckStatus.UpToDate)]
    [InlineData("1.9", "1.10", BiosCheckStatus.UpdateAvailable)]
    public async Task GetLatestVersionAsync_MsiAlphanumericAndHexRevisionComparison_IgnoresIdenticalDate(
        string currentVersion,
        string catalogVersion,
        BiosCheckStatus expectedStatus)
    {
        var handler = new FakeBiosHttpHandler();
        var system = BiosIdentityFactory.Msi(biosVersion: currentVersion);
        // Same date as BiosIdentityFactory.Msi (2023-10-05) so version logic alone decides!
        handler.MapJson(BuildDefaultMsiUrl("MS-7D25"), BuildSingleMsiCatalog(catalogVersion, "2023-10-05"));

        var latest = await MsiBiosUpdateProvider.CreateWithHandler(handler).GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(expectedStatus, latest.Status);
    }

    [Theory]
    [InlineData("E16R5IMS.109", "E16R5IMS.10C", BiosCheckStatus.UpdateAvailable)]
    [InlineData("E16R5IMS.10C", "E16R5IMS.10F", BiosCheckStatus.UpdateAvailable)]
    [InlineData("E16R5IMS.10F", "E16R5IMS.110", BiosCheckStatus.UpdateAvailable)]
    [InlineData("E16R5IMS.110", "E16R5IMS.10F", BiosCheckStatus.UpToDate)]
    public async Task GetLatestVersionAsync_MsiLaptopRomOrdering(
        string currentVersion,
        string catalogVersion,
        BiosCheckStatus expectedStatus)
    {
        var handler = new FakeBiosHttpHandler();
        var system = BiosIdentityFactory.Msi(
            model: "MS-16R5",
            boardProduct: "MS-16R5",
            biosVersion: currentVersion);
        handler.MapJson(BuildDefaultMsiUrl("MS-16R5"), BuildSingleMsiCatalog(catalogVersion, "2023-10-05"));

        var latest = await MsiBiosUpdateProvider.CreateWithHandler(handler).GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(expectedStatus, latest.Status);
    }

    [Fact]
    public async Task GetLatestVersionAsync_CrossBranchAndWrongBoardCode_NeverCrossUpgradesEvenOnNewerDate()
    {
        // 1. Incompatible Major letter branch ('1' vs 'A') with much newer date -> MUST NOT recommend upgrade
        var branchHandler = new FakeBiosHttpHandler();
        var system1 = BiosIdentityFactory.Msi(boardProduct: "MS-7D75", model: "MS-7D75", biosVersion: "1.A0");
        branchHandler.MapJson(BuildDefaultMsiUrl("MS-7D75"), BuildSingleMsiCatalog("A.G0", "2026-01-01"));

        var branchResult = await MsiBiosUpdateProvider.CreateWithHandler(branchHandler).GetLatestVersionAsync(system1, system1.CurrentBios);
        Assert.NotEqual(BiosCheckStatus.UpdateAvailable, branchResult.Status);
        Assert.Equal(BiosCheckStatus.UnsupportedHardware, branchResult.Status);

        // 2. Incompatible letter branches ('A' vs 'H') with much newer date -> MUST NOT recommend upgrade
        var letterHandler = new FakeBiosHttpHandler();
        var systemA = BiosIdentityFactory.Msi(boardProduct: "MS-7D75", model: "MS-7D75", biosVersion: "A.E0");
        letterHandler.MapJson(BuildDefaultMsiUrl("MS-7D75"), BuildSingleMsiCatalog("H.20", "2026-01-01"));

        var letterResult = await MsiBiosUpdateProvider.CreateWithHandler(letterHandler).GetLatestVersionAsync(systemA, systemA.CurrentBios);
        Assert.NotEqual(BiosCheckStatus.UpdateAvailable, letterResult.Status);
        Assert.Equal(BiosCheckStatus.UnsupportedHardware, letterResult.Status);

        // 3. Wrong board code (system MS-7D75 vs catalog entry 7E07v1G) -> ignored!
        var wrongBoardHandler = new FakeBiosHttpHandler();
        wrongBoardHandler.MapJson(BuildDefaultMsiUrl("MS-7D75"), """
        {
          "result": {
            "downloads": {
              "BIOS": [
                { "download_version": "7E07v1G", "download_release": "2026-01-01", "download_url": "https://download.msi.com/bos_exe/mb/7E07v1G.zip" },
                { "download_version": "7D75v1A", "download_release": "2024-01-01", "download_url": "https://download.msi.com/bos_exe/mb/7D75v1A.zip" }
              ]
            }
          }
        }
        """);

        var wrongBoardResult = await MsiBiosUpdateProvider.CreateWithHandler(wrongBoardHandler).GetLatestVersionAsync(system1, system1.CurrentBios);
        Assert.Equal(BiosCheckStatus.UpToDate, wrongBoardResult.Status);
        Assert.Equal("7D75v1A", wrongBoardResult.LatestVersion);
    }

    [Fact]
    public async Task GetLatestVersionAsync_BetaOnlyCatalogReturnsUnsupported_AndNon64HexChecksumIgnored()
    {
        var system = BiosIdentityFactory.Msi(boardProduct: "MS-7D75", model: "MS-7D75", biosVersion: "1.90");

        var betaHandler = new FakeBiosHttpHandler();
        betaHandler.MapJson(BuildDefaultMsiUrl("MS-7D75"), """
        {
          "BIOS": [
            { "download_version": "7D75v1A1", "download_release": "2024-06-01", "download_url": "https://download.msi.com/bos_exe/mb/7D75v1A1.zip" },
            { "download_version": "7D75v1B1(Beta version)", "download_release": "2024-07-01", "download_url": "https://download.msi.com/bos_exe/mb/7D75v1B1.zip" }
          ]
        }
        """);

        var betaResult = await MsiBiosUpdateProvider.CreateWithHandler(betaHandler).GetLatestVersionAsync(system, system.CurrentBios);
        Assert.Equal(BiosCheckStatus.UnsupportedHardware, betaResult.Status);

        var badHashHandler = new FakeBiosHttpHandler();
        badHashHandler.MapJson(BuildDefaultMsiUrl("MS-7D75"), """
        {
          "BIOS": [
            { "download_version": "7D75v1A", "download_release": "2024-06-01", "download_sha256": "deadbeef", "download_url": "https://download.msi.com/bos_exe/mb/7D75v1A.zip" }
          ]
        }
        """);
        var badHashResult = await MsiBiosUpdateProvider.CreateWithHandler(badHashHandler).GetLatestVersionAsync(system, system.CurrentBios);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, badHashResult.Status);
        Assert.Null(badHashResult.Sha256);
    }

    // =========================================================================
    // M6 — 24+ Mixed Entries Strict-Weak-Order Shuffle Invariance
    // =========================================================================

    [Fact]
    public async Task GetLatestVersionAsync_24MixedEntries_StrictWeakOrderShuffleInvariance()
    {
        var system = BiosIdentityFactory.Msi(boardProduct: "MS-7D25", model: "MS-7D25", biosVersion: "1.90");
        var rawEntries = new List<(string Version, string? Date, string Id, string Url)>
        {
            // Literal '#' collision triples
            ("A1##", "2024-01-01", "m01", "https://download.msi.com/bos_exe/mb/m01.zip"),
            ("A1#2", "2024-01-02", "m02", "https://download.msi.com/bos_exe/mb/m02.zip"),
            ("A##2", "2024-01-03", "m03", "https://download.msi.com/bos_exe/mb/m03.zip"),
            ("X1#2", "2024-01-04", "m04", "https://download.msi.com/bos_exe/mb/m04.zip"),
            ("X##3", "2024-01-05", "m05", "https://download.msi.com/bos_exe/mb/m05.zip"),
            ("X2#1", "2024-01-06", "m06", "https://download.msi.com/bos_exe/mb/m06.zip"),
            // >64-bit numeric overflow strings
            ("99999999999999999999999999", "2023-05-01", "m07", "https://download.msi.com/bos_exe/mb/m07.zip"),
            ("99999999999999999999999998", null, "m08", "https://download.msi.com/bos_exe/mb/m08.zip"),
            // MSI numeric-major & v-notation & AMI ROM forms
            ("1.90", "2023-08-01", "m09", "https://download.msi.com/bos_exe/mb/m09.zip"),
            ("1.A0", "2023-10-01", "m10", "https://download.msi.com/bos_exe/mb/m10.zip"),
            ("7D25v1B", "2024-01-01", "m11", "https://download.msi.com/bos_exe/mb/m11.zip"),
            ("E7D25IMS.1F0", "2024-05-01", "m12", "https://download.msi.com/bos_exe/mb/m12.zip"),
            ("7D25v1G", "2024-08-15", "m13", "https://download.msi.com/bos_exe/mb/m13.zip"),
            ("7D25v1H1(Beta version)", "2024-09-01", "m14", "https://download.msi.com/bos_exe/mb/m14.zip"),
            // Generic dotted / prefix / backslash skeletons
            ("1.2.3", "2023-04-01", "m15", "https://download.msi.com/bos_exe/mb/m15.zip"),
            ("1.10.0", "2023-06-01", "m16", "https://download.msi.com/bos_exe/mb/m16.zip"),
            ("V.8", null, "m17", "https://download.msi.com/bos_exe/mb/m17.zip"),
            ("M\\1#2", "2023-03-01", "m18", "https://download.msi.com/bos_exe/mb/m18.zip"),
            ("M\\#12", "2023-03-02", "m19", "https://download.msi.com/bos_exe/mb/m19.zip"),
            // Unicode U+017F edge case
            ("ſ10", "2023-02-01", "m20", "https://download.msi.com/bos_exe/mb/m20.zip"),
            ("S10", "2023-02-01", "m21", "https://download.msi.com/bos_exe/mb/m21.zip"),
            ("s10", "2023-02-02", "m22", "https://download.msi.com/bos_exe/mb/m22.zip"),
            // Duplicate & missing dates
            ("1.G0", null, "m23", "https://download.msi.com/bos_exe/mb/m23.zip"),
            ("MISC-REV", null, "m24", "https://download.msi.com/bos_exe/mb/m24.zip"),
        };

        int[] modes = [0, 1, 42, 1337, 9001, 202606];
        BiosLatestInfo? baseline = null;

        foreach (var mode in modes)
        {
            var permuted = Permute(rawEntries, mode);
            var payload = JsonSerializer.Serialize(new
            {
                result = new
                {
                    downloads = new Dictionary<string, object>
                    {
                        ["AMI BIOS"] = permuted.Select(e => new
                        {
                            download_id = e.Id,
                            download_version = e.Version,
                            download_release = e.Date,
                            download_url = e.Url,
                        }),
                    },
                },
            });

            var handler = new FakeBiosHttpHandler();
            handler.MapJson(BuildDefaultMsiUrl("MS-7D25"), payload);
            var provider = MsiBiosUpdateProvider.CreateWithHandler(handler);

            var result = await provider.GetLatestVersionAsync(system, system.CurrentBios);
            Assert.Equal(BiosCheckStatus.UpdateAvailable, result.Status);
            Assert.Equal("7D25v1G", result.LatestVersion);

            if (baseline is null)
            {
                baseline = result;
            }
            else
            {
                Assert.Equal(baseline.Status, result.Status);
                Assert.Equal(baseline.LatestVersion, result.LatestVersion);
                Assert.Equal(baseline.ReleaseDate, result.ReleaseDate);
                Assert.Equal(baseline.DownloadUrl, result.DownloadUrl);
                Assert.Equal(baseline.PackageId, result.PackageId);
            }
        }
    }

    // =========================================================================
    // M7 — Placeholders & Malicious SMBIOS Tokens -> UnsupportedHardware (0 HTTP Calls)
    // =========================================================================

    [Theory]
    [InlineData("", "")]
    [InlineData("   ", "   ")]
    [InlineData("Default string", "Default string")]
    [InlineData("To Be Filled By O.E.M.", "To Be Filled By O.E.M.")]
    [InlineData("System Product Name", "None")]
    [InlineData("N/A", "Unknown")]
    [InlineData("MS-7D75&whoami", "MS-7D75")]
    [InlineData("MS-7D75;calc.exe", "MS-7D75")]
    [InlineData("MS-7D75|powershell", "MS-7D75")]
    [InlineData("$(id)", "MS-7D75")]
    [InlineData("../../secret", "MS-7D75")]
    [InlineData("MS-7D75?x=1", "MS-7D75")]
    [InlineData("MS-7D75\r\nHost: evil.com", "MS-7D75")]
    [InlineData("PRO Z690-A WIFI (MS-7D25);calc", "MS-7D25")]
    [InlineData("MS-7D75", "MS-7D75&whoami")]
    public async Task GetLatestVersionAsync_PlaceholdersAndMaliciousSmbiosTokens_ReturnsUnsupportedWithZeroHttpCalls(
        string boardProduct,
        string model)
    {
        var handler = new FakeBiosHttpHandler();
        var provider = MsiBiosUpdateProvider.CreateWithHandler(handler);
        var system = BiosIdentityFactory.Msi(model: model, boardProduct: boardProduct);

        var latest = await provider.GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.UnsupportedHardware, latest.Status);
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task GetLatestVersionAsync_OverlongBoardToken_ReturnsUnsupportedWithZeroHttpCalls()
    {
        var handler = new FakeBiosHttpHandler();
        var provider = MsiBiosUpdateProvider.CreateWithHandler(handler);
        var system = BiosIdentityFactory.Msi(boardProduct: new string('M', 100), model: "MS-7D25");

        var latest = await provider.GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.UnsupportedHardware, latest.Status);
        Assert.Empty(handler.Requests);
    }

    // =========================================================================
    // M8 — HTTP Status Mapping, Network Errors, Timeout & Cancellation
    // =========================================================================

    [Theory]
    [InlineData(HttpStatusCode.NotFound, BiosCheckStatus.UnsupportedHardware)]
    [InlineData(HttpStatusCode.TooManyRequests, BiosCheckStatus.ProviderUnavailable)]
    [InlineData(HttpStatusCode.InternalServerError, BiosCheckStatus.ProviderUnavailable)]
    [InlineData(HttpStatusCode.BadGateway, BiosCheckStatus.ProviderUnavailable)]
    [InlineData(HttpStatusCode.ServiceUnavailable, BiosCheckStatus.ProviderUnavailable)]
    [InlineData(HttpStatusCode.GatewayTimeout, BiosCheckStatus.ProviderUnavailable)]
    [InlineData(HttpStatusCode.BadRequest, BiosCheckStatus.Failed)]
    [InlineData(HttpStatusCode.Forbidden, BiosCheckStatus.Failed)]
    public async Task GetLatestVersionAsync_HttpStatusMapping(HttpStatusCode statusCode, BiosCheckStatus expectedStatus)
    {
        var handler = new FakeBiosHttpHandler();
        var system = BiosIdentityFactory.Msi();
        handler.MapStatus(BuildDefaultMsiUrl("MS-7D25"), statusCode);

        var latest = await MsiBiosUpdateProvider.CreateWithHandler(handler).GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(expectedStatus, latest.Status);
    }

    [Fact]
    public async Task GetLatestVersionAsync_NetworkTimeoutAndCancellation()
    {
        var system = BiosIdentityFactory.Msi();
        var url = BuildDefaultMsiUrl("MS-7D25");

        var netHandler = new FakeBiosHttpHandler();
        netHandler.MapException(url, () => new HttpRequestException("Network failure", new SocketException((int)SocketError.ConnectionRefused)));
        var netResult = await MsiBiosUpdateProvider.CreateWithHandler(netHandler).GetLatestVersionAsync(system, system.CurrentBios);
        Assert.Equal(BiosCheckStatus.Offline, netResult.Status);

        var timeoutHandler = new FakeBiosHttpHandler();
        timeoutHandler.MapException(url, () => new TaskCanceledException("Timed out", new TimeoutException()));
        var timeoutResult = await MsiBiosUpdateProvider.CreateWithHandler(timeoutHandler).GetLatestVersionAsync(system, system.CurrentBios);
        Assert.Equal(BiosCheckStatus.Offline, timeoutResult.Status);

        using var preCts = new CancellationTokenSource();
        preCts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => MsiBiosUpdateProvider.CreateWithHandler(new FakeBiosHttpHandler()).GetLatestVersionAsync(system, system.CurrentBios, preCts.Token));

        using var midCts = new CancellationTokenSource();
        var midHandler = new FakeBiosHttpHandler();
        midHandler.Map(url, (_, ct) =>
        {
            midCts.Cancel();
            ct.ThrowIfCancellationRequested();
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        });
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => MsiBiosUpdateProvider.CreateWithHandler(midHandler).GetLatestVersionAsync(system, system.CurrentBios, midCts.Token));
    }

    // =========================================================================
    // M9 — Redirects, Oversized Payload & Malformed/Degenerate JSON
    // =========================================================================

    [Fact]
    public async Task GetLatestVersionAsync_AllowedSameDomainRedirect_Succeeds()
    {
        var handler = new FakeBiosHttpHandler();
        var system = BiosIdentityFactory.Msi();
        var initialUrl = BuildDefaultMsiUrl("MS-7D25");
        var redirectedUrl = "https://download.msi.com/api/v2/bios.json";

        handler.MapRedirect(initialUrl, redirectedUrl, HttpStatusCode.Redirect);
        handler.MapJson(redirectedUrl, BuildSingleMsiCatalog("7D25vAG", "2024-06-20"));

        var latest = await MsiBiosUpdateProvider.CreateWithHandler(handler).GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal("7D25vAG", latest.LatestVersion);
        Assert.Equal(2, handler.Requests.Count);
    }

    [Theory]
    [InlineData("https://evil.com/bios.json")]
    [InlineData("http://download.msi.com/bios.json")]
    [InlineData("//evil.com/bios.json")]
    [InlineData(null)]
    public async Task GetLatestVersionAsync_UnsafeRedirect_ReturnsFailed(string? targetLocation)
    {
        var handler = new FakeBiosHttpHandler();
        var system = BiosIdentityFactory.Msi();
        handler.MapRedirect(BuildDefaultMsiUrl("MS-7D25"), targetLocation, HttpStatusCode.Redirect);

        var latest = await MsiBiosUpdateProvider.CreateWithHandler(handler).GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.Failed, latest.Status);
        Assert.Single(handler.Requests);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task GetLatestVersionAsync_OversizedPayload_ContentLengthAndChunked_ReturnsFailed(bool includeContentLength)
    {
        var handler = new FakeBiosHttpHandler();
        var system = BiosIdentityFactory.Msi();
        var oversized = new byte[MsiBiosUpdateProvider.MaxCatalogJsonBytes + 1024];
        Array.Fill(oversized, (byte)' ');
        oversized[0] = (byte)'[';
        oversized[^1] = (byte)']';

        handler.MapBytes(BuildDefaultMsiUrl("MS-7D25"), oversized, includeContentLength: includeContentLength);

        var latest = await MsiBiosUpdateProvider.CreateWithHandler(handler).GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.Failed, latest.Status);
    }

    [Theory]
    [InlineData("", BiosCheckStatus.Failed)]
    [InlineData("   ", BiosCheckStatus.Failed)]
    [InlineData("<html>error</html>", BiosCheckStatus.Failed)]
    [InlineData("{bad", BiosCheckStatus.Failed)]
    [InlineData("null", BiosCheckStatus.Failed)]
    [InlineData("123", BiosCheckStatus.Failed)]
    [InlineData("[]", BiosCheckStatus.UnsupportedHardware)]
    [InlineData("{\"result\":{\"downloads\":{\"BIOS\":[]}}}", BiosCheckStatus.UnsupportedHardware)]
    [InlineData("{\"result\":null}", BiosCheckStatus.UnsupportedHardware)]
    public async Task GetLatestVersionAsync_MalformedOrDegenerateJson_ReturnsExpectedStatus(
        string body,
        BiosCheckStatus expectedStatus)
    {
        var handler = new FakeBiosHttpHandler();
        var system = BiosIdentityFactory.Msi();
        handler.MapText(BuildDefaultMsiUrl("MS-7D25"), body, "application/json");

        var latest = await MsiBiosUpdateProvider.CreateWithHandler(handler).GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(expectedStatus, latest.Status);
    }

    // =========================================================================
    // M10 — URL Security, Traversal & SerialNumber Redaction
    // =========================================================================

    [Theory]
    [InlineData("http://download.msi.com/bos_exe/mb/7D25vAG.zip")]
    [InlineData("https://evil.com/7D25vAG.zip")]
    [InlineData("https://msi.com.evil.com/7D25vAG.zip")]
    [InlineData("https://comsi.com/7D25vAG.zip")]
    [InlineData("https://msi.com@evil.com/7D25vAG.zip")]
    [InlineData("file:///C:/bios.zip")]
    [InlineData("//download.msi.com/bos_exe/mb/7D25vAG.zip")]
    [InlineData("https://download.msi.com/bos_exe/%2e%2e/evil.zip")]
    [InlineData("https://download.msi.com/bos_exe/%252e%252e/evil.zip")]
    [InlineData("https://download.msi.com/bos_exe/7D25%00.zip")]
    public async Task GetLatestVersionAsync_UntrustedDownloadUrl_ReturnsFailed(string badUrl)
    {
        var handler = new FakeBiosHttpHandler();
        var system = BiosIdentityFactory.Msi();
        var json = JsonSerializer.Serialize(new
        {
            BIOS = new[]
            {
                new { download_version = "7D25vAG", download_release = "2024-06-20", download_url = badUrl },
            },
        });
        handler.MapJson(BuildDefaultMsiUrl("MS-7D25"), json);

        var latest = await MsiBiosUpdateProvider.CreateWithHandler(handler).GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.Failed, latest.Status);
        Assert.Null(latest.DownloadUrl);
    }

    [Fact]
    public async Task GetLatestVersionAsync_UntrustedReleaseNotesUrlDropped_AndUnsafeEndpointFailsWithZeroCalls()
    {
        var handler = new FakeBiosHttpHandler();
        var system = BiosIdentityFactory.Msi();
        handler.MapJson(BuildDefaultMsiUrl("MS-7D25"), """
        {
          "BIOS": [
            {
              "download_version": "7D25vAG",
              "download_release": "2024-06-20",
              "release_notes_url": "https://comsi.com/notes",
              "download_url": "https://download.msi.com/bos_exe/mb/7D25vAG.zip"
            }
          ]
        }
        """);

        var latest = await MsiBiosUpdateProvider.CreateWithHandler(handler).GetLatestVersionAsync(system, system.CurrentBios);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Null(latest.ReleaseNotesUrl);

        var evilHandler = new FakeBiosHttpHandler();
        var badProvider = MsiBiosUpdateProvider.CreateWithHandler(evilHandler, catalogEndpoint: "https://comsi.com/api?product={product}");
        var badResult = await badProvider.GetLatestVersionAsync(system, system.CurrentBios);
        Assert.Equal(BiosCheckStatus.Failed, badResult.Status);
        Assert.Empty(evilHandler.Requests);
    }

    [Fact]
    public async Task GetLatestVersionAsync_ErrorAndPayloadContainingSerialNumber_RedactsSecret()
    {
        var handler = new FakeBiosHttpHandler();
        var log = new CapturedLog();
        var system = BiosIdentityFactory.Msi();
        var secret = BiosIdentityFactory.SentinelSerialNumber;

        handler.MapJson(BuildDefaultMsiUrl("MS-7D25"), $$"""
        {
          "BIOS": [
            {
              "download_id": "id-{{secret}}",
              "download_version": "7D25vAG",
              "download_description": "Echoed {{secret}} in BIOS notes",
              "download_release": "2024-06-20",
              "download_url": "https://download.msi.com/bos_exe/mb/7D25vAG.zip"
            }
          ]
        }
        """);

        var okResult = await MsiBiosUpdateProvider.CreateWithHandler(handler, log.Logger).GetLatestVersionAsync(system, system.CurrentBios);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, okResult.Status);
        Assert.DoesNotContain(secret, okResult.ReleaseSummary ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(secret, okResult.PackageId ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(secret, okResult.Message ?? "", StringComparison.OrdinalIgnoreCase);
        log.AssertDoesNotContainSecret();

        var errHandler = new FakeBiosHttpHandler();
        errHandler.MapException(BuildDefaultMsiUrl("MS-7D25"), () => new InvalidOperationException($"Failure for {secret}"));
        var errLog = new CapturedLog();
        var errResult = await MsiBiosUpdateProvider.CreateWithHandler(errHandler, errLog.Logger).GetLatestVersionAsync(system, system.CurrentBios);
        Assert.Equal(BiosCheckStatus.Failed, errResult.Status);
        Assert.DoesNotContain(secret, errResult.Message ?? "", StringComparison.OrdinalIgnoreCase);
        errLog.AssertDoesNotContainSecret();
    }

    // =========================================================================
    // M11 — Explicit Check-Only InstallAsync Contract
    // =========================================================================

    [Fact]
    public async Task InstallAsync_ReturnsUnsupported_AndGuardsNullAndCancellation()
    {
        var handler = new FakeBiosHttpHandler();
        var log = new CapturedLog();
        var progress = new SyncProgress<BiosInstallProgress>();
        var provider = MsiBiosUpdateProvider.CreateWithHandler(handler, log.Logger);

        await Assert.ThrowsAsync<ArgumentNullException>(() => provider.InstallAsync(null!));

        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => provider.InstallAsync(CreateMsiInstallRequest(), progress, cts.Token));

        var result = await provider.InstallAsync(CreateMsiInstallRequest(), progress);

        Assert.False(result.Succeeded);
        Assert.Equal(BiosInstallStatus.Unsupported, result.Status);
        Assert.False(result.RequiresReboot);
        Assert.False(result.BitLockerSuspended);
        Assert.Equal("A.E0", result.PreviousVersion);
        Assert.Equal("7D25vAG", result.TargetVersion);
        Assert.Empty(handler.Requests);
        Assert.Empty(progress.Reports);
        log.AssertDoesNotContainSecret();
        Assert.DoesNotContain(BiosIdentityFactory.SentinelSerialNumber, result.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(BiosIdentityFactory.SentinelSerialNumber, result.LogTail ?? "", StringComparison.OrdinalIgnoreCase);
    }

    // =========================================================================
    // M12 — DI Validation & BiosUpdateService Integration
    // =========================================================================

    [Fact]
    public async Task DiRegistration_ValidateOnBuildAndScopes_ResolvesAndIntegratesWithBiosUpdateService()
    {
        var bareServices = new ServiceCollection();
        bareServices.AddBiosUpdates();
        bareServices.AddBiosUpdateProvider<MsiBiosUpdateProvider>();
        await using (var bareSp = bareServices.BuildServiceProvider(
            new ServiceProviderOptions { ValidateOnBuild = true, ValidateScopes = true }))
        {
            var bareSvc = bareSp.GetRequiredService<IBiosUpdateService>();
            Assert.Contains(bareSvc.Providers, p => p.VendorId == "msi");
        }

        var system = BiosIdentityFactory.Msi();
        var handler = new FakeBiosHttpHandler();
        handler.MapJson(BuildDefaultMsiUrl("MS-7D25"), BuildSingleMsiCatalog("7D25vAG", "2024-06-20"));
        var safetyProbe = new CountingSafetyProbe(BiosIdentityFactory.SafeSnapshot());

        var services = new ServiceCollection();
        services.AddSingleton<IBiosSystemProbe>(new StubSystemProbe(system));
        services.AddSingleton<IBiosInstallSafetyProbe>(safetyProbe);
        services.AddBiosUpdates();
        services.AddBiosUpdateProvider(_ => MsiBiosUpdateProvider.CreateWithHandler(handler));

        await using var sp = services.BuildServiceProvider(
            new ServiceProviderOptions { ValidateOnBuild = true, ValidateScopes = true });
        var service = sp.GetRequiredService<IBiosUpdateService>();

        var resolved = service.ResolveProvider(system);
        Assert.NotNull(resolved);
        Assert.Equal("msi", resolved.VendorId);

        var check = await service.CheckForUpdateAsync();
        Assert.Equal("msi", check.ProviderId);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, check.Latest.Status);
        Assert.Equal("7D25vAG", check.Latest.LatestVersion);

        var installRequest = new BiosInstallRequest(system, check.Current, check.Latest, Approved: true, ApprovedBy: "op");
        var installResult = await service.InstallUpdateAsync(installRequest);

        Assert.False(installResult.Succeeded);
        Assert.Equal(BiosInstallStatus.Unsupported, installResult.Status);
        Assert.Equal(0, safetyProbe.CallCount);
        Assert.Single(handler.Requests);
    }

    // =========================================================================
    // M13 — Iteration 2 Hardening & Regression Tests
    // =========================================================================

    [Theory]
    [InlineData("MAG B650 TOMAHAWK WIFI", "7D75v1G")]
    [InlineData("MPG Z790 CARBON LAN", "7D75v1G")]
    [InlineData("Improve USB / NVMe / Thunderbolt compatibility", "7D75v1G")]
    public async Task GetLatestVersionAsync_ExplicitAmiBiosCategoryWithPeripheralBoardTitles_AcceptedWhileToolsRejected(
        string biosTitle,
        string expectedVersion)
    {
        var handler = new FakeBiosHttpHandler();
        var system = BiosIdentityFactory.Msi(
            model: "MAG B650 TOMAHAWK WIFI",
            boardProduct: "MAG B650 TOMAHAWK WIFI (MS-7D75)",
            biosVersion: "1.A0");
        var json = JsonSerializer.Serialize(new
        {
            result = new
            {
                downloads = new Dictionary<string, object>
                {
                    ["AMI BIOS"] = new[]
                    {
                        new
                        {
                            download_title = "Intel ME Update Tool",
                            download_version = "7D75v9Z",
                            download_release = "2026-01-01",
                            download_url = "https://download.msi.com/bos_exe/mb/MEUpdateTool.zip",
                        },
                        new
                        {
                            download_title = biosTitle,
                            download_version = expectedVersion,
                            download_release = "2024-06-20",
                            download_url = "https://download.msi.com/bos_exe/mb/7D75v1G.zip",
                        },
                    },
                },
            },
        });
        handler.MapJson(BuildDefaultMsiUrl("MS-7D75"), json);

        var latest = await MsiBiosUpdateProvider.CreateWithHandler(handler).GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal(expectedVersion, latest.LatestVersion);
        Assert.Equal("https://download.msi.com/bos_exe/mb/7D75v1G.zip", latest.DownloadUrl);
    }

    [Theory]
    [InlineData("7D75v1A1(Beta version)", "7D75v1A")]
    [InlineData("7D75v1A1", "7D75v1A")]
    [InlineData("7D75v111", "7D75v11")]
    public async Task CheckForUpdateAsync_BetaCurrentVersionRoundTrip_ReturnsUpdateAvailableAgainstFinalRelease(
        string currentBetaVersion,
        string catalogFinalVersion)
    {
        var baseSystem = BiosIdentityFactory.Msi(
            model: "MS-7D75",
            boardProduct: "MS-7D75",
            biosVersion: currentBetaVersion);
        var system = baseSystem with
        {
            CurrentBios = baseSystem.CurrentBios with { ReleaseDate = new DateOnly(2024, 1, 15) },
        };

        var handler = new FakeBiosHttpHandler();
        handler.MapJson(BuildDefaultMsiUrl("MS-7D75"), BuildSingleMsiCatalog(catalogFinalVersion, "2024-01-15"));

        var services = new ServiceCollection();
        services.AddSingleton<IBiosSystemProbe>(new StubSystemProbe(system));
        services.AddSingleton<IBiosInstallSafetyProbe>(new CountingSafetyProbe(BiosIdentityFactory.SafeSnapshot()));
        services.AddBiosUpdates();
        services.AddBiosUpdateProvider(_ => MsiBiosUpdateProvider.CreateWithHandler(handler));

        await using var sp = services.BuildServiceProvider(
            new ServiceProviderOptions { ValidateOnBuild = true, ValidateScopes = true });
        var service = sp.GetRequiredService<IBiosUpdateService>();

        var outcome = await service.CheckForUpdateAsync();

        Assert.Equal("msi", outcome.ProviderId);
        Assert.Equal("true", outcome.Current.Metadata?["isBeta"]);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, outcome.Latest.Status);
        Assert.Equal(catalogFinalVersion, outcome.Latest.LatestVersion);
    }

    [Fact]
    public async Task GetLatestVersionAsync_DesktopBeta1A1AndAmiRomConsistency_AndLaptopRomRoundTripPreserved()
    {
        // 1. Direct SMBIOS desktop beta strings "1.A1" and "E7D75AMS.1A1" vs final "1.A0" / "7D75v1A" -> UpdateAvailable
        foreach (var (currentVer, catalogVer) in new[]
        {
            ("1.A1", "1.A0"),
            ("1.A1", "7D75v1A"),
            ("E7D75AMS.1A1", "7D75v1A"),
        })
        {
            var handler = new FakeBiosHttpHandler();
            handler.MapJson(BuildDefaultMsiUrl("MS-7D75"), BuildSingleMsiCatalog(catalogVer, "2024-01-15"));
            var baseSystem = BiosIdentityFactory.Msi(model: "MS-7D75", boardProduct: "MS-7D75", biosVersion: currentVer);
            var system = baseSystem with
            {
                CurrentBios = baseSystem.CurrentBios with { ReleaseDate = new DateOnly(2024, 1, 15) },
            };

            var latest = await MsiBiosUpdateProvider.CreateWithHandler(handler).GetLatestVersionAsync(system, system.CurrentBios);
            Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        }

        // 2. Catalog containing unlabeled desktop beta ["1.A1", "1.A0"] or ["E7D75AMS.1A1", "E7D75AMS.1A0"] skips beta and selects final
        foreach (var (betaVer, finalVer) in new[]
        {
            ("1.A1", "1.A0"),
            ("E7D75AMS.1A1", "E7D75AMS.1A0"),
        })
        {
            var handler = new FakeBiosHttpHandler();
            handler.MapJson(BuildDefaultMsiUrl("MS-7D75"), JsonSerializer.Serialize(new
            {
                BIOS = new[]
                {
                    new { download_version = betaVer, download_release = "2024-02-01", download_url = "https://download.msi.com/bos_exe/mb/beta.zip" },
                    new { download_version = finalVer, download_release = "2024-01-15", download_url = "https://download.msi.com/bos_exe/mb/final.zip" },
                },
            }));
            var system = BiosIdentityFactory.Msi(model: "MS-7D75", boardProduct: "MS-7D75", biosVersion: "1.90");
            var latest = await MsiBiosUpdateProvider.CreateWithHandler(handler).GetLatestVersionAsync(system, system.CurrentBios);

            Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
            Assert.Equal(finalVer, latest.LatestVersion);
        }

        // 3. Laptop ROM "E16R5IMS.10C" full round-trip -> UpToDate (not falsely marked beta!)
        var baseLaptop = BiosIdentityFactory.Msi(model: "MS-16R5", boardProduct: "MS-16R5", biosVersion: "E16R5IMS.10C");
        var laptopSystem = baseLaptop with
        {
            CurrentBios = baseLaptop.CurrentBios with { ReleaseDate = new DateOnly(2024, 1, 15) },
        };
        var laptopHandler = new FakeBiosHttpHandler();
        laptopHandler.MapJson(BuildDefaultMsiUrl("MS-16R5"), BuildSingleMsiCatalog("E16R5IMS.10C", "2024-01-15"));
        var laptopProvider = MsiBiosUpdateProvider.CreateWithHandler(laptopHandler);
        var normalizedLaptop = await laptopProvider.GetCurrentVersionAsync(laptopSystem);
        Assert.False(normalizedLaptop.Metadata?.ContainsKey("isBeta") ?? false);

        var laptopLatest = await laptopProvider.GetLatestVersionAsync(laptopSystem, normalizedLaptop);
        Assert.Equal(BiosCheckStatus.UpToDate, laptopLatest.Status);
    }

    [Fact]
    public async Task GetLatestVersionAsync_NumericMajorUpgradeMonotonicity_Selects200Over1H0()
    {
        var baseSystem = BiosIdentityFactory.Msi(model: "MS-7D75", boardProduct: "MS-7D75", biosVersion: "1.H0");
        var system = baseSystem with
        {
            CurrentBios = baseSystem.CurrentBios with { ReleaseDate = new DateOnly(2024, 1, 1) },
        };

        var handler = new FakeBiosHttpHandler();
        handler.MapJson(BuildDefaultMsiUrl("MS-7D75"), """
        {
          "BIOS": [
            { "download_version": "1.H0", "download_release": "2024-01-01", "download_url": "https://download.msi.com/bos_exe/mb/1H0.zip" },
            { "download_version": "2.00", "download_release": "2025-01-01", "download_url": "https://download.msi.com/bos_exe/mb/200.zip" }
          ]
        }
        """);

        var latest = await MsiBiosUpdateProvider.CreateWithHandler(handler).GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal("2.00", latest.LatestVersion);
        Assert.Equal("https://download.msi.com/bos_exe/mb/200.zip", latest.DownloadUrl);
    }

    [Fact]
    public async Task CompareMsiVersions_CrossKindBetaNonCycle_SatisfiesStrictWeakOrderingAndShuffleInvariance()
    {
        // Direct verification of CompareMsiVersions across the formerly cycling triple (7D75v11, 1.11.0, 7D75v111)
        // and neighboring numeric/beta/MSI forms: zero antisymmetry or transitivity violations!
        var parseMethod = typeof(MsiBiosUpdateProvider).GetMethod(
            "ParseMsiVersion",
            System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic)!;
        var compareMethod = typeof(MsiBiosUpdateProvider).GetMethod(
            "CompareMsiVersions",
            System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic)!;

        object Parse(string v) => parseMethod.Invoke(null, [v, null, null])!;
        int? Compare(object a, object b) => (int?)compareMethod.Invoke(null, [a, b]);

        var rawVersions = new[]
        {
            "7D75v10", "7D75v11", "7D75v111", "7D75v111(Beta version)", "7D75v12",
            "1.10", "1.11", "1.11.0", "1.10.0", "1.9", "1.09", "1.A0", "1.A1",
            "E7D75AMS.110", "E7D75AMS.1A0", "E7D75AMS.1A1", "E16R5IMS.10C", "2.00",
        };
        var parsedVersions = rawVersions.Select(Parse).ToArray();

        // Specific regression check: beta 7D75v111 must NOT bridge to generic 1.11.0
        var v11 = Parse("7D75v11");
        var v111 = Parse("7D75v111");
        var gen1110 = Parse("1.11.0");
        Assert.Null(Compare(v111, gen1110));
        Assert.Null(Compare(gen1110, v111));
        Assert.True(Compare(v11, v111) > 0);
        Assert.True(Compare(v11, gen1110) < 0);

        for (var i = 0; i < parsedVersions.Length; i++)
        {
            Assert.Equal(0, Compare(parsedVersions[i], parsedVersions[i]));

            for (var j = 0; j < parsedVersions.Length; j++)
            {
                var ab = Compare(parsedVersions[i], parsedVersions[j]);
                var ba = Compare(parsedVersions[j], parsedVersions[i]);
                Assert.Equal(ab.HasValue, ba.HasValue);
                if (ab.HasValue)
                    Assert.Equal(-Math.Sign(ab.Value), Math.Sign(ba!.Value));

                if (!ab.HasValue)
                    continue;

                for (var k = 0; k < parsedVersions.Length; k++)
                {
                    var bc = Compare(parsedVersions[j], parsedVersions[k]);
                    var ac = Compare(parsedVersions[i], parsedVersions[k]);
                    if (!bc.HasValue || !ac.HasValue)
                        continue;

                    if (ab.Value <= 0 && bc.Value <= 0)
                    {
                        Assert.True(
                            ac.Value <= 0,
                            $"Transitivity violation: {rawVersions[i]} <= {rawVersions[j]} <= {rawVersions[k]} but cmp(a,c)={ac.Value}");
                        if (ab.Value < 0 || bc.Value < 0)
                        {
                            Assert.True(
                                ac.Value < 0,
                                $"Strict transitivity violation: {rawVersions[i]}, {rawVersions[j]}, {rawVersions[k]}");
                        }
                    }
                }
            }
        }

        // Mixed catalog permutation invariance with 7D75v11, 1.11.0, and beta 7D75v111
        var system = BiosIdentityFactory.Msi(model: "MS-7D75", boardProduct: "MS-7D75", biosVersion: "1.09");
        var entries = new[]
        {
            new { download_version = "7D75v11", download_release = "2024-02-01", download_url = "https://download.msi.com/bos_exe/mb/11.zip" },
            new { download_version = "1.11.0", download_release = "2024-03-01", download_url = "https://download.msi.com/bos_exe/mb/1110.zip" },
            new { download_version = "7D75v111", download_release = "2024-04-01", download_url = "https://download.msi.com/bos_exe/mb/111b.zip" },
        };

        BiosLatestInfo? baseline = null;
        foreach (var mode in new[] { 0, 1, 7, 42 })
        {
            var handler = new FakeBiosHttpHandler();
            handler.MapJson(BuildDefaultMsiUrl("MS-7D75"), JsonSerializer.Serialize(new { BIOS = Permute(entries, mode) }));
            var res = await MsiBiosUpdateProvider.CreateWithHandler(handler).GetLatestVersionAsync(system, system.CurrentBios);
            Assert.Equal(BiosCheckStatus.UpdateAvailable, res.Status);
            if (baseline is null)
                baseline = res;
            else
                Assert.Equal(baseline.LatestVersion, res.LatestVersion);
        }
    }

    [Fact]
    public async Task GetLatestVersionAsync_SerialNumberInVersionUrlsUntrustedLogAndModelException_CompletelyRedacted()
    {
        const string secret = "SN-TOPSECRET-424242";

        // 1. Echoed serial in Version, DownloadUrl, and ReleaseNotesUrl
        var echoHandler = new FakeBiosHttpHandler();
        var echoLog = new CapturedLog();
        var system = BiosIdentityFactory.Msi(model: "MS-7D75", boardProduct: "MS-7D75", biosVersion: "1.90") with
        {
            SerialNumber = secret,
        };
        echoHandler.MapJson(BuildDefaultMsiUrl("MS-7D75"), $$"""
        {
          "BIOS": [
            {
              "download_version": "VER-{{secret}}",
              "download_release": "2025-05-01",
              "release_notes_url": "https://www.msi.com/support/{{secret}}/notes",
              "download_url": "https://download.msi.com/bos_exe/{{secret}}/1G.zip"
            }
          ]
        }
        """);

        var echoResult = await MsiBiosUpdateProvider.CreateWithHandler(echoHandler, echoLog.Logger)
            .GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, echoResult.Status);
        Assert.DoesNotContain(secret, echoResult.LatestVersion ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.Null(echoResult.DownloadUrl);
        Assert.Null(echoResult.ReleaseNotesUrl);
        Assert.DoesNotContain(secret, echoResult.Message ?? "", StringComparison.OrdinalIgnoreCase);
        echoLog.AssertDoesNotContainSecret(secret);

        // 2. Untrusted URL entry whose Version contains secret -> warning log must NOT leak secret
        var untrustedHandler = new FakeBiosHttpHandler();
        var untrustedLog = new CapturedLog();
        untrustedHandler.MapJson(BuildDefaultMsiUrl("MS-7D75"), $$"""
        {
          "BIOS": [
            {
              "download_version": "VER-{{secret}}",
              "download_release": "2025-05-01",
              "download_url": "https://evil.com/1G.zip"
            }
          ]
        }
        """);

        var untrustedResult = await MsiBiosUpdateProvider.CreateWithHandler(untrustedHandler, untrustedLog.Logger)
            .GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.Failed, untrustedResult.Status);
        untrustedLog.AssertDoesNotContainSecret(secret);

        // 3. Model contains secret and request throws -> warning log must redact productToken AND exception message
        var errHandler = new FakeBiosHttpHandler();
        var errLog = new CapturedLog();
        var secretModel = $"MSI-{secret}";
        var secretModelSystem = BiosIdentityFactory.Msi(model: secretModel, boardProduct: "Default string", biosVersion: "1.90") with
        {
            SerialNumber = secret,
        };
        errHandler.MapException(BuildDefaultMsiUrl(secretModel), () => new InvalidOperationException($"Boom for {secret}"));

        var errResult = await MsiBiosUpdateProvider.CreateWithHandler(errHandler, errLog.Logger)
            .GetLatestVersionAsync(secretModelSystem, secretModelSystem.CurrentBios);

        Assert.Equal(BiosCheckStatus.Failed, errResult.Status);
        Assert.DoesNotContain(secret, errResult.Message ?? "", StringComparison.OrdinalIgnoreCase);
        errLog.AssertDoesNotContainSecret(secret);
    }

    [Theory]
    [InlineData("https://download.msi.com/api/%2e%2e/secret.json")]
    [InlineData("/pub/%2e%2e/evil.json")]
    [InlineData("/pub/../evil.json")]
    public async Task GetLatestVersionAsync_SameDomainRedirectWithPathTraversal_FailsClosedWithSingleHttpCall(
        string unsafeLocation)
    {
        var handler = new FakeBiosHttpHandler();
        var system = BiosIdentityFactory.Msi();
        handler.MapRedirect(BuildDefaultMsiUrl("MS-7D25"), unsafeLocation, HttpStatusCode.Redirect);
        handler.MapJson("https://download.msi.com/secret.json", BuildSingleMsiCatalog("7D25vAG", "2025-01-01"));
        handler.MapJson("https://www.msi.com/evil.json", BuildSingleMsiCatalog("7D25vAG", "2025-01-01"));

        var latest = await MsiBiosUpdateProvider.CreateWithHandler(handler)
            .GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.Failed, latest.Status);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task GetLatestVersionAsync_OrderCandidates_PrefersValidDownloadUrlAndBreaksUrlCaseAndShaTiesDeterministically()
    {
        var system = BiosIdentityFactory.Msi(model: "MS-7D75", boardProduct: "MS-7D75", biosVersion: "1.90");

        // 1. Valid DownloadUrl beats null DownloadUrl on identical version/date regardless of order
        foreach (var reversed in new[] { false, true })
        {
            var items = new object[]
            {
                new { download_title = "7D75v1G", download_version = "7D75v1G", download_release = "2024-06-20", download_url = (string?)null },
                new { download_title = "7D75v1G", download_version = "7D75v1G", download_release = "2024-06-20", download_url = "https://download.msi.com/bos_exe/mb/7D75v1G.zip" },
            };
            if (reversed)
                Array.Reverse(items);

            var handler = new FakeBiosHttpHandler();
            handler.MapJson(BuildDefaultMsiUrl("MS-7D75"), JsonSerializer.Serialize(new { BIOS = items }));
            var result = await MsiBiosUpdateProvider.CreateWithHandler(handler).GetLatestVersionAsync(system, system.CurrentBios);

            Assert.Equal(BiosCheckStatus.UpdateAvailable, result.Status);
            Assert.Equal("https://download.msi.com/bos_exe/mb/7D75v1G.zip", result.DownloadUrl);
        }

        // 2. Identical version/date/packageId with URL casing tie & distinct SHA-256 -> identical winner across permutations
        var shaA = new string('a', 64);
        var shaB = new string('b', 64);
        var tieEntries = new[]
        {
            new { download_version = "7D75v1G", download_release = "2025-05-01", download_url = "https://download.msi.com/bos_exe/mb/7D75V1G.zip", download_sha256 = shaA },
            new { download_version = "7D75v1G", download_release = "2025-05-01", download_url = "https://download.msi.com/bos_exe/mb/7d75v1g.zip", download_sha256 = shaB },
            new { download_version = "7D75v1G", download_release = "2025-05-01", download_url = "https://download.msi.com/bos_exe/mb/7D75V1G.zip", download_sha256 = shaB },
        };

        BiosLatestInfo? baseline = null;
        foreach (var mode in new[] { 0, 1, 7, 42, 99 })
        {
            var permuted = Permute(tieEntries, mode);
            var handler = new FakeBiosHttpHandler();
            handler.MapJson(BuildDefaultMsiUrl("MS-7D75"), JsonSerializer.Serialize(new { BIOS = permuted }));
            var result = await MsiBiosUpdateProvider.CreateWithHandler(handler).GetLatestVersionAsync(system, system.CurrentBios);

            Assert.Equal(BiosCheckStatus.UpdateAvailable, result.Status);
            if (baseline is null)
            {
                baseline = result;
            }
            else
            {
                Assert.Equal(baseline.DownloadUrl, result.DownloadUrl);
                Assert.Equal(baseline.Sha256, result.Sha256);
            }
        }
    }

    [Theory]
    [InlineData("12,5 MB", 13_107_200L)]
    [InlineData("16,45 MBytes", 17_249_075L)]
    [InlineData("1,024 KB", 1_048_576L)]
    [InlineData("15,728,640 bytes", 15_728_640L)]
    [InlineData("16,777,216", 16_777_216L)]
    public async Task GetLatestVersionAsync_FileSizeEuropeanDecimalCommaAndThousandsGrouping_ParsesAccurately(
        string fileSize,
        long expectedBytes)
    {
        var handler = new FakeBiosHttpHandler();
        var system = BiosIdentityFactory.Msi(model: "MS-7D75", boardProduct: "MS-7D75", biosVersion: "1.90");
        handler.MapJson(BuildDefaultMsiUrl("MS-7D75"), JsonSerializer.Serialize(new
        {
            BIOS = new[]
            {
                new
                {
                    download_version = "7D75v1G",
                    download_release = "2024-06-20",
                    download_size = fileSize,
                    download_url = "https://download.msi.com/bos_exe/mb/7D75v1G.zip",
                },
            },
        }));

        var latest = await MsiBiosUpdateProvider.CreateWithHandler(handler).GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal(expectedBytes, latest.SizeBytes);
    }

    [Fact]
    public async Task GetLatestVersionAsync_MixedTrustedAndUntrustedCatalogs_SymmetricFailClosedAndArchivedUpToDate()
    {
        // 1. Older trusted (7D75v1A) + newer untrusted (7D75v1G) -> Failed, null DownloadUrl
        var newerBadHandler = new FakeBiosHttpHandler();
        newerBadHandler.MapJson(BuildDefaultMsiUrl("MS-7D75"), """
        {
          "BIOS": [
            { "download_version": "7D75v1A", "download_release": "2024-01-01", "download_url": "https://download.msi.com/bos_exe/mb/7D75v1A.zip" },
            { "download_version": "7D75v1G", "download_release": "2025-05-01", "download_url": "http://evil.com/7D75v1G.zip" }
          ]
        }
        """);
        var sysOld = BiosIdentityFactory.Msi(model: "MS-7D75", boardProduct: "MS-7D75", biosVersion: "1.90");
        var newerBadResult = await MsiBiosUpdateProvider.CreateWithHandler(newerBadHandler)
            .GetLatestVersionAsync(sysOld, sysOld.CurrentBios);
        Assert.Equal(BiosCheckStatus.Failed, newerBadResult.Status);
        Assert.Null(newerBadResult.DownloadUrl);

        // 2. Newer trusted (7D75v1G, matching current) + strictly older archived untrusted (7D75v1A) -> UpToDate
        var archivedBadHandler = new FakeBiosHttpHandler();
        archivedBadHandler.MapJson(BuildDefaultMsiUrl("MS-7D75"), """
        {
          "BIOS": [
            { "download_version": "7D75v1G", "download_release": "2025-01-01", "download_url": "https://download.msi.com/bos_exe/mb/7D75v1G.zip" },
            { "download_version": "7D75v1A", "download_release": "2023-01-01", "download_url": "http://download.msi.com/bos_exe/mb/7D75v1A.zip" }
          ]
        }
        """);
        var sysCurrent = BiosIdentityFactory.Msi(model: "MS-7D75", boardProduct: "MS-7D75", biosVersion: "1.G0");
        var archivedResult = await MsiBiosUpdateProvider.CreateWithHandler(archivedBadHandler)
            .GetLatestVersionAsync(sysCurrent, sysCurrent.CurrentBios);
        Assert.Equal(BiosCheckStatus.UpToDate, archivedResult.Status);
        Assert.Equal("7D75v1G", archivedResult.LatestVersion);

        // 3. Equal-version untrusted (7D75v1G) alongside trusted (7D75v1G) when up to date -> Failed
        var equalBadHandler = new FakeBiosHttpHandler();
        equalBadHandler.MapJson(BuildDefaultMsiUrl("MS-7D75"), """
        {
          "BIOS": [
            { "download_version": "7D75v1G", "download_release": "2025-01-01", "download_url": "https://download.msi.com/bos_exe/mb/7D75v1G.zip" },
            { "download_version": "7D75v1G", "download_release": "2025-01-01", "download_url": "http://evil.com/7D75v1G.zip" }
          ]
        }
        """);
        var equalBadResult = await MsiBiosUpdateProvider.CreateWithHandler(equalBadHandler)
            .GetLatestVersionAsync(sysCurrent, sysCurrent.CurrentBios);
        Assert.Equal(BiosCheckStatus.Failed, equalBadResult.Status);
    }

    [Fact]
    public async Task GetLatestVersionAsync_NullAliasFallthroughAndWrongKindDownloadUrl()
    {
        var system = BiosIdentityFactory.Msi(model: "MS-7D75", boardProduct: "MS-7D75", biosVersion: "1.90");

        // 1. Null-valued alias falls through to secondary alias
        var aliasHandler = new FakeBiosHttpHandler();
        aliasHandler.MapJson(BuildDefaultMsiUrl("MS-7D75"), """
        {
          "BIOS": [
            {
              "download_version": null,
              "biosVersion": "7D75v1G",
              "download_release": "2024-06-20",
              "download_url": null,
              "url": "https://download.msi.com/bos_exe/mb/7D75v1G.zip"
            }
          ]
        }
        """);
        var aliasResult = await MsiBiosUpdateProvider.CreateWithHandler(aliasHandler)
            .GetLatestVersionAsync(system, system.CurrentBios);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, aliasResult.Status);
        Assert.Equal("7D75v1G", aliasResult.LatestVersion);
        Assert.Equal("https://download.msi.com/bos_exe/mb/7D75v1G.zip", aliasResult.DownloadUrl);

        // 2. Non-null wrong JsonValueKind on download_url -> Failed
        foreach (var badJson in new[]
        {
            """{"BIOS":[{"download_version":"7D75v1G","download_release":"2024-06-20","download_url":12345}]}""",
            """{"BIOS":[{"download_version":"7D75v1G","download_release":"2024-06-20","download_url":true}]}""",
            """{"BIOS":[{"download_version":"7D75v1G","download_release":"2024-06-20","download_url":[]}]}""",
        })
        {
            var wrongKindHandler = new FakeBiosHttpHandler();
            wrongKindHandler.MapJson(BuildDefaultMsiUrl("MS-7D75"), badJson);
            var wrongResult = await MsiBiosUpdateProvider.CreateWithHandler(wrongKindHandler)
                .GetLatestVersionAsync(system, system.CurrentBios);
            Assert.Equal(BiosCheckStatus.Failed, wrongResult.Status);
            Assert.Null(wrongResult.DownloadUrl);
        }
    }

    [Fact]
    public async Task GetLatestVersionAsync_CustomPathPlaceholderEndpoint_RejectsSlashInModelTokenWithZeroCalls()
    {
        const string endpoint = "https://www.msi.com/api/{model}/bios.json";
        var handler = new FakeBiosHttpHandler();
        var provider = MsiBiosUpdateProvider.CreateWithHandler(handler, catalogEndpoint: endpoint);

        var slashSystem = BiosIdentityFactory.Msi(model: "Raider/GE78", boardProduct: "Raider/GE78", biosVersion: "1.90");
        var slashResult = await provider.GetLatestVersionAsync(slashSystem, slashSystem.CurrentBios);

        Assert.Equal(BiosCheckStatus.Failed, slashResult.Status);
        Assert.Empty(handler.Requests);
    }

    // =========================================================================
    // Iteration 3 Surgical Hardening Regression Tests
    // =========================================================================

    [Theory]
    [InlineData("https:../secret.json")]
    [InlineData("https:./secret.json")]
    [InlineData("https:secret.json")]
    [InlineData("https:/secret.json")]
    [InlineData("http:www.msi.com")]
    [InlineData("javascript:alert(1)")]
    [InlineData("file:foo")]
    public async Task GetLatestVersionAsync_SameSchemeRelativeOrNonHttpsColonRedirect_FailsClosedWithSingleHttpCall(
        string unsafeLocation)
    {
        var handler = new FakeBiosHttpHandler();
        var system = BiosIdentityFactory.Msi();
        handler.MapRedirect(BuildDefaultMsiUrl("MS-7D25"), unsafeLocation, HttpStatusCode.Redirect);
        handler.MapPredicate(_ => true, (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(BuildSingleMsiCatalog("7D25vAG", "2025-01-01"), System.Text.Encoding.UTF8, "application/json"),
        }));

        var latest = await MsiBiosUpdateProvider.CreateWithHandler(handler)
            .GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.Failed, latest.Status);
        Assert.Single(handler.Requests);
    }

    [Theory]
    [InlineData("https://www.msi.com/safe.json", "https://evil.com/pwn.json")]
    [InlineData("https://www.msi.com/safe.json", "/pub/%2e%2e/secret.json")]
    [InlineData("https://www.msi.com/safe.json", "https://www.msi.com/safe2.json")]
    public async Task GetLatestVersionAsync_MultipleLocationHeaders_FailsClosedWithSingleHttpCall(
        string firstLocation,
        string secondLocation)
    {
        var handler = new FakeBiosHttpHandler();
        var system = BiosIdentityFactory.Msi();
        handler.Map(BuildDefaultMsiUrl("MS-7D25"), (_, _) =>
        {
            var msg = new HttpResponseMessage(HttpStatusCode.Redirect);
            msg.Headers.TryAddWithoutValidation("Location", firstLocation);
            msg.Headers.TryAddWithoutValidation("Location", secondLocation);
            return Task.FromResult(msg);
        });
        handler.MapJson("https://www.msi.com/safe.json", BuildSingleMsiCatalog("7D25vAG", "2025-01-01"));
        handler.MapJson("https://www.msi.com/safe2.json", BuildSingleMsiCatalog("7D25vAG", "2025-01-01"));

        var latest = await MsiBiosUpdateProvider.CreateWithHandler(handler)
            .GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.Failed, latest.Status);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task GetLatestVersionAsync_UriEscapedAndPartiallyEscapedSerialNumber_CompletelyRedacted()
    {
        // 1. HttpRequestException containing RequestUri.AbsoluteUri with SN%204242 -> zero leak in logs or Message
        const string spaceSecret = "SN 4242";
        const string escapedSpaceSecret = "SN%204242";
        const string modelWithSerial = "GF63 Thin SN 4242";
        var errHandler = new FakeBiosHttpHandler();
        var errLog = new CapturedLog();
        var errSystem = BiosIdentityFactory.Msi(model: modelWithSerial, boardProduct: "Default string", biosVersion: "1.90") with
        {
            SerialNumber = spaceSecret,
        };
        errHandler.Map(BuildDefaultMsiUrl(modelWithSerial), (req, _) =>
            Task.FromException<HttpResponseMessage>(new HttpRequestException($"Connection refused to {req.RequestUri!.AbsoluteUri}")));

        var errResult = await MsiBiosUpdateProvider.CreateWithHandler(errHandler, errLog.Logger)
            .GetLatestVersionAsync(errSystem, errSystem.CurrentBios);

        Assert.Equal(BiosCheckStatus.Offline, errResult.Status);
        Assert.DoesNotContain(spaceSecret, errResult.Message ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(escapedSpaceSecret, errResult.Message ?? "", StringComparison.OrdinalIgnoreCase);
        errLog.AssertDoesNotContainSecret(spaceSecret);
        errLog.AssertDoesNotContainSecret(escapedSpaceSecret);

        // 2. Catalog JSON echoes escaped & form-encoded serial in Version, Description, PackageId
        var echoHandler = new FakeBiosHttpHandler();
        var echoLog = new CapturedLog();
        var echoSystem = BiosIdentityFactory.Msi(model: "MS-7D75", boardProduct: "MS-7D75", biosVersion: "1.90") with
        {
            SerialNumber = spaceSecret,
        };
        echoHandler.MapJson(BuildDefaultMsiUrl("MS-7D75"), """
        {
          "BIOS": [
            {
              "download_id": "PKG-SN%204242",
              "download_version": "VER-SN%204242",
              "download_description": "BIOS update for SN%204242 and SN+4242",
              "download_release": "2025-05-01",
              "download_url": "https://download.msi.com/bos_exe/mb/7D75v1G.zip"
            }
          ]
        }
        """);

        var echoResult = await MsiBiosUpdateProvider.CreateWithHandler(echoHandler, echoLog.Logger)
            .GetLatestVersionAsync(echoSystem, echoSystem.CurrentBios);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, echoResult.Status);
        Assert.DoesNotContain(escapedSpaceSecret, echoResult.LatestVersion ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(escapedSpaceSecret, echoResult.ReleaseSummary ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("SN+4242", echoResult.ReleaseSummary ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(escapedSpaceSecret, echoResult.PackageId ?? "", StringComparison.OrdinalIgnoreCase);
        echoLog.AssertDoesNotContainSecret(escapedSpaceSecret);

        // 3. Mixed/partially-encoded serials in DownloadUrl and ReleaseNotesUrl -> both nulled
        foreach (var (mixedSerial, dlUrl, notesUrl) in new[]
        {
            ("SN:9988 77", "https://download.msi.com/bos_exe/mb/7D75v1G.zip?sn=SN:9988%2077", "https://www.msi.com/support/notes?sn=SN:9988%2077"),
            ("SN/4242 99", "https://download.msi.com/SN/4242%2099/bios.zip", "https://www.msi.com/support/SN/4242%2099/notes"),
        })
        {
            var urlHandler = new FakeBiosHttpHandler();
            var urlSystem = BiosIdentityFactory.Msi(model: "MS-7D75", boardProduct: "MS-7D75", biosVersion: "1.90") with
            {
                SerialNumber = mixedSerial,
            };
            urlHandler.MapJson(BuildDefaultMsiUrl("MS-7D75"), JsonSerializer.Serialize(new
            {
                BIOS = new[]
                {
                    new
                    {
                        download_version = "7D75v1G",
                        download_release = "2025-05-01",
                        download_url = dlUrl,
                        release_notes_url = notesUrl,
                    },
                },
            }));

            var urlResult = await MsiBiosUpdateProvider.CreateWithHandler(urlHandler)
                .GetLatestVersionAsync(urlSystem, urlSystem.CurrentBios);

            Assert.Equal(BiosCheckStatus.UpdateAvailable, urlResult.Status);
            Assert.Null(urlResult.DownloadUrl);
            Assert.Null(urlResult.ReleaseNotesUrl);
        }

        // 4. GetCurrentVersionAsync and InstallAsync redact URI-escaped serials too
        var provider = MsiBiosUpdateProvider.CreateWithHandler(new FakeBiosHttpHandler());
        var curSystem = BiosIdentityFactory.Msi(model: "MS-7D75", boardProduct: "MS-7D75", biosVersion: $"1.90-{escapedSpaceSecret}") with
        {
            SerialNumber = spaceSecret,
        };
        var cur = await provider.GetCurrentVersionAsync(curSystem);
        Assert.DoesNotContain(escapedSpaceSecret, cur.Version, StringComparison.OrdinalIgnoreCase);

        var installReq = CreateMsiInstallRequest(curSystem, targetVersion: $"7D75v1G-{escapedSpaceSecret}");
        var installRes = await provider.InstallAsync(installReq);
        Assert.DoesNotContain(escapedSpaceSecret, installRes.PreviousVersion ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(escapedSpaceSecret, installRes.TargetVersion ?? "", StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("0,500 MB", 524_288L)]
    [InlineData("0,125 GB", 134_217_728L)]
    [InlineData("1,234.56 MB", 1_294_529_987L)]
    [InlineData("1234,567.89 KB", null)]
    [InlineData("000,001", null)]
    public async Task GetLatestVersionAsync_FileSizeLeadingZeroEuropeanAndMalformedGrouping_HandledAccurately(
        string fileSize,
        long? expectedBytes)
    {
        var handler = new FakeBiosHttpHandler();
        var system = BiosIdentityFactory.Msi(model: "MS-7D75", boardProduct: "MS-7D75", biosVersion: "1.90");
        handler.MapJson(BuildDefaultMsiUrl("MS-7D75"), JsonSerializer.Serialize(new
        {
            BIOS = new[]
            {
                new
                {
                    download_version = "7D75v1G",
                    download_release = "2024-06-20",
                    download_size = fileSize,
                    download_url = "https://download.msi.com/bos_exe/mb/7D75v1G.zip",
                },
            },
        }));

        var latest = await MsiBiosUpdateProvider.CreateWithHandler(handler)
            .GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal(expectedBytes, latest.SizeBytes);
    }

    // =========================================================================
    // Local Test Helpers
    // =========================================================================

    private static string BuildDefaultMsiUrl(string product) =>
        MsiBiosUpdateProvider.DefaultCatalogEndpoint.Replace("{product}", Uri.EscapeDataString(product), StringComparison.OrdinalIgnoreCase);

    private static string BuildSingleMsiCatalog(string version, string releaseDate) =>
        JsonSerializer.Serialize(new
        {
            result = new
            {
                downloads = new Dictionary<string, object>
                {
                    ["AMI BIOS"] = new[]
                    {
                        new
                        {
                            download_version = version,
                            download_release = releaseDate,
                            download_url = "https://download.msi.com/bos_exe/mb/bios-update.zip",
                        },
                    },
                },
            },
        });

    private static BiosInstallRequest CreateMsiInstallRequest(
        BiosSystemIdentity? system = null,
        string targetVersion = "7D25vAG")
    {
        var id = system ?? BiosIdentityFactory.Msi();
        var target = BiosLatestInfo.UpdateAvailable(
            providerId: "msi",
            latestVersion: targetVersion,
            downloadUrl: "https://download.msi.com/bos_exe/mb/7D25vAG.zip",
            sha256: ValidSha256);

        return new BiosInstallRequest(
            System: id,
            Current: id.CurrentBios,
            Target: target,
            Approved: true,
            ApprovedBy: "operator@contoso.com");
    }

    private static List<T> Permute<T>(IReadOnlyList<T> source, int mode)
    {
        var list = new List<T>(source);
        if (mode == 0)
            return list;
        if (mode == 1)
        {
            list.Reverse();
            return list;
        }

        var rng = new Random(mode);
        for (var i = list.Count - 1; i > 0; i--)
        {
            var j = rng.Next(i + 1);
            (list[i], list[j]) = (list[j], list[i]);
        }

        return list;
    }

    private sealed class StubSystemProbe(BiosSystemIdentity identity) : IBiosSystemProbe
    {
        public Task<BiosSystemIdentity> ProbeAsync(CancellationToken ct = default) => Task.FromResult(identity);
    }

    private sealed class CountingSafetyProbe(BiosSafetySnapshot snapshot) : IBiosInstallSafetyProbe
    {
        public int CallCount { get; private set; }

        public Task<BiosSafetySnapshot> ProbeAsync(CancellationToken ct = default)
        {
            CallCount++;
            return Task.FromResult(snapshot);
        }
    }
}
