using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Core.Bios;

namespace RemotePCDiagnostics.Tests.Bios;

public sealed class AsusBiosUpdateProviderTests
{
    private const string ValidSha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    // =========================================================================
    // A1 — Metadata & Capabilities
    // =========================================================================

    [Fact]
    public void Metadata_MatchesContract()
    {
        var provider = new AsusBiosUpdateProvider();

        Assert.Equal("asus", provider.VendorId);
        Assert.Equal("ASUS", provider.DisplayName);
        Assert.Equal(100, provider.Priority);
        Assert.Equal(["asus.com"], AsusBiosUpdateProvider.AllowedHostSuffixes);
        Assert.True(provider.Capabilities.CanCheckLatest);
        Assert.False(provider.Capabilities.CanInstall);
        Assert.False(provider.Capabilities.SupportsSilentInstall);
        Assert.False(provider.Capabilities.RequiresReboot);
        Assert.False(provider.Capabilities.RequiresElevation);
        Assert.True(provider.Capabilities.RequiresInternet);
    }

    // =========================================================================
    // A2 — CanHandle Positive & Negative Matrix
    // =========================================================================

    [Theory]
    [InlineData("ASUSTeK COMPUTER INC.", "")]
    [InlineData("ASUSTek Computer Inc.", "")]
    [InlineData("ASUS", "")]
    [InlineData("ASUS Technology", "")]
    [InlineData("Generic OEM", "ASUSTeK COMPUTER INC.")]
    [InlineData("", "ASUS")]
    public void CanHandle_AsusManufacturers_ReturnsTrue(string manufacturer, string boardManufacturer)
    {
        var provider = new AsusBiosUpdateProvider();
        var identity = BiosIdentityFactory.Asus(manufacturer: manufacturer) with
        {
            BoardManufacturer = boardManufacturer,
        };

        Assert.True(provider.CanHandle(identity));
    }

    [Theory]
    [InlineData("Pegasus")]
    [InlineData("Pegasus Systems")]
    [InlineData("Casus Corp")]
    [InlineData("AsuSystems")]
    [InlineData("HP")]
    [InlineData("Dell Inc.")]
    [InlineData("LENOVO")]
    [InlineData("Acer")]
    [InlineData("Micro-Star International Co., Ltd.")]
    public void CanHandle_NonAsusOrSubstringManufacturers_ReturnsFalse(string manufacturer)
    {
        var provider = new AsusBiosUpdateProvider();
        var identity = BiosIdentityFactory.GenericUefi(manufacturer);

        Assert.False(provider.CanHandle(identity));
    }

    [Fact]
    public void CanHandle_EmptyWhitespaceLargeAndNull_ReturnsFalseWithoutThrowing()
    {
        var provider = new AsusBiosUpdateProvider();

        Assert.False(provider.CanHandle(BiosIdentityFactory.Unknown()));
        Assert.False(provider.CanHandle(null!));

        var whitespace = BiosIdentityFactory.GenericUefi("   ");
        Assert.False(provider.CanHandle(whitespace));

        var large = BiosIdentityFactory.GenericUefi(new string('X', 4096));
        Assert.False(provider.CanHandle(large));
    }

    // =========================================================================
    // A3 — GetCurrentVersionAsync Normalization & Redaction
    // =========================================================================

    [Theory]
    [InlineData("2802", "2802", "")]
    [InlineData(" 2802 ", "2802", "")]
    [InlineData("Version 2802", "2802", "")]
    [InlineData("BIOS Version 2802", "2802", "")]
    [InlineData("Ver. 2802", "2802", "")]
    [InlineData("Rev. 2802", "2802", "")]
    [InlineData("ROG STRIX Z690-E GAMING WIFI BIOS 2802", "2802", "")]
    [InlineData("UX3402ZA.310", "310", "UX3402ZA")]
    [InlineData("GA402RJ.318", "318", "GA402RJ")]
    [InlineData("", "", "")]
    public async Task GetCurrentVersionAsync_SetsProviderIdNormalizesAndRedactsSerial(
        string rawVersion,
        string expectedVersion,
        string expectedFamily)
    {
        var log = new CapturedLog();
        var provider = new AsusBiosUpdateProvider(log: log.Logger);
        var identity = BiosIdentityFactory.Asus(biosVersion: rawVersion);

        var current = await provider.GetCurrentVersionAsync(identity);

        Assert.Equal("asus", current.ProviderId);
        Assert.Equal(expectedVersion, current.Version);
        Assert.Equal(expectedFamily, current.Family);
        log.AssertDoesNotContainSecret();
        if (current.Metadata is not null)
        {
            foreach (var kv in current.Metadata)
                Assert.DoesNotContain(BiosIdentityFactory.SentinelSerialNumber, kv.Value, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public async Task GetCurrentVersionAsync_NullAndCancelled_Throws()
    {
        var provider = new AsusBiosUpdateProvider();
        await Assert.ThrowsAsync<ArgumentNullException>(() => provider.GetCurrentVersionAsync(null!));

        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => provider.GetCurrentVersionAsync(BiosIdentityFactory.Asus(), cts.Token));
    }

    // =========================================================================
    // A4 — GetLatestVersionAsync Happy Path, UpToDate, Downgrade & Fallbacks
    // =========================================================================

    [Fact]
    public async Task GetLatestVersionAsync_ValidGetPdBiosCatalog_ReturnsUpdateAvailable()
    {
        var handler = new FakeBiosHttpHandler();
        var log = new CapturedLog();
        var model = "ROG STRIX Z690-E GAMING WIFI";
        var expectedUrl = BuildDefaultAsusUrl(model);

        var json = $$"""
        {
          "Result": {
            "Obj": [
              {
                "Name": "BIOS-Utilities",
                "Files": [
                  {
                    "Version": "9999",
                    "Title": "BIOSRenamer for USB BIOS FlashBack",
                    "ReleaseDate": "2025/01/01",
                    "DownloadUrl": { "Global": "https://dlcdnets.asus.com/pub/ASUS/mb/BIOS/BIOSRenamer.zip" }
                  }
                ]
              },
              {
                "Name": "BIOS",
                "Files": [
                  {
                    "Id": "asus-3201",
                    "Version": "Version 3201",
                    "Title": "ROG STRIX Z690-E GAMING WIFI BIOS 3201",
                    "Description": "1. Improve system stability.<br/>2. Fix CVE-2024-0001 security vulnerability.",
                    "ReleaseDate": "2024/08/15",
                    "FileSize": "16.45 MBytes",
                    "Sha256": "{{ValidSha256.ToUpperInvariant()}}",
                    "ReleaseNotesUrl": "https://www.asus.com/support/faq/1044348/",
                    "DownloadUrl": {
                      "Global": "https://dlcdnets.asus.com/pub/ASUS/mb/BIOS/ROG-STRIX-Z690-E-GAMING-WIFI-ASUS-3201.ZIP",
                      "China": "https://dlcdnets.asus.com.cn/pub/ASUS/mb/BIOS/ROG-STRIX-Z690-E-GAMING-WIFI-ASUS-3201.ZIP"
                    }
                  },
                  {
                    "Id": "asus-2802",
                    "Version": "2802",
                    "Title": "ROG STRIX Z690-E GAMING WIFI BIOS 2802",
                    "ReleaseDate": "2023/09/01",
                    "DownloadUrl": { "Global": "https://dlcdnets.asus.com/pub/ASUS/mb/BIOS/ROG-STRIX-Z690-E-GAMING-WIFI-ASUS-2802.ZIP" }
                  }
                ]
              }
            ]
          },
          "Status": "SUCCESS"
        }
        """;

        handler.MapJson(expectedUrl, json);
        var provider = AsusBiosUpdateProvider.CreateWithHandler(handler, log.Logger);
        var system = BiosIdentityFactory.Asus(model: model, biosVersion: "2802");

        var latest = await provider.GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal("asus", latest.ProviderId);
        Assert.Equal("3201", latest.LatestVersion);
        Assert.Equal(new DateOnly(2024, 8, 15), latest.ReleaseDate);
        Assert.Equal(BiosUpdateSeverity.Critical, latest.Severity);
        Assert.Equal("asus-3201", latest.PackageId);
        Assert.Equal("https://dlcdnets.asus.com/pub/ASUS/mb/BIOS/ROG-STRIX-Z690-E-GAMING-WIFI-ASUS-3201.ZIP", latest.DownloadUrl);
        Assert.Equal("https://www.asus.com/support/faq/1044348/", latest.ReleaseNotesUrl);
        Assert.Equal(ValidSha256, latest.Sha256);
        Assert.Equal((long)Math.Round(16.45 * 1024 * 1024, MidpointRounding.AwayFromZero), latest.SizeBytes);
        Assert.NotNull(latest.ReleaseSummary);
        Assert.DoesNotContain("<br", latest.ReleaseSummary, StringComparison.OrdinalIgnoreCase);
        Assert.True(latest.RequiresReboot);
        Assert.Single(handler.Requests);
        Assert.DoesNotContain(BiosIdentityFactory.SentinelSerialNumber, handler.Requests[0].RequestUri!.AbsoluteUri, StringComparison.OrdinalIgnoreCase);
        log.AssertDoesNotContainSecret();
    }

    [Theory]
    [InlineData("3201", "3201")]
    [InlineData("3400", "3201")]
    [InlineData("1.14", "1.14.0")]
    [InlineData("2402", "Version 2402")]
    public async Task GetLatestVersionAsync_CurrentEqualsOrExceedsLatest_ReturnsUpToDate(
        string currentVersion,
        string catalogVersion)
    {
        var handler = new FakeBiosHttpHandler();
        var model = "ROG STRIX Z790-E GAMING WIFI";
        handler.MapJson(BuildDefaultAsusUrl(model), BuildSingleAsusCatalog(catalogVersion, "2025/02/01"));

        var provider = AsusBiosUpdateProvider.CreateWithHandler(handler);
        var system = BiosIdentityFactory.Asus(model: model, biosVersion: currentVersion);

        var latest = await provider.GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.UpToDate, latest.Status);
        Assert.Null(latest.DownloadUrl);
    }

    [Theory]
    [InlineData("System Product Name", "ROG STRIX Z690-E GAMING WIFI", "ROG STRIX Z690-E GAMING WIFI")]
    [InlineData("To Be Filled By O.E.M.", "PRIME B650-PLUS", "PRIME B650-PLUS")]
    [InlineData("All Series", "TUF GAMING X670E-PLUS", "TUF GAMING X670E-PLUS")]
    [InlineData("", "ROG STRIX Z690-E GAMING WIFI", "ROG STRIX Z690-E GAMING WIFI")]
    [InlineData("ZenBook UX425EA", "", "ZenBook UX425EA")]
    public async Task GetLatestVersionAsync_ModelPlaceholderFallsBackToBoardProduct(
        string model,
        string boardProduct,
        string expectedToken)
    {
        var handler = new FakeBiosHttpHandler();
        handler.MapJson(BuildDefaultAsusUrl(expectedToken), BuildSingleAsusCatalog("3201", "2024/08/15"));

        var provider = AsusBiosUpdateProvider.CreateWithHandler(handler);
        var system = BiosIdentityFactory.Asus(model: model, boardProduct: boardProduct, biosVersion: "2802");

        var latest = await provider.GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal("3201", latest.LatestVersion);
        Assert.Single(handler.Requests);
        Assert.Contains(Uri.EscapeDataString(expectedToken), handler.Requests[0].RequestUri!.AbsoluteUri, StringComparison.Ordinal);
    }

    // =========================================================================
    // A5 — Version Formats, Laptop Family.Build, Date Fallback & Beta/Peripheral Filtering
    // =========================================================================

    [Theory]
    [InlineData("1801", "2402", BiosCheckStatus.UpdateAvailable)]
    [InlineData("0805", "1001", BiosCheckStatus.UpdateAvailable)]
    [InlineData("1.9", "1.10", BiosCheckStatus.UpdateAvailable)]
    [InlineData("UX3402ZA.310", "312", BiosCheckStatus.UpdateAvailable)]
    [InlineData("GA402RJ.318", "GA402RJ.319", BiosCheckStatus.UpdateAvailable)]
    [InlineData("GA402RJ.319", "GA402RJ.318", BiosCheckStatus.UpToDate)]
    public async Task GetLatestVersionAsync_VersionFormatsComparison(
        string currentVersion,
        string catalogVersion,
        BiosCheckStatus expectedStatus)
    {
        var handler = new FakeBiosHttpHandler();
        var model = "UX3402ZA";
        handler.MapJson(BuildDefaultAsusUrl(model), BuildSingleAsusCatalog(catalogVersion, "2023/09/01"));

        var provider = AsusBiosUpdateProvider.CreateWithHandler(handler);
        var system = BiosIdentityFactory.Asus(model: model, boardProduct: model, biosVersion: currentVersion);
        var normalizedCurrent = await provider.GetCurrentVersionAsync(system);

        var latest = await provider.GetLatestVersionAsync(system, normalizedCurrent);

        Assert.Equal(expectedStatus, latest.Status);
    }

    [Fact]
    public async Task GetLatestVersionAsync_IncomparableVersionUsesDateFallback_AndIgnoresNon64HexChecksum()
    {
        var handler = new FakeBiosHttpHandler();
        var model = "PRIME Z790-A";
        var json = """
        {
          "Files": [
            {
              "Version": "CUSTOM-REV-B",
              "ReleaseDate": "2024-11-20T00:00:00Z",
              "Sha256": "d41d8cd98f00b204e9800998ecf8427e",
              "DownloadUrl": "https://dlcdnets.asus.com/pub/ASUS/mb/BIOS/prime-z790.zip"
            }
          ]
        }
        """;
        handler.MapJson(BuildDefaultAsusUrl(model), json);

        var provider = AsusBiosUpdateProvider.CreateWithHandler(handler);
        var system = BiosIdentityFactory.Asus(model: model, biosVersion: "1801");

        var latest = await provider.GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal(new DateOnly(2024, 11, 20), latest.ReleaseDate);
        Assert.Null(latest.Sha256);

        // Older date with incomparable version -> UpToDate
        var newerSystem = system with
        {
            CurrentBios = system.CurrentBios with { ReleaseDate = new DateOnly(2025, 1, 1) },
        };
        var upToDate = await provider.GetLatestVersionAsync(newerSystem, newerSystem.CurrentBios);
        Assert.Equal(BiosCheckStatus.UpToDate, upToDate.Status);
    }

    [Fact]
    public async Task GetLatestVersionAsync_BetaAndNonBiosFiltering_AndOnlyBetaReturnsUnsupported()
    {
        var handler = new FakeBiosHttpHandler();
        var model = "ROG STRIX B650E-F GAMING WIFI";
        var json = """
        {
          "Result": {
            "Obj": [
              {
                "Name": "BIOS",
                "Files": [
                  { "Version": "3401 Beta Version", "Title": "BIOS 3401 Beta Version", "ReleaseDate": "2025/03/01", "DownloadUrl": { "Global": "https://dlcdnets.asus.com/pub/ASUS/mb/BIOS/3401b.zip" } },
                  { "Version": "3301", "IsRelease": "0", "Title": "BIOS 3301", "ReleaseDate": "2025/02/01", "DownloadUrl": { "Global": "https://dlcdnets.asus.com/pub/ASUS/mb/BIOS/3301.zip" } },
                  { "Version": "16.1.30", "Title": "Intel ME Update Tool", "ReleaseDate": "2025/02/15", "DownloadUrl": { "Global": "https://dlcdnets.asus.com/pub/ASUS/mb/BIOS/MEUpdateTool.zip" } },
                  { "Version": "3201", "Title": "ROG STRIX B650E-F GAMING WIFI BIOS 3201", "ReleaseDate": "2024/10/01", "DownloadUrl": { "Global": "https://dlcdnets.asus.com/pub/ASUS/mb/BIOS/3201.zip" } }
                ]
              }
            ]
          }
        }
        """;
        handler.MapJson(BuildDefaultAsusUrl(model), json);

        var provider = AsusBiosUpdateProvider.CreateWithHandler(handler);
        var system = BiosIdentityFactory.Asus(model: model, biosVersion: "2802");

        var latest = await provider.GetLatestVersionAsync(system, system.CurrentBios);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal("3201", latest.LatestVersion);

        // Catalog with ONLY beta entries -> UnsupportedHardware
        var betaOnlyHandler = new FakeBiosHttpHandler();
        betaOnlyHandler.MapJson(BuildDefaultAsusUrl(model), """
        [
          { "Version": "3401 Beta Version", "ReleaseDate": "2025/03/01", "DownloadUrl": "https://dlcdnets.asus.com/pub/ASUS/mb/BIOS/3401b.zip" }
        ]
        """);
        var betaProvider = AsusBiosUpdateProvider.CreateWithHandler(betaOnlyHandler);
        var betaResult = await betaProvider.GetLatestVersionAsync(system, system.CurrentBios);
        Assert.Equal(BiosCheckStatus.UnsupportedHardware, betaResult.Status);
    }

    // =========================================================================
    // A6 — 24+ Mixed Entries Strict-Weak-Order Shuffle Invariance
    // =========================================================================

    [Fact]
    public async Task GetLatestVersionAsync_24MixedEntries_StrictWeakOrderShuffleInvariance()
    {
        var model = "ROG STRIX Z690-E GAMING WIFI";
        var rawEntries = new List<(string Version, string? Date, string Id, string Url)>
        {
            // Literal '#' collision triples (must NEVER break transitivity!)
            ("A1##", "2024-01-01", "e01", "https://dlcdnets.asus.com/pub/e01.zip"),
            ("A1#2", "2024-01-02", "e02", "https://dlcdnets.asus.com/pub/e02.zip"),
            ("A##2", "2024-01-03", "e03", "https://dlcdnets.asus.com/pub/e03.zip"),
            ("X1#2", "2024-01-04", "e04", "https://dlcdnets.asus.com/pub/e04.zip"),
            ("X##3", "2024-01-05", "e05", "https://dlcdnets.asus.com/pub/e05.zip"),
            ("X2#1", "2024-01-06", "e06", "https://dlcdnets.asus.com/pub/e06.zip"),
            // >64-bit numeric overflow strings
            ("99999999999999999999999999", "2023-05-01", "e07", "https://dlcdnets.asus.com/pub/e07.zip"),
            ("99999999999999999999999998", null, "e08", "https://dlcdnets.asus.com/pub/e08.zip"),
            // Dotted numeric & 4-digit numeric
            ("1801", "2023-06-01", "e09", "https://dlcdnets.asus.com/pub/e09.zip"),
            ("2402", "2024-02-01", "e10", "https://dlcdnets.asus.com/pub/e10.zip"),
            ("3201", "2025-01-15", "e11", "https://dlcdnets.asus.com/pub/e11.zip"),
            ("1.9", "2023-07-01", "e12", "https://dlcdnets.asus.com/pub/e12.zip"),
            ("1.10", "2023-08-01", "e13", "https://dlcdnets.asus.com/pub/e13.zip"),
            ("1.10.0", "2023-08-01", "e14", "https://dlcdnets.asus.com/pub/e14.zip"),
            // Prefix numeric & skeletons
            ("F.8", "2023-04-01", "e15", "https://dlcdnets.asus.com/pub/e15.zip"),
            ("F.24", "2023-09-01", "e16", "https://dlcdnets.asus.com/pub/e16.zip"),
            ("P.10", null, "e17", "https://dlcdnets.asus.com/pub/e17.zip"),
            ("A\\1#2", "2023-03-01", "e18", "https://dlcdnets.asus.com/pub/e18.zip"),
            ("A\\#12", "2023-03-02", "e19", "https://dlcdnets.asus.com/pub/e19.zip"),
            // Archaic Unicode / case-folding edge case (U+017F)
            ("ſ10", "2023-02-01", "e20", "https://dlcdnets.asus.com/pub/e20.zip"),
            ("S10", "2023-02-01", "e21", "https://dlcdnets.asus.com/pub/e21.zip"),
            ("s10", "2023-02-02", "e22", "https://dlcdnets.asus.com/pub/e22.zip"),
            // Duplicates & missing dates
            ("3201", null, "e23", "https://dlcdnets.asus.com/pub/e23.zip"),
            ("REV-ALPHA-X", null, "e24", "https://dlcdnets.asus.com/pub/e24.zip"),
        };

        int[] modes = [0, 1, 42, 1337, 9001, 202606];
        BiosLatestInfo? baseline = null;
        var system = BiosIdentityFactory.Asus(model: model, biosVersion: "2802");

        foreach (var mode in modes)
        {
            var permuted = Permute(rawEntries, mode);
            var payload = JsonSerializer.Serialize(new
            {
                Files = permuted.Select(e => new
                {
                    Id = e.Id,
                    Version = e.Version,
                    ReleaseDate = e.Date,
                    DownloadUrl = e.Url,
                }),
            });

            var handler = new FakeBiosHttpHandler();
            handler.MapJson(BuildDefaultAsusUrl(model), payload);
            var provider = AsusBiosUpdateProvider.CreateWithHandler(handler);

            var result = await provider.GetLatestVersionAsync(system, system.CurrentBios);
            Assert.Equal(BiosCheckStatus.UpdateAvailable, result.Status);
            Assert.Equal("3201", result.LatestVersion);

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
    // A7 — Placeholders & Malicious SMBIOS Tokens -> UnsupportedHardware (0 HTTP Calls)
    // =========================================================================

    [Theory]
    [InlineData("", "")]
    [InlineData("   ", "   ")]
    [InlineData("To Be Filled By O.E.M.", "To Be Filled By O.E.M.")]
    [InlineData("Default string", "Default string")]
    [InlineData("System Product Name", "None")]
    [InlineData("SKU", "N/A")]
    [InlineData("Unknown", "0000")]
    [InlineData("ROG; calc.exe", "ROG STRIX Z690-E GAMING WIFI")]
    [InlineData("ROG&whoami", "ROG STRIX Z690-E GAMING WIFI")]
    [InlineData("ROG|powershell", "ROG STRIX Z690-E GAMING WIFI")]
    [InlineData("$(id)", "ROG STRIX Z690-E GAMING WIFI")]
    [InlineData("../../etc/passwd", "ROG STRIX Z690-E GAMING WIFI")]
    [InlineData("ROG?inject=1", "ROG STRIX Z690-E GAMING WIFI")]
    [InlineData("ROG\r\nHost: evil.com", "ROG STRIX Z690-E GAMING WIFI")]
    [InlineData("To Be Filled By O.E.M.; calc.exe", "ROG STRIX Z690-E GAMING WIFI")]
    [InlineData("ROG STRIX Z690-E GAMING WIFI", "BOARD&whoami")]
    public async Task GetLatestVersionAsync_PlaceholdersAndMaliciousSmbiosTokens_ReturnsUnsupportedWithZeroHttpCalls(
        string model,
        string boardProduct)
    {
        var handler = new FakeBiosHttpHandler();
        var provider = AsusBiosUpdateProvider.CreateWithHandler(handler);
        var system = BiosIdentityFactory.Asus(model: model, boardProduct: boardProduct);

        var latest = await provider.GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.UnsupportedHardware, latest.Status);
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task GetLatestVersionAsync_OverlongModelToken_ReturnsUnsupportedWithZeroHttpCalls()
    {
        var handler = new FakeBiosHttpHandler();
        var provider = AsusBiosUpdateProvider.CreateWithHandler(handler);
        var system = BiosIdentityFactory.Asus(model: new string('A', 100), boardProduct: "ROG STRIX Z690-E");

        var latest = await provider.GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.UnsupportedHardware, latest.Status);
        Assert.Empty(handler.Requests);
    }

    // =========================================================================
    // A8 — HTTP Status Mapping, Network Errors, Timeout & Cancellation
    // =========================================================================

    [Theory]
    [InlineData(HttpStatusCode.NotFound, BiosCheckStatus.UnsupportedHardware)]
    [InlineData(HttpStatusCode.TooManyRequests, BiosCheckStatus.ProviderUnavailable)]
    [InlineData(HttpStatusCode.InternalServerError, BiosCheckStatus.ProviderUnavailable)]
    [InlineData(HttpStatusCode.BadGateway, BiosCheckStatus.ProviderUnavailable)]
    [InlineData(HttpStatusCode.ServiceUnavailable, BiosCheckStatus.ProviderUnavailable)]
    [InlineData(HttpStatusCode.BadRequest, BiosCheckStatus.Failed)]
    [InlineData(HttpStatusCode.Forbidden, BiosCheckStatus.Failed)]
    public async Task GetLatestVersionAsync_HttpStatusMapping(HttpStatusCode statusCode, BiosCheckStatus expectedStatus)
    {
        var handler = new FakeBiosHttpHandler();
        var system = BiosIdentityFactory.Asus();
        handler.MapStatus(BuildDefaultAsusUrl(system.Model), statusCode);

        var provider = AsusBiosUpdateProvider.CreateWithHandler(handler);
        var latest = await provider.GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(expectedStatus, latest.Status);
    }

    [Fact]
    public async Task GetLatestVersionAsync_NetworkTimeoutAndCancellation()
    {
        var system = BiosIdentityFactory.Asus();
        var url = BuildDefaultAsusUrl(system.Model);

        // HttpRequestException -> Offline
        var netHandler = new FakeBiosHttpHandler();
        netHandler.MapException(url, () => new HttpRequestException("Network down", new SocketException((int)SocketError.HostNotFound)));
        var netResult = await AsusBiosUpdateProvider.CreateWithHandler(netHandler).GetLatestVersionAsync(system, system.CurrentBios);
        Assert.Equal(BiosCheckStatus.Offline, netResult.Status);

        // Internal timeout TaskCanceledException (caller ct NOT cancelled) -> Offline
        var timeoutHandler = new FakeBiosHttpHandler();
        timeoutHandler.MapException(url, () => new TaskCanceledException("Timed out", new TimeoutException()));
        var timeoutResult = await AsusBiosUpdateProvider.CreateWithHandler(timeoutHandler).GetLatestVersionAsync(system, system.CurrentBios);
        Assert.Equal(BiosCheckStatus.Offline, timeoutResult.Status);

        // Pre-cancelled caller ct -> rethrows OperationCanceledException
        using var preCts = new CancellationTokenSource();
        preCts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => AsusBiosUpdateProvider.CreateWithHandler(new FakeBiosHttpHandler()).GetLatestVersionAsync(system, system.CurrentBios, preCts.Token));

        // Mid-request caller ct cancellation -> rethrows OperationCanceledException
        using var midCts = new CancellationTokenSource();
        var midHandler = new FakeBiosHttpHandler();
        midHandler.Map(url, (_, ct) =>
        {
            midCts.Cancel();
            ct.ThrowIfCancellationRequested();
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        });
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => AsusBiosUpdateProvider.CreateWithHandler(midHandler).GetLatestVersionAsync(system, system.CurrentBios, midCts.Token));
    }

    // =========================================================================
    // A9 — Redirects, Oversized Payload & Malformed/Degenerate JSON
    // =========================================================================

    [Fact]
    public async Task GetLatestVersionAsync_AllowedSameDomainRedirect_Succeeds()
    {
        var handler = new FakeBiosHttpHandler();
        var system = BiosIdentityFactory.Asus();
        var initialUrl = BuildDefaultAsusUrl(system.Model);
        var redirectedUrl = "https://dlcdnets.asus.com/support/api/bios-v2.json";

        handler.MapRedirect(initialUrl, redirectedUrl, HttpStatusCode.Redirect);
        handler.MapJson(redirectedUrl, BuildSingleAsusCatalog("3201", "2024/08/15"));

        var latest = await AsusBiosUpdateProvider.CreateWithHandler(handler).GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal("3201", latest.LatestVersion);
        Assert.Equal(2, handler.Requests.Count);
    }

    [Theory]
    [InlineData("https://evil.com/bios.json")]
    [InlineData("http://www.asus.com/support/api/bios.json")]
    [InlineData("//evil.com/bios.json")]
    [InlineData(null)]
    public async Task GetLatestVersionAsync_UnsafeRedirect_ReturnsFailed(string? targetLocation)
    {
        var handler = new FakeBiosHttpHandler();
        var system = BiosIdentityFactory.Asus();
        handler.MapRedirect(BuildDefaultAsusUrl(system.Model), targetLocation, HttpStatusCode.Redirect);

        var latest = await AsusBiosUpdateProvider.CreateWithHandler(handler).GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.Failed, latest.Status);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task GetLatestVersionAsync_RedirectLoopAndExcessiveHops_ReturnsFailed()
    {
        var system = BiosIdentityFactory.Asus();
        var startUrl = BuildDefaultAsusUrl(system.Model);

        var loopHandler = new FakeBiosHttpHandler();
        var hopB = "https://www.asus.com/support/api/hop-b";
        loopHandler.MapRedirect(startUrl, hopB);
        loopHandler.MapRedirect(hopB, startUrl);
        var loopResult = await AsusBiosUpdateProvider.CreateWithHandler(loopHandler).GetLatestVersionAsync(system, system.CurrentBios);
        Assert.Equal(BiosCheckStatus.Failed, loopResult.Status);

        var chainHandler = new FakeBiosHttpHandler();
        var prev = startUrl;
        for (var i = 1; i <= 6; i++)
        {
            var next = $"https://www.asus.com/support/api/hop-{i}";
            chainHandler.MapRedirect(prev, next);
            prev = next;
        }

        chainHandler.MapJson(prev, BuildSingleAsusCatalog("3201", "2024/08/15"));
        var chainResult = await AsusBiosUpdateProvider.CreateWithHandler(chainHandler).GetLatestVersionAsync(system, system.CurrentBios);
        Assert.Equal(BiosCheckStatus.Failed, chainResult.Status);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task GetLatestVersionAsync_OversizedPayload_ContentLengthAndChunked_ReturnsFailed(bool includeContentLength)
    {
        var handler = new FakeBiosHttpHandler();
        var system = BiosIdentityFactory.Asus();
        var oversized = new byte[AsusBiosUpdateProvider.MaxCatalogJsonBytes + 1024];
        Array.Fill(oversized, (byte)' ');
        oversized[0] = (byte)'[';
        oversized[^1] = (byte)']';

        handler.MapBytes(BuildDefaultAsusUrl(system.Model), oversized, includeContentLength: includeContentLength);

        var latest = await AsusBiosUpdateProvider.CreateWithHandler(handler).GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.Failed, latest.Status);
    }

    [Theory]
    [InlineData("", BiosCheckStatus.Failed)]
    [InlineData("   ", BiosCheckStatus.Failed)]
    [InlineData("<html>503</html>", BiosCheckStatus.Failed)]
    [InlineData("{invalid", BiosCheckStatus.Failed)]
    [InlineData("null", BiosCheckStatus.Failed)]
    [InlineData("123", BiosCheckStatus.Failed)]
    [InlineData("[]", BiosCheckStatus.UnsupportedHardware)]
    [InlineData("{\"Result\":null}", BiosCheckStatus.UnsupportedHardware)]
    [InlineData("{\"Result\":{\"Obj\":[]}}", BiosCheckStatus.UnsupportedHardware)]
    [InlineData("{\"Files\":\"not-array\"}", BiosCheckStatus.UnsupportedHardware)]
    public async Task GetLatestVersionAsync_MalformedOrDegenerateJson_ReturnsExpectedStatus(
        string body,
        BiosCheckStatus expectedStatus)
    {
        var handler = new FakeBiosHttpHandler();
        var system = BiosIdentityFactory.Asus();
        handler.MapText(BuildDefaultAsusUrl(system.Model), body, "application/json");

        var latest = await AsusBiosUpdateProvider.CreateWithHandler(handler).GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(expectedStatus, latest.Status);
    }

    [Fact]
    public async Task GetLatestVersionAsync_Utf8BomPrefixedJson_ParsesCleanly()
    {
        var handler = new FakeBiosHttpHandler();
        var system = BiosIdentityFactory.Asus();
        var jsonBytes = Encoding.UTF8.GetBytes(BuildSingleAsusCatalog("3201", "2024/08/15"));
        var withBom = new byte[3 + jsonBytes.Length];
        withBom[0] = 0xEF;
        withBom[1] = 0xBB;
        withBom[2] = 0xBF;
        Buffer.BlockCopy(jsonBytes, 0, withBom, 3, jsonBytes.Length);

        handler.MapBytes(BuildDefaultAsusUrl(system.Model), withBom);

        var latest = await AsusBiosUpdateProvider.CreateWithHandler(handler).GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal("3201", latest.LatestVersion);
    }

    // =========================================================================
    // A10 — URL Security, Traversal & SerialNumber Redaction
    // =========================================================================

    [Theory]
    [InlineData("http://dlcdnets.asus.com/pub/a.zip")]
    [InlineData("https://evil.com/a.zip")]
    [InlineData("https://asus.com.evil.com/a.zip")]
    [InlineData("https://evilasus.com/a.zip")]
    [InlineData("https://asus.com@evil.com/a.zip")]
    [InlineData("file:///C:/a.zip")]
    [InlineData("//dlcdnets.asus.com/pub/a.zip")]
    [InlineData("https://dlcdnets.asus.com/pub/%2e%2e/evil.zip")]
    [InlineData("https://dlcdnets.asus.com/pub/%252e%252e/evil.zip")]
    [InlineData("https://dlcdnets.asus.com/pub/a%00.zip")]
    public async Task GetLatestVersionAsync_UntrustedDownloadUrl_ReturnsFailed(string badUrl)
    {
        var handler = new FakeBiosHttpHandler();
        var system = BiosIdentityFactory.Asus();
        var json = JsonSerializer.Serialize(new
        {
            Result = new
            {
                Obj = new[]
                {
                    new
                    {
                        Name = "BIOS",
                        Files = new[]
                        {
                            new
                            {
                                Version = "3201",
                                ReleaseDate = "2024/08/15",
                                DownloadUrl = new { Global = badUrl, China = "https://dlcdnets.asus.com/pub/fallback.zip" },
                            },
                        },
                    },
                },
            },
        });
        handler.MapJson(BuildDefaultAsusUrl(system.Model), json);

        var latest = await AsusBiosUpdateProvider.CreateWithHandler(handler).GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.Failed, latest.Status);
        Assert.Null(latest.DownloadUrl);
    }

    [Fact]
    public async Task GetLatestVersionAsync_UntrustedReleaseNotesUrlDroppedToNull_AndUnsafeEndpointFailsWithZeroCalls()
    {
        var handler = new FakeBiosHttpHandler();
        var system = BiosIdentityFactory.Asus();
        var json = """
        {
          "Files": [
            {
              "Version": "3201",
              "ReleaseDate": "2024/08/15",
              "ReleaseNotesUrl": "https://evil.com/notes",
              "DownloadUrl": "https://dlcdnets.asus.com/pub/3201.zip"
            }
          ]
        }
        """;
        handler.MapJson(BuildDefaultAsusUrl(system.Model), json);

        var latest = await AsusBiosUpdateProvider.CreateWithHandler(handler).GetLatestVersionAsync(system, system.CurrentBios);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Null(latest.ReleaseNotesUrl);

        // Unsafe custom catalogEndpoint -> Failed with 0 HTTP calls
        var evilHandler = new FakeBiosHttpHandler();
        var badProvider = AsusBiosUpdateProvider.CreateWithHandler(evilHandler, catalogEndpoint: "https://evil.com/api?model={model}");
        var badResult = await badProvider.GetLatestVersionAsync(system, system.CurrentBios);
        Assert.Equal(BiosCheckStatus.Failed, badResult.Status);
        Assert.Empty(evilHandler.Requests);
    }

    [Fact]
    public async Task GetLatestVersionAsync_ErrorAndPayloadContainingSerialNumber_RedactsSecret()
    {
        var handler = new FakeBiosHttpHandler();
        var log = new CapturedLog();
        var system = BiosIdentityFactory.Asus();
        var secret = BiosIdentityFactory.SentinelSerialNumber;

        // 1. Payload summary containing secret -> redacted in ReleaseSummary
        handler.MapJson(BuildDefaultAsusUrl(system.Model), $$"""
        {
          "Files": [
            {
              "Id": "pkg-{{secret}}",
              "Version": "3201",
              "Description": "Diagnostic echo {{secret}} in release notes",
              "ReleaseDate": "2024/08/15",
              "DownloadUrl": "https://dlcdnets.asus.com/pub/3201.zip"
            }
          ]
        }
        """);

        var provider = AsusBiosUpdateProvider.CreateWithHandler(handler, log.Logger);
        var okResult = await provider.GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, okResult.Status);
        Assert.DoesNotContain(secret, okResult.ReleaseSummary ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(secret, okResult.PackageId ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(secret, okResult.Message ?? "", StringComparison.OrdinalIgnoreCase);
        log.AssertDoesNotContainSecret();

        // 2. Exception message echoing secret -> redacted in Failed Message & logs
        var errHandler = new FakeBiosHttpHandler();
        errHandler.MapException(BuildDefaultAsusUrl(system.Model), () => new InvalidOperationException($"Upstream error for {secret}"));
        var errLog = new CapturedLog();
        var errResult = await AsusBiosUpdateProvider.CreateWithHandler(errHandler, errLog.Logger).GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.Failed, errResult.Status);
        Assert.DoesNotContain(secret, errResult.Message ?? "", StringComparison.OrdinalIgnoreCase);
        errLog.AssertDoesNotContainSecret();
    }

    // =========================================================================
    // A11 — Explicit Check-Only InstallAsync Contract
    // =========================================================================

    [Fact]
    public async Task InstallAsync_ReturnsUnsupported_AndGuardsNullAndCancellation()
    {
        var handler = new FakeBiosHttpHandler();
        var log = new CapturedLog();
        var progress = new SyncProgress<BiosInstallProgress>();
        var provider = AsusBiosUpdateProvider.CreateWithHandler(handler, log.Logger);

        await Assert.ThrowsAsync<ArgumentNullException>(() => provider.InstallAsync(null!));

        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => provider.InstallAsync(CreateAsusInstallRequest(), progress, cts.Token));

        var request = CreateAsusInstallRequest();
        var result = await provider.InstallAsync(request, progress);

        Assert.False(result.Succeeded);
        Assert.Equal(BiosInstallStatus.Unsupported, result.Status);
        Assert.False(result.RequiresReboot);
        Assert.False(result.BitLockerSuspended);
        Assert.Equal("2802", result.PreviousVersion);
        Assert.Equal("3201", result.TargetVersion);
        Assert.Empty(handler.Requests);
        Assert.Empty(progress.Reports);
        log.AssertDoesNotContainSecret();
        Assert.DoesNotContain(BiosIdentityFactory.SentinelSerialNumber, result.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(BiosIdentityFactory.SentinelSerialNumber, result.LogTail ?? "", StringComparison.OrdinalIgnoreCase);
    }

    // =========================================================================
    // A12 — DI Validation & BiosUpdateService Integration
    // =========================================================================

    [Fact]
    public async Task DiRegistration_ValidateOnBuildAndScopes_ResolvesAndIntegratesWithBiosUpdateService()
    {
        // 1. Bare AddBiosUpdates().AddBiosUpdateProvider<AsusBiosUpdateProvider>() with ZERO optional services
        var bareServices = new ServiceCollection();
        bareServices.AddBiosUpdates();
        bareServices.AddBiosUpdateProvider<AsusBiosUpdateProvider>();
        await using (var bareSp = bareServices.BuildServiceProvider(
            new ServiceProviderOptions { ValidateOnBuild = true, ValidateScopes = true }))
        {
            var bareSvc = bareSp.GetRequiredService<IBiosUpdateService>();
            Assert.Contains(bareSvc.Providers, p => p.VendorId == "asus");
        }

        // 2. Full wired BiosUpdateService integration
        var system = BiosIdentityFactory.Asus();
        var handler = new FakeBiosHttpHandler();
        handler.MapJson(BuildDefaultAsusUrl(system.Model), BuildSingleAsusCatalog("3201", "2024/08/15"));
        var safetyProbe = new CountingSafetyProbe(BiosIdentityFactory.SafeSnapshot());

        var services = new ServiceCollection();
        services.AddSingleton<IBiosSystemProbe>(new StubSystemProbe(system));
        services.AddSingleton<IBiosInstallSafetyProbe>(safetyProbe);
        services.AddBiosUpdates();
        services.AddBiosUpdateProvider(_ => AsusBiosUpdateProvider.CreateWithHandler(handler));

        await using var sp = services.BuildServiceProvider(
            new ServiceProviderOptions { ValidateOnBuild = true, ValidateScopes = true });
        var service = sp.GetRequiredService<IBiosUpdateService>();

        var resolved = service.ResolveProvider(system);
        Assert.NotNull(resolved);
        Assert.Equal("asus", resolved.VendorId);

        var check = await service.CheckForUpdateAsync();
        Assert.Equal("asus", check.ProviderId);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, check.Latest.Status);
        Assert.Equal("3201", check.Latest.LatestVersion);

        var installRequest = new BiosInstallRequest(system, check.Current, check.Latest, Approved: true, ApprovedBy: "op");
        var installResult = await service.InstallUpdateAsync(installRequest);

        Assert.False(installResult.Succeeded);
        Assert.Equal(BiosInstallStatus.Unsupported, installResult.Status);
        Assert.Equal(0, safetyProbe.CallCount);
        Assert.Single(handler.Requests); // only the check GET; zero install requests
    }

    // =========================================================================
    // A13 — Iteration 2 Hardening & Regression Tests
    // =========================================================================

    [Theory]
    [InlineData("TUF GAMING B650-PLUS WIFI", "2402")]
    [InlineData("ROG MAXIMUS Z790 LAN", "2402")]
    [InlineData("Improve USB / NVMe / Thunderbolt stability", "2402")]
    public async Task GetLatestVersionAsync_ExplicitBiosCategoryWithPeripheralBoardTitles_AcceptedWhileToolsRejected(
        string biosTitle,
        string expectedVersion)
    {
        var handler = new FakeBiosHttpHandler();
        var model = "TUF GAMING B650-PLUS WIFI";
        var json = JsonSerializer.Serialize(new
        {
            Result = new
            {
                Obj = new[]
                {
                    new
                    {
                        Name = "BIOS",
                        Files = new[]
                        {
                            new
                            {
                                Title = "BIOSRenamer for USB BIOS FlashBack",
                                Version = "9999",
                                ReleaseDate = "2026/01/01",
                                DownloadUrl = new { Global = "https://dlcdnets.asus.com/pub/BIOSRenamer.zip" },
                            },
                            new
                            {
                                Title = "Intel ME Update Tool",
                                Version = "9998",
                                ReleaseDate = "2026/01/01",
                                DownloadUrl = new { Global = "https://dlcdnets.asus.com/pub/MEUpdateTool.zip" },
                            },
                            new
                            {
                                Title = biosTitle,
                                Version = expectedVersion,
                                ReleaseDate = "2024/08/15",
                                DownloadUrl = new { Global = "https://dlcdnets.asus.com/pub/2402.zip" },
                            },
                        },
                    },
                },
            },
        });
        handler.MapJson(BuildDefaultAsusUrl(model), json);

        var system = BiosIdentityFactory.Asus(model: model, biosVersion: "1801");
        var latest = await AsusBiosUpdateProvider.CreateWithHandler(handler).GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal(expectedVersion, latest.LatestVersion);
        Assert.Equal("https://dlcdnets.asus.com/pub/2402.zip", latest.DownloadUrl);
    }

    [Fact]
    public async Task GetLatestVersionAsync_LaptopFamilyMismatch_ReturnsUnsupportedEvenWithNewerDate()
    {
        var handler = new FakeBiosHttpHandler();
        var model = "UX3402ZA";
        handler.MapJson(BuildDefaultAsusUrl(model), BuildSingleAsusCatalog("GA402RJ.318", "2026/01/01"));

        var provider = AsusBiosUpdateProvider.CreateWithHandler(handler);
        var system = BiosIdentityFactory.Asus(model: model, boardProduct: model, biosVersion: "UX3402ZA.310");
        var normalizedCurrent = await provider.GetCurrentVersionAsync(system);

        var latest = await provider.GetLatestVersionAsync(system, normalizedCurrent);

        Assert.Equal(BiosCheckStatus.UnsupportedHardware, latest.Status);
        Assert.Null(latest.DownloadUrl);
    }

    [Fact]
    public async Task GetLatestVersionAsync_SerialNumberInVersionUrlsUntrustedLogAndModelException_CompletelyRedacted()
    {
        const string secret = "SN-SECRET-998877";

        // 1. Echoed serial in Version, DownloadUrl, and ReleaseNotesUrl
        var echoHandler = new FakeBiosHttpHandler();
        var echoLog = new CapturedLog();
        var system = BiosIdentityFactory.Asus(model: "ROG STRIX Z690-E", biosVersion: "1801") with
        {
            SerialNumber = secret,
        };
        echoHandler.MapJson(BuildDefaultAsusUrl(system.Model), $$"""
        {
          "Files": [
            {
              "Version": "2402-{{secret}}",
              "ReleaseDate": "2025/05/01",
              "ReleaseNotesUrl": "https://www.asus.com/support/{{secret}}/notes",
              "DownloadUrl": "https://dlcdnets.asus.com/pub/{{secret}}/2402.zip"
            }
          ]
        }
        """);

        var echoResult = await AsusBiosUpdateProvider.CreateWithHandler(echoHandler, echoLog.Logger)
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
        untrustedHandler.MapJson(BuildDefaultAsusUrl(system.Model), $$"""
        {
          "Files": [
            {
              "Version": "9999-{{secret}}",
              "ReleaseDate": "2025/05/01",
              "DownloadUrl": "http://evil.com/x.zip"
            }
          ]
        }
        """);

        var untrustedResult = await AsusBiosUpdateProvider.CreateWithHandler(untrustedHandler, untrustedLog.Logger)
            .GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.Failed, untrustedResult.Status);
        untrustedLog.AssertDoesNotContainSecret(secret);

        // 3. Model equals secret and request throws -> warning log must redact modelToken AND exception message
        var errHandler = new FakeBiosHttpHandler();
        var errLog = new CapturedLog();
        var secretModelSystem = BiosIdentityFactory.Asus(model: secret, boardProduct: "Default string", biosVersion: "1801") with
        {
            SerialNumber = secret,
        };
        errHandler.MapException(BuildDefaultAsusUrl(secret), () => new HttpRequestException($"boom for {secret}"));

        var errResult = await AsusBiosUpdateProvider.CreateWithHandler(errHandler, errLog.Logger)
            .GetLatestVersionAsync(secretModelSystem, secretModelSystem.CurrentBios);

        Assert.Equal(BiosCheckStatus.Offline, errResult.Status);
        Assert.DoesNotContain(secret, errResult.Message ?? "", StringComparison.OrdinalIgnoreCase);
        errLog.AssertDoesNotContainSecret(secret);
    }

    [Theory]
    [InlineData("https://dlcdnets.asus.com/api/%2e%2e/secret.json")]
    [InlineData("/pub/%2e%2e/evil.json")]
    [InlineData("/pub/../evil.json")]
    public async Task GetLatestVersionAsync_SameDomainRedirectWithPathTraversal_FailsClosedWithSingleHttpCall(
        string unsafeLocation)
    {
        var handler = new FakeBiosHttpHandler();
        var system = BiosIdentityFactory.Asus();
        handler.MapRedirect(BuildDefaultAsusUrl(system.Model), unsafeLocation, HttpStatusCode.Redirect);
        handler.MapJson("https://dlcdnets.asus.com/secret.json", BuildSingleAsusCatalog("3201", "2025/01/01"));
        handler.MapJson("https://www.asus.com/evil.json", BuildSingleAsusCatalog("3201", "2025/01/01"));

        var latest = await AsusBiosUpdateProvider.CreateWithHandler(handler)
            .GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.Failed, latest.Status);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task GetLatestVersionAsync_OrderCandidates_PrefersValidDownloadUrlAndBreaksUrlCaseAndShaTiesDeterministically()
    {
        var system = BiosIdentityFactory.Asus(model: "ROG STRIX Z690-E", biosVersion: "1801");

        // 1. Valid DownloadUrl beats null DownloadUrl on identical version/date regardless of order
        foreach (var reversed in new[] { false, true })
        {
            var items = new object[]
            {
                new { Title = "BIOS 2402", Version = "2402", ReleaseDate = "2024/06/01", DownloadUrl = (string?)null },
                new { Title = "BIOS 2402", Version = "2402", ReleaseDate = "2024/06/01", DownloadUrl = "https://dlcdnets.asus.com/pub/2402.zip" },
            };
            if (reversed)
                Array.Reverse(items);

            var handler = new FakeBiosHttpHandler();
            handler.MapJson(BuildDefaultAsusUrl(system.Model), JsonSerializer.Serialize(new { Files = items }));
            var result = await AsusBiosUpdateProvider.CreateWithHandler(handler).GetLatestVersionAsync(system, system.CurrentBios);

            Assert.Equal(BiosCheckStatus.UpdateAvailable, result.Status);
            Assert.Equal("https://dlcdnets.asus.com/pub/2402.zip", result.DownloadUrl);
        }

        // 2. Identical version/date/packageId with URL casing tie & distinct SHA-256 -> identical winner across all permutations
        var shaA = new string('a', 64);
        var shaB = new string('b', 64);
        var tieEntries = new[]
        {
            new { Version = "9999", ReleaseDate = "2025/05/01", DownloadUrl = "https://dlcdnets.asus.com/UPPER.zip", Sha256 = shaA },
            new { Version = "9999", ReleaseDate = "2025/05/01", DownloadUrl = "https://dlcdnets.asus.com/upper.zip", Sha256 = shaB },
            new { Version = "9999", ReleaseDate = "2025/05/01", DownloadUrl = "https://dlcdnets.asus.com/UPPER.zip", Sha256 = shaB },
        };

        BiosLatestInfo? baseline = null;
        foreach (var mode in new[] { 0, 1, 7, 42, 99 })
        {
            var permuted = Permute(tieEntries, mode);
            var handler = new FakeBiosHttpHandler();
            handler.MapJson(BuildDefaultAsusUrl(system.Model), JsonSerializer.Serialize(new { Files = permuted }));
            var result = await AsusBiosUpdateProvider.CreateWithHandler(handler).GetLatestVersionAsync(system, system.CurrentBios);

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
        var system = BiosIdentityFactory.Asus(model: "ROG STRIX Z690-E", biosVersion: "1801");
        handler.MapJson(BuildDefaultAsusUrl(system.Model), JsonSerializer.Serialize(new
        {
            Files = new[]
            {
                new
                {
                    Version = "2402",
                    ReleaseDate = "2024/08/15",
                    FileSize = fileSize,
                    DownloadUrl = "https://dlcdnets.asus.com/pub/2402.zip",
                },
            },
        }));

        var latest = await AsusBiosUpdateProvider.CreateWithHandler(handler).GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal(expectedBytes, latest.SizeBytes);
    }

    [Fact]
    public async Task GetLatestVersionAsync_MixedTrustedAndUntrustedCatalogs_SymmetricFailClosedAndArchivedUpToDate()
    {
        var model = "ROG STRIX Z690-E";

        // 1. Older trusted (2000) + newer untrusted (9999) -> Failed, null DownloadUrl
        var newerBadHandler = new FakeBiosHttpHandler();
        newerBadHandler.MapJson(BuildDefaultAsusUrl(model), """
        {
          "Files": [
            { "Version": "2000", "ReleaseDate": "2023/01/01", "DownloadUrl": "https://dlcdnets.asus.com/pub/2000.zip" },
            { "Version": "9999", "ReleaseDate": "2025/05/01", "DownloadUrl": "http://evil.com/9999.zip" }
          ]
        }
        """);
        var sysOld = BiosIdentityFactory.Asus(model: model, biosVersion: "1801");
        var newerBadResult = await AsusBiosUpdateProvider.CreateWithHandler(newerBadHandler)
            .GetLatestVersionAsync(sysOld, sysOld.CurrentBios);
        Assert.Equal(BiosCheckStatus.Failed, newerBadResult.Status);
        Assert.Null(newerBadResult.DownloadUrl);

        // 2. Newer trusted (3201, matching current) + strictly older archived untrusted (2402) -> UpToDate
        var archivedBadHandler = new FakeBiosHttpHandler();
        archivedBadHandler.MapJson(BuildDefaultAsusUrl(model), """
        {
          "Files": [
            { "Version": "3201", "ReleaseDate": "2025/01/01", "DownloadUrl": "https://dlcdnets.asus.com/pub/3201.zip" },
            { "Version": "2402", "ReleaseDate": "2023/01/01", "DownloadUrl": "http://dlcdnets.asus.com/pub/2402.zip" }
          ]
        }
        """);
        var sysCurrent = BiosIdentityFactory.Asus(model: model, biosVersion: "3201");
        var archivedResult = await AsusBiosUpdateProvider.CreateWithHandler(archivedBadHandler)
            .GetLatestVersionAsync(sysCurrent, sysCurrent.CurrentBios);
        Assert.Equal(BiosCheckStatus.UpToDate, archivedResult.Status);
        Assert.Equal("3201", archivedResult.LatestVersion);

        // 3. Equal-version untrusted (3201) alongside trusted (3201) when up to date -> Failed
        var equalBadHandler = new FakeBiosHttpHandler();
        equalBadHandler.MapJson(BuildDefaultAsusUrl(model), """
        {
          "Files": [
            { "Version": "3201", "ReleaseDate": "2025/01/01", "DownloadUrl": "https://dlcdnets.asus.com/pub/3201.zip" },
            { "Version": "3201", "ReleaseDate": "2025/01/01", "DownloadUrl": "http://evil.com/3201.zip" }
          ]
        }
        """);
        var equalBadResult = await AsusBiosUpdateProvider.CreateWithHandler(equalBadHandler)
            .GetLatestVersionAsync(sysCurrent, sysCurrent.CurrentBios);
        Assert.Equal(BiosCheckStatus.Failed, equalBadResult.Status);
    }

    [Fact]
    public async Task GetLatestVersionAsync_NullAliasFallthroughAndWrongKindDownloadUrl()
    {
        var model = "ROG STRIX Z690-E";
        var system = BiosIdentityFactory.Asus(model: model, biosVersion: "1801");

        // 1. Null-valued alias falls through to secondary alias
        var aliasHandler = new FakeBiosHttpHandler();
        aliasHandler.MapJson(BuildDefaultAsusUrl(model), """
        {
          "Files": [
            {
              "Version": null,
              "BiosVersion": "2402",
              "ReleaseDate": "2024/08/15",
              "DownloadUrl": null,
              "Url": "https://dlcdnets.asus.com/pub/2402.zip"
            }
          ]
        }
        """);
        var aliasResult = await AsusBiosUpdateProvider.CreateWithHandler(aliasHandler)
            .GetLatestVersionAsync(system, system.CurrentBios);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, aliasResult.Status);
        Assert.Equal("2402", aliasResult.LatestVersion);
        Assert.Equal("https://dlcdnets.asus.com/pub/2402.zip", aliasResult.DownloadUrl);

        // 2. Non-null wrong JsonValueKind on DownloadUrl (number, bool, array) -> Failed
        foreach (var badJson in new[]
        {
            """{"Files":[{"Version":"2402","ReleaseDate":"2024/08/15","DownloadUrl":12345}]}""",
            """{"Files":[{"Version":"2402","ReleaseDate":"2024/08/15","DownloadUrl":true}]}""",
            """{"Files":[{"Version":"2402","ReleaseDate":"2024/08/15","DownloadUrl":[]}]}""",
            """{"Files":[{"Version":"2402","ReleaseDate":"2024/08/15","DownloadUrl":{"Global":12345,"China":"https://dlcdnets.asus.com/pub/2402.zip"}}]}""",
        })
        {
            var wrongKindHandler = new FakeBiosHttpHandler();
            wrongKindHandler.MapJson(BuildDefaultAsusUrl(model), badJson);
            var wrongResult = await AsusBiosUpdateProvider.CreateWithHandler(wrongKindHandler)
                .GetLatestVersionAsync(system, system.CurrentBios);
            Assert.Equal(BiosCheckStatus.Failed, wrongResult.Status);
            Assert.Null(wrongResult.DownloadUrl);
        }
    }

    [Fact]
    public async Task GetLatestVersionAsync_CustomPathPlaceholderEndpoint_RejectsSlashInModelTokenWithZeroCalls()
    {
        const string endpoint = "https://www.asus.com/api/{model}/bios.json";
        var handler = new FakeBiosHttpHandler();
        var provider = AsusBiosUpdateProvider.CreateWithHandler(handler, catalogEndpoint: endpoint);

        var slashSystem = BiosIdentityFactory.Asus(model: "ROG/STRIX", boardProduct: "ROG/STRIX", biosVersion: "1801");
        var slashResult = await provider.GetLatestVersionAsync(slashSystem, slashSystem.CurrentBios);

        Assert.Equal(BiosCheckStatus.Failed, slashResult.Status);
        Assert.Empty(handler.Requests);
    }

    // =========================================================================
    // A14 — Iteration 3 Surgical Hardening Regression Tests
    // =========================================================================

    [Theory]
    [InlineData("https:../secret.json")]
    [InlineData("https:./secret.json")]
    [InlineData("https:secret.json")]
    [InlineData("https:/secret.json")]
    [InlineData("http:www.asus.com")]
    [InlineData("javascript:alert(1)")]
    [InlineData("file:foo")]
    public async Task GetLatestVersionAsync_SameSchemeRelativeOrNonHttpsColonRedirect_FailsClosedWithSingleHttpCall(
        string unsafeLocation)
    {
        var handler = new FakeBiosHttpHandler();
        var system = BiosIdentityFactory.Asus();
        handler.MapRedirect(BuildDefaultAsusUrl(system.Model), unsafeLocation, HttpStatusCode.Redirect);
        handler.MapPredicate(_ => true, (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(BuildSingleAsusCatalog("3201", "2025/01/01"), System.Text.Encoding.UTF8, "application/json"),
        }));

        var latest = await AsusBiosUpdateProvider.CreateWithHandler(handler)
            .GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.Failed, latest.Status);
        Assert.Single(handler.Requests);
    }

    [Theory]
    [InlineData("https://www.asus.com/safe.json", "https://evil.com/pwn.json")]
    [InlineData("https://www.asus.com/safe.json", "/pub/%2e%2e/secret.json")]
    [InlineData("https://www.asus.com/safe.json", "https://www.asus.com/safe2.json")]
    public async Task GetLatestVersionAsync_MultipleLocationHeaders_FailsClosedWithSingleHttpCall(
        string firstLocation,
        string secondLocation)
    {
        var handler = new FakeBiosHttpHandler();
        var system = BiosIdentityFactory.Asus();
        handler.Map(BuildDefaultAsusUrl(system.Model), (_, _) =>
        {
            var msg = new HttpResponseMessage(HttpStatusCode.Redirect);
            msg.Headers.TryAddWithoutValidation("Location", firstLocation);
            msg.Headers.TryAddWithoutValidation("Location", secondLocation);
            return Task.FromResult(msg);
        });
        handler.MapJson("https://www.asus.com/safe.json", BuildSingleAsusCatalog("3201", "2025/01/01"));
        handler.MapJson("https://www.asus.com/safe2.json", BuildSingleAsusCatalog("3201", "2025/01/01"));

        var latest = await AsusBiosUpdateProvider.CreateWithHandler(handler)
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
        const string modelWithSerial = "ROG Zephyrus SN 4242";
        var errHandler = new FakeBiosHttpHandler();
        var errLog = new CapturedLog();
        var errSystem = BiosIdentityFactory.Asus(model: modelWithSerial, boardProduct: "Default string", biosVersion: "1801") with
        {
            SerialNumber = spaceSecret,
        };
        errHandler.Map(BuildDefaultAsusUrl(modelWithSerial), (req, _) =>
            Task.FromException<HttpResponseMessage>(new HttpRequestException($"Connection refused to {req.RequestUri!.AbsoluteUri}")));

        var errResult = await AsusBiosUpdateProvider.CreateWithHandler(errHandler, errLog.Logger)
            .GetLatestVersionAsync(errSystem, errSystem.CurrentBios);

        Assert.Equal(BiosCheckStatus.Offline, errResult.Status);
        Assert.DoesNotContain(spaceSecret, errResult.Message ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(escapedSpaceSecret, errResult.Message ?? "", StringComparison.OrdinalIgnoreCase);
        errLog.AssertDoesNotContainSecret(spaceSecret);
        errLog.AssertDoesNotContainSecret(escapedSpaceSecret);

        // 2. Catalog JSON echoes escaped & form-encoded serial in Version, Description, PackageId
        var echoHandler = new FakeBiosHttpHandler();
        var echoLog = new CapturedLog();
        var echoSystem = BiosIdentityFactory.Asus(model: "ROG STRIX Z690-E", biosVersion: "1801") with
        {
            SerialNumber = spaceSecret,
        };
        echoHandler.MapJson(BuildDefaultAsusUrl(echoSystem.Model), """
        {
          "Files": [
            {
              "Id": "PKG-SN%204242",
              "Version": "2402-SN%204242",
              "Description": "Firmware update for SN%204242 and SN+4242",
              "ReleaseDate": "2025/05/01",
              "DownloadUrl": "https://dlcdnets.asus.com/pub/2402.zip"
            }
          ]
        }
        """);

        var echoResult = await AsusBiosUpdateProvider.CreateWithHandler(echoHandler, echoLog.Logger)
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
            ("SN:9988 77", "https://dlcdnets.asus.com/pub/2402.zip?sn=SN:9988%2077", "https://www.asus.com/support/notes?sn=SN:9988%2077"),
            ("SN/4242 99", "https://dlcdnets.asus.com/SN/4242%2099/2402.zip", "https://www.asus.com/support/SN/4242%2099/notes"),
        })
        {
            var urlHandler = new FakeBiosHttpHandler();
            var urlSystem = BiosIdentityFactory.Asus(model: "ROG STRIX Z690-E", biosVersion: "1801") with
            {
                SerialNumber = mixedSerial,
            };
            urlHandler.MapJson(BuildDefaultAsusUrl(urlSystem.Model), JsonSerializer.Serialize(new
            {
                Files = new[]
                {
                    new
                    {
                        Version = "2402",
                        ReleaseDate = "2025/05/01",
                        DownloadUrl = dlUrl,
                        ReleaseNotesUrl = notesUrl,
                    },
                },
            }));

            var urlResult = await AsusBiosUpdateProvider.CreateWithHandler(urlHandler)
                .GetLatestVersionAsync(urlSystem, urlSystem.CurrentBios);

            Assert.Equal(BiosCheckStatus.UpdateAvailable, urlResult.Status);
            Assert.Null(urlResult.DownloadUrl);
            Assert.Null(urlResult.ReleaseNotesUrl);
        }

        // 4. GetCurrentVersionAsync and InstallAsync redact URI-escaped serials too
        var provider = AsusBiosUpdateProvider.CreateWithHandler(new FakeBiosHttpHandler());
        var curSystem = BiosIdentityFactory.Asus(model: "ROG STRIX Z690-E", biosVersion: $"1801-{escapedSpaceSecret}") with
        {
            SerialNumber = spaceSecret,
        };
        var cur = await provider.GetCurrentVersionAsync(curSystem);
        Assert.DoesNotContain(escapedSpaceSecret, cur.Version, StringComparison.OrdinalIgnoreCase);

        var installReq = CreateAsusInstallRequest(curSystem, targetVersion: $"2402-{escapedSpaceSecret}");
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
        var system = BiosIdentityFactory.Asus(model: "ROG STRIX Z690-E", biosVersion: "1801");
        handler.MapJson(BuildDefaultAsusUrl(system.Model), JsonSerializer.Serialize(new
        {
            Files = new[]
            {
                new
                {
                    Version = "2402",
                    ReleaseDate = "2024/08/15",
                    FileSize = fileSize,
                    DownloadUrl = "https://dlcdnets.asus.com/pub/2402.zip",
                },
            },
        }));

        var latest = await AsusBiosUpdateProvider.CreateWithHandler(handler)
            .GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal(expectedBytes, latest.SizeBytes);
    }

    // =========================================================================
    // Local Test Helpers
    // =========================================================================

    private static string BuildDefaultAsusUrl(string model) =>
        AsusBiosUpdateProvider.DefaultCatalogEndpoint.Replace("{model}", Uri.EscapeDataString(model), StringComparison.OrdinalIgnoreCase);

    private static string BuildSingleAsusCatalog(string version, string releaseDate) =>
        JsonSerializer.Serialize(new
        {
            Result = new
            {
                Obj = new[]
                {
                    new
                    {
                        Name = "BIOS",
                        Files = new[]
                        {
                            new
                            {
                                Version = version,
                                ReleaseDate = releaseDate,
                                DownloadUrl = new { Global = "https://dlcdnets.asus.com/pub/ASUS/mb/BIOS/bios-update.zip" },
                            },
                        },
                    },
                },
            },
        });

    private static BiosInstallRequest CreateAsusInstallRequest(
        BiosSystemIdentity? system = null,
        string targetVersion = "3201")
    {
        var id = system ?? BiosIdentityFactory.Asus();
        var target = BiosLatestInfo.UpdateAvailable(
            providerId: "asus",
            latestVersion: targetVersion,
            downloadUrl: "https://dlcdnets.asus.com/pub/ASUS/mb/BIOS/bios-3201.zip",
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
