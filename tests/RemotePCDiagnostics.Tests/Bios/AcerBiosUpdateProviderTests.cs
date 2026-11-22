using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Core.Bios;

namespace RemotePCDiagnostics.Tests.Bios;

public sealed class AcerBiosUpdateProviderTests
{
    private const string ValidSha256 = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    // =========================================================================
    // C1 — Metadata & Capabilities
    // =========================================================================

    [Fact]
    public void Metadata_MatchesContract()
    {
        var provider = new AcerBiosUpdateProvider();

        Assert.Equal("acer", provider.VendorId);
        Assert.Equal("Acer", provider.DisplayName);
        Assert.Equal(100, provider.Priority);
        Assert.Equal(["acer.com"], AcerBiosUpdateProvider.AllowedHostSuffixes);
        Assert.True(provider.Capabilities.CanCheckLatest);
        Assert.False(provider.Capabilities.CanInstall);
        Assert.False(provider.Capabilities.SupportsSilentInstall);
        Assert.False(provider.Capabilities.RequiresReboot);
        Assert.False(provider.Capabilities.RequiresElevation);
        Assert.True(provider.Capabilities.RequiresInternet);
    }

    // =========================================================================
    // C2 — CanHandle Positive & Negative Matrix
    // =========================================================================

    [Theory]
    [InlineData("Acer", "TGL")]
    [InlineData("Acer Inc.", "")]
    [InlineData("Acer Incorporated", "")]
    [InlineData("ACER", "")]
    [InlineData("Generic OEM", "Acer")]
    [InlineData("", "Acer Inc.")]
    public void CanHandle_AcerManufacturers_ReturnsTrue(string manufacturer, string boardManufacturer)
    {
        var provider = new AcerBiosUpdateProvider();
        var identity = BiosIdentityFactory.Acer(manufacturer: manufacturer) with
        {
            BoardManufacturer = boardManufacturer,
        };

        Assert.True(provider.CanHandle(identity));
    }

    [Theory]
    [InlineData("Racer")]
    [InlineData("Racer PC")]
    [InlineData("Tracer")]
    [InlineData("Pacer Corp")]
    [InlineData("Macerate")]
    [InlineData("HP")]
    [InlineData("Dell Inc.")]
    [InlineData("LENOVO")]
    [InlineData("ASUSTeK COMPUTER INC.")]
    [InlineData("Micro-Star International Co., Ltd.")]
    public void CanHandle_NonAcerOrSubstringManufacturers_ReturnsFalse(string manufacturer)
    {
        var provider = new AcerBiosUpdateProvider();
        var identity = BiosIdentityFactory.GenericUefi(manufacturer);

        Assert.False(provider.CanHandle(identity));
    }

    [Fact]
    public void CanHandle_EmptyWhitespaceLargeAndNull_ReturnsFalseWithoutThrowing()
    {
        var provider = new AcerBiosUpdateProvider();

        Assert.False(provider.CanHandle(BiosIdentityFactory.Unknown()));
        Assert.False(provider.CanHandle(null!));
        Assert.False(provider.CanHandle(BiosIdentityFactory.GenericUefi("   ")));
        Assert.False(provider.CanHandle(BiosIdentityFactory.GenericUefi(new string('A', 4096))));
    }

    // =========================================================================
    // C3 — GetCurrentVersionAsync Normalization & Redaction
    // =========================================================================

    [Theory]
    [InlineData("V1.10", "1.10")]
    [InlineData("v1.10", "1.10")]
    [InlineData("V 1.08", "1.08")]
    [InlineData("V.1.08", "1.08")]
    [InlineData("Version 1.08", "1.08")]
    [InlineData("BIOS Version V1.14", "1.14")]
    [InlineData(" 1.10 ", "1.10")]
    [InlineData("R01-A4", "R01-A4")]
    [InlineData("", "")]
    public async Task GetCurrentVersionAsync_SetsProviderIdNormalizesAndRedactsSerial(
        string rawVersion,
        string expectedVersion)
    {
        var log = new CapturedLog();
        var provider = new AcerBiosUpdateProvider(log: log.Logger);
        var identity = BiosIdentityFactory.Acer(biosVersion: rawVersion);

        var current = await provider.GetCurrentVersionAsync(identity);

        Assert.Equal("acer", current.ProviderId);
        Assert.Equal(expectedVersion, current.Version);
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
        var provider = new AcerBiosUpdateProvider();
        await Assert.ThrowsAsync<ArgumentNullException>(() => provider.GetCurrentVersionAsync(null!));

        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => provider.GetCurrentVersionAsync(BiosIdentityFactory.Acer(), cts.Token));
    }

    // =========================================================================
    // C4 — GetLatestVersionAsync Happy Path, UpToDate, Downgrade & Fallbacks
    // =========================================================================

    [Fact]
    public async Task GetLatestVersionAsync_ValidCatalog_ReturnsUpdateAvailable()
    {
        var handler = new FakeBiosHttpHandler();
        var log = new CapturedLog();
        var model = "Predator PH315-55";

        var json = $$"""
        {
          "data": {
            "bios": [
              {
                "id": "acer-bios-114",
                "category": "BIOS",
                "version": "V1.14",
                "title": "BIOS Update for Predator PH315-55",
                "description": "Updates Intel microcode.<br/>Improves thermal control.",
                "date": "2024-06-12",
                "size": "13.25 MB",
                "sha256": "{{ValidSha256.ToUpperInvariant()}}",
                "severity": "Recommended",
                "readmeUrl": "https://www.acer.com/us-en/support/bios/readme-114",
                "url": "https://global-download.acer.com/GDFiles/BIOS/BIOS/BIOS_Acer_1.14_A_A.zip"
              },
              {
                "id": "acer-audio-99",
                "category": "Audio",
                "version": "V9.99",
                "title": "Realtek Audio Driver",
                "date": "2025-01-01",
                "url": "https://global-download.acer.com/GDFiles/Driver/Audio/Audio.zip"
              }
            ]
          }
        }
        """;

        handler.MapJson(BuildDefaultAcerUrl(model), json);
        var provider = AcerBiosUpdateProvider.CreateWithHandler(handler, log.Logger);
        var system = BiosIdentityFactory.Acer(model: model, biosVersion: "V1.08");

        var latest = await provider.GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal("acer", latest.ProviderId);
        Assert.Equal("1.14", latest.LatestVersion);
        Assert.Equal(new DateOnly(2024, 6, 12), latest.ReleaseDate);
        Assert.Equal(BiosUpdateSeverity.Recommended, latest.Severity);
        Assert.Equal("acer-bios-114", latest.PackageId);
        Assert.Equal("https://global-download.acer.com/GDFiles/BIOS/BIOS/BIOS_Acer_1.14_A_A.zip", latest.DownloadUrl);
        Assert.Equal("https://www.acer.com/us-en/support/bios/readme-114", latest.ReleaseNotesUrl);
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
    [InlineData("V1.14", "V1.14")]
    [InlineData("1.14", "V1.14")]
    [InlineData("V1.14", "1.14.0")]
    [InlineData("V1.20", "V1.14")]
    [InlineData("R01-B1", "R01-A4")]
    public async Task GetLatestVersionAsync_CurrentEqualsOrExceedsLatest_ReturnsUpToDate(
        string currentVersion,
        string catalogVersion)
    {
        var handler = new FakeBiosHttpHandler();
        var model = "Swift SF314-512";
        handler.MapJson(BuildDefaultAcerUrl(model), BuildSingleAcerCatalog(catalogVersion, "2025-03-01"));

        var provider = AcerBiosUpdateProvider.CreateWithHandler(handler);
        var system = BiosIdentityFactory.Acer(model: model, biosVersion: currentVersion);

        var latest = await provider.GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.UpToDate, latest.Status);
        Assert.Null(latest.DownloadUrl);
    }

    [Theory]
    [InlineData("To Be Filled By O.E.M.", "Aspire TC-1780", "Aspire TC-1780")]
    [InlineData("System Product Name", "Veriton X4690G", "Veriton X4690G")]
    [InlineData("", "TGL_TL", "TGL_TL")]
    [InlineData("Swift SF314-512", "", "Swift SF314-512")]
    public async Task GetLatestVersionAsync_ModelPlaceholderFallsBackToBoardProduct(
        string model,
        string boardProduct,
        string expectedToken)
    {
        var handler = new FakeBiosHttpHandler();
        handler.MapJson(BuildDefaultAcerUrl(expectedToken), BuildSingleAcerCatalog("V1.14", "2024-06-12"));

        var provider = AcerBiosUpdateProvider.CreateWithHandler(handler);
        var system = BiosIdentityFactory.Acer(model: model, boardProduct: boardProduct, biosVersion: "V1.08");

        var latest = await provider.GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Single(handler.Requests);
        Assert.Contains(Uri.EscapeDataString(expectedToken), handler.Requests[0].RequestUri!.AbsoluteUri, StringComparison.Ordinal);
    }

    // =========================================================================
    // C5 — Version Formats (V1.x, 1.08A/B, R01-A4 -> R01-A10 -> R01-B1 -> R02-A0) & Filtering
    // =========================================================================

    [Theory]
    [InlineData("V1.9", "V1.10", BiosCheckStatus.UpdateAvailable)]
    [InlineData("V1.08", "V1.14", BiosCheckStatus.UpdateAvailable)]
    [InlineData("1.08", "1.08A", BiosCheckStatus.UpdateAvailable)]
    [InlineData("1.08A", "1.08B", BiosCheckStatus.UpdateAvailable)]
    [InlineData("1.08B", "1.14", BiosCheckStatus.UpdateAvailable)]
    [InlineData("R01-A4", "R01-A10", BiosCheckStatus.UpdateAvailable)]
    [InlineData("R01-A10", "R01-B1", BiosCheckStatus.UpdateAvailable)]
    [InlineData("R01-B1", "R02-A0", BiosCheckStatus.UpdateAvailable)]
    [InlineData("R01-B1", "R01-A10", BiosCheckStatus.UpToDate)]
    public async Task GetLatestVersionAsync_VersionFormatsComparison(
        string currentVersion,
        string catalogVersion,
        BiosCheckStatus expectedStatus)
    {
        var handler = new FakeBiosHttpHandler();
        var model = "Aspire TC-1780";
        // Identical release date so version ordering alone decides!
        handler.MapJson(BuildDefaultAcerUrl(model), BuildSingleAcerCatalog(catalogVersion, "2023-07-10"));

        var provider = AcerBiosUpdateProvider.CreateWithHandler(handler);
        var system = BiosIdentityFactory.Acer(model: model, biosVersion: currentVersion);

        var latest = await provider.GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(expectedStatus, latest.Status);
    }

    [Fact]
    public async Task GetLatestVersionAsync_CrossPrefixDesktopRevFallsBackToDate_AndFiltersNonBiosDrivers()
    {
        var handler = new FakeBiosHttpHandler();
        var model = "Veriton M4680G";
        var json = """
        {
          "drivers": [
            { "category": "Audio", "version": "V9.0", "date": "2025-05-01", "url": "https://global-download.acer.com/audio.zip" },
            { "category": "VGA", "version": "V31.0", "date": "2025-05-01", "url": "https://global-download.acer.com/vga.zip" },
            { "category": "BIOS", "version": "P01-B1", "date": "2024-09-01", "sha256": "not-a-valid-sha256", "url": "https://global-download.acer.com/bios.zip" }
          ]
        }
        """;
        handler.MapJson(BuildDefaultAcerUrl(model), json);

        var provider = AcerBiosUpdateProvider.CreateWithHandler(handler);
        var system = BiosIdentityFactory.Acer(model: model, biosVersion: "R01-A4");

        // R01-A4 (2023-07-10) vs P01-B1 (2024-09-01) -> different prefix letters fall back to date -> UpdateAvailable
        var latest = await provider.GetLatestVersionAsync(system, system.CurrentBios);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal("P01-B1", latest.LatestVersion);
        Assert.Null(latest.Sha256);

        // With newer current date -> UpToDate
        var newerCurrent = system.CurrentBios with { ReleaseDate = new DateOnly(2025, 1, 1) };
        var upToDate = await provider.GetLatestVersionAsync(system, newerCurrent);
        Assert.Equal(BiosCheckStatus.UpToDate, upToDate.Status);

        // Drivers-only catalog -> UnsupportedHardware
        var driverOnlyHandler = new FakeBiosHttpHandler();
        driverOnlyHandler.MapJson(BuildDefaultAcerUrl(model), """
        {
          "drivers": [
            { "category": "Chipset", "version": "10.1.1", "date": "2024-09-01", "url": "https://global-download.acer.com/chipset.zip" },
            { "category": "Manual", "version": "1.0", "date": "2024-09-01", "url": "https://global-download.acer.com/manual.pdf" }
          ]
        }
        """);
        var driverOnly = await AcerBiosUpdateProvider.CreateWithHandler(driverOnlyHandler).GetLatestVersionAsync(system, system.CurrentBios);
        Assert.Equal(BiosCheckStatus.UnsupportedHardware, driverOnly.Status);
    }

    // =========================================================================
    // C6 — 24+ Mixed Entries Strict-Weak-Order Shuffle Invariance
    // =========================================================================

    [Fact]
    public async Task GetLatestVersionAsync_24MixedEntries_StrictWeakOrderShuffleInvariance()
    {
        var model = "Swift SF314-512";
        var rawEntries = new List<(string Version, string? Date, string Id, string Url)>
        {
            // Literal '#' collision triples
            ("A1##", "2024-01-01", "c01", "https://global-download.acer.com/c01.zip"),
            ("A1#2", "2024-01-02", "c02", "https://global-download.acer.com/c02.zip"),
            ("A##2", "2024-01-03", "c03", "https://global-download.acer.com/c03.zip"),
            ("X1#2", "2024-01-04", "c04", "https://global-download.acer.com/c04.zip"),
            ("X##3", "2024-01-05", "c05", "https://global-download.acer.com/c05.zip"),
            ("X2#1", "2024-01-06", "c06", "https://global-download.acer.com/c06.zip"),
            // >64-bit overflow numbers
            ("99999999999999999999999999", "2023-05-01", "c07", "https://global-download.acer.com/c07.zip"),
            ("99999999999999999999999998", null, "c08", "https://global-download.acer.com/c08.zip"),
            // V1.x + trailing letter + dotted numeric
            ("V1.08", "2023-06-01", "c09", "https://global-download.acer.com/c09.zip"),
            ("V1.08A", "2023-07-01", "c10", "https://global-download.acer.com/c10.zip"),
            ("V1.14", "2024-05-01", "c11", "https://global-download.acer.com/c11.zip"),
            ("V1.20", "2025-02-15", "c12", "https://global-download.acer.com/c12.zip"),
            ("1.20.0", "2025-02-15", "c13", "https://global-download.acer.com/c13.zip"),
            // Acer desktop revisions
            ("R01-A4", "2023-04-01", "c14", "https://global-download.acer.com/c14.zip"),
            ("R01-A10", "2023-08-01", "c15", "https://global-download.acer.com/c15.zip"),
            ("R01-B1", "2024-01-10", "c16", "https://global-download.acer.com/c16.zip"),
            ("P01-A3", null, "c17", "https://global-download.acer.com/c17.zip"),
            // Backslash / hash skeletons & Unicode U+017F
            ("B\\1#2", "2023-03-01", "c18", "https://global-download.acer.com/c18.zip"),
            ("B\\#12", "2023-03-02", "c19", "https://global-download.acer.com/c19.zip"),
            ("ſ10", "2023-02-01", "c20", "https://global-download.acer.com/c20.zip"),
            ("S10", "2023-02-01", "c21", "https://global-download.acer.com/c21.zip"),
            ("s10", "2023-02-02", "c22", "https://global-download.acer.com/c22.zip"),
            // Missing dates & duplicates
            ("V1.20", null, "c23", "https://global-download.acer.com/c23.zip"),
            ("PLAIN-LITERAL", null, "c24", "https://global-download.acer.com/c24.zip"),
        };

        int[] modes = [0, 1, 42, 1337, 9001, 202606];
        BiosLatestInfo? baseline = null;
        var system = BiosIdentityFactory.Acer(model: model, biosVersion: "V1.10");

        foreach (var mode in modes)
        {
            var permuted = Permute(rawEntries, mode);
            var payload = JsonSerializer.Serialize(new
            {
                bios = permuted.Select(e => new
                {
                    id = e.Id,
                    version = e.Version,
                    date = e.Date,
                    url = e.Url,
                }),
            });

            var handler = new FakeBiosHttpHandler();
            handler.MapJson(BuildDefaultAcerUrl(model), payload);
            var provider = AcerBiosUpdateProvider.CreateWithHandler(handler);

            var result = await provider.GetLatestVersionAsync(system, system.CurrentBios);
            Assert.Equal(BiosCheckStatus.UpdateAvailable, result.Status);
            Assert.Equal("1.20", result.LatestVersion);

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
    // C7 — Placeholders & Malicious SMBIOS Tokens -> UnsupportedHardware (0 HTTP Calls)
    // =========================================================================

    [Theory]
    [InlineData("", "")]
    [InlineData("   ", "   ")]
    [InlineData("To Be Filled By O.E.M.", "To Be Filled By O.E.M.")]
    [InlineData("Default string", "Default string")]
    [InlineData("System Product Name", "None")]
    [InlineData("N/A", "Unknown")]
    [InlineData("Swift; calc.exe", "TGL_TL")]
    [InlineData("Swift&whoami", "TGL_TL")]
    [InlineData("Swift|powershell", "TGL_TL")]
    [InlineData("$(id)", "TGL_TL")]
    [InlineData("../../etc/passwd", "TGL_TL")]
    [InlineData("Swift?x=1", "TGL_TL")]
    [InlineData("Swift\r\nHost: evil.com", "TGL_TL")]
    [InlineData("Swift SF314-512", "TGL;whoami")]
    public async Task GetLatestVersionAsync_PlaceholdersAndMaliciousSmbiosTokens_ReturnsUnsupportedWithZeroHttpCalls(
        string model,
        string boardProduct)
    {
        var handler = new FakeBiosHttpHandler();
        var provider = AcerBiosUpdateProvider.CreateWithHandler(handler);
        var system = BiosIdentityFactory.Acer(model: model, boardProduct: boardProduct);

        var latest = await provider.GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.UnsupportedHardware, latest.Status);
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task GetLatestVersionAsync_OverlongModelToken_ReturnsUnsupportedWithZeroHttpCalls()
    {
        var handler = new FakeBiosHttpHandler();
        var provider = AcerBiosUpdateProvider.CreateWithHandler(handler);
        var system = BiosIdentityFactory.Acer(model: new string('A', 100), boardProduct: "TGL_TL");

        var latest = await provider.GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.UnsupportedHardware, latest.Status);
        Assert.Empty(handler.Requests);
    }

    // =========================================================================
    // C8 — HTTP Status Mapping, Network Errors, Timeout & Cancellation
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
        var system = BiosIdentityFactory.Acer();
        handler.MapStatus(BuildDefaultAcerUrl(system.Model), statusCode);

        var latest = await AcerBiosUpdateProvider.CreateWithHandler(handler).GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(expectedStatus, latest.Status);
    }

    [Fact]
    public async Task GetLatestVersionAsync_NetworkTimeoutAndCancellation()
    {
        var system = BiosIdentityFactory.Acer();
        var url = BuildDefaultAcerUrl(system.Model);

        var netHandler = new FakeBiosHttpHandler();
        netHandler.MapException(url, () => new HttpRequestException("Network error", new SocketException((int)SocketError.NetworkUnreachable)));
        var netResult = await AcerBiosUpdateProvider.CreateWithHandler(netHandler).GetLatestVersionAsync(system, system.CurrentBios);
        Assert.Equal(BiosCheckStatus.Offline, netResult.Status);

        var timeoutHandler = new FakeBiosHttpHandler();
        timeoutHandler.MapException(url, () => new TaskCanceledException("Timed out", new TimeoutException()));
        var timeoutResult = await AcerBiosUpdateProvider.CreateWithHandler(timeoutHandler).GetLatestVersionAsync(system, system.CurrentBios);
        Assert.Equal(BiosCheckStatus.Offline, timeoutResult.Status);

        using var preCts = new CancellationTokenSource();
        preCts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => AcerBiosUpdateProvider.CreateWithHandler(new FakeBiosHttpHandler()).GetLatestVersionAsync(system, system.CurrentBios, preCts.Token));

        using var midCts = new CancellationTokenSource();
        var midHandler = new FakeBiosHttpHandler();
        midHandler.Map(url, (_, ct) =>
        {
            midCts.Cancel();
            ct.ThrowIfCancellationRequested();
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        });
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => AcerBiosUpdateProvider.CreateWithHandler(midHandler).GetLatestVersionAsync(system, system.CurrentBios, midCts.Token));
    }

    // =========================================================================
    // C9 — Redirects, Oversized Payload & Malformed/Degenerate JSON
    // =========================================================================

    [Fact]
    public async Task GetLatestVersionAsync_AllowedSameDomainRedirect_Succeeds()
    {
        var handler = new FakeBiosHttpHandler();
        var system = BiosIdentityFactory.Acer();
        var initialUrl = BuildDefaultAcerUrl(system.Model);
        var redirectedUrl = "https://global-download.acer.com/api/bios-v2.json";

        handler.MapRedirect(initialUrl, redirectedUrl, HttpStatusCode.Redirect);
        handler.MapJson(redirectedUrl, BuildSingleAcerCatalog("V1.14", "2024-06-12"));

        var latest = await AcerBiosUpdateProvider.CreateWithHandler(handler).GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal("1.14", latest.LatestVersion);
        Assert.Equal(2, handler.Requests.Count);
    }

    [Theory]
    [InlineData("https://evil.com/bios.json")]
    [InlineData("http://www.acer.com/bios.json")]
    [InlineData("//evil.com/bios.json")]
    [InlineData(null)]
    public async Task GetLatestVersionAsync_UnsafeRedirect_ReturnsFailed(string? targetLocation)
    {
        var handler = new FakeBiosHttpHandler();
        var system = BiosIdentityFactory.Acer();
        handler.MapRedirect(BuildDefaultAcerUrl(system.Model), targetLocation, HttpStatusCode.Redirect);

        var latest = await AcerBiosUpdateProvider.CreateWithHandler(handler).GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.Failed, latest.Status);
        Assert.Single(handler.Requests);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task GetLatestVersionAsync_OversizedPayload_ContentLengthAndChunked_ReturnsFailed(bool includeContentLength)
    {
        var handler = new FakeBiosHttpHandler();
        var system = BiosIdentityFactory.Acer();
        var oversized = new byte[AcerBiosUpdateProvider.MaxCatalogJsonBytes + 1024];
        Array.Fill(oversized, (byte)' ');
        oversized[0] = (byte)'[';
        oversized[^1] = (byte)']';

        handler.MapBytes(BuildDefaultAcerUrl(system.Model), oversized, includeContentLength: includeContentLength);

        var latest = await AcerBiosUpdateProvider.CreateWithHandler(handler).GetLatestVersionAsync(system, system.CurrentBios);

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
    [InlineData("{\"bios\":[]}", BiosCheckStatus.UnsupportedHardware)]
    [InlineData("{\"data\":null}", BiosCheckStatus.UnsupportedHardware)]
    public async Task GetLatestVersionAsync_MalformedOrDegenerateJson_ReturnsExpectedStatus(
        string body,
        BiosCheckStatus expectedStatus)
    {
        var handler = new FakeBiosHttpHandler();
        var system = BiosIdentityFactory.Acer();
        handler.MapText(BuildDefaultAcerUrl(system.Model), body, "application/json");

        var latest = await AcerBiosUpdateProvider.CreateWithHandler(handler).GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(expectedStatus, latest.Status);
    }

    // =========================================================================
    // C10 — URL Security, Traversal & SerialNumber Redaction
    // =========================================================================

    [Theory]
    [InlineData("http://global-download.acer.com/bios.zip")]
    [InlineData("https://evil.com/bios.zip")]
    [InlineData("https://acer.com.evil.com/bios.zip")]
    [InlineData("https://racer.com/bios.zip")]
    [InlineData("https://acer.com@evil.com/bios.zip")]
    [InlineData("file:///C:/bios.zip")]
    [InlineData("//global-download.acer.com/bios.zip")]
    [InlineData("https://global-download.acer.com/%2e%2e/evil.zip")]
    [InlineData("https://global-download.acer.com/%252e%252e/evil.zip")]
    [InlineData("https://global-download.acer.com/bios%00.zip")]
    public async Task GetLatestVersionAsync_UntrustedDownloadUrl_ReturnsFailed(string badUrl)
    {
        var handler = new FakeBiosHttpHandler();
        var system = BiosIdentityFactory.Acer();
        var json = JsonSerializer.Serialize(new
        {
            bios = new[]
            {
                new { version = "V1.14", date = "2024-06-12", url = badUrl },
            },
        });
        handler.MapJson(BuildDefaultAcerUrl(system.Model), json);

        var latest = await AcerBiosUpdateProvider.CreateWithHandler(handler).GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.Failed, latest.Status);
        Assert.Null(latest.DownloadUrl);
    }

    [Fact]
    public async Task GetLatestVersionAsync_UntrustedReleaseNotesUrlDropped_AndUnsafeEndpointFailsWithZeroCalls()
    {
        var handler = new FakeBiosHttpHandler();
        var system = BiosIdentityFactory.Acer();
        handler.MapJson(BuildDefaultAcerUrl(system.Model), """
        {
          "bios": [
            {
              "version": "V1.14",
              "date": "2024-06-12",
              "readmeUrl": "https://racer.com/readme.txt",
              "url": "https://global-download.acer.com/GDFiles/BIOS/BIOS/BIOS_Acer_1.14.zip"
            }
          ]
        }
        """);

        var latest = await AcerBiosUpdateProvider.CreateWithHandler(handler).GetLatestVersionAsync(system, system.CurrentBios);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Null(latest.ReleaseNotesUrl);

        var evilHandler = new FakeBiosHttpHandler();
        var badProvider = AcerBiosUpdateProvider.CreateWithHandler(evilHandler, catalogEndpoint: "https://racer.com/api?model={model}");
        var badResult = await badProvider.GetLatestVersionAsync(system, system.CurrentBios);
        Assert.Equal(BiosCheckStatus.Failed, badResult.Status);
        Assert.Empty(evilHandler.Requests);
    }

    [Fact]
    public async Task GetLatestVersionAsync_ErrorAndPayloadContainingSerialNumber_RedactsSecret()
    {
        var handler = new FakeBiosHttpHandler();
        var log = new CapturedLog();
        var system = BiosIdentityFactory.Acer();
        var secret = BiosIdentityFactory.SentinelSerialNumber;

        handler.MapJson(BuildDefaultAcerUrl(system.Model), $$"""
        {
          "bios": [
            {
              "id": "id-{{secret}}",
              "version": "V1.14",
              "description": "Echoed {{secret}} from server",
              "date": "2024-06-12",
              "url": "https://global-download.acer.com/GDFiles/BIOS/BIOS/BIOS_Acer_1.14.zip"
            }
          ]
        }
        """);

        var okResult = await AcerBiosUpdateProvider.CreateWithHandler(handler, log.Logger).GetLatestVersionAsync(system, system.CurrentBios);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, okResult.Status);
        Assert.DoesNotContain(secret, okResult.ReleaseSummary ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(secret, okResult.PackageId ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(secret, okResult.Message ?? "", StringComparison.OrdinalIgnoreCase);
        log.AssertDoesNotContainSecret();

        var errHandler = new FakeBiosHttpHandler();
        errHandler.MapException(BuildDefaultAcerUrl(system.Model), () => new InvalidOperationException($"Failure for {secret}"));
        var errLog = new CapturedLog();
        var errResult = await AcerBiosUpdateProvider.CreateWithHandler(errHandler, errLog.Logger).GetLatestVersionAsync(system, system.CurrentBios);
        Assert.Equal(BiosCheckStatus.Failed, errResult.Status);
        Assert.DoesNotContain(secret, errResult.Message ?? "", StringComparison.OrdinalIgnoreCase);
        errLog.AssertDoesNotContainSecret();
    }

    // =========================================================================
    // C11 — Explicit Check-Only InstallAsync Contract
    // =========================================================================

    [Fact]
    public async Task InstallAsync_ReturnsUnsupported_AndGuardsNullAndCancellation()
    {
        var handler = new FakeBiosHttpHandler();
        var log = new CapturedLog();
        var progress = new SyncProgress<BiosInstallProgress>();
        var provider = AcerBiosUpdateProvider.CreateWithHandler(handler, log.Logger);

        await Assert.ThrowsAsync<ArgumentNullException>(() => provider.InstallAsync(null!));

        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => provider.InstallAsync(CreateAcerInstallRequest(), progress, cts.Token));

        var result = await provider.InstallAsync(CreateAcerInstallRequest(), progress);

        Assert.False(result.Succeeded);
        Assert.Equal(BiosInstallStatus.Unsupported, result.Status);
        Assert.False(result.RequiresReboot);
        Assert.False(result.BitLockerSuspended);
        Assert.Equal("V1.10", result.PreviousVersion);
        Assert.Equal("1.14", result.TargetVersion);
        Assert.Empty(handler.Requests);
        Assert.Empty(progress.Reports);
        log.AssertDoesNotContainSecret();
        Assert.DoesNotContain(BiosIdentityFactory.SentinelSerialNumber, result.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(BiosIdentityFactory.SentinelSerialNumber, result.LogTail ?? "", StringComparison.OrdinalIgnoreCase);
    }

    // =========================================================================
    // C12 — DI Validation & BiosUpdateService Integration
    // =========================================================================

    [Fact]
    public async Task DiRegistration_ValidateOnBuildAndScopes_ResolvesAndIntegratesWithBiosUpdateService()
    {
        var bareServices = new ServiceCollection();
        bareServices.AddBiosUpdates();
        bareServices.AddBiosUpdateProvider<AcerBiosUpdateProvider>();
        await using (var bareSp = bareServices.BuildServiceProvider(
            new ServiceProviderOptions { ValidateOnBuild = true, ValidateScopes = true }))
        {
            var bareSvc = bareSp.GetRequiredService<IBiosUpdateService>();
            Assert.Contains(bareSvc.Providers, p => p.VendorId == "acer");
        }

        var system = BiosIdentityFactory.Acer();
        var handler = new FakeBiosHttpHandler();
        handler.MapJson(BuildDefaultAcerUrl(system.Model), BuildSingleAcerCatalog("V1.14", "2024-06-12"));
        var safetyProbe = new CountingSafetyProbe(BiosIdentityFactory.SafeSnapshot());

        var services = new ServiceCollection();
        services.AddSingleton<IBiosSystemProbe>(new StubSystemProbe(system));
        services.AddSingleton<IBiosInstallSafetyProbe>(safetyProbe);
        services.AddBiosUpdates();
        services.AddBiosUpdateProvider(_ => AcerBiosUpdateProvider.CreateWithHandler(handler));

        await using var sp = services.BuildServiceProvider(
            new ServiceProviderOptions { ValidateOnBuild = true, ValidateScopes = true });
        var service = sp.GetRequiredService<IBiosUpdateService>();

        var resolved = service.ResolveProvider(system);
        Assert.NotNull(resolved);
        Assert.Equal("acer", resolved.VendorId);

        var check = await service.CheckForUpdateAsync();
        Assert.Equal("acer", check.ProviderId);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, check.Latest.Status);
        Assert.Equal("1.14", check.Latest.LatestVersion);

        var installRequest = new BiosInstallRequest(system, check.Current, check.Latest, Approved: true, ApprovedBy: "op");
        var installResult = await service.InstallUpdateAsync(installRequest);

        Assert.False(installResult.Succeeded);
        Assert.Equal(BiosInstallStatus.Unsupported, installResult.Status);
        Assert.Equal(0, safetyProbe.CallCount);
        Assert.Single(handler.Requests);
    }

    // =========================================================================
    // C13 — Iteration 2 Hardening & Regression Tests
    // =========================================================================

    [Theory]
    [InlineData("Aspire 5 WiFi", "1.15")]
    [InlineData("Improve USB / NVMe / Thunderbolt stability", "1.15")]
    [InlineData("Predator LAN Edition", "1.15")]
    public async Task GetLatestVersionAsync_ExplicitBiosCategoryWithPeripheralTitles_AcceptedWhileToolsRejected(
        string biosTitle,
        string expectedVersion)
    {
        var handler = new FakeBiosHttpHandler();
        var model = "Aspire 5";
        var json = JsonSerializer.Serialize(new
        {
            drivers = new[]
            {
                new
                {
                    category = "BIOS",
                    title = "Intel ME Update Tool",
                    version = "9.99",
                    date = "2026-01-01",
                    url = "https://global-download.acer.com/MEUpdateTool.zip",
                },
                new
                {
                    category = "BIOS",
                    title = biosTitle,
                    version = expectedVersion,
                    date = "2024-08-15",
                    url = "https://global-download.acer.com/115.zip",
                },
            },
        });
        handler.MapJson(BuildDefaultAcerUrl(model), json);

        var system = BiosIdentityFactory.Acer(model: model, biosVersion: "1.08");
        var latest = await AcerBiosUpdateProvider.CreateWithHandler(handler).GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal(expectedVersion, latest.LatestVersion);
        Assert.Equal("https://global-download.acer.com/115.zip", latest.DownloadUrl);
    }

    [Fact]
    public async Task GetLatestVersionAsync_BiosSecurityPatchAccepted_AndNonBiosPatchCategoryRejected()
    {
        var model = "Swift SF314-512";
        var system = BiosIdentityFactory.Acer(model: model, biosVersion: "1.08");

        // 1. "BIOS Security Patch 1.15" under category "BIOS" -> UpdateAvailable
        var patchTitleHandler = new FakeBiosHttpHandler();
        patchTitleHandler.MapJson(BuildDefaultAcerUrl(model), """
        {
          "bios": [
            {
              "category": "BIOS",
              "title": "BIOS Security Patch 1.15",
              "version": "1.15",
              "releaseDate": "2024-07-01",
              "downloadUrl": "https://global-download.acer.com/115.zip"
            }
          ]
        }
        """);
        var patchTitleResult = await AcerBiosUpdateProvider.CreateWithHandler(patchTitleHandler)
            .GetLatestVersionAsync(system, system.CurrentBios);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, patchTitleResult.Status);
        Assert.Equal("1.15", patchTitleResult.LatestVersion);

        // 2. Category "BIOS Patch" -> UpdateAvailable
        var biosPatchCatHandler = new FakeBiosHttpHandler();
        biosPatchCatHandler.MapJson(BuildDefaultAcerUrl(model), """
        {
          "drivers": [
            {
              "category": "BIOS Patch",
              "title": "Security Update for CVE-2024-1234",
              "version": "1.16",
              "releaseDate": "2024-08-01",
              "downloadUrl": "https://global-download.acer.com/116.zip"
            }
          ]
        }
        """);
        var biosPatchCatResult = await AcerBiosUpdateProvider.CreateWithHandler(biosPatchCatHandler)
            .GetLatestVersionAsync(system, system.CurrentBios);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, biosPatchCatResult.Status);
        Assert.Equal("1.16", biosPatchCatResult.LatestVersion);

        // 3. Non-BIOS category "Patch" with non-BIOS title -> UnsupportedHardware
        var nonBiosPatchHandler = new FakeBiosHttpHandler();
        nonBiosPatchHandler.MapJson(BuildDefaultAcerUrl(model), """
        {
          "drivers": [
            {
              "category": "Patch",
              "title": "Touchpad Hotfix",
              "version": "2.00",
              "releaseDate": "2025-01-01",
              "downloadUrl": "https://global-download.acer.com/patch.zip"
            }
          ]
        }
        """);
        var nonBiosPatchResult = await AcerBiosUpdateProvider.CreateWithHandler(nonBiosPatchHandler)
            .GetLatestVersionAsync(system, system.CurrentBios);
        Assert.Equal(BiosCheckStatus.UnsupportedHardware, nonBiosPatchResult.Status);
    }

    [Fact]
    public async Task GetLatestVersionAsync_SerialNumberInVersionUrlsUntrustedLogAndModelException_CompletelyRedacted()
    {
        const string secret = "SN-SECRET-998877";

        // 1. Echoed serial in Version, DownloadUrl, and ReleaseNotesUrl
        var echoHandler = new FakeBiosHttpHandler();
        var echoLog = new CapturedLog();
        var system = BiosIdentityFactory.Acer(model: "Swift SF314-512", biosVersion: "1.08") with
        {
            SerialNumber = secret,
        };
        echoHandler.MapJson(BuildDefaultAcerUrl(system.Model), $$"""
        {
          "bios": [
            {
              "version": "1.14-{{secret}}",
              "date": "2025-05-01",
              "readmeUrl": "https://www.acer.com/support/{{secret}}/notes",
              "downloadUrl": "https://global-download.acer.com/{{secret}}/114.zip"
            }
          ]
        }
        """);

        var echoResult = await AcerBiosUpdateProvider.CreateWithHandler(echoHandler, echoLog.Logger)
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
        untrustedHandler.MapJson(BuildDefaultAcerUrl(system.Model), $$"""
        {
          "bios": [
            {
              "version": "9.99-{{secret}}",
              "date": "2025-05-01",
              "downloadUrl": "http://evil.com/x.zip"
            }
          ]
        }
        """);

        var untrustedResult = await AcerBiosUpdateProvider.CreateWithHandler(untrustedHandler, untrustedLog.Logger)
            .GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.Failed, untrustedResult.Status);
        untrustedLog.AssertDoesNotContainSecret(secret);

        // 3. Model equals secret and request throws -> warning log must redact modelToken AND exception message
        var errHandler = new FakeBiosHttpHandler();
        var errLog = new CapturedLog();
        var secretModelSystem = BiosIdentityFactory.Acer(model: secret, boardProduct: "Default string", biosVersion: "1.08") with
        {
            SerialNumber = secret,
        };
        errHandler.MapException(BuildDefaultAcerUrl(secret), () => new HttpRequestException($"boom for {secret}"));

        var errResult = await AcerBiosUpdateProvider.CreateWithHandler(errHandler, errLog.Logger)
            .GetLatestVersionAsync(secretModelSystem, secretModelSystem.CurrentBios);

        Assert.Equal(BiosCheckStatus.Offline, errResult.Status);
        Assert.DoesNotContain(secret, errResult.Message ?? "", StringComparison.OrdinalIgnoreCase);
        errLog.AssertDoesNotContainSecret(secret);
    }

    [Theory]
    [InlineData("https://global-download.acer.com/api/%2e%2e/secret.json")]
    [InlineData("/pub/%2e%2e/evil.json")]
    [InlineData("/pub/../evil.json")]
    public async Task GetLatestVersionAsync_SameDomainRedirectWithPathTraversal_FailsClosedWithSingleHttpCall(
        string unsafeLocation)
    {
        var handler = new FakeBiosHttpHandler();
        var system = BiosIdentityFactory.Acer();
        handler.MapRedirect(BuildDefaultAcerUrl(system.Model), unsafeLocation, HttpStatusCode.Redirect);
        handler.MapJson("https://global-download.acer.com/secret.json", BuildSingleAcerCatalog("V1.14", "2025-01-01"));
        handler.MapJson("https://www.acer.com/evil.json", BuildSingleAcerCatalog("V1.14", "2025-01-01"));

        var latest = await AcerBiosUpdateProvider.CreateWithHandler(handler)
            .GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.Failed, latest.Status);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task GetLatestVersionAsync_OrderCandidates_PrefersValidDownloadUrlAndBreaksUrlCaseAndShaTiesDeterministically()
    {
        var system = BiosIdentityFactory.Acer(model: "Swift SF314-512", biosVersion: "1.08");

        // 1. Valid DownloadUrl beats null DownloadUrl on identical version/date regardless of order
        foreach (var reversed in new[] { false, true })
        {
            var items = new object[]
            {
                new { title = "BIOS 1.15", version = "1.15", date = "2024-06-01", downloadUrl = (string?)null },
                new { title = "BIOS 1.15", version = "1.15", date = "2024-06-01", downloadUrl = "https://global-download.acer.com/115.zip" },
            };
            if (reversed)
                Array.Reverse(items);

            var handler = new FakeBiosHttpHandler();
            handler.MapJson(BuildDefaultAcerUrl(system.Model), JsonSerializer.Serialize(new { bios = items }));
            var result = await AcerBiosUpdateProvider.CreateWithHandler(handler).GetLatestVersionAsync(system, system.CurrentBios);

            Assert.Equal(BiosCheckStatus.UpdateAvailable, result.Status);
            Assert.Equal("https://global-download.acer.com/115.zip", result.DownloadUrl);
        }

        // 2. Identical version/date/packageId with URL casing tie & distinct SHA-256 -> identical winner across permutations
        var shaA = new string('a', 64);
        var shaB = new string('b', 64);
        var tieEntries = new[]
        {
            new { version = "9.99", date = "2025-05-01", url = "https://global-download.acer.com/UPPER.zip", sha256 = shaA },
            new { version = "9.99", date = "2025-05-01", url = "https://global-download.acer.com/upper.zip", sha256 = shaB },
            new { version = "9.99", date = "2025-05-01", url = "https://global-download.acer.com/UPPER.zip", sha256 = shaB },
        };

        BiosLatestInfo? baseline = null;
        foreach (var mode in new[] { 0, 1, 7, 42, 99 })
        {
            var permuted = Permute(tieEntries, mode);
            var handler = new FakeBiosHttpHandler();
            handler.MapJson(BuildDefaultAcerUrl(system.Model), JsonSerializer.Serialize(new { bios = permuted }));
            var result = await AcerBiosUpdateProvider.CreateWithHandler(handler).GetLatestVersionAsync(system, system.CurrentBios);

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
        var system = BiosIdentityFactory.Acer(model: "Swift SF314-512", biosVersion: "1.08");
        handler.MapJson(BuildDefaultAcerUrl(system.Model), JsonSerializer.Serialize(new
        {
            bios = new[]
            {
                new
                {
                    version = "1.15",
                    date = "2024-08-15",
                    fileSize,
                    downloadUrl = "https://global-download.acer.com/115.zip",
                },
            },
        }));

        var latest = await AcerBiosUpdateProvider.CreateWithHandler(handler).GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal(expectedBytes, latest.SizeBytes);
    }

    [Fact]
    public async Task GetLatestVersionAsync_MixedTrustedAndUntrustedCatalogs_SymmetricFailClosedAndArchivedUpToDate()
    {
        var model = "Swift SF314-512";

        // 1. Older trusted (1.10) + newer untrusted (9.99) -> Failed, null DownloadUrl
        var newerBadHandler = new FakeBiosHttpHandler();
        newerBadHandler.MapJson(BuildDefaultAcerUrl(model), """
        {
          "bios": [
            { "version": "1.10", "date": "2023-01-01", "url": "https://global-download.acer.com/110.zip" },
            { "version": "9.99", "date": "2025-05-01", "url": "http://evil.com/999.zip" }
          ]
        }
        """);
        var sysOld = BiosIdentityFactory.Acer(model: model, biosVersion: "1.08");
        var newerBadResult = await AcerBiosUpdateProvider.CreateWithHandler(newerBadHandler)
            .GetLatestVersionAsync(sysOld, sysOld.CurrentBios);
        Assert.Equal(BiosCheckStatus.Failed, newerBadResult.Status);
        Assert.Null(newerBadResult.DownloadUrl);

        // 2. Newer trusted (1.15, matching current) + strictly older archived untrusted (1.08) -> UpToDate
        var archivedBadHandler = new FakeBiosHttpHandler();
        archivedBadHandler.MapJson(BuildDefaultAcerUrl(model), """
        {
          "bios": [
            { "version": "1.15", "date": "2025-01-01", "url": "https://global-download.acer.com/115.zip" },
            { "version": "1.08", "date": "2023-01-01", "url": "http://global-download.acer.com/108.zip" }
          ]
        }
        """);
        var sysCurrent = BiosIdentityFactory.Acer(model: model, biosVersion: "1.15");
        var archivedResult = await AcerBiosUpdateProvider.CreateWithHandler(archivedBadHandler)
            .GetLatestVersionAsync(sysCurrent, sysCurrent.CurrentBios);
        Assert.Equal(BiosCheckStatus.UpToDate, archivedResult.Status);
        Assert.Equal("1.15", archivedResult.LatestVersion);

        // 3. Equal-version untrusted (1.15) alongside trusted (1.15) when up to date -> Failed
        var equalBadHandler = new FakeBiosHttpHandler();
        equalBadHandler.MapJson(BuildDefaultAcerUrl(model), """
        {
          "bios": [
            { "version": "1.15", "date": "2025-01-01", "url": "https://global-download.acer.com/115.zip" },
            { "version": "1.15", "date": "2025-01-01", "url": "http://evil.com/115.zip" }
          ]
        }
        """);
        var equalBadResult = await AcerBiosUpdateProvider.CreateWithHandler(equalBadHandler)
            .GetLatestVersionAsync(sysCurrent, sysCurrent.CurrentBios);
        Assert.Equal(BiosCheckStatus.Failed, equalBadResult.Status);
    }

    [Fact]
    public async Task GetLatestVersionAsync_NullAliasFallthroughAndWrongKindDownloadUrl()
    {
        var model = "Swift SF314-512";
        var system = BiosIdentityFactory.Acer(model: model, biosVersion: "1.08");

        // 1. Null-valued alias falls through to secondary alias
        var aliasHandler = new FakeBiosHttpHandler();
        aliasHandler.MapJson(BuildDefaultAcerUrl(model), """
        {
          "bios": [
            {
              "version": null,
              "biosVersion": "1.15",
              "date": "2024-08-15",
              "downloadUrl": null,
              "url": "https://global-download.acer.com/115.zip"
            }
          ]
        }
        """);
        var aliasResult = await AcerBiosUpdateProvider.CreateWithHandler(aliasHandler)
            .GetLatestVersionAsync(system, system.CurrentBios);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, aliasResult.Status);
        Assert.Equal("1.15", aliasResult.LatestVersion);
        Assert.Equal("https://global-download.acer.com/115.zip", aliasResult.DownloadUrl);

        // 2. Non-null wrong JsonValueKind on downloadUrl -> Failed
        foreach (var badJson in new[]
        {
            """{"bios":[{"version":"1.15","date":"2024-08-15","downloadUrl":12345}]}""",
            """{"bios":[{"version":"1.15","date":"2024-08-15","downloadUrl":true}]}""",
            """{"bios":[{"version":"1.15","date":"2024-08-15","downloadUrl":[]}]}""",
        })
        {
            var wrongKindHandler = new FakeBiosHttpHandler();
            wrongKindHandler.MapJson(BuildDefaultAcerUrl(model), badJson);
            var wrongResult = await AcerBiosUpdateProvider.CreateWithHandler(wrongKindHandler)
                .GetLatestVersionAsync(system, system.CurrentBios);
            Assert.Equal(BiosCheckStatus.Failed, wrongResult.Status);
            Assert.Null(wrongResult.DownloadUrl);
        }
    }

    [Fact]
    public async Task GetLatestVersionAsync_CustomPathPlaceholderEndpoint_RejectsSlashInModelTokenWithZeroCalls()
    {
        const string endpoint = "https://www.acer.com/api/{model}/bios.json";
        var handler = new FakeBiosHttpHandler();
        var provider = AcerBiosUpdateProvider.CreateWithHandler(handler, catalogEndpoint: endpoint);

        var slashSystem = BiosIdentityFactory.Acer(model: "Swift/SF314", boardProduct: "Swift/SF314", biosVersion: "1.08");
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
    [InlineData("http:www.acer.com")]
    [InlineData("javascript:alert(1)")]
    [InlineData("file:foo")]
    public async Task GetLatestVersionAsync_SameSchemeRelativeOrNonHttpsColonRedirect_FailsClosedWithSingleHttpCall(
        string unsafeLocation)
    {
        var handler = new FakeBiosHttpHandler();
        var system = BiosIdentityFactory.Acer();
        handler.MapRedirect(BuildDefaultAcerUrl(system.Model), unsafeLocation, HttpStatusCode.Redirect);
        handler.MapPredicate(_ => true, (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(BuildSingleAcerCatalog("V1.14", "2025-01-01"), System.Text.Encoding.UTF8, "application/json"),
        }));

        var latest = await AcerBiosUpdateProvider.CreateWithHandler(handler)
            .GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.Failed, latest.Status);
        Assert.Single(handler.Requests);
    }

    [Theory]
    [InlineData("https://www.acer.com/safe.json", "https://evil.com/pwn.json")]
    [InlineData("https://www.acer.com/safe.json", "/pub/%2e%2e/secret.json")]
    [InlineData("https://www.acer.com/safe.json", "https://www.acer.com/safe2.json")]
    public async Task GetLatestVersionAsync_MultipleLocationHeaders_FailsClosedWithSingleHttpCall(
        string firstLocation,
        string secondLocation)
    {
        var handler = new FakeBiosHttpHandler();
        var system = BiosIdentityFactory.Acer();
        handler.Map(BuildDefaultAcerUrl(system.Model), (_, _) =>
        {
            var msg = new HttpResponseMessage(HttpStatusCode.Redirect);
            msg.Headers.TryAddWithoutValidation("Location", firstLocation);
            msg.Headers.TryAddWithoutValidation("Location", secondLocation);
            return Task.FromResult(msg);
        });
        handler.MapJson("https://www.acer.com/safe.json", BuildSingleAcerCatalog("V1.14", "2025-01-01"));
        handler.MapJson("https://www.acer.com/safe2.json", BuildSingleAcerCatalog("V1.14", "2025-01-01"));

        var latest = await AcerBiosUpdateProvider.CreateWithHandler(handler)
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
        const string modelWithSerial = "Aspire 5 SN 4242";
        var errHandler = new FakeBiosHttpHandler();
        var errLog = new CapturedLog();
        var errSystem = BiosIdentityFactory.Acer(model: modelWithSerial, boardProduct: "Default string", biosVersion: "1.08") with
        {
            SerialNumber = spaceSecret,
        };
        errHandler.Map(BuildDefaultAcerUrl(modelWithSerial), (req, _) =>
            Task.FromException<HttpResponseMessage>(new HttpRequestException($"Connection refused to {req.RequestUri!.AbsoluteUri}")));

        var errResult = await AcerBiosUpdateProvider.CreateWithHandler(errHandler, errLog.Logger)
            .GetLatestVersionAsync(errSystem, errSystem.CurrentBios);

        Assert.Equal(BiosCheckStatus.Offline, errResult.Status);
        Assert.DoesNotContain(spaceSecret, errResult.Message ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(escapedSpaceSecret, errResult.Message ?? "", StringComparison.OrdinalIgnoreCase);
        errLog.AssertDoesNotContainSecret(spaceSecret);
        errLog.AssertDoesNotContainSecret(escapedSpaceSecret);

        // 2. Catalog JSON echoes escaped & form-encoded serial in Version, Description, PackageId
        var echoHandler = new FakeBiosHttpHandler();
        var echoLog = new CapturedLog();
        var echoSystem = BiosIdentityFactory.Acer(model: "Swift SF314-512", biosVersion: "1.08") with
        {
            SerialNumber = spaceSecret,
        };
        echoHandler.MapJson(BuildDefaultAcerUrl(echoSystem.Model), """
        {
          "bios": [
            {
              "id": "PKG-SN%204242",
              "version": "1.15-SN%204242",
              "description": "Firmware update for SN%204242 and SN+4242",
              "date": "2025-05-01",
              "downloadUrl": "https://global-download.acer.com/115.zip"
            }
          ]
        }
        """);

        var echoResult = await AcerBiosUpdateProvider.CreateWithHandler(echoHandler, echoLog.Logger)
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
            ("SN:9988 77", "https://global-download.acer.com/115.zip?sn=SN:9988%2077", "https://www.acer.com/support/notes?sn=SN:9988%2077"),
            ("SN/4242 99", "https://global-download.acer.com/SN/4242%2099/115.zip", "https://www.acer.com/support/SN/4242%2099/notes"),
        })
        {
            var urlHandler = new FakeBiosHttpHandler();
            var urlSystem = BiosIdentityFactory.Acer(model: "Swift SF314-512", biosVersion: "1.08") with
            {
                SerialNumber = mixedSerial,
            };
            urlHandler.MapJson(BuildDefaultAcerUrl(urlSystem.Model), JsonSerializer.Serialize(new
            {
                bios = new[]
                {
                    new
                    {
                        version = "1.15",
                        date = "2025-05-01",
                        downloadUrl = dlUrl,
                        readmeUrl = notesUrl,
                    },
                },
            }));

            var urlResult = await AcerBiosUpdateProvider.CreateWithHandler(urlHandler)
                .GetLatestVersionAsync(urlSystem, urlSystem.CurrentBios);

            Assert.Equal(BiosCheckStatus.UpdateAvailable, urlResult.Status);
            Assert.Null(urlResult.DownloadUrl);
            Assert.Null(urlResult.ReleaseNotesUrl);
        }

        // 4. GetCurrentVersionAsync and InstallAsync redact URI-escaped serials too
        var provider = AcerBiosUpdateProvider.CreateWithHandler(new FakeBiosHttpHandler());
        var curSystem = BiosIdentityFactory.Acer(model: "Swift SF314-512", biosVersion: $"1.08-{escapedSpaceSecret}") with
        {
            SerialNumber = spaceSecret,
        };
        var cur = await provider.GetCurrentVersionAsync(curSystem);
        Assert.DoesNotContain(escapedSpaceSecret, cur.Version, StringComparison.OrdinalIgnoreCase);

        var installReq = CreateAcerInstallRequest(curSystem, targetVersion: $"1.15-{escapedSpaceSecret}");
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
        var system = BiosIdentityFactory.Acer(model: "Swift SF314-512", biosVersion: "1.08");
        handler.MapJson(BuildDefaultAcerUrl(system.Model), JsonSerializer.Serialize(new
        {
            bios = new[]
            {
                new
                {
                    version = "1.15",
                    date = "2024-08-15",
                    fileSize,
                    downloadUrl = "https://global-download.acer.com/115.zip",
                },
            },
        }));

        var latest = await AcerBiosUpdateProvider.CreateWithHandler(handler)
            .GetLatestVersionAsync(system, system.CurrentBios);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal(expectedBytes, latest.SizeBytes);
    }

    // =========================================================================
    // Local Test Helpers
    // =========================================================================

    private static string BuildDefaultAcerUrl(string model) =>
        AcerBiosUpdateProvider.DefaultCatalogEndpoint.Replace("{model}", Uri.EscapeDataString(model), StringComparison.OrdinalIgnoreCase);

    private static string BuildSingleAcerCatalog(string version, string releaseDate) =>
        JsonSerializer.Serialize(new
        {
            bios = new[]
            {
                new
                {
                    version,
                    date = releaseDate,
                    url = "https://global-download.acer.com/GDFiles/BIOS/BIOS/BIOS_Acer.zip",
                },
            },
        });

    private static BiosInstallRequest CreateAcerInstallRequest(
        BiosSystemIdentity? system = null,
        string targetVersion = "1.14")
    {
        var id = system ?? BiosIdentityFactory.Acer();
        var target = BiosLatestInfo.UpdateAvailable(
            providerId: "acer",
            latestVersion: targetVersion,
            downloadUrl: "https://global-download.acer.com/GDFiles/BIOS/BIOS/BIOS_Acer_1.14.zip",
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
