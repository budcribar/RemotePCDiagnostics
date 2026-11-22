using System.Net;
using System.Text;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Bios;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;
using Xunit;

namespace RemotePCDiagnostics.Tests.Bios;

public sealed class MicrosoftSurfaceBiosUpdateProviderTests
{
    private const string SampleMsiUrl =
        "https://download.microsoft.com/download/surface/SurfaceLaptop5_Win11_22621_24.051.12345.0.msi";

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
        var pipeName = $"rpd-bios-surface-{Guid.NewGuid():N}";
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

    private static BiosInstallRequest CreateSurfaceInstallRequest(
        BiosSystemIdentity? system = null,
        string? downloadUrl = SampleMsiUrl,
        string? sha256 = null,
        string targetVersion = "18.101.143",
        bool suspendBitLocker = true,
        bool allowReboot = false,
        bool verifyHash = true,
        string? stagingDirectory = null,
        string? packageId = "SurfaceLaptop5_Win11_24.051")
    {
        var id = system ?? BiosIdentityFactory.MicrosoftSurface();
        var target = BiosLatestInfo.UpdateAvailable(
            providerId: MicrosoftSurfaceBiosUpdateProvider.ProviderVendorId,
            latestVersion: targetVersion,
            packageId: packageId,
            downloadUrl: downloadUrl,
            sha256: sha256);

        return new BiosInstallRequest(
            System: id,
            Current: id.CurrentBios,
            Target: target,
            Approved: true,
            ApprovedBy: "operator@contoso.com",
            SuspendBitLocker: suspendBitLocker,
            AllowReboot: allowReboot,
            VerifyHash: verifyHash,
            StagingDirectory: stagingDirectory);
    }

    // -------------------------------------------------------------------------
    // Metadata, Capabilities & CanHandle
    // -------------------------------------------------------------------------

    [Fact]
    public void Metadata_And_Capabilities_Match_Contract()
    {
        var provider = new MicrosoftSurfaceBiosUpdateProvider();

        Assert.Equal("microsoft", provider.VendorId);
        Assert.Equal("Microsoft Surface", provider.DisplayName);
        Assert.Equal(100, provider.Priority);
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
        var ctors = typeof(MicrosoftSurfaceBiosUpdateProvider).GetConstructors();
        Assert.Single(ctors);
        Assert.All(ctors[0].GetParameters(), p => Assert.True(p.HasDefaultValue));
    }

    [Theory]
    [InlineData("Microsoft Corporation", "Surface Pro 9", "Microsoft Corporation", "Surface Pro 9", true)]
    [InlineData("Microsoft Corporation", "Surface Laptop 5", "Microsoft Corporation", "Surface Laptop 5", true)]
    [InlineData("Microsoft Corporation", "Surface Studio 2+", "Microsoft Corporation", "Surface Studio 2+", true)]
    [InlineData("Microsoft Corporation", "Surface Go 4", "Microsoft Corporation", "Surface Go 4", true)]
    [InlineData("Microsoft Corporation", "To Be Filled By O.E.M.", "Microsoft Corporation", "Surface Laptop Studio 2", true)]
    [InlineData("Microsoft Corporation", "Virtual Machine", "Microsoft Corporation", "Virtual Machine", false)]
    [InlineData("Microsoft Corporation", "Surface Virtual Machine", "Microsoft Corporation", "Surface Virtual Machine", false)]
    [InlineData("Microsoft Corporation", "Xbox Series X", "Microsoft Corporation", "Xbox", false)]
    [InlineData("Contoso", "Surface Clone 9", "Contoso", "Surface Clone 9", false)]
    [InlineData("Dell Inc.", "Latitude 7430", "Dell Inc.", "0ABCDE", false)]
    [InlineData("HP", "EliteBook 840 G8", "HP", "880D", false)]
    [InlineData("", "", "", "", false)]
    public void CanHandle_Matches_Surface_And_Excludes_HyperV_And_OtherVendors(
        string manufacturer,
        string model,
        string boardManufacturer,
        string boardProduct,
        bool expected)
    {
        var provider = new MicrosoftSurfaceBiosUpdateProvider();
        var id = BiosIdentityFactory.MicrosoftSurface(model: model, boardProduct: boardProduct) with
        {
            Manufacturer = manufacturer,
            BoardManufacturer = boardManufacturer,
        };

        Assert.Equal(expected, provider.CanHandle(id));
    }

    [Fact]
    public void CanHandle_Null_And_HyperVVmFactory_ReturnFalse()
    {
        var provider = new MicrosoftSurfaceBiosUpdateProvider();
        Assert.False(provider.CanHandle(null!));
        Assert.False(provider.CanHandle(BiosIdentityFactory.HyperVVm()));
        Assert.False(provider.CanHandle(BiosIdentityFactory.Unknown()));
    }

    // -------------------------------------------------------------------------
    // GetCurrentVersionAsync
    // -------------------------------------------------------------------------

    [Theory]
    [InlineData("18.101.143", "18.101.143")]
    [InlineData("235.3732.768.0", "235.3732.768.0")]
    [InlineData("Surface UEFI 18.101.143", "18.101.143")]
    [InlineData("UEFI 235.3732.768.0", "235.3732.768.0")]
    [InlineData("BIOS Version 18.101.143 (08/20/2023)", "18.101.143")]
    [InlineData("v11.101.143", "11.101.143")]
    public async Task GetCurrentVersionAsync_Normalizes_SurfaceVersions_And_PopulatesMetadata(string rawVersion, string expected)
    {
        var provider = new MicrosoftSurfaceBiosUpdateProvider();
        var sys = BiosIdentityFactory.MicrosoftSurface(
            model: "Surface Pro 9",
            biosVersion: rawVersion);

        var info = await provider.GetCurrentVersionAsync(sys);

        Assert.Equal("microsoft", info.ProviderId);
        Assert.Equal(expected, info.Version);
        Assert.NotNull(info.Metadata);
        Assert.Equal("Surface Pro 9", info.Metadata!["model"]);
        Assert.Equal("win11", info.Metadata["os"]);
        if (!string.Equals(rawVersion.Trim(), expected, StringComparison.Ordinal))
            Assert.Equal(rawVersion.Trim(), info.Metadata["rawVersion"]);
    }

    [Fact]
    public async Task GetCurrentVersionAsync_Redacts_SerialNumber()
    {
        var provider = new MicrosoftSurfaceBiosUpdateProvider();
        var sys = BiosIdentityFactory.MicrosoftSurface(
            biosVersion: $"18.101.143 {BiosIdentityFactory.SentinelSerialNumber}");
        sys = sys with
        {
            CurrentBios = sys.CurrentBios with
            {
                Family = $"Family-{BiosIdentityFactory.SentinelSerialNumber}",
                Metadata = new Dictionary<string, string>
                {
                    ["note"] = $"SN={BiosIdentityFactory.SentinelSerialNumber}",
                },
            },
        };

        var info = await provider.GetCurrentVersionAsync(sys);

        Assert.DoesNotContain(BiosIdentityFactory.SentinelSerialNumber, info.Version, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(BiosIdentityFactory.SentinelSerialNumber, info.Family ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(BiosIdentityFactory.SentinelSerialNumber, info.Metadata?["note"] ?? "", StringComparison.OrdinalIgnoreCase);
    }

    // -------------------------------------------------------------------------
    // GetLatestVersionAsync — JSON & XML schemas, filtering, SWO, security
    // -------------------------------------------------------------------------

    [Fact]
    public async Task GetLatestVersionAsync_JsonCatalog_DriversAndFirmware_UpdateAvailable()
    {
        var sha = TestPayload.FromString("surface-msi-content").Sha256;
        var handler = new FakeBiosHttpHandler();
        handler.MapPrefix(
            "https://www.microsoft.com/surface/api/firmware",
            (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent($$"""
                {
                  "releases": [
                    {
                      "title": "Surface Laptop 5 Drivers and Firmware",
                      "category": "Drivers and Firmware",
                      "model": "Surface Laptop 5",
                      "os": "Windows 11",
                      "architecture": "x64",
                      "uefiVersion": "18.101.143",
                      "releaseDate": "2024-05-15",
                      "severity": "Critical",
                      "packageId": "104680",
                      "downloadUrl": "{{SampleMsiUrl}}",
                      "sha256": "{{sha.ToUpperInvariant()}}",
                      "sizeBytes": 566231040,
                      "description": "Addresses CVE-2024-1234 UEFI security fix."
                    }
                  ]
                }
                """, Encoding.UTF8, "application/json"),
            }));

        var log = new CapturedLog();
        var provider = MicrosoftSurfaceBiosUpdateProvider.CreateWithHandler(handler, log: log.Logger);
        var sys = BiosIdentityFactory.MicrosoftSurface(biosVersion: "11.101.143");

        var latest = await provider.GetLatestVersionAsync(sys, sys.CurrentBios);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal("microsoft", latest.ProviderId);
        Assert.Equal("18.101.143", latest.LatestVersion);
        Assert.Equal(new DateOnly(2024, 5, 15), latest.ReleaseDate);
        Assert.Equal(BiosUpdateSeverity.Critical, latest.Severity);
        Assert.Equal(SampleMsiUrl, latest.DownloadUrl);
        Assert.Equal(sha, latest.Sha256);
        Assert.Equal(566231040, latest.SizeBytes);
        Assert.True(latest.RequiresReboot);
        Assert.Equal(BiosAgentInstallModes.MicrosoftSurfaceMsi, latest.Metadata?["installMode"]);
        log.AssertDoesNotContainSecret();
    }

    [Fact]
    public async Task GetLatestVersionAsync_XmlCatalog_WithBom_UpdateAvailable()
    {
        var sha = TestPayload.FromString("surface-xml-msi").Sha256;
        var xml = $"""
            <?xml version="1.0" encoding="utf-8"?>
            <SurfaceCatalog>
              <Release version="235.3732.768.0" releaseDate="2024-06-01" os="Win11" model="Surface Pro 9">
                <Title>Surface Pro 9 Drivers and Firmware</Title>
                <DownloadUrl>{SampleMsiUrl}</DownloadUrl>
                <Sha256>{sha}</Sha256>
                <Size>512 MB</Size>
                <Severity>Recommended</Severity>
              </Release>
            </SurfaceCatalog>
            """;
        var withBom = new byte[] { 0xEF, 0xBB, 0xBF }.Concat(Encoding.UTF8.GetBytes(xml)).ToArray();

        var handler = new FakeBiosHttpHandler();
        handler.MapPrefix(
            "https://www.microsoft.com/surface/api/firmware",
            (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(withBom),
            }));

        var provider = MicrosoftSurfaceBiosUpdateProvider.CreateWithHandler(handler);
        var sys = BiosIdentityFactory.MicrosoftSurface(model: "Surface Pro 9", boardProduct: "Surface Pro 9", biosVersion: "235.3700.768.0");

        var latest = await provider.GetLatestVersionAsync(sys, sys.CurrentBios);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal("235.3732.768.0", latest.LatestVersion);
        Assert.Equal(sha, latest.Sha256);
        Assert.Equal(512L * 1024 * 1024, latest.SizeBytes);
    }

    [Theory]
    [InlineData("18.101.143", "18.101.143.0")] // 3-part vs 4-part zero-padded equality
    [InlineData("18.101.143.0", "18.101.143")]
    [InlineData("19.100.0", "18.101.143")] // Downgrade protection
    public async Task GetLatestVersionAsync_EqualOrNewerCurrent_ReturnsUpToDate(string currentVer, string catalogVer)
    {
        var handler = new FakeBiosHttpHandler();
        handler.MapPrefix(
            "https://www.microsoft.com/surface/api/firmware",
            (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent($$"""
                [
                  {
                    "title": "Surface Laptop 5 Drivers and Firmware",
                    "uefiVersion": "{{catalogVer}}",
                    "releaseDate": "2024-05-15",
                    "downloadUrl": "{{SampleMsiUrl}}"
                  }
                ]
                """, Encoding.UTF8, "application/json"),
            }));

        var provider = MicrosoftSurfaceBiosUpdateProvider.CreateWithHandler(handler);
        var sys = BiosIdentityFactory.MicrosoftSurface(biosVersion: currentVer);

        var latest = await provider.GetLatestVersionAsync(sys, sys.CurrentBios);

        Assert.Equal(BiosCheckStatus.UpToDate, latest.Status);
        Assert.Null(latest.DownloadUrl);
    }

    [Fact]
    public async Task GetLatestVersionAsync_FiltersOut_RecoveryImages_Toolkits_Peripherals_WrongModel_And_Betas()
    {
        var handler = new FakeBiosHttpHandler();
        handler.MapPrefix(
            "https://www.microsoft.com/surface/api/firmware",
            (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent($$"""
                {
                  "value": [
                    { "title": "Surface Diagnostic Toolkit", "uefiVersion": "99.0.0", "downloadUrl": "{{SampleMsiUrl}}" },
                    { "title": "Surface Recovery Image", "uefiVersion": "98.0.0", "downloadUrl": "{{SampleMsiUrl}}" },
                    { "title": "Surface Dock 2 Firmware", "uefiVersion": "97.0.0", "downloadUrl": "{{SampleMsiUrl}}" },
                    { "title": "Surface Laptop 5 Drivers and Firmware Beta", "isBeta": true, "uefiVersion": "96.0.0", "downloadUrl": "{{SampleMsiUrl}}" },
                    { "title": "Surface Pro 8 Drivers and Firmware", "model": "Surface Pro 8", "uefiVersion": "95.0.0", "downloadUrl": "{{SampleMsiUrl}}" },
                    { "title": "Surface Laptop 5 ARM64 Firmware", "model": "Surface Laptop 5", "architecture": "arm64", "uefiVersion": "94.0.0", "downloadUrl": "{{SampleMsiUrl}}" },
                    { "title": "Surface Laptop 5 Drivers and Firmware", "model": "Surface_Laptop_5", "os": "Win10", "uefiVersion": "20.1.0", "downloadUrl": "{{SampleMsiUrl}}" },
                    { "title": "Surface Laptop 5 Drivers and Firmware", "model": "Surface Laptop 5", "os": "Win11", "uefiVersion": "18.2.0", "downloadUrl": "{{SampleMsiUrl}}" }
                  ]
                }
                """, Encoding.UTF8, "application/json"),
            }));

        var provider = MicrosoftSurfaceBiosUpdateProvider.CreateWithHandler(handler);
        var sys = BiosIdentityFactory.MicrosoftSurface(biosVersion: "11.101.143");

        var latest = await provider.GetLatestVersionAsync(sys, sys.CurrentBios);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        // Win11 exact match (OsPrefRank 0) wins over Win10 fallback (OsPrefRank 2) and all rejected entries.
        Assert.Equal("18.2.0", latest.LatestVersion);
    }

    [Fact]
    public async Task GetLatestVersionAsync_HyperV_And_UnsafeSmbiosTokens_FailClosed_WithZeroHttpCalls()
    {
        var handler = new FakeBiosHttpHandler();
        var provider = MicrosoftSurfaceBiosUpdateProvider.CreateWithHandler(handler);

        // Hyper-V VM
        var vm = BiosIdentityFactory.HyperVVm();
        var vmResult = await provider.GetLatestVersionAsync(vm, vm.CurrentBios);
        Assert.Equal(BiosCheckStatus.UnsupportedHardware, vmResult.Status);

        // Unsafe Model even with valid BoardProduct -> fail closed, 0 HTTP calls
        var unsafeModel = BiosIdentityFactory.MicrosoftSurface(model: "Surface Pro 9; calc.exe", boardProduct: "Surface Pro 9");
        var unsafeModelRes = await provider.GetLatestVersionAsync(unsafeModel, unsafeModel.CurrentBios);
        Assert.Equal(BiosCheckStatus.UnsupportedHardware, unsafeModelRes.Status);

        // Unsafe BoardProduct even with valid Model -> fail closed, 0 HTTP calls
        var unsafeBoard = BiosIdentityFactory.MicrosoftSurface(model: "Surface Pro 9", boardProduct: "../../etc/passwd");
        var unsafeBoardRes = await provider.GetLatestVersionAsync(unsafeBoard, unsafeBoard.CurrentBios);
        Assert.Equal(BiosCheckStatus.UnsupportedHardware, unsafeBoardRes.Status);

        // Placeholder-only Model and BoardProduct -> Unsupported, 0 HTTP calls
        var placeholders = BiosIdentityFactory.MicrosoftSurface(model: "To Be Filled By O.E.M.", boardProduct: "Default string");
        var placeholderRes = await provider.GetLatestVersionAsync(placeholders, placeholders.CurrentBios);
        Assert.Equal(BiosCheckStatus.UnsupportedHardware, placeholderRes.Status);

        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task GetLatestVersionAsync_PlaceholderModel_FallsBackToValidBoardProduct()
    {
        var handler = new FakeBiosHttpHandler();
        handler.MapPrefix(
            "https://www.microsoft.com/surface/api/firmware",
            (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent($$"""
                { "uefiVersion": "15.0.1", "downloadUrl": "{{SampleMsiUrl}}" }
                """, Encoding.UTF8, "application/json"),
            }));

        var provider = MicrosoftSurfaceBiosUpdateProvider.CreateWithHandler(handler);
        var sys = BiosIdentityFactory.MicrosoftSurface(model: "To Be Filled By O.E.M.", boardProduct: "Surface Pro 9", biosVersion: "14.0.0");

        var latest = await provider.GetLatestVersionAsync(sys, sys.CurrentBios);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Single(handler.Requests);
        Assert.Contains("Surface%20Pro%209", handler.Requests[0].RequestUri!.AbsoluteUri);
    }

    [Fact]
    public async Task GetLatestVersionAsync_SafeRedirect_WithinMicrosoftCom_Succeeds()
    {
        const string initialUrl = "https://www.microsoft.com/surface/api/firmware?model=Surface%20Laptop%205&os=win11";
        const string finalUrl = "https://download.microsoft.com/surface/catalog/sl5.json";

        var handler = new FakeBiosHttpHandler()
            .MapRedirect(initialUrl, finalUrl, HttpStatusCode.Found)
            .MapJson(finalUrl, $$"""{ "uefiVersion": "18.5.0", "downloadUrl": "{{SampleMsiUrl}}" }""");

        var provider = MicrosoftSurfaceBiosUpdateProvider.CreateWithHandler(handler);
        var sys = BiosIdentityFactory.MicrosoftSurface(biosVersion: "11.101.143");

        var latest = await provider.GetLatestVersionAsync(sys, sys.CurrentBios);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal("18.5.0", latest.LatestVersion);
        Assert.Equal(2, handler.Requests.Count);
    }

    [Theory]
    [InlineData("https://evil.example.com/surface.json")]
    [InlineData("http://download.microsoft.com/surface.json")]
    [InlineData("//evil.example.com/surface.json")]
    [InlineData("javascript:alert(1)")]
    [InlineData("foo:bar/baz")]
    [InlineData("https://www.microsoft.com/surface/%2e%2e/secret.json")]
    public async Task GetLatestVersionAsync_UnsafeRedirects_FailClosed_NeverTouchUntrustedHost(string badLocation)
    {
        const string initialUrl = "https://www.microsoft.com/surface/api/firmware?model=Surface%20Laptop%205&os=win11";

        var handler = new FakeBiosHttpHandler()
            .MapRedirect(initialUrl, badLocation, HttpStatusCode.Found);

        var provider = MicrosoftSurfaceBiosUpdateProvider.CreateWithHandler(handler);
        var sys = BiosIdentityFactory.MicrosoftSurface();

        var latest = await provider.GetLatestVersionAsync(sys, sys.CurrentBios);

        Assert.Equal(BiosCheckStatus.Failed, latest.Status);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task GetLatestVersionAsync_DuplicateLocationHeader_And_RedirectLoop_FailClosed()
    {
        const string initialUrl = "https://www.microsoft.com/surface/api/firmware?model=Surface%20Laptop%205&os=win11";

        var dupHandler = new FakeBiosHttpHandler();
        dupHandler.Map(initialUrl, (_, _) =>
        {
            var resp = new HttpResponseMessage(HttpStatusCode.Found);
            resp.Headers.TryAddWithoutValidation("Location", "https://download.microsoft.com/a.json");
            resp.Headers.TryAddWithoutValidation("Location", "https://download.microsoft.com/b.json");
            return Task.FromResult(resp);
        });

        var provider1 = MicrosoftSurfaceBiosUpdateProvider.CreateWithHandler(dupHandler);
        var sys = BiosIdentityFactory.MicrosoftSurface();
        var dupRes = await provider1.GetLatestVersionAsync(sys, sys.CurrentBios);
        Assert.Equal(BiosCheckStatus.Failed, dupRes.Status);
        Assert.Single(dupHandler.Requests);

        // Redirect loop
        const string hopB = "https://download.microsoft.com/hop-b.json";
        var loopHandler = new FakeBiosHttpHandler()
            .MapRedirect(initialUrl, hopB)
            .MapRedirect(hopB, initialUrl);
        var provider2 = MicrosoftSurfaceBiosUpdateProvider.CreateWithHandler(loopHandler);
        var loopRes = await provider2.GetLatestVersionAsync(sys, sys.CurrentBios);
        Assert.Equal(BiosCheckStatus.Failed, loopRes.Status);
    }

    [Fact]
    public async Task GetLatestVersionAsync_XxeDtd_And_UntrustedDownloadUrl_FailClosed()
    {
        // XXE DTD rejection (E2E-T2-INT-04)
        const string xxeXml = """
            <?xml version="1.0"?>
            <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
            <SurfaceCatalog><Release version="18.1.0"><Title>&xxe;</Title></Release></SurfaceCatalog>
            """;
        var xxeHandler = new FakeBiosHttpHandler();
        xxeHandler.MapPrefix("https://www.microsoft.com/surface/api/firmware",
            (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(xxeXml, Encoding.UTF8, "application/xml"),
            }));

        var sys = BiosIdentityFactory.MicrosoftSurface();
        var xxeRes = await MicrosoftSurfaceBiosUpdateProvider.CreateWithHandler(xxeHandler).GetLatestVersionAsync(sys, sys.CurrentBios);
        Assert.Equal(BiosCheckStatus.Failed, xxeRes.Status);

        // Untrusted / non-.msi download URL in catalog fails closed
        var badUrlHandler = new FakeBiosHttpHandler();
        badUrlHandler.MapPrefix("https://www.microsoft.com/surface/api/firmware",
            (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""
                {
                  "releases": [
                    { "title": "Surface Laptop 5 Drivers and Firmware", "uefiVersion": "18.1.0", "downloadUrl": "https://evil.example.com/fw.msi" }
                  ]
                }
                """, Encoding.UTF8, "application/json"),
            }));

        var badUrlRes = await MicrosoftSurfaceBiosUpdateProvider.CreateWithHandler(badUrlHandler).GetLatestVersionAsync(sys, sys.CurrentBios);
        Assert.Equal(BiosCheckStatus.Failed, badUrlRes.Status);
    }

    [Fact]
    public async Task GetLatestVersionAsync_HttpErrors_And_Cancellation_MappedProperly()
    {
        var sys = BiosIdentityFactory.MicrosoftSurface();

        // 404 -> UnsupportedHardware
        var h404 = new FakeBiosHttpHandler();
        h404.MapPrefix("https://www.microsoft.com/", (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound)));
        Assert.Equal(BiosCheckStatus.UnsupportedHardware,
            (await MicrosoftSurfaceBiosUpdateProvider.CreateWithHandler(h404).GetLatestVersionAsync(sys, sys.CurrentBios)).Status);

        // 503 -> ProviderUnavailable
        var h503 = new FakeBiosHttpHandler();
        h503.MapPrefix("https://www.microsoft.com/", (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)));
        Assert.Equal(BiosCheckStatus.ProviderUnavailable,
            (await MicrosoftSurfaceBiosUpdateProvider.CreateWithHandler(h503).GetLatestVersionAsync(sys, sys.CurrentBios)).Status);

        // Network exception -> Offline
        var hOffline = new FakeBiosHttpHandler();
        hOffline.MapPrefix("https://www.microsoft.com/", (_, _) => Task.FromException<HttpResponseMessage>(new HttpRequestException("offline")));
        Assert.Equal(BiosCheckStatus.Offline,
            (await MicrosoftSurfaceBiosUpdateProvider.CreateWithHandler(hOffline).GetLatestVersionAsync(sys, sys.CurrentBios)).Status);

        // Caller cancellation -> throws OperationCanceledException
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            MicrosoftSurfaceBiosUpdateProvider.CreateWithHandler(h404).GetLatestVersionAsync(sys, sys.CurrentBios, cts.Token));
    }

    [Fact]
    public async Task GetLatestVersionAsync_SwoComparator_IsPermutationInvariant_AcrossMixedFormats()
    {
        var entries = new[]
        {
            $$"""{ "title": "Surface Laptop 5 Drivers and Firmware", "os": "Win11", "uefiVersion": "18.101.143", "releaseDate": "2024-03-01", "packageId": "p1", "downloadUrl": "{{SampleMsiUrl}}" }""",
            $$"""{ "title": "Surface Laptop 5 Drivers and Firmware", "os": "Win11", "uefiVersion": "18.101.143.0", "releaseDate": "2024-03-01", "packageId": "p2", "downloadUrl": "{{SampleMsiUrl}}" }""",
            $$"""{ "title": "Surface Laptop 5 Drivers and Firmware", "os": "Win11", "uefiVersion": "235.3732.768.0", "releaseDate": "2024-05-01", "packageId": "p3", "downloadUrl": "{{SampleMsiUrl}}" }""",
            $$"""{ "title": "Surface Laptop 5 Drivers and Firmware", "os": "Win11", "uefiVersion": "R12", "releaseDate": "2024-01-01", "packageId": "p4", "downloadUrl": "{{SampleMsiUrl}}" }""",
            $$"""{ "title": "Surface Laptop 5 Drivers and Firmware", "os": "Win11", "uefiVersion": "S#1A-2", "releaseDate": "2024-02-01", "packageId": "p5", "downloadUrl": "{{SampleMsiUrl}}" }""",
            $$"""{ "title": "Surface Laptop 5 Drivers and Firmware", "os": "Win10", "uefiVersion": "299.0.0", "releaseDate": "2024-06-01", "packageId": "p6", "downloadUrl": "{{SampleMsiUrl}}" }""",
        };

        var sys = BiosIdentityFactory.MicrosoftSurface(biosVersion: "11.101.143");
        var rng = new Random(12345);

        for (var trial = 0; trial < 20; trial++)
        {
            var shuffled = trial == 0 ? entries : entries.OrderBy(_ => rng.Next()).ToArray();
            var json = $"{{\"releases\":[{string.Join(',', shuffled)}]}}";
            var handler = new FakeBiosHttpHandler();
            handler.MapPrefix("https://www.microsoft.com/surface/api/firmware",
                (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(json, Encoding.UTF8, "application/json"),
                }));

            var latest = await MicrosoftSurfaceBiosUpdateProvider.CreateWithHandler(handler)
                .GetLatestVersionAsync(sys, sys.CurrentBios);

            Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
            Assert.Equal("235.3732.768.0", latest.LatestVersion);
            Assert.Equal("p3", latest.PackageId);
        }
    }

    // -------------------------------------------------------------------------
    // InstallAsync — Local Elevated, Security, BitLocker & Live Agent Pipe
    // -------------------------------------------------------------------------

    [Theory]
    [InlineData(false, 0)]
    [InlineData(false, 3010)]
    [InlineData(true, 3010)]
    public async Task InstallAsync_Elevated_InvokesMsiexec_WithExactArgs_And_BitLockerSuspend(bool allowReboot, int msiExitCode)
    {
        var payload = TestPayload.FromString("fake-surface-msi-bytes");
        var handler = new FakeBiosHttpHandler().MapBytes(SampleMsiUrl, payload.Bytes);
        var launcher = CreateGuardedLauncher((call, _) =>
        {
            if (call.BaseName.Equals("manage-bde.exe", StringComparison.OrdinalIgnoreCase))
                return Task.FromResult(new ProcessResult(0, "Protectors disabled.", ""));
            if (call.BaseName.Equals("msiexec.exe", StringComparison.OrdinalIgnoreCase))
                return Task.FromResult(new ProcessResult(msiExitCode, "MSI completed.", ""));
            throw new InvalidOperationException($"Unexpected binary: {call.FileName}");
        });

        var log = new CapturedLog();
        var commands = RecordingProcessLauncher.CreateCommandRunner(launcher, log: log.Logger, isProcessElevated: true);
        var progress = new SyncProgress<BiosInstallProgress>();

        using var staging = new TempStagingDir();
        var provider = MicrosoftSurfaceBiosUpdateProvider.CreateWithHandler(
            handler,
            commands: commands,
            signatureVerifier: new FakeSignatureVerifier(true),
            isProcessElevated: () => true,
            log: log.Logger);

        var req = CreateSurfaceInstallRequest(
            sha256: payload.Sha256,
            suspendBitLocker: true,
            allowReboot: allowReboot,
            stagingDirectory: staging.Path);

        var result = await provider.InstallAsync(req, progress);

        Assert.True(result.Succeeded);
        Assert.Equal(BiosInstallStatus.StagedForReboot, result.Status);
        Assert.True(result.RequiresReboot);
        Assert.True(result.BitLockerSuspended);
        Assert.Equal(msiExitCode, result.ExitCode);

        Assert.Equal(2, launcher.Calls.Count);
        Assert.Equal("manage-bde.exe", launcher.Calls[0].BaseName);
        Assert.Equal("msiexec.exe", launcher.Calls[1].BaseName);

        var msiArgs = launcher.Calls[1].Arguments;
        Assert.Equal("/i", msiArgs[0]);
        Assert.EndsWith(".msi", msiArgs[1], StringComparison.OrdinalIgnoreCase);
        Assert.Equal("/qn", msiArgs[2]);
        if (allowReboot)
            Assert.Equal(3, msiArgs.Count);
        else
        {
            Assert.Equal(4, msiArgs.Count);
            Assert.Equal("/norestart", msiArgs[3]);
        }

        Assert.Contains(progress.Reports, r => r.Stage == BiosInstallStage.Downloading);
        Assert.Contains(progress.Reports, r => r.Stage == BiosInstallStage.Verifying);
        Assert.Contains(progress.Reports, r => r.Stage == BiosInstallStage.SuspendingBitLocker);
        Assert.Contains(progress.Reports, r => r.Stage == BiosInstallStage.RebootRequired && r.Percent == 100);
        log.AssertDoesNotContainSecret();
    }

    [Fact]
    public async Task InstallAsync_Rejects_NonHttps_NonMicrosoft_And_NonMsi_PreDownload_ZeroHttpCalls()
    {
        var handler = new FakeBiosHttpHandler();
        var launcher = CreateGuardedLauncher();
        var commands = RecordingProcessLauncher.CreateCommandRunner(launcher, isProcessElevated: true);
        var provider = MicrosoftSurfaceBiosUpdateProvider.CreateWithHandler(handler, commands: commands, isProcessElevated: () => true);

        string[] badUrls =
        [
            "http://download.microsoft.com/surface.msi",
            "https://evil.example.com/surface.msi",
            "https://download.microsoft.com/surface/%2e%2e/surface.msi",
            "https://download.microsoft.com/surface/setup.exe",
        ];

        foreach (var badUrl in badUrls)
        {
            var res = await provider.InstallAsync(CreateSurfaceInstallRequest(downloadUrl: badUrl));
            Assert.False(res.Succeeded);
            Assert.Equal(BiosInstallStatus.Failed, res.Status);
        }

        Assert.Empty(handler.Requests);
        Assert.Empty(launcher.Calls);
    }

    [Fact]
    public async Task InstallAsync_Sha256Mismatch_And_UnsignedNoHash_DeletePackage_And_SkipBitLockerAndMsiexec()
    {
        var payload = TestPayload.FromString("tampered-msi");
        var handler = new FakeBiosHttpHandler().MapBytes(SampleMsiUrl, payload.Bytes);
        var launcher = CreateGuardedLauncher();
        var commands = RecordingProcessLauncher.CreateCommandRunner(launcher, isProcessElevated: true);

        using var staging = new TempStagingDir();

        // 1. SHA-256 mismatch
        var provider1 = MicrosoftSurfaceBiosUpdateProvider.CreateWithHandler(
            handler, commands: commands, signatureVerifier: new FakeSignatureVerifier(true), isProcessElevated: () => true);
        var mismatchRes = await provider1.InstallAsync(CreateSurfaceInstallRequest(
            sha256: new string('a', 64), stagingDirectory: staging.Path));
        Assert.False(mismatchRes.Succeeded);
        Assert.Empty(Directory.GetFileSystemEntries(staging.Path));

        // 2. Missing SHA-256 + Authenticode fails
        var provider2 = MicrosoftSurfaceBiosUpdateProvider.CreateWithHandler(
            handler, commands: commands, signatureVerifier: new FakeSignatureVerifier(false), isProcessElevated: () => true);
        var unsignedRes = await provider2.InstallAsync(CreateSurfaceInstallRequest(
            sha256: null, stagingDirectory: staging.Path));
        Assert.False(unsignedRes.Succeeded);
        Assert.Empty(Directory.GetFileSystemEntries(staging.Path));
        Assert.Empty(launcher.Calls);
    }

    [Fact]
    public async Task InstallAsync_MsiErrorExitCode_ReturnsFailed_And_RedactsSerialFromLogTail()
    {
        var payload = TestPayload.FromString("surface-msi-err");
        var handler = new FakeBiosHttpHandler().MapBytes(SampleMsiUrl, payload.Bytes);
        var launcher = CreateGuardedLauncher((call, _) =>
        {
            if (call.BaseName.Equals("manage-bde.exe", StringComparison.OrdinalIgnoreCase))
                return Task.FromResult(new ProcessResult(1, "", "Volume is not encrypted."));
            return Task.FromResult(new ProcessResult(1603, "", $"Fatal MSI error on {BiosIdentityFactory.SentinelSerialNumber}"));
        });

        var log = new CapturedLog();
        var commands = RecordingProcessLauncher.CreateCommandRunner(launcher, log: log.Logger, isProcessElevated: true);
        var provider = MicrosoftSurfaceBiosUpdateProvider.CreateWithHandler(
            handler, commands: commands, signatureVerifier: new FakeSignatureVerifier(true), isProcessElevated: () => true, log: log.Logger);

        var res = await provider.InstallAsync(CreateSurfaceInstallRequest(sha256: payload.Sha256) with { BitLockerKnownOff = true });

        Assert.False(res.Succeeded);
        Assert.Equal(BiosInstallStatus.Failed, res.Status);
        Assert.Equal(1603, res.ExitCode);
        Assert.False(res.BitLockerSuspended);
        Assert.DoesNotContain(BiosIdentityFactory.SentinelSerialNumber, res.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(BiosIdentityFactory.SentinelSerialNumber, res.LogTail ?? "", StringComparison.OrdinalIgnoreCase);
        log.AssertDoesNotContainSecret();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task InstallAsync_UnElevated_LiveNamedPipe_RoutesBitLockerAndMsiThroughAgent(bool allowReboot)
    {
        var payload = TestPayload.FromString("surface-msi-live-pipe-payload");
        var handler = new FakeBiosHttpHandler().MapBytes(SampleMsiUrl, payload.Bytes);
        var localLauncher = CreateGuardedLauncher();
        var agentLauncher = CreateGuardedLauncher((call, _) =>
            Task.FromResult(new ProcessResult(call.BaseName.Equals("msiexec.exe", StringComparison.OrdinalIgnoreCase) ? 3010 : 0, "OK", "")));

        using var adminRoot = new TempStagingDir();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));

        var ops = new AgentBiosOperations(
            agentLauncher,
            signatureVerifier: new FakeSignatureVerifier(true),
            stagingRoot: adminRoot.Path);

        var (server, serverTask, client) = await StartPipeAsync(agentLauncher, ops, cts.Token);
        using (server)
        {
            await using (client)
            {
                var log = new CapturedLog();
                var provider = MicrosoftSurfaceBiosUpdateProvider.CreateWithHandler(
                    handler,
                    commands: null, // Verify no short-circuit when _commands == null and bridge is connected!
                    signatureVerifier: new FakeSignatureVerifier(true),
                    elevatedBridge: client,
                    isProcessElevated: () => false,
                    log: log.Logger);

                // Omit SHA-256 to also verify Host pins computed 64-hex SHA-256 on Agent request!
                var req = CreateSurfaceInstallRequest(sha256: null, suspendBitLocker: true, allowReboot: allowReboot);
                var result = await provider.InstallAsync(req, ct: cts.Token);

                Assert.True(result.Succeeded);
                Assert.Equal(BiosInstallStatus.StagedForReboot, result.Status);
                Assert.True(result.BitLockerSuspended);
                Assert.Equal(3010, result.ExitCode);
                Assert.Empty(localLauncher.Calls);

                Assert.Equal(2, agentLauncher.Calls.Count);
                Assert.Equal("manage-bde.exe", agentLauncher.Calls[0].BaseName);
                Assert.Equal(["-protectors", "-disable", "C:", "-RebootCount", "1"], agentLauncher.Calls[0].Arguments);

                Assert.Equal("msiexec.exe", agentLauncher.Calls[1].BaseName);
                var msiArgs = agentLauncher.Calls[1].Arguments;
                Assert.Equal("/i", msiArgs[0]);
                Assert.StartsWith(adminRoot.Path, msiArgs[1], StringComparison.OrdinalIgnoreCase);
                Assert.EndsWith(".msi", msiArgs[1], StringComparison.OrdinalIgnoreCase);
                Assert.Equal("/qn", msiArgs[2]);
                if (allowReboot)
                    Assert.Equal(3, msiArgs.Count);
                else
                    Assert.Equal("/norestart", msiArgs[3]);

                log.AssertDoesNotContainSecret();
            }

            await serverTask;
        }

        // Agent cleaned its admin staging directory unconditionally.
        Assert.Empty(Directory.GetFileSystemEntries(adminRoot.Path));
    }

    [Fact]
    public async Task InstallAsync_UnElevated_DisconnectedBridge_And_LegacyAgent_FailClosed_ZeroLocalCalls()
    {
        var payload = TestPayload.FromString("surface-msi-fail-closed");
        var handler = new FakeBiosHttpHandler().MapBytes(SampleMsiUrl, payload.Bytes);
        var localLauncher = CreateGuardedLauncher();
        var commands = RecordingProcessLauncher.CreateCommandRunner(localLauncher, isProcessElevated: false);

        // 1. Disconnected / null bridge
        var noBridgeProvider = MicrosoftSurfaceBiosUpdateProvider.CreateWithHandler(
            handler,
            commands: commands,
            signatureVerifier: new FakeSignatureVerifier(true),
            elevatedBridge: null,
            isProcessElevated: () => false);

        var noBridgeRes = await noBridgeProvider.InstallAsync(CreateSurfaceInstallRequest(sha256: payload.Sha256, suspendBitLocker: true));
        Assert.False(noBridgeRes.Succeeded);
        Assert.Equal(SystemCommandRunner.AgentFailedExitCode, noBridgeRes.ExitCode);
        Assert.Empty(localLauncher.Calls);

        // 2. Legacy Agent (biosOperations: null) -> fails closed, zero local fallback
        var agentLauncher = CreateGuardedLauncher();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var (server, serverTask, client) = await StartPipeAsync(agentLauncher, biosOps: null, cts.Token);
        using (server)
        {
            await using (client)
            {
                var legacyProvider = MicrosoftSurfaceBiosUpdateProvider.CreateWithHandler(
                    handler,
                    commands: commands,
                    signatureVerifier: new FakeSignatureVerifier(true),
                    elevatedBridge: client,
                    isProcessElevated: () => false);

                var legacyRes = await legacyProvider.InstallAsync(
                    CreateSurfaceInstallRequest(sha256: payload.Sha256, suspendBitLocker: false),
                    ct: cts.Token);

                Assert.False(legacyRes.Succeeded);
                Assert.Equal(SystemCommandRunner.AgentFailedExitCode, legacyRes.ExitCode);
                Assert.Empty(localLauncher.Calls);
                Assert.Empty(agentLauncher.Calls);
            }

            await serverTask;
        }
    }

    [Fact]
    public async Task InstallAsync_UnElevated_LivePipe_UnsignedMsiRejectedByAgent_CleansStaging()
    {
        var payload = TestPayload.FromString("unsigned-surface-msi");
        var handler = new FakeBiosHttpHandler().MapBytes(SampleMsiUrl, payload.Bytes);
        var agentLauncher = CreateGuardedLauncher();

        using var adminRoot = new TempStagingDir();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));

        // Agent rejects Authenticode signature even when SHA-256 matches!
        var ops = new AgentBiosOperations(
            agentLauncher,
            signatureVerifier: new FakeSignatureVerifier(false),
            stagingRoot: adminRoot.Path);

        var (server, serverTask, client) = await StartPipeAsync(agentLauncher, ops, cts.Token);
        using (server)
        {
            await using (client)
            {
                var provider = MicrosoftSurfaceBiosUpdateProvider.CreateWithHandler(
                    handler,
                    signatureVerifier: new FakeSignatureVerifier(true),
                    elevatedBridge: client,
                    isProcessElevated: () => false);

                var res = await provider.InstallAsync(
                    CreateSurfaceInstallRequest(sha256: payload.Sha256, suspendBitLocker: false),
                    ct: cts.Token);

                Assert.False(res.Succeeded);
                Assert.Equal(BiosInstallStatus.Failed, res.Status);
                Assert.Empty(agentLauncher.Calls);
            }

            await serverTask;
        }

        Assert.Empty(Directory.GetFileSystemEntries(adminRoot.Path));
    }

    [Fact]
    public async Task GetLatestVersionAsync_RedactsSerialFromUrlAndFields_And_RejectsUntrustedNewerCompetingRelease()
    {
        var serial = BiosIdentityFactory.SentinelSerialNumber;
        var sys = BiosIdentityFactory.MicrosoftSurface(biosVersion: "11.101.143", serialNumber: serial);

        // 1. Serial embedded in DownloadUrl, ReleaseNotesUrl, Summary, PackageId -> URLs nulled, text redacted
        var hSerial = new FakeBiosHttpHandler();
        hSerial.MapPrefix("https://www.microsoft.com/surface/api/firmware",
            (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent($$"""
                {
                  "releases": [
                    {
                      "title": "Surface Laptop 5 Drivers and Firmware for {{serial}}",
                      "uefiVersion": "18.101.143",
                      "packageId": "pkg-{{serial}}",
                      "downloadUrl": "https://download.microsoft.com/download/{{Uri.EscapeDataString(serial)}}/fw.msi",
                      "releaseNotesUrl": "https://www.microsoft.com/notes?sn={{serial}}"
                    }
                  ]
                }
                """, Encoding.UTF8, "application/json"),
            }));

        var log = new CapturedLog();
        var serialRes = await MicrosoftSurfaceBiosUpdateProvider.CreateWithHandler(hSerial, log: log.Logger)
            .GetLatestVersionAsync(sys, sys.CurrentBios);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, serialRes.Status);
        Assert.Null(serialRes.DownloadUrl);
        Assert.Null(serialRes.ReleaseNotesUrl);
        Assert.DoesNotContain(serial, serialRes.ReleaseSummary ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(serial, serialRes.PackageId ?? "", StringComparison.OrdinalIgnoreCase);
        log.AssertDoesNotContainSecret();

        // 2. Trusted older + untrusted newer release -> fail closed!
        var hDowngrade = new FakeBiosHttpHandler();
        hDowngrade.MapPrefix("https://www.microsoft.com/surface/api/firmware",
            (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent($$"""
                {
                  "releases": [
                    { "title": "Surface Laptop 5 Drivers and Firmware", "uefiVersion": "12.0.0", "downloadUrl": "{{SampleMsiUrl}}" },
                    { "title": "Surface Laptop 5 Drivers and Firmware", "uefiVersion": "19.0.0", "downloadUrl": "https://evil.example.com/fw.msi" }
                  ]
                }
                """, Encoding.UTF8, "application/json"),
            }));

        var dgRes = await MicrosoftSurfaceBiosUpdateProvider.CreateWithHandler(hDowngrade)
            .GetLatestVersionAsync(sys, sys.CurrentBios);
        Assert.Equal(BiosCheckStatus.Failed, dgRes.Status);

        // 3. Win11-only MSI skipped on explicit Win10 system -> UnsupportedHardware
        var win10Sys = sys with { OsVersion = "Microsoft Windows 10 Pro 10.0.19045" };
        var hWin11Only = new FakeBiosHttpHandler();
        hWin11Only.MapPrefix("https://www.microsoft.com/surface/api/firmware",
            (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent($$"""
                {
                  "releases": [
                    { "title": "Surface Laptop 5 Drivers and Firmware", "os": "Windows 11", "uefiVersion": "18.0.0", "downloadUrl": "{{SampleMsiUrl}}" }
                  ]
                }
                """, Encoding.UTF8, "application/json"),
            }));

        var w10Res = await MicrosoftSurfaceBiosUpdateProvider.CreateWithHandler(hWin11Only)
            .GetLatestVersionAsync(win10Sys, win10Sys.CurrentBios);
        Assert.Equal(BiosCheckStatus.UnsupportedHardware, w10Res.Status);
    }

    [Fact]
    public async Task InstallAsync_ExtensionlessUrl_RenamesToMsi_And_AutoStagingCleansUp()
    {
        const string extlessUrl = "https://download.microsoft.com/download/surface-fw?id=999";
        var payload = TestPayload.FromString("extless-msi-bytes");
        var handler = new FakeBiosHttpHandler().MapBytes(extlessUrl, payload.Bytes);

        string? stagedPath = null;
        var launcher = CreateGuardedLauncher((call, _) =>
        {
            if (call.BaseName.Equals("msiexec.exe", StringComparison.OrdinalIgnoreCase))
            {
                stagedPath = call.Arguments[1];
                Assert.True(File.Exists(stagedPath));
                Assert.EndsWith(".msi", stagedPath, StringComparison.OrdinalIgnoreCase);
            }

            return Task.FromResult(new ProcessResult(0, "OK", ""));
        });

        var commands = RecordingProcessLauncher.CreateCommandRunner(launcher, isProcessElevated: true);
        var provider = MicrosoftSurfaceBiosUpdateProvider.CreateWithHandler(
            handler, commands: commands, signatureVerifier: new FakeSignatureVerifier(true), isProcessElevated: () => true);

        var res = await provider.InstallAsync(CreateSurfaceInstallRequest(
            downloadUrl: extlessUrl,
            sha256: payload.Sha256,
            suspendBitLocker: false,
            stagingDirectory: null));

        Assert.True(res.Succeeded);
        Assert.NotNull(stagedPath);
        Assert.False(File.Exists(stagedPath));
        Assert.False(Directory.Exists(Path.GetDirectoryName(stagedPath)!));
    }

    // -------------------------------------------------------------------------
    // M4 Iteration 2 Regression Tests
    // -------------------------------------------------------------------------

    [Theory]
    [InlineData("Firmware", "Surface Slim Pen 2 Firmware", "Pen firmware update")]
    [InlineData("Firmware", "Surface Thunderbolt 4 Dock 2 Firmware", "Dock firmware update")]
    [InlineData("Firmware", "Surface Audio Firmware", "Audio subsystem update")]
    [InlineData("Firmware", "Surface Camera Firmware", "Camera ISP update")]
    [InlineData("Firmware", "Surface Bluetooth Firmware", "Bluetooth radio update")]
    [InlineData("Firmware", "Surface Wi-Fi Firmware", "Wireless radio update")]
    [InlineData("Firmware", "Surface Pro 9 Firmware", "Surface Diagnostic Toolkit for Surface Pro 9")]
    [InlineData("Firmware", "Surface Laptop 5 Firmware", "Surface Recovery Image package")]
    public async Task GetLatestVersionAsync_RejectsPeripheralFirmwareAndAlwaysRejectDescriptions(
        string category,
        string title,
        string description)
    {
        var sys = BiosIdentityFactory.MicrosoftSurface(model: "Surface Pro 9", boardProduct: "Surface Pro 9", biosVersion: "11.0.0");
        const string url = "https://www.microsoft.com/surface/api/firmware";
        var json = $$"""
            {
              "releases": [
                {
                  "model": "Surface Pro 9",
                  "category": "{{category}}",
                  "title": "{{title}}",
                  "description": "{{description}}",
                  "uefiVersion": "18.200.0",
                  "downloadUrl": "{{SampleMsiUrl}}"
                }
              ]
            }
            """;
        var handler = new FakeBiosHttpHandler().MapPrefix(url, (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json"),
        }));

        var latest = await MicrosoftSurfaceBiosUpdateProvider
            .CreateWithHandler(handler, catalogUrlTemplate: url)
            .GetLatestVersionAsync(sys, sys.CurrentBios);

        Assert.Single(handler.Requests);
        Assert.Equal(BiosCheckStatus.UnsupportedHardware, latest.Status);
    }

    [Fact]
    public async Task GetLatestVersionAsync_SurfaceHub_DriversAndFirmware_NotFalseRejected()
    {
        var sys = BiosIdentityFactory.MicrosoftSurface(model: "Surface Hub 2S", boardProduct: "Surface Hub 2S", biosVersion: "10.0.0");
        const string url = "https://www.microsoft.com/surface/api/firmware";
        var json = $$"""
            {
              "releases": [
                {
                  "model": "Surface Hub 2S",
                  "category": "Drivers and Firmware",
                  "title": "Surface Hub 2S Drivers and Firmware",
                  "uefiVersion": "18.101.143",
                  "downloadUrl": "{{SampleMsiUrl}}"
                }
              ]
            }
            """;
        var handler = new FakeBiosHttpHandler().MapPrefix(url, (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json"),
        }));

        var latest = await MicrosoftSurfaceBiosUpdateProvider
            .CreateWithHandler(handler, catalogUrlTemplate: url)
            .GetLatestVersionAsync(sys, sys.CurrentBios);

        Assert.Single(handler.Requests);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal("18.101.143", latest.LatestVersion);
    }

    [Fact]
    public async Task GetLatestVersionAsync_OsPrefRank_AntiDowngradeAndStaleWin10Isolation()
    {
        var win11Sys = BiosIdentityFactory.MicrosoftSurface(biosVersion: "11.0.0");
        const string url = "https://www.microsoft.com/surface/api/firmware";

        // 1. Untrusted exact-Win11 (OsPrefRank=0) outranks trusted Win10 fallback (OsPrefRank=2) even with lower version -> FAIL CLOSED.
        var downgradeJson = $$"""
            {
              "releases": [
                {
                  "model": "Surface Laptop 5",
                  "os": "win11",
                  "title": "Surface Laptop 5 Drivers and Firmware",
                  "uefiVersion": "18.2.0",
                  "downloadUrl": "https://evil.example.com/surface-win11.msi"
                },
                {
                  "model": "Surface Laptop 5",
                  "os": "win10",
                  "title": "Surface Laptop 5 Drivers and Firmware",
                  "uefiVersion": "20.1.0",
                  "downloadUrl": "{{SampleMsiUrl}}"
                }
              ]
            }
            """;
        var hDowngrade = new FakeBiosHttpHandler().MapPrefix(url, (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(downgradeJson, Encoding.UTF8, "application/json"),
        }));
        var resDowngrade = await MicrosoftSurfaceBiosUpdateProvider
            .CreateWithHandler(hDowngrade, catalogUrlTemplate: url)
            .GetLatestVersionAsync(win11Sys, win11Sys.CurrentBios);
        Assert.Single(hDowngrade.Requests);
        Assert.Equal(BiosCheckStatus.Failed, resDowngrade.Status);

        // 2. Stale untrusted Win10 fallback (OsPrefRank=2) must NOT poison healthy exact-Win11 (OsPrefRank=0).
        var staleWin10Json = $$"""
            {
              "releases": [
                {
                  "model": "Surface Laptop 5",
                  "os": "win11",
                  "title": "Surface Laptop 5 Drivers and Firmware",
                  "uefiVersion": "18.5.0",
                  "downloadUrl": "{{SampleMsiUrl}}"
                },
                {
                  "model": "Surface Laptop 5",
                  "os": "win10",
                  "title": "Surface Laptop 5 Drivers and Firmware",
                  "uefiVersion": "99.0.0",
                  "downloadUrl": "https://evil.example.com/stale-win10.msi"
                }
              ]
            }
            """;
        var hStaleWin10 = new FakeBiosHttpHandler().MapPrefix(url, (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(staleWin10Json, Encoding.UTF8, "application/json"),
        }));
        var resHealthy = await MicrosoftSurfaceBiosUpdateProvider
            .CreateWithHandler(hStaleWin10, catalogUrlTemplate: url)
            .GetLatestVersionAsync(win11Sys, win11Sys.CurrentBios);
        Assert.Single(hStaleWin10.Requests);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, resHealthy.Status);
        Assert.Equal("18.5.0", resHealthy.LatestVersion);
    }

    [Fact]
    public async Task GetLatestVersionAsync_SingleObjectJsonWithNestedFilesArray_And_PoisonedExplicitDownloadUrl()
    {
        var sys = BiosIdentityFactory.MicrosoftSurface(biosVersion: "11.0.0");
        const string url = "https://www.microsoft.com/surface/api/firmware";

        // 1. Single-object JSON release with nested "files" array must be parsed cleanly.
        var singleJson = $$"""
            {
              "model": "Surface Laptop 5",
              "title": "Surface Laptop 5 Drivers and Firmware",
              "uefiVersion": "18.101.143",
              "files": [
                { "name": "readme.txt", "url": "https://download.microsoft.com/dl/readme.txt" },
                { "name": "surface.msi", "url": "{{SampleMsiUrl}}" }
              ]
            }
            """;
        var hSingle = new FakeBiosHttpHandler().MapPrefix(url, (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(singleJson, Encoding.UTF8, "application/json"),
        }));
        var resSingle = await MicrosoftSurfaceBiosUpdateProvider
            .CreateWithHandler(hSingle, catalogUrlTemplate: url)
            .GetLatestVersionAsync(sys, sys.CurrentBios);
        Assert.Single(hSingle.Requests);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, resSingle.Status);
        Assert.Equal("18.101.143", resSingle.LatestVersion);
        Assert.Equal(SampleMsiUrl, resSingle.DownloadUrl);

        // 2. Poisoned explicit "downloadUrl" alongside a valid fallback "url" must fail closed.
        var poisonedJson = $$"""
            {
              "releases": [
                {
                  "model": "Surface Laptop 5",
                  "title": "Surface Laptop 5 Drivers and Firmware",
                  "uefiVersion": "18.101.143",
                  "downloadUrl": "https://evil.example.com/pwn.msi",
                  "url": "{{SampleMsiUrl}}"
                }
              ]
            }
            """;
        var hPoisoned = new FakeBiosHttpHandler().MapPrefix(url, (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(poisonedJson, Encoding.UTF8, "application/json"),
        }));
        var resPoisoned = await MicrosoftSurfaceBiosUpdateProvider
            .CreateWithHandler(hPoisoned, catalogUrlTemplate: url)
            .GetLatestVersionAsync(sys, sys.CurrentBios);
        Assert.Single(hPoisoned.Requests);
        Assert.Equal(BiosCheckStatus.Failed, resPoisoned.Status);
    }

    [Fact]
    public async Task InstallAsync_RejectsAdversarialPackageRedirects_And_NonMsiRedirectTarget()
    {
        var payload = TestPayload.FromString("msi-payload");
        string[] adversarialTargets =
        [
            "https:../evil.msi",
            "https://download.microsoft.com/a/%252e%252e/b.msi",
            "https://download.microsoft.com/a/%2f/b.msi",
            "https://download.microsoft.com/a/%5c/b.msi",
            "https://download.microsoft.com/a/%00/b.msi",
            "https://download.microsoft.com/evil.exe",
        ];

        foreach (var targetLoc in adversarialTargets)
        {
            var reqCount = 0;
            var handler = new FakeBiosHttpHandler().MapPredicate(_ => true, (req, _) =>
            {
                reqCount++;
                if (req.RequestUri!.AbsoluteUri == SampleMsiUrl)
                {
                    var resp = new HttpResponseMessage(HttpStatusCode.Found);
                    resp.Headers.TryAddWithoutValidation("Location", targetLoc);
                    return Task.FromResult(resp);
                }

                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(payload.Bytes),
                });
            });

            var launcher = CreateGuardedLauncher();
            var commands = RecordingProcessLauncher.CreateCommandRunner(launcher, isProcessElevated: true);
            var provider = MicrosoftSurfaceBiosUpdateProvider.CreateWithHandler(
                handler, commands: commands, signatureVerifier: new FakeSignatureVerifier(true), isProcessElevated: () => true);

            var res = await provider.InstallAsync(CreateSurfaceInstallRequest(
                downloadUrl: SampleMsiUrl, sha256: payload.Sha256, suspendBitLocker: true));

            Assert.False(res.Succeeded, $"Expected redirect target '{targetLoc}' to be rejected.");
            Assert.Equal(1, reqCount);
            Assert.Empty(launcher.Calls);
        }

        // Duplicate Location headers must also fail closed on package download.
        {
            var reqCount = 0;
            var handler = new FakeBiosHttpHandler().MapPredicate(_ => true, (_, _) =>
            {
                reqCount++;
                var resp = new HttpResponseMessage(HttpStatusCode.Found);
                resp.Headers.TryAddWithoutValidation("Location", "https://download.microsoft.com/a.msi");
                resp.Headers.TryAddWithoutValidation("Location", "https://download.microsoft.com/b.msi");
                return Task.FromResult(resp);
            });

            var launcher = CreateGuardedLauncher();
            var commands = RecordingProcessLauncher.CreateCommandRunner(launcher, isProcessElevated: true);
            var provider = MicrosoftSurfaceBiosUpdateProvider.CreateWithHandler(
                handler, commands: commands, signatureVerifier: new FakeSignatureVerifier(true), isProcessElevated: () => true);

            var res = await provider.InstallAsync(CreateSurfaceInstallRequest(
                downloadUrl: SampleMsiUrl, sha256: payload.Sha256, suspendBitLocker: true));

            Assert.False(res.Succeeded);
            Assert.Equal(1, reqCount);
            Assert.Empty(launcher.Calls);
        }
    }

    [Fact]
    public async Task InstallAsync_LongMsiFileNameOver128Chars_PreservesMsiExtensionAndSucceeds()
    {
        var longName = new string('a', 135) + "_SurfaceLaptop5_Win11.msi";
        var longUrl = "https://download.microsoft.com/download/surface/" + longName;
        var payload = TestPayload.FromString("long-name-surface-msi");
        var handler = new FakeBiosHttpHandler().MapBytes(longUrl, payload.Bytes);

        string? stagedPath = null;
        var launcher = CreateGuardedLauncher((call, _) =>
        {
            if (call.BaseName.Equals("msiexec.exe", StringComparison.OrdinalIgnoreCase))
            {
                stagedPath = call.Arguments[1];
                Assert.EndsWith(".msi", stagedPath, StringComparison.OrdinalIgnoreCase);
                Assert.True(Path.GetFileName(stagedPath).Length <= 128);
            }

            return Task.FromResult(new ProcessResult(0, "OK", ""));
        });

        var commands = RecordingProcessLauncher.CreateCommandRunner(launcher, isProcessElevated: true);
        var provider = MicrosoftSurfaceBiosUpdateProvider.CreateWithHandler(
            handler, commands: commands, signatureVerifier: new FakeSignatureVerifier(true), isProcessElevated: () => true);

        var res = await provider.InstallAsync(CreateSurfaceInstallRequest(
            downloadUrl: longUrl, sha256: payload.Sha256, suspendBitLocker: false));

        Assert.True(res.Succeeded);
        Assert.NotNull(stagedPath);
    }

    [Fact]
    public async Task InstallAsync_SymlinkDanglingAncestorAndPartTarget_RejectedFailClosed()
    {
        var root = Path.Combine(Path.GetTempPath(), $"rpd-surf-sym-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        try
        {
            var payload = TestPayload.FromString("surface-msi-bytes");
            var outsideDir = Path.Combine(root, "outside");
            Directory.CreateDirectory(outsideDir);
            var symStage = Path.Combine(root, "sym-stage");
            Directory.CreateSymbolicLink(symStage, outsideDir);

            var danglingStage = Path.Combine(root, "dangling-stage");
            Directory.CreateSymbolicLink(danglingStage, Path.Combine(root, "does-not-exist"));

            var symParent = Path.Combine(root, "sym-parent");
            Directory.CreateSymbolicLink(symParent, outsideDir);
            var nestedUnderSym = Path.Combine(symParent, "nested-stage");

            var realStage = Path.Combine(root, "real-stage");
            Directory.CreateDirectory(realStage);
            var victimFile = Path.Combine(root, "victim.txt");
            await File.WriteAllTextAsync(victimFile, "ORIGINAL-VICTIM");
            var partLink = Path.Combine(realStage, Path.GetFileName(new Uri(SampleMsiUrl).AbsolutePath) + ".part");
            File.CreateSymbolicLink(partLink, victimFile);

            foreach (var dir in new[] { symStage, danglingStage, nestedUnderSym, realStage })
            {
                var httpCalled = false;
                var handler = new FakeBiosHttpHandler().MapPredicate(_ => true, (_, _) =>
                {
                    httpCalled = true;
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new ByteArrayContent(payload.Bytes),
                    });
                });

                var launcher = CreateGuardedLauncher();
                var commands = RecordingProcessLauncher.CreateCommandRunner(launcher, isProcessElevated: true);
                var provider = MicrosoftSurfaceBiosUpdateProvider.CreateWithHandler(
                    handler, commands: commands, signatureVerifier: new FakeSignatureVerifier(true), isProcessElevated: () => true);

                var res = await provider.InstallAsync(CreateSurfaceInstallRequest(
                    downloadUrl: SampleMsiUrl, sha256: payload.Sha256, suspendBitLocker: true, stagingDirectory: dir));

                Assert.False(res.Succeeded, $"Expected symlink staging path '{dir}' to be rejected.");
                Assert.False(httpCalled);
                Assert.Empty(launcher.Calls);
            }

            Assert.Equal("ORIGINAL-VICTIM", await File.ReadAllTextAsync(victimFile));
            Assert.Empty(Directory.GetFiles(outsideDir));
        }
        finally
        {
            if (Directory.Exists(root))
                Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task SerialNumberRedaction_CoversGetCurrentCatalogPathSpaceSubdelimAndInstallLogsProgress()
    {
        const string complexSerial = "SN 123,456";
        var sysWithLeaks = BiosIdentityFactory.MicrosoftSurface(serialNumber: complexSerial) with
        {
            CurrentBios = new BiosCurrentInfo(
                Vendor: $"Microsoft {complexSerial}",
                Version: $"11.101-{complexSerial}",
                ReleaseDate: new DateOnly(2024, 1, 1),
                ReleaseDateRaw: $"20240101-{complexSerial}",
                SmbiosRevision: $"3.3-{complexSerial}",
                FirmwareMode: BiosFirmwareMode.Uefi,
                Family: $"Surface-{complexSerial}"),
        };

        // 1. GetCurrentVersionAsync redacts Vendor, ReleaseDateRaw, SmbiosRevision, Version, Family.
        var curProvider = new MicrosoftSurfaceBiosUpdateProvider();
        var cur = await curProvider.GetCurrentVersionAsync(sysWithLeaks);
        Assert.DoesNotContain(complexSerial, cur.Vendor, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(complexSerial, cur.Version, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(complexSerial, cur.ReleaseDateRaw, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(complexSerial, cur.SmbiosRevision, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(complexSerial, cur.Family, StringComparison.OrdinalIgnoreCase);

        // 2. ContainsSerialInUrl nulls space+subdelim URLs in path segments.
        const string catUrl = "https://www.microsoft.com/surface/api/firmware";
        const string catJson = """
            {
              "releases": [
                {
                  "model": "Surface Laptop 5",
                  "title": "Surface Laptop 5 Drivers and Firmware",
                  "uefiVersion": "18.101.143",
                  "releaseDate": "2025-05-01",
                  "downloadUrl": "https://download.microsoft.com/SN+123,456/surface.msi",
                  "releaseNotesUrl": "https://www.microsoft.com/notes/SN+123,456"
                }
              ]
            }
            """;
        var hCat = new FakeBiosHttpHandler().MapPrefix(catUrl, (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(catJson, Encoding.UTF8, "application/json"),
        }));
        var sysForCatalog = BiosIdentityFactory.MicrosoftSurface(biosVersion: "11.101.143", serialNumber: complexSerial);
        var latest = await MicrosoftSurfaceBiosUpdateProvider
            .CreateWithHandler(hCat, catalogUrlTemplate: catUrl)
            .GetLatestVersionAsync(sysForCatalog, sysForCatalog.CurrentBios);
        Assert.Single(hCat.Requests);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Null(latest.DownloadUrl);
        Assert.Null(latest.ReleaseNotesUrl);

        // 3. InstallAsync redacts SerialNumber in ILogger & IProgress on download error AND installer launch.
        const string serial = BiosIdentityFactory.SentinelSerialNumber;
        var log = new CapturedLog();
        var progress = new SyncProgress<BiosInstallProgress>();

        var secretUrl = $"https://download.microsoft.com/dl/{serial}.msi";
        var hErr = new FakeBiosHttpHandler().MapException(secretUrl, () => new HttpRequestException($"Connection failed for {secretUrl}"));
        var pErr = MicrosoftSurfaceBiosUpdateProvider.CreateWithHandler(hErr, log: log.Logger, isProcessElevated: () => true);
        var rErr = await pErr.InstallAsync(
            CreateSurfaceInstallRequest(downloadUrl: secretUrl, targetVersion: $"18.101-{serial}", suspendBitLocker: false),
            progress: progress);
        Assert.False(rErr.Succeeded);
        Assert.DoesNotContain(serial, rErr.Message, StringComparison.OrdinalIgnoreCase);
        log.AssertDoesNotContainSecret();

        var payload = TestPayload.FromString("msi-secret-target");
        var hOk = new FakeBiosHttpHandler().MapBytes(secretUrl, payload.Bytes);
        var launcher = CreateGuardedLauncher();
        var commands = RecordingProcessLauncher.CreateCommandRunner(launcher, log: log.Logger, isProcessElevated: true);
        var pOk = MicrosoftSurfaceBiosUpdateProvider.CreateWithHandler(
            hOk, commands: commands, signatureVerifier: new FakeSignatureVerifier(true), isProcessElevated: () => true, log: log.Logger);
        var rOk = await pOk.InstallAsync(
            CreateSurfaceInstallRequest(downloadUrl: secretUrl, sha256: payload.Sha256, targetVersion: $"18.101-{serial}", suspendBitLocker: false),
            progress: progress);
        Assert.True(rOk.Succeeded);
        Assert.DoesNotContain(serial, rOk.TargetVersion ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(serial, rOk.Message, StringComparison.OrdinalIgnoreCase);
        log.AssertDoesNotContainSecret();
        Assert.NotEmpty(progress.Reports);
        Assert.All(progress.Reports, ev => Assert.DoesNotContain(serial, ev.Detail ?? "", StringComparison.OrdinalIgnoreCase));
    }
}
