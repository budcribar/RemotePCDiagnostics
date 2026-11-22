using System.IO.Compression;
using System.Net;
using System.Text;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Bios;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;
using Xunit;

namespace RemotePCDiagnostics.Tests.Bios;

public sealed class FrameworkBiosUpdateProviderTests
{
    private const string SampleCabUrl = "https://cdn.fwupd.org/downloads/framework-laptop13-amd-03.05.cab";
    private const string SampleExeUrl = "https://downloads.frame.work/bios/Framework_Laptop_13_AMD_7040_BIOS_03.05.exe";

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
        var pipeName = $"rpd-bios-framework-{Guid.NewGuid():N}";
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

    private static BiosInstallRequest CreateFrameworkInstallRequest(
        BiosSystemIdentity? system = null,
        string? downloadUrl = SampleCabUrl,
        string? sha256 = null,
        string targetVersion = "03.05",
        bool suspendBitLocker = true,
        bool allowReboot = false,
        bool verifyHash = true,
        string? stagingDirectory = null)
    {
        var id = system ?? BiosIdentityFactory.Framework();
        var target = BiosLatestInfo.UpdateAvailable(
            providerId: FrameworkBiosUpdateProvider.ProviderVendorId,
            latestVersion: targetVersion,
            packageId: "work.frame.Laptop13AMD.firmware:03.05",
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

    private static byte[] BuildSampleCapsuleCab(
        string infName = "firmware.inf",
        bool includeCat = true,
        bool msZip = false)
    {
        var files = new Dictionary<string, byte[]>(StringComparer.Ordinal)
        {
            [infName] = Encoding.UTF8.GetBytes("[Version]\nSignature=\"$WINDOWS NT$\"\nClass=Firmware\n"),
            ["firmware.bin"] = Encoding.UTF8.GetBytes("UEFI-CAPSULE-PAYLOAD-DATA"),
        };

        if (includeCat)
            files["firmware.cat"] = Encoding.UTF8.GetBytes("SIGNED-CATALOG-CONTENT");

        return msZip
            ? TestCabBuilder.CreateMsZip(files)
            : TestCabBuilder.CreateUncompressed(files);
    }

    // -------------------------------------------------------------------------
    // Metadata, Capabilities & CanHandle
    // -------------------------------------------------------------------------

    [Fact]
    public void Metadata_And_Capabilities_Match_Contract()
    {
        var provider = new FrameworkBiosUpdateProvider();

        Assert.Equal("framework", provider.VendorId);
        Assert.Equal("Framework", provider.DisplayName);
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
        var ctors = typeof(FrameworkBiosUpdateProvider).GetConstructors();
        Assert.Single(ctors);
        Assert.All(ctors[0].GetParameters(), p => Assert.True(p.HasDefaultValue));
    }

    [Theory]
    [InlineData("Framework", "Framework", true)]
    [InlineData("Framework Computer Inc.", "Other", true)]
    [InlineData("Other", "Framework", true)]
    [InlineData("MyFrameworkClone", "Other", false)]
    [InlineData("Dell Inc.", "Dell Inc.", false)]
    [InlineData("Microsoft Corporation", "Microsoft Corporation", false)]
    [InlineData("", "", false)]
    public void CanHandle_Matches_Framework_WordBoundary(string mfr, string boardMfr, bool expected)
    {
        var provider = new FrameworkBiosUpdateProvider();
        var sys = BiosIdentityFactory.Framework() with
        {
            Manufacturer = mfr,
            BoardManufacturer = boardMfr,
        };

        Assert.Equal(expected, provider.CanHandle(sys));
    }

    [Fact]
    public void CanHandle_Null_And_Unknown_ReturnFalse()
    {
        var provider = new FrameworkBiosUpdateProvider();
        Assert.False(provider.CanHandle(null!));
        Assert.False(provider.CanHandle(BiosIdentityFactory.Unknown()));
    }

    // -------------------------------------------------------------------------
    // GetCurrentVersionAsync & Version Comparison
    // -------------------------------------------------------------------------

    [Theory]
    [InlineData("03.03", "03.03")]
    [InlineData("03.03b", "03.03b")]
    [InlineData("BIOS 03.05", "03.05")]
    [InlineData("Ver. 3.05", "3.05")]
    [InlineData("v03.05", "03.05")]
    public async Task GetCurrentVersionAsync_Normalizes_FrameworkVersions_And_PopulatesMetadata(string raw, string expected)
    {
        var provider = new FrameworkBiosUpdateProvider();
        var sys = BiosIdentityFactory.Framework(biosVersion: raw);

        var info = await provider.GetCurrentVersionAsync(sys);

        Assert.Equal("framework", info.ProviderId);
        Assert.Equal(expected, info.Version);
        Assert.Equal("Laptop 13 (AMD Ryzen 7040Series)", info.Metadata?["model"]);
        Assert.Equal("FRANMDCP07", info.Metadata?["boardProduct"]);
    }

    [Theory]
    [InlineData("03.03", "03.03b", BiosCheckStatus.UpdateAvailable)]
    [InlineData("03.03b", "03.05", BiosCheckStatus.UpdateAvailable)]
    [InlineData("03.05", "3.05", BiosCheckStatus.UpToDate)]
    [InlineData("3.05", "03.05", BiosCheckStatus.UpToDate)]
    [InlineData("03.05", "03.03b", BiosCheckStatus.UpToDate)]
    public async Task FrameworkVersionComparison_HandlesTrailingLetters_And_LeadingZeros(
        string currentVer,
        string catalogVer,
        BiosCheckStatus expectedStatus)
    {
        const string jsonUrl = "https://api.frame.work/v1/bios.json";
        var handler = new FakeBiosHttpHandler().MapJson(jsonUrl, $$"""
            {
              "releases": [
                {
                  "boardProduct": "FRANMDCP07",
                  "version": "{{catalogVer}}",
                  "releaseDate": "2024-03-29",
                  "downloadUrl": "{{SampleCabUrl}}"
                }
              ]
            }
            """);

        var sys = BiosIdentityFactory.Framework(biosVersion: currentVer);
        var latest = await FrameworkBiosUpdateProvider.CreateWithHandler(handler, catalogUrl: jsonUrl)
            .GetLatestVersionAsync(sys, sys.CurrentBios);

        Assert.Equal(expectedStatus, latest.Status);
    }

    // -------------------------------------------------------------------------
    // GetLatestVersionAsync — LVFS .xml.gz / XML, frame.work JSON, Security
    // -------------------------------------------------------------------------

    [Fact]
    public async Task GetLatestVersionAsync_LvfsGzipAppStream_PrefersContainerSha256_IgnoresContentSha256_And_Peripherals()
    {
        var containerSha = TestPayload.FromString("cab-container-bytes").Sha256;
        var contentSha = TestPayload.FromString("inner-firmware-bin").Sha256;

        var lvfsXml = $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <components version="0.8">
              <component type="firmware">
                <id>work.frame.Fingerprint.firmware</id>
                <name>Framework Fingerprint Reader</name>
                <developer_name>Framework</developer_name>
                <releases>
                  <release version="99.99" date="2025-01-01">
                    <artifacts><artifact type="binary"><location>{SampleCabUrl}</location></artifact></artifacts>
                  </release>
                </releases>
              </component>
              <component type="firmware">
                <id>work.frame.Laptop16AMD.firmware</id>
                <name>Framework Laptop 16 AMD Ryzen 7040 Series System Firmware</name>
                <developer_name>Framework</developer_name>
                <releases>
                  <release version="09.00" date="2025-01-01">
                    <artifacts><artifact type="binary"><location>{SampleCabUrl}</location></artifact></artifacts>
                  </release>
                </releases>
              </component>
              <component type="firmware">
                <id>work.frame.Laptop13AMD.firmware</id>
                <name>Framework Laptop 13 AMD Ryzen 7040 Series System Firmware</name>
                <summary>UEFI BIOS for Framework Laptop 13 AMD 7040 Series</summary>
                <developer_name>Framework</developer_name>
                <keywords><keyword>FRANMDCP07</keyword></keywords>
                <releases>
                  <release version="03.06-beta" type="development" date="2025-02-01">
                    <artifacts><artifact type="binary"><location>{SampleCabUrl}</location></artifact></artifacts>
                  </release>
                  <release version="03.05" date="2024-03-29" urgency="high">
                    <description><p>Security and stability fixes for AMD 7040 Series.</p></description>
                    <url type="details">https://frame.work/support/bios-0305</url>
                    <artifacts>
                      <artifact type="binary">
                        <location>{SampleCabUrl}</location>
                        <checksum type="sha256" target="content">{contentSha}</checksum>
                        <checksum type="sha256" target="container">{containerSha.ToUpperInvariant()}</checksum>
                        <size type="installed">33554432</size>
                        <size type="download">16777216</size>
                      </artifact>
                    </artifacts>
                  </release>
                </releases>
              </component>
            </components>
            """;

        var gzBytes = TestPayload.CreateGzip(Encoding.UTF8.GetBytes(lvfsXml));
        var handler = new FakeBiosHttpHandler()
            .MapBytes(FrameworkBiosUpdateProvider.DefaultCatalogUrl, gzBytes);

        var log = new CapturedLog();
        var provider = FrameworkBiosUpdateProvider.CreateWithHandler(handler, log: log.Logger);
        var sys = BiosIdentityFactory.Framework(biosVersion: "03.03b");

        var latest = await provider.GetLatestVersionAsync(sys, sys.CurrentBios);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal("framework", latest.ProviderId);
        Assert.Equal("03.05", latest.LatestVersion);
        Assert.Equal(new DateOnly(2024, 3, 29), latest.ReleaseDate);
        Assert.Equal(BiosUpdateSeverity.Critical, latest.Severity);
        Assert.Equal(SampleCabUrl, latest.DownloadUrl);
        // MUST pick container SHA-256, NEVER target="content"!
        Assert.Equal(containerSha, latest.Sha256);
        Assert.NotEqual(contentSha, latest.Sha256);
        Assert.Equal(16777216, latest.SizeBytes);
        Assert.Equal("https://frame.work/support/bios-0305", latest.ReleaseNotesUrl);
        Assert.Equal(BiosAgentInstallModes.FrameworkCabCapsule, latest.Metadata?["installMode"]);
        Assert.Equal("cab", latest.Metadata?["packageFormat"]);
        Assert.Equal("lvfs", latest.Metadata?["source"]);
        log.AssertDoesNotContainSecret();
    }

    [Fact]
    public async Task GetLatestVersionAsync_LvfsAppStream0x_ContentOnlyChecksum_SetsSha256Null_NeverUsesContentHash()
    {
        var contentSha = TestPayload.FromString("inner-only-bin").Sha256;
        var xml = $"""
            <components>
              <component type="firmware">
                <id>work.frame.Laptop13AMD.firmware</id>
                <name>Framework Laptop 13 AMD Ryzen 7040 Series System Firmware</name>
                <developer_name>Framework</developer_name>
                <releases>
                  <release version="03.05" timestamp="1711670400">
                    <location>{SampleCabUrl}</location>
                    <checksum type="sha256" target="content">{contentSha}</checksum>
                  </release>
                </releases>
              </component>
            </components>
            """;

        var handler = new FakeBiosHttpHandler()
            .MapText(FrameworkBiosUpdateProvider.DefaultCatalogUrl, xml, "application/xml");

        var provider = FrameworkBiosUpdateProvider.CreateWithHandler(handler);
        var sys = BiosIdentityFactory.Framework(
            model: "Laptop 13 (AMD Ryzen 7040Series)",
            boardProduct: "FRANMDCP07",
            biosVersion: "03.03");

        var latest = await provider.GetLatestVersionAsync(sys, sys.CurrentBios);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Null(latest.Sha256); // NEVER accept target="content"!
        Assert.Equal(new DateOnly(2024, 3, 29), latest.ReleaseDate);
    }

    [Fact]
    public async Task GetLatestVersionAsync_FrameWorkJson_ExePackage_And_CrossModelGuard()
    {
        var exeSha = TestPayload.FromString("framework-exe-installer").Sha256;
        const string jsonUrl = "https://api.frame.work/v1/bios.json";
        var handler = new FakeBiosHttpHandler().MapJson(jsonUrl, $$"""
            {
              "releases": [
                {
                  "model": "Laptop 13 (13th Gen Intel Core)",
                  "version": "03.09",
                  "releaseDate": "2024-06-01",
                  "downloadUrl": "{{SampleExeUrl}}",
                  "sha256": "{{exeSha}}"
                },
                {
                  "model": "Laptop 16 (AMD Ryzen 7040 Series)",
                  "version": "03.08",
                  "releaseDate": "2024-05-01",
                  "downloadUrl": "{{SampleExeUrl}}",
                  "sha256": "{{exeSha}}"
                },
                {
                  "model": "Laptop 13 (AMD Ryzen 7040 Series)",
                  "boardProduct": "FRANMDCP07",
                  "version": "03.05",
                  "releaseDate": "2024-03-29",
                  "downloadUrl": "{{SampleExeUrl}}",
                  "sha256": "{{exeSha}}"
                }
              ]
            }
            """);

        var provider = FrameworkBiosUpdateProvider.CreateWithHandler(handler, catalogUrl: jsonUrl);
        var sys = BiosIdentityFactory.Framework(biosVersion: "3.05"); // Equivalent to 03.05!

        var upToDate = await provider.GetLatestVersionAsync(sys, sys.CurrentBios);
        Assert.Equal(BiosCheckStatus.UpToDate, upToDate.Status);
        Assert.Equal("03.05", upToDate.LatestVersion);
        Assert.Equal(BiosAgentInstallModes.FrameworkBiosExe, upToDate.Metadata?["installMode"]);
        Assert.Equal("exe", upToDate.Metadata?["packageFormat"]);
    }

    [Fact]
    public async Task GetLatestVersionAsync_UnsafeSmbiosTokens_FailClosed_ZeroHttpCalls()
    {
        var handler = new FakeBiosHttpHandler();
        var provider = FrameworkBiosUpdateProvider.CreateWithHandler(handler);

        var badModel = BiosIdentityFactory.Framework(model: "Laptop 13; whoami", boardProduct: "FRANMDCP07");
        var badBoard = BiosIdentityFactory.Framework(model: "Laptop 13", boardProduct: "../evil");
        var badSku = BiosIdentityFactory.Framework() with { SystemSku = "FRAN & calc" };
        var allPlaceholder = BiosIdentityFactory.Framework(model: "None", boardProduct: "Default string") with { SystemSku = "N/A" };

        Assert.Equal(BiosCheckStatus.UnsupportedHardware, (await provider.GetLatestVersionAsync(badModel, badModel.CurrentBios)).Status);
        Assert.Equal(BiosCheckStatus.UnsupportedHardware, (await provider.GetLatestVersionAsync(badBoard, badBoard.CurrentBios)).Status);
        Assert.Equal(BiosCheckStatus.UnsupportedHardware, (await provider.GetLatestVersionAsync(badSku, badSku.CurrentBios)).Status);
        Assert.Equal(BiosCheckStatus.UnsupportedHardware, (await provider.GetLatestVersionAsync(allPlaceholder, allPlaceholder.CurrentBios)).Status);

        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task GetLatestVersionAsync_GzipBomb_And_XxeDtd_And_UnsafeRedirects_FailClosed()
    {
        var sys = BiosIdentityFactory.Framework();

        // 1. GZip bomb exceeding MaxCatalogDecompressedBytes (64 MiB) — compresses 65 MiB of zeros to ~65 KB!
        byte[] bombGzip;
        using (var ms = new MemoryStream())
        {
            using (var gz = new GZipStream(ms, CompressionLevel.Fastest, leaveOpen: true))
            {
                var zeroChunk = new byte[1024 * 1024];
                for (var i = 0; i < 65; i++)
                    gz.Write(zeroChunk, 0, zeroChunk.Length);
            }

            bombGzip = ms.ToArray();
        }

        var bombHandler = new FakeBiosHttpHandler().MapBytes(FrameworkBiosUpdateProvider.DefaultCatalogUrl, bombGzip);
        var bombRes = await FrameworkBiosUpdateProvider.CreateWithHandler(bombHandler).GetLatestVersionAsync(sys, sys.CurrentBios);
        Assert.Equal(BiosCheckStatus.Failed, bombRes.Status);

        // 2. XXE DTD attack (E2E-T2-INT-04)
        const string xxeXml = """
            <?xml version="1.0"?>
            <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
            <components><component type="firmware"><name>&xxe;</name></component></components>
            """;
        var xxeHandler = new FakeBiosHttpHandler().MapText(FrameworkBiosUpdateProvider.DefaultCatalogUrl, xxeXml, "application/xml");
        var xxeRes = await FrameworkBiosUpdateProvider.CreateWithHandler(xxeHandler).GetLatestVersionAsync(sys, sys.CurrentBios);
        Assert.Equal(BiosCheckStatus.Failed, xxeRes.Status);

        // 3. Cross-domain redirect attack
        var redirHandler = new FakeBiosHttpHandler()
            .MapRedirect(FrameworkBiosUpdateProvider.DefaultCatalogUrl, "https://evil.example.com/firmware.xml.gz");
        var redirRes = await FrameworkBiosUpdateProvider.CreateWithHandler(redirHandler).GetLatestVersionAsync(sys, sys.CurrentBios);
        Assert.Equal(BiosCheckStatus.Failed, redirRes.Status);
        Assert.Single(redirHandler.Requests);
    }

    [Fact]
    public async Task GetLatestVersionAsync_SwoComparator_IsPermutationInvariant()
    {
        const string jsonUrl = "https://api.frame.work/v1/bios.json";
        var entries = new[]
        {
            $$"""{ "boardProduct": "FRANMDCP07", "version": "03.03", "releaseDate": "2023-10-17", "packageId": "p1", "downloadUrl": "{{SampleCabUrl}}" }""",
            $$"""{ "boardProduct": "FRANMDCP07", "version": "03.03b", "releaseDate": "2023-11-01", "packageId": "p2", "downloadUrl": "{{SampleCabUrl}}" }""",
            $$"""{ "boardProduct": "FRANMDCP07", "version": "03.05", "releaseDate": "2024-03-29", "packageId": "p3", "downloadUrl": "{{SampleCabUrl}}" }""",
            $$"""{ "boardProduct": "FRANMDCP07", "version": "3.05", "releaseDate": "2024-03-29", "packageId": "p4", "downloadUrl": "{{SampleExeUrl}}" }""",
            $$"""{ "boardProduct": "FRANMDCP07", "version": "A#1-2", "releaseDate": "2024-01-01", "packageId": "p5", "downloadUrl": "{{SampleCabUrl}}" }""",
            $$"""{ "model": "Laptop 13 AMD Ryzen 7040", "version": "09.99", "releaseDate": "2025-01-01", "packageId": "p6", "downloadUrl": "{{SampleCabUrl}}" }""",
        };

        var sys = BiosIdentityFactory.Framework(biosVersion: "03.01");
        var rng = new Random(998877);

        for (var trial = 0; trial < 20; trial++)
        {
            var shuffled = trial == 0 ? entries : entries.OrderBy(_ => rng.Next()).ToArray();
            var json = $"{{\"releases\":[{string.Join(',', shuffled)}]}}";
            var handler = new FakeBiosHttpHandler().MapJson(jsonUrl, json);

            var latest = await FrameworkBiosUpdateProvider.CreateWithHandler(handler, catalogUrl: jsonUrl)
                .GetLatestVersionAsync(sys, sys.CurrentBios);

            Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
            // MatchRank 3 (exact board FRANMDCP07) + version 03.05 beats MatchRank 1 even with higher version 09.99.
            Assert.Equal("03.05", latest.LatestVersion);
            Assert.Equal("p3", latest.PackageId);
        }
    }

    // -------------------------------------------------------------------------
    // InstallAsync — CAB Pre-Validation, Local Elevated, EXE & Live Agent Pipe
    // -------------------------------------------------------------------------

    [Fact]
    public async Task InstallAsync_Elevated_CabCapsule_ExtractsSafely_InvokesPnputil_And_CleansExtractDir()
    {
        var cabBytes = BuildSampleCapsuleCab(infName: "sub/Firmware.INF", includeCat: true, msZip: true);
        var payload = TestPayload.FromBytes(cabBytes);
        var handler = new FakeBiosHttpHandler().MapBytes(SampleCabUrl, payload.Bytes);

        string? observedExtractDir = null;
        string? observedInfArg = null;

        var launcher = CreateGuardedLauncher((call, _) =>
        {
            if (call.BaseName.Equals("manage-bde.exe", StringComparison.OrdinalIgnoreCase))
                return Task.FromResult(new ProcessResult(0, "Suspended.", ""));

            if (call.BaseName.Equals("pnputil.exe", StringComparison.OrdinalIgnoreCase))
            {
                observedExtractDir = call.WorkingDirectory;
                observedInfArg = call.Arguments[1];
                Assert.True(File.Exists(observedInfArg), "Extracted .inf must exist when pnputil runs.");
                return Task.FromResult(new ProcessResult(3010, "Driver package added.", ""));
            }

            throw new InvalidOperationException($"Unexpected binary: {call.FileName}");
        });

        using var staging = new TempStagingDir();
        var log = new CapturedLog();
        var commands = RecordingProcessLauncher.CreateCommandRunner(launcher, log: log.Logger, isProcessElevated: true);
        var provider = FrameworkBiosUpdateProvider.CreateWithHandler(
            handler,
            commands: commands,
            signatureVerifier: new FakeSignatureVerifier(true),
            isProcessElevated: () => true,
            log: log.Logger);

        var res = await provider.InstallAsync(CreateFrameworkInstallRequest(
            downloadUrl: SampleCabUrl,
            sha256: payload.Sha256,
            stagingDirectory: staging.Path));

        Assert.True(res.Succeeded);
        Assert.Equal(BiosInstallStatus.StagedForReboot, res.Status);
        Assert.True(res.BitLockerSuspended);
        Assert.Equal(3010, res.ExitCode);

        Assert.Equal(2, launcher.Calls.Count);
        Assert.Equal("pnputil.exe", launcher.Calls[1].BaseName);
        Assert.Equal("/add-driver", launcher.Calls[1].Arguments[0]);
        Assert.EndsWith("Firmware.INF", observedInfArg!, StringComparison.Ordinal);
        Assert.Equal("/install", launcher.Calls[1].Arguments[2]);

        // Dedicated cab-extract-* directory MUST be cleaned in finally!
        Assert.NotNull(observedExtractDir);
        Assert.False(Directory.Exists(observedExtractDir));
        log.AssertDoesNotContainSecret();
    }

    [Fact]
    public async Task InstallAsync_Elevated_PnputilExitCode259_IsTreatedAsFailure_NotSuccess()
    {
        var cabBytes = BuildSampleCapsuleCab();
        var payload = TestPayload.FromBytes(cabBytes);
        var handler = new FakeBiosHttpHandler().MapBytes(SampleCabUrl, payload.Bytes);

        var launcher = CreateGuardedLauncher((call, _) =>
            call.BaseName.Equals("pnputil.exe", StringComparison.OrdinalIgnoreCase)
                ? Task.FromResult(new ProcessResult(259, "", "No more data is available."))
                : Task.FromResult(new ProcessResult(0, "", "")));

        var commands = RecordingProcessLauncher.CreateCommandRunner(launcher, isProcessElevated: true);
        var provider = FrameworkBiosUpdateProvider.CreateWithHandler(
            handler, commands: commands, signatureVerifier: new FakeSignatureVerifier(true), isProcessElevated: () => true);

        var res = await provider.InstallAsync(CreateFrameworkInstallRequest(downloadUrl: SampleCabUrl, sha256: payload.Sha256));

        Assert.False(res.Succeeded);
        Assert.Equal(BiosInstallStatus.Failed, res.Status);
        Assert.Equal(259, res.ExitCode);
    }

    [Fact]
    public async Task InstallAsync_CabWithoutInf_Or_CorruptCab_Or_CollisionCab_FailsBeforeBitLockerAndPnputil()
    {
        var launcher = CreateGuardedLauncher();
        var commands = RecordingProcessLauncher.CreateCommandRunner(launcher, isProcessElevated: true);

        // 1. CAB missing .inf (E2E-T2-VER-06)
        var noInfCab = TestPayload.FromBytes(TestCabBuilder.CreateUncompressed(new Dictionary<string, byte[]>
        {
            ["firmware.bin"] = Encoding.UTF8.GetBytes("bin-only"),
        }));
        var h1 = new FakeBiosHttpHandler().MapBytes(SampleCabUrl, noInfCab.Bytes);
        var r1 = await FrameworkBiosUpdateProvider.CreateWithHandler(h1, commands: commands, isProcessElevated: () => true)
            .InstallAsync(CreateFrameworkInstallRequest(downloadUrl: SampleCabUrl, sha256: noInfCab.Sha256, suspendBitLocker: true));
        Assert.False(r1.Succeeded);
        Assert.Contains(".inf", r1.Message, StringComparison.OrdinalIgnoreCase);

        // 2. Corrupt CAB bytes
        var corruptCab = TestPayload.FromString("NOT-A-VALID-MSCF-CAB");
        var h2 = new FakeBiosHttpHandler().MapBytes(SampleCabUrl, corruptCab.Bytes);
        var r2 = await FrameworkBiosUpdateProvider.CreateWithHandler(h2, commands: commands, isProcessElevated: () => true)
            .InstallAsync(CreateFrameworkInstallRequest(downloadUrl: SampleCabUrl, sha256: corruptCab.Sha256, suspendBitLocker: true));
        Assert.False(r2.Succeeded);

        // 3. File-vs-directory collision CAB ("sub" and "sub/firmware.inf")
        var collisionCab = TestPayload.FromBytes(TestCabBuilder.CreateUncompressed(new Dictionary<string, byte[]>
        {
            ["sub"] = Encoding.UTF8.GetBytes("file-named-sub"),
            ["sub/firmware.inf"] = Encoding.UTF8.GetBytes("[Version]"),
        }));
        var h3 = new FakeBiosHttpHandler().MapBytes(SampleCabUrl, collisionCab.Bytes);
        var r3 = await FrameworkBiosUpdateProvider.CreateWithHandler(h3, commands: commands, isProcessElevated: () => true)
            .InstallAsync(CreateFrameworkInstallRequest(downloadUrl: SampleCabUrl, sha256: collisionCab.Sha256, suspendBitLocker: true));
        Assert.False(r3.Succeeded);

        // 4. Forbidden metacharacter entry path in CAB
        var metaCab = TestPayload.FromBytes(TestCabBuilder.CreateUncompressed(new Dictionary<string, byte[]>
        {
            ["firm;calc.inf"] = Encoding.UTF8.GetBytes("[Version]"),
        }));
        var h4 = new FakeBiosHttpHandler().MapBytes(SampleCabUrl, metaCab.Bytes);
        var r4 = await FrameworkBiosUpdateProvider.CreateWithHandler(h4, commands: commands, isProcessElevated: () => true)
            .InstallAsync(CreateFrameworkInstallRequest(downloadUrl: SampleCabUrl, sha256: metaCab.Sha256, suspendBitLocker: true));
        Assert.False(r4.Succeeded);

        // CRITICAL: Zero manage-bde.exe and zero pnputil.exe calls across all 4 invalid CABs!
        Assert.Empty(launcher.Calls);
    }

    [Fact]
    public async Task InstallAsync_RejectsDisallowedExtension_And_UntrustedDomain_ZeroHttpCalls()
    {
        var handler = new FakeBiosHttpHandler();
        var launcher = CreateGuardedLauncher();
        var commands = RecordingProcessLauncher.CreateCommandRunner(launcher, isProcessElevated: true);
        var provider = FrameworkBiosUpdateProvider.CreateWithHandler(handler, commands: commands, isProcessElevated: () => true);

        string[] badUrls =
        [
            "https://cdn.fwupd.org/downloads/bios.zip",
            "https://downloads.frame.work/bios/bios.msi",
            "https://evil.example.com/bios.cab",
            "http://cdn.fwupd.org/downloads/bios.cab",
        ];

        foreach (var url in badUrls)
        {
            var res = await provider.InstallAsync(CreateFrameworkInstallRequest(downloadUrl: url));
            Assert.False(res.Succeeded);
        }

        Assert.Empty(handler.Requests);
        Assert.Empty(launcher.Calls);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task InstallAsync_UnElevated_LiveNamedPipe_FrameworkBiosExe_RoutesThroughAgent(bool allowReboot)
    {
        var payload = TestPayload.FromString("framework-exe-live-pipe");
        var handler = new FakeBiosHttpHandler().MapBytes(SampleExeUrl, payload.Bytes);
        var localLauncher = CreateGuardedLauncher();
        var agentLauncher = CreateGuardedLauncher((call, _) =>
            Task.FromResult(new ProcessResult(call.BaseName.Equals("manage-bde.exe", StringComparison.OrdinalIgnoreCase) ? 0 : 3010, "OK", "")));

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
                var commands = RecordingProcessLauncher.CreateCommandRunner(localLauncher, isProcessElevated: false);
                var provider = FrameworkBiosUpdateProvider.CreateWithHandler(
                    handler,
                    commands: commands,
                    signatureVerifier: new FakeSignatureVerifier(true),
                    elevatedBridge: client,
                    isProcessElevated: () => false);

                var res = await provider.InstallAsync(
                    CreateFrameworkInstallRequest(downloadUrl: SampleExeUrl, sha256: payload.Sha256, allowReboot: allowReboot),
                    ct: cts.Token);

                Assert.True(res.Succeeded);
                Assert.Equal(BiosInstallStatus.StagedForReboot, res.Status);
                Assert.True(res.BitLockerSuspended);
                Assert.Empty(localLauncher.Calls);

                Assert.Equal(2, agentLauncher.Calls.Count);
                Assert.Equal("manage-bde.exe", agentLauncher.Calls[0].BaseName);
                Assert.StartsWith(adminRoot.Path, agentLauncher.Calls[1].FileName, StringComparison.OrdinalIgnoreCase);
                Assert.EndsWith(".exe", agentLauncher.Calls[1].FileName, StringComparison.OrdinalIgnoreCase);

                if (allowReboot)
                    Assert.Equal(["/silent"], agentLauncher.Calls[1].Arguments);
                else
                    Assert.Equal(["/silent", "/norestart"], agentLauncher.Calls[1].Arguments);
            }

            await serverTask;
        }

        Assert.Empty(Directory.GetFileSystemEntries(adminRoot.Path));
    }

    [Theory]
    [InlineData(true)]  // Outer .cab signed
    [InlineData(false)] // Outer .cab unsigned, but SHA-256 pinned + inner .cat signed!
    public async Task InstallAsync_UnElevated_LiveNamedPipe_FrameworkCabCapsule_OuterSignedOrSignedInnerCat_Succeeds(bool outerCabSigned)
    {
        var cabBytes = BuildSampleCapsuleCab(infName: "Firmware.INF", includeCat: true);
        var payload = TestPayload.FromBytes(cabBytes);
        var handler = new FakeBiosHttpHandler().MapBytes(SampleCabUrl, payload.Bytes);
        var localLauncher = CreateGuardedLauncher();
        var agentLauncher = CreateGuardedLauncher((call, _) =>
            Task.FromResult(new ProcessResult(call.BaseName.Equals("pnputil.exe", StringComparison.OrdinalIgnoreCase) ? 3010 : 0, "OK", "")));

        using var hostStaging = new TempStagingDir();
        using var adminRoot = new TempStagingDir();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));

        var agentVerifier = new FakeSignatureVerifier((path, _) =>
            Task.FromResult(outerCabSigned
                ? path.EndsWith(".cab", StringComparison.OrdinalIgnoreCase)
                : path.EndsWith(".cat", StringComparison.OrdinalIgnoreCase)));

        var ops = new AgentBiosOperations(agentLauncher, signatureVerifier: agentVerifier, stagingRoot: adminRoot.Path);

        var (server, serverTask, client) = await StartPipeAsync(agentLauncher, ops, cts.Token);
        using (server)
        {
            await using (client)
            {
                var provider = FrameworkBiosUpdateProvider.CreateWithHandler(
                    handler,
                    commands: RecordingProcessLauncher.CreateCommandRunner(localLauncher, isProcessElevated: false),
                    signatureVerifier: new FakeSignatureVerifier(true),
                    elevatedBridge: client,
                    isProcessElevated: () => false);

                var res = await provider.InstallAsync(
                    CreateFrameworkInstallRequest(
                        downloadUrl: SampleCabUrl,
                        sha256: payload.Sha256,
                        stagingDirectory: hostStaging.Path),
                    ct: cts.Token);

                Assert.True(res.Succeeded);
                Assert.Equal(BiosInstallStatus.StagedForReboot, res.Status);
                Assert.True(res.BitLockerSuspended);
                Assert.Empty(localLauncher.Calls);

                // Host MUST NOT have extracted any cab-extract-* folder when un-elevated!
                Assert.Empty(Directory.GetDirectories(hostStaging.Path));

                Assert.Equal(2, agentLauncher.Calls.Count);
                Assert.Equal("manage-bde.exe", agentLauncher.Calls[0].BaseName);
                Assert.Equal("pnputil.exe", agentLauncher.Calls[1].BaseName);
                Assert.Equal("/add-driver", agentLauncher.Calls[1].Arguments[0]);
                Assert.StartsWith(adminRoot.Path, agentLauncher.Calls[1].Arguments[1], StringComparison.OrdinalIgnoreCase);
                Assert.EndsWith("Firmware.INF", agentLauncher.Calls[1].Arguments[1], StringComparison.Ordinal);
                Assert.Equal("/install", agentLauncher.Calls[1].Arguments[2]);
            }

            await serverTask;
        }

        Assert.Empty(Directory.GetFileSystemEntries(adminRoot.Path));
    }

    [Fact]
    public async Task InstallAsync_UnElevated_LiveNamedPipe_UnsignedCabWithNoSignedCat_RejectedFailClosed()
    {
        var cabBytes = BuildSampleCapsuleCab(includeCat: true);
        var payload = TestPayload.FromBytes(cabBytes);
        var handler = new FakeBiosHttpHandler().MapBytes(SampleCabUrl, payload.Bytes);
        var agentLauncher = CreateGuardedLauncher();

        using var adminRoot = new TempStagingDir();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));

        // Neither .cab nor .cat passes Authenticode -> Agent MUST fail closed even when SHA-256 matches!
        var ops = new AgentBiosOperations(
            agentLauncher,
            signatureVerifier: new FakeSignatureVerifier(false),
            stagingRoot: adminRoot.Path);

        var (server, serverTask, client) = await StartPipeAsync(agentLauncher, ops, cts.Token);
        using (server)
        {
            await using (client)
            {
                var provider = FrameworkBiosUpdateProvider.CreateWithHandler(
                    handler,
                    signatureVerifier: new FakeSignatureVerifier(true),
                    elevatedBridge: client,
                    isProcessElevated: () => false);

                var res = await provider.InstallAsync(
                    CreateFrameworkInstallRequest(downloadUrl: SampleCabUrl, sha256: payload.Sha256, suspendBitLocker: false),
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
    public async Task InstallAsync_UnElevated_DisconnectedBridge_And_LegacyAgent_FailClosed_ZeroLocalCalls()
    {
        var cabBytes = BuildSampleCapsuleCab();
        var payload = TestPayload.FromBytes(cabBytes);
        var handler = new FakeBiosHttpHandler().MapBytes(SampleCabUrl, payload.Bytes);
        var localLauncher = CreateGuardedLauncher();
        var commands = RecordingProcessLauncher.CreateCommandRunner(localLauncher, isProcessElevated: false);

        // 1. Disconnected / null bridge
        var noBridgeProvider = FrameworkBiosUpdateProvider.CreateWithHandler(
            handler, commands: commands, elevatedBridge: null, isProcessElevated: () => false);
        var r1 = await noBridgeProvider.InstallAsync(CreateFrameworkInstallRequest(downloadUrl: SampleCabUrl, sha256: payload.Sha256));
        Assert.False(r1.Succeeded);
        Assert.Equal(SystemCommandRunner.AgentFailedExitCode, r1.ExitCode);
        Assert.Empty(localLauncher.Calls);

        // 2. Legacy Agent (biosOperations: null)
        var agentLauncher = CreateGuardedLauncher();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var (server, serverTask, client) = await StartPipeAsync(agentLauncher, biosOps: null, cts.Token);
        using (server)
        {
            await using (client)
            {
                var legacyProvider = FrameworkBiosUpdateProvider.CreateWithHandler(
                    handler, commands: commands, elevatedBridge: client, isProcessElevated: () => false);
                var r2 = await legacyProvider.InstallAsync(
                    CreateFrameworkInstallRequest(downloadUrl: SampleCabUrl, sha256: payload.Sha256, suspendBitLocker: false),
                    ct: cts.Token);
                Assert.False(r2.Succeeded);
                Assert.Equal(SystemCommandRunner.AgentFailedExitCode, r2.ExitCode);
                Assert.Empty(localLauncher.Calls);
                Assert.Empty(agentLauncher.Calls);
            }

            await serverTask;
        }
    }

    [Fact]
    public async Task InstallAsync_Elevated_ExeMode_HonorsAllowReboot_And_RedactsSerialFromLogTail()
    {
        var payload = TestPayload.FromString("framework-exe-local");
        var handler = new FakeBiosHttpHandler().MapBytes(SampleExeUrl, payload.Bytes);

        // 1. AllowReboot = false -> ["/silent", "/norestart"]
        var launcher1 = CreateGuardedLauncher();
        var p1 = FrameworkBiosUpdateProvider.CreateWithHandler(
            handler,
            commands: RecordingProcessLauncher.CreateCommandRunner(launcher1, isProcessElevated: true),
            signatureVerifier: new FakeSignatureVerifier(true),
            isProcessElevated: () => true);
        var r1 = await p1.InstallAsync(CreateFrameworkInstallRequest(downloadUrl: SampleExeUrl, sha256: payload.Sha256, suspendBitLocker: false, allowReboot: false));
        Assert.True(r1.Succeeded);
        Assert.Equal(["/silent", "/norestart"], launcher1.Calls[0].Arguments);

        // 2. AllowReboot = true + non-zero exit code with serial leak -> ["/silent"], redacted
        var log = new CapturedLog();
        var launcher2 = CreateGuardedLauncher((_, _) =>
            Task.FromResult(new ProcessResult(5, "", $"Flash error on {BiosIdentityFactory.SentinelSerialNumber}")));
        var p2 = FrameworkBiosUpdateProvider.CreateWithHandler(
            handler,
            commands: RecordingProcessLauncher.CreateCommandRunner(launcher2, log: log.Logger, isProcessElevated: true),
            signatureVerifier: new FakeSignatureVerifier(true),
            isProcessElevated: () => true,
            log: log.Logger);
        var r2 = await p2.InstallAsync(CreateFrameworkInstallRequest(downloadUrl: SampleExeUrl, sha256: payload.Sha256, suspendBitLocker: false, allowReboot: true));
        Assert.False(r2.Succeeded);
        Assert.Equal(5, r2.ExitCode);
        Assert.Equal(["/silent"], launcher2.Calls[0].Arguments);
        Assert.DoesNotContain(BiosIdentityFactory.SentinelSerialNumber, r2.LogTail ?? "", StringComparison.OrdinalIgnoreCase);
        log.AssertDoesNotContainSecret();
    }

    [Fact]
    public async Task InstallAsync_MultipleInfsInCab_DeterministicallySelectsShallowestFirmwareInf()
    {
        var cabBytes = TestCabBuilder.CreateUncompressed(new Dictionary<string, byte[]>(StringComparer.Ordinal)
        {
            ["deep/nested/firmware.inf"] = Encoding.UTF8.GetBytes("[Version]"),
            ["aaa_driver.inf"] = Encoding.UTF8.GetBytes("[Version]"),
            ["FrameworkFirmware.INF"] = Encoding.UTF8.GetBytes("[Version]"),
            ["firmware.bin"] = Encoding.UTF8.GetBytes("DATA"),
        });

        var payload = TestPayload.FromBytes(cabBytes);
        var handler = new FakeBiosHttpHandler().MapBytes(SampleCabUrl, payload.Bytes);
        var launcher = CreateGuardedLauncher();

        var provider = FrameworkBiosUpdateProvider.CreateWithHandler(
            handler,
            commands: RecordingProcessLauncher.CreateCommandRunner(launcher, isProcessElevated: true),
            signatureVerifier: new FakeSignatureVerifier(true),
            isProcessElevated: () => true);

        var res = await provider.InstallAsync(CreateFrameworkInstallRequest(
            downloadUrl: SampleCabUrl, sha256: payload.Sha256, suspendBitLocker: false));

        Assert.True(res.Succeeded);
        Assert.Single(launcher.Calls);
        Assert.Equal("pnputil.exe", launcher.Calls[0].BaseName);
        // Shallowest depth (1) + firmware-named ("FrameworkFirmware.INF") beats "aaa_driver.inf" and "deep/nested/firmware.inf"!
        Assert.EndsWith("FrameworkFirmware.INF", launcher.Calls[0].Arguments[1], StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetLatestVersionAsync_UntrustedCompetingRelease_HttpErrors_And_Cancellation()
    {
        var sys = BiosIdentityFactory.Framework(biosVersion: "03.03");
        const string jsonUrl = "https://api.frame.work/v1/bios.json";

        // 1. Trusted older + untrusted newer -> fail closed
        var hDg = new FakeBiosHttpHandler().MapJson(jsonUrl, $$"""
            {
              "releases": [
                { "boardProduct": "FRANMDCP07", "version": "03.04", "downloadUrl": "{{SampleCabUrl}}" },
                { "boardProduct": "FRANMDCP07", "version": "03.09", "downloadUrl": "https://evil.example.com/fw.cab" }
              ]
            }
            """);
        Assert.Equal(BiosCheckStatus.Failed,
            (await FrameworkBiosUpdateProvider.CreateWithHandler(hDg, catalogUrl: jsonUrl).GetLatestVersionAsync(sys, sys.CurrentBios)).Status);

        // 2. 404 -> UnsupportedHardware, 503 -> ProviderUnavailable, network error -> Offline
        var h404 = new FakeBiosHttpHandler().MapStatus(jsonUrl, HttpStatusCode.NotFound);
        Assert.Equal(BiosCheckStatus.UnsupportedHardware,
            (await FrameworkBiosUpdateProvider.CreateWithHandler(h404, catalogUrl: jsonUrl).GetLatestVersionAsync(sys, sys.CurrentBios)).Status);

        var h503 = new FakeBiosHttpHandler().MapStatus(jsonUrl, HttpStatusCode.ServiceUnavailable);
        Assert.Equal(BiosCheckStatus.ProviderUnavailable,
            (await FrameworkBiosUpdateProvider.CreateWithHandler(h503, catalogUrl: jsonUrl).GetLatestVersionAsync(sys, sys.CurrentBios)).Status);

        var hOff = new FakeBiosHttpHandler().MapException(jsonUrl, () => new HttpRequestException("dns fail"));
        Assert.Equal(BiosCheckStatus.Offline,
            (await FrameworkBiosUpdateProvider.CreateWithHandler(hOff, catalogUrl: jsonUrl).GetLatestVersionAsync(sys, sys.CurrentBios)).Status);

        // 3. Cancellation throws
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            FrameworkBiosUpdateProvider.CreateWithHandler(h404, catalogUrl: jsonUrl).GetLatestVersionAsync(sys, sys.CurrentBios, cts.Token));
    }

    // -------------------------------------------------------------------------
    // M4 Iteration 2 Regression Tests
    // -------------------------------------------------------------------------

    [Fact]
    public async Task InstallAsync_SymlinkDanglingAncestorAndPartTarget_RejectedFailClosedForCabAndExe()
    {
        var root = Path.Combine(Path.GetTempPath(), $"rpd-fw-sym-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        try
        {
            var cabPayload = TestPayload.FromBytes(BuildSampleCapsuleCab());
            var exePayload = TestPayload.FromString("framework-exe-payload");

            var outsideDir = Path.Combine(root, "outside");
            Directory.CreateDirectory(outsideDir);

            var symStage = Path.Combine(root, "sym-stage");
            Directory.CreateSymbolicLink(symStage, outsideDir);

            var danglingStage = Path.Combine(root, "dangling-stage");
            Directory.CreateSymbolicLink(danglingStage, Path.Combine(root, "missing-target"));

            var symParent = Path.Combine(root, "sym-parent");
            Directory.CreateSymbolicLink(symParent, outsideDir);
            var nestedUnderSym = Path.Combine(symParent, "nested-stage");

            var realStage = Path.Combine(root, "real-stage");
            Directory.CreateDirectory(realStage);
            var victimFile = Path.Combine(root, "victim.txt");
            await File.WriteAllTextAsync(victimFile, "ORIGINAL-VICTIM-CONTENT");
            var cabPartLink = Path.Combine(realStage, Path.GetFileName(new Uri(SampleCabUrl).AbsolutePath) + ".part");
            File.CreateSymbolicLink(cabPartLink, victimFile);
            var exePartLink = Path.Combine(realStage, Path.GetFileName(new Uri(SampleExeUrl).AbsolutePath) + ".part");
            File.CreateSymbolicLink(exePartLink, victimFile);

            foreach (var (url, payload) in new[] { (SampleCabUrl, cabPayload), (SampleExeUrl, exePayload) })
            {
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
                    var provider = FrameworkBiosUpdateProvider.CreateWithHandler(
                        handler,
                        commands: commands,
                        signatureVerifier: new FakeSignatureVerifier(true),
                        isProcessElevated: () => true);

                    var res = await provider.InstallAsync(CreateFrameworkInstallRequest(
                        downloadUrl: url,
                        sha256: payload.Sha256,
                        suspendBitLocker: true,
                        stagingDirectory: dir));

                    Assert.False(res.Succeeded, $"Expected symlink staging '{dir}' for '{url}' to fail closed.");
                    Assert.False(res.BitLockerSuspended);
                    Assert.False(httpCalled);
                    Assert.Empty(launcher.Calls);
                }
            }

            Assert.Equal("ORIGINAL-VICTIM-CONTENT", await File.ReadAllTextAsync(victimFile));
            Assert.Empty(Directory.GetFiles(outsideDir));
        }
        finally
        {
            if (Directory.Exists(root))
                Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task InstallAsync_CallerStaging_DeletesRejectedCabOnAllPreValidationFailures()
    {
        var cases = new (string Name, byte[] Bytes)[]
        {
            ("corrupt", Encoding.UTF8.GetBytes("NOT-A-VALID-CAB")),
            ("zero-inf", TestCabBuilder.CreateUncompressed(new Dictionary<string, byte[]>
            {
                ["firmware.bin"] = Encoding.UTF8.GetBytes("bin-only"),
            })),
            ("traversal-dotdot", TestCabBuilder.CreateUncompressed(new Dictionary<string, byte[]>
            {
                ["../evil.inf"] = Encoding.UTF8.GetBytes("[Version]"),
            })),
            ("traversal-abs", TestCabBuilder.CreateUncompressed(new Dictionary<string, byte[]>
            {
                ["/abs.inf"] = Encoding.UTF8.GetBytes("[Version]"),
            })),
            ("metachar-semicolon", TestCabBuilder.CreateUncompressed(new Dictionary<string, byte[]>
            {
                ["firm;calc.inf"] = Encoding.UTF8.GetBytes("[Version]"),
            })),
            ("metachar-ads", TestCabBuilder.CreateUncompressed(new Dictionary<string, byte[]>
            {
                ["sub:ads/a.inf"] = Encoding.UTF8.GetBytes("[Version]"),
            })),
            ("collision-casevariant", TestCabBuilder.CreateUncompressed(new Dictionary<string, byte[]>
            {
                ["Sub"] = Encoding.UTF8.GetBytes("file"),
                ["sub/firmware.inf"] = Encoding.UTF8.GetBytes("[Version]"),
            })),
        };

        var root = Path.Combine(Path.GetTempPath(), $"rpd-fw-clean-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        try
        {
            foreach (var (name, bytes) in cases)
            {
                var callerStage = Path.Combine(root, name);
                Directory.CreateDirectory(callerStage);

                var cabUrl = $"https://cdn.fwupd.org/downloads/bad-{name}.cab";
                var payload = TestPayload.FromBytes(bytes);
                var handler = new FakeBiosHttpHandler().MapBytes(cabUrl, payload.Bytes);
                var launcher = CreateGuardedLauncher();
                var commands = RecordingProcessLauncher.CreateCommandRunner(launcher, isProcessElevated: true);

                var provider = FrameworkBiosUpdateProvider.CreateWithHandler(
                    handler,
                    commands: commands,
                    signatureVerifier: new FakeSignatureVerifier(true),
                    isProcessElevated: () => true);

                var res = await provider.InstallAsync(CreateFrameworkInstallRequest(
                    downloadUrl: cabUrl,
                    sha256: payload.Sha256,
                    suspendBitLocker: true,
                    stagingDirectory: callerStage));

                Assert.False(res.Succeeded, $"Expected invalid CAB case '{name}' to fail.");
                Assert.False(res.BitLockerSuspended);
                Assert.Empty(launcher.Calls);
                Assert.Empty(Directory.GetFiles(callerStage));
            }
        }
        finally
        {
            if (Directory.Exists(root))
                Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task InstallAsync_LongLvfsCabFileNameOver128Chars_PreservesCabExtensionAndSucceeds()
    {
        var shaPrefix = new string('a', 64);
        var longCabName = $"{shaPrefix}-Framework_Laptop_13_AMD_Ryzen_AI_300_Series_System_Firmware_03.05_Release.cab";
        Assert.True(longCabName.Length > 128);

        var longUrl = "https://cdn.fwupd.org/downloads/" + longCabName;
        var payload = TestPayload.FromBytes(BuildSampleCapsuleCab());
        var handler = new FakeBiosHttpHandler().MapBytes(longUrl, payload.Bytes);
        var launcher = CreateGuardedLauncher();
        var commands = RecordingProcessLauncher.CreateCommandRunner(launcher, isProcessElevated: true);

        var provider = FrameworkBiosUpdateProvider.CreateWithHandler(
            handler,
            commands: commands,
            signatureVerifier: new FakeSignatureVerifier(true),
            isProcessElevated: () => true);

        var res = await provider.InstallAsync(CreateFrameworkInstallRequest(
            downloadUrl: longUrl,
            sha256: payload.Sha256,
            suspendBitLocker: false));

        Assert.True(res.Succeeded);
        Assert.Single(launcher.Calls);
        Assert.Equal("pnputil.exe", launcher.Calls[0].BaseName);
    }

    [Fact]
    public async Task InstallAsync_RejectsAdversarialPackageRedirects_And_ExtensionMismatch()
    {
        var payload = TestPayload.FromBytes(BuildSampleCapsuleCab());
        string[] adversarialTargets =
        [
            "https:../evil.cab",
            "https://cdn.fwupd.org/downloads/%252e%252e/evil.cab",
            "https://cdn.fwupd.org/downloads/%2f/evil.cab",
            "https://cdn.fwupd.org/downloads/evil.exe",
        ];

        foreach (var targetLoc in adversarialTargets)
        {
            var reqCount = 0;
            var handler = new FakeBiosHttpHandler().MapPredicate(_ => true, (_, _) =>
            {
                reqCount++;
                var resp = new HttpResponseMessage(HttpStatusCode.Found);
                resp.Headers.TryAddWithoutValidation("Location", targetLoc);
                return Task.FromResult(resp);
            });

            var launcher = CreateGuardedLauncher();
            var commands = RecordingProcessLauncher.CreateCommandRunner(launcher, isProcessElevated: true);
            var provider = FrameworkBiosUpdateProvider.CreateWithHandler(
                handler, commands: commands, signatureVerifier: new FakeSignatureVerifier(true), isProcessElevated: () => true);

            var res = await provider.InstallAsync(CreateFrameworkInstallRequest(
                downloadUrl: SampleCabUrl, sha256: payload.Sha256, suspendBitLocker: true));

            Assert.False(res.Succeeded, $"Expected redirect '{targetLoc}' to fail closed.");
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
                resp.Headers.TryAddWithoutValidation("Location", "https://cdn.fwupd.org/downloads/a.cab");
                resp.Headers.TryAddWithoutValidation("Location", "https://cdn.fwupd.org/downloads/b.cab");
                return Task.FromResult(resp);
            });

            var launcher = CreateGuardedLauncher();
            var commands = RecordingProcessLauncher.CreateCommandRunner(launcher, isProcessElevated: true);
            var provider = FrameworkBiosUpdateProvider.CreateWithHandler(
                handler, commands: commands, signatureVerifier: new FakeSignatureVerifier(true), isProcessElevated: () => true);

            var res = await provider.InstallAsync(CreateFrameworkInstallRequest(
                downloadUrl: SampleCabUrl, sha256: payload.Sha256, suspendBitLocker: true));

            Assert.False(res.Succeeded);
            Assert.Equal(1, reqCount);
            Assert.Empty(launcher.Calls);
        }
    }

    [Fact]
    public async Task GetLatestVersionAsync_HigherMatchRankUntrustedRelease_FailsClosedOnEqualAndLowerVersion()
    {
        var sys = BiosIdentityFactory.Framework(
            model: "Laptop 13 (AMD Ryzen 7040Series)",
            boardProduct: "FRANMDCP07",
            biosVersion: "03.03");
        const string jsonUrl = "https://api.frame.work/v1/bios.json";

        // 1. Equal version: Rank 3 (exact board FRANMDCP07) untrusted vs Rank 2 (model match) trusted -> FAIL CLOSED.
        var hEqual = new FakeBiosHttpHandler().MapJson(jsonUrl, $$"""
            {
              "releases": [
                { "model": "Laptop 13 (AMD Ryzen 7040 Series)", "version": "03.05", "downloadUrl": "{{SampleCabUrl}}" },
                { "boardProduct": "FRANMDCP07", "version": "03.05", "downloadUrl": "https://evil.example.com/fw0305.cab" }
              ]
            }
            """);
        Assert.Equal(BiosCheckStatus.Failed,
            (await FrameworkBiosUpdateProvider.CreateWithHandler(hEqual, catalogUrl: jsonUrl)
                .GetLatestVersionAsync(sys, sys.CurrentBios)).Status);

        // 2. Lower version at higher rank: Rank 3 untrusted (03.04) vs Rank 2 trusted (03.05) -> FAIL CLOSED.
        var hLower = new FakeBiosHttpHandler().MapJson(jsonUrl, $$"""
            {
              "releases": [
                { "model": "Laptop 13 (AMD Ryzen 7040 Series)", "version": "03.05", "downloadUrl": "{{SampleCabUrl}}" },
                { "boardProduct": "FRANMDCP07", "version": "03.04", "downloadUrl": "https://evil.example.com/fw0304.cab" }
              ]
            }
            """);
        Assert.Equal(BiosCheckStatus.Failed,
            (await FrameworkBiosUpdateProvider.CreateWithHandler(hLower, catalogUrl: jsonUrl)
                .GetLatestVersionAsync(sys, sys.CurrentBios)).Status);
    }

    [Fact]
    public async Task GetLatestVersionAsync_RejectsPeripheralComponentEvenWhenSummaryMentionsUefi()
    {
        var sys = BiosIdentityFactory.Framework(
            model: "Laptop 13 (AMD Ryzen 7040Series)",
            boardProduct: "FRANMDCP07",
            biosVersion: "03.03");
        const string xmlUrl = "https://cdn.fwupd.org/downloads/firmware.xml";
        const string xml = """
            <?xml version="1.0" encoding="UTF-8"?>
            <components>
              <component type="firmware">
                <id>work.frame.Laptop13AMD.fingerprint</id>
                <developer_name>Framework</developer_name>
                <name>Framework Laptop 13 (AMD Ryzen 7040 Series) Fingerprint Reader Firmware</name>
                <summary>Fingerprint reader update for UEFI systems</summary>
                <keywords><keyword>FRANMDCP07</keyword></keywords>
                <releases>
                  <release version="09.99" timestamp="1735689600">
                    <location>https://cdn.fwupd.org/downloads/fp.cab</location>
                  </release>
                </releases>
              </component>
            </components>
            """;

        var handler = new FakeBiosHttpHandler().MapText(xmlUrl, xml, "application/xml");
        var latest = await FrameworkBiosUpdateProvider
            .CreateWithHandler(handler, catalogUrl: xmlUrl)
            .GetLatestVersionAsync(sys, sys.CurrentBios);

        Assert.Equal(BiosCheckStatus.UnsupportedHardware, latest.Status);
    }

    [Fact]
    public async Task SerialNumberRedaction_CoversGetCurrentInstallLogsProgressAndUrlPaths()
    {
        const string complexSerial = "FW SN 9988,77";
        var sysWithLeaks = BiosIdentityFactory.Framework(serialNumber: complexSerial) with
        {
            CurrentBios = new BiosCurrentInfo(
                Vendor: $"INSYDE {complexSerial}",
                Version: $"03.03-{complexSerial}",
                ReleaseDate: new DateOnly(2024, 1, 1),
                ReleaseDateRaw: $"20240101-{complexSerial}",
                SmbiosRevision: $"3.4-{complexSerial}",
                FirmwareMode: BiosFirmwareMode.Uefi,
                Family: $"Framework-{complexSerial}"),
        };

        // 1. GetCurrentVersionAsync redacts Vendor, ReleaseDateRaw, SmbiosRevision, Version, Family.
        var cur = await new FrameworkBiosUpdateProvider().GetCurrentVersionAsync(sysWithLeaks);
        Assert.DoesNotContain(complexSerial, cur.Vendor, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(complexSerial, cur.Version, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(complexSerial, cur.ReleaseDateRaw, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(complexSerial, cur.SmbiosRevision, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(complexSerial, cur.Family, StringComparison.OrdinalIgnoreCase);

        // 2. ContainsSerialInUrl nulls space+subdelim serial in URL path.
        const string jsonUrl = "https://api.frame.work/v1/bios.json";
        var hCat = new FakeBiosHttpHandler().MapJson(jsonUrl, """
            {
              "releases": [
                {
                  "boardProduct": "FRANMDCP07",
                  "version": "03.05",
                  "downloadUrl": "https://cdn.fwupd.org/downloads/FW+SN+9988,77/fw.cab"
                }
              ]
            }
            """);
        var sysForCatalog = BiosIdentityFactory.Framework(biosVersion: "03.03", serialNumber: complexSerial);
        var latest = await FrameworkBiosUpdateProvider
            .CreateWithHandler(hCat, catalogUrl: jsonUrl)
            .GetLatestVersionAsync(sysForCatalog, sysForCatalog.CurrentBios);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Null(latest.DownloadUrl);

        // 3. InstallAsync redacts raw & URL-encoded serial in ILogger and IProgress on download error AND installer launch.
        const string spaceSerial = "FW SN 998877";
        var encodedSerial = Uri.EscapeDataString(spaceSerial);
        var secretExeUrl = $"https://downloads.frame.work/bios/fw-{encodedSerial}.exe";
        var log = new CapturedLog();
        var progress = new SyncProgress<BiosInstallProgress>();

        var sysSpace = BiosIdentityFactory.Framework(serialNumber: spaceSerial);
        var hErr = new FakeBiosHttpHandler().MapException(
            secretExeUrl,
            () => new HttpRequestException($"Failed GET https://downloads.frame.work/bios/{encodedSerial}/bios.exe for {spaceSerial}"));
        var pErr = FrameworkBiosUpdateProvider.CreateWithHandler(hErr, log: log.Logger, isProcessElevated: () => true);
        var rErr = await pErr.InstallAsync(
            CreateFrameworkInstallRequest(system: sysSpace, downloadUrl: secretExeUrl, targetVersion: $"03.05-{spaceSerial}", suspendBitLocker: false),
            progress: progress);
        Assert.False(rErr.Succeeded);
        Assert.DoesNotContain(spaceSerial, rErr.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(encodedSerial, rErr.Message, StringComparison.OrdinalIgnoreCase);

        var payload = TestPayload.FromString("framework-exe-secret");
        var hOk = new FakeBiosHttpHandler().MapBytes(secretExeUrl, payload.Bytes);
        var launcher = CreateGuardedLauncher();
        var commands = RecordingProcessLauncher.CreateCommandRunner(launcher, log: log.Logger, isProcessElevated: true);
        var pOk = FrameworkBiosUpdateProvider.CreateWithHandler(
            hOk, commands: commands, signatureVerifier: new FakeSignatureVerifier(true), isProcessElevated: () => true, log: log.Logger);
        var rOk = await pOk.InstallAsync(
            CreateFrameworkInstallRequest(system: sysSpace, downloadUrl: secretExeUrl, sha256: payload.Sha256, targetVersion: $"03.05-{spaceSerial}", suspendBitLocker: false),
            progress: progress);
        Assert.True(rOk.Succeeded);

        log.AssertDoesNotContainSecret(spaceSerial);
        log.AssertDoesNotContainSecret(encodedSerial);
        Assert.NotEmpty(progress.Reports);
        Assert.All(progress.Reports, ev =>
        {
            Assert.DoesNotContain(spaceSerial, ev.Detail ?? "", StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(encodedSerial, ev.Detail ?? "", StringComparison.OrdinalIgnoreCase);
        });
    }
}
