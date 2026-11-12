using System.Net;
using System.Text;
using System.Text.Json;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Benchmarks;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Preferences;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Workflow;

namespace RemotePCDiagnostics.Tests;

public class ShopRelayIntegrationTests
{
    private const string SamplePngDataUri =
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";

    private sealed class StubHttpHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> responder) : HttpMessageHandler
    {
        public int CallCount { get; private set; }
        public HttpRequestMessage? LastRequest { get; private set; }
        public string? LastRequestBody { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            CallCount++;
            LastRequest = request;
            if (request.Content is not null)
                LastRequestBody = await request.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            return await responder(request, cancellationToken).ConfigureAwait(false);
        }
    }

    private static HttpResponseMessage JsonResponse(HttpStatusCode status, string json) => new(status)
    {
        Content = new StringContent(json, Encoding.UTF8, "application/json"),
    };

    private static Func<string, string?> Env(params (string K, string V)[] kv) =>
        k => kv.FirstOrDefault(x => x.K == k).V;

    [Theory]
    [InlineData(new[] { "-u=https://relay.example", "-g=acme-pc" }, "acme-pc")]
    [InlineData(new[] { "-u=https://relay.example", "--group=NorthSide-Repair" }, "northside-repair")]
    [InlineData(new[] { "-u=https://relay.example", "-g", "  Acme-PC  " }, "acme-pc")]
    [InlineData(new[] { "-u=https://relay.example", "--group", "\"Bench_01\"" }, "bench_01")]
    public void SessionLaunchOptions_ParsesAndNormalizesCliGroupFlags(string[] args, string expectedGroup)
    {
        var opts = SessionLaunchOptions.Parse(args);
        Assert.Equal(SessionMode.Remote, opts.Mode);
        Assert.Equal(expectedGroup, opts.Group);

        var ctx = new SessionContext(opts.Mode, opts.ServerUri, opts.Id, opts.Unattended, opts.Voice, opts.Group);
        Assert.Equal(expectedGroup, ctx.Group);
    }

    [Fact]
    public void SessionLaunchOptions_FallsBackToRemotePcGroupEnvVar_AndStripsGroupOnStaleResume()
    {
        var fromEnv = SessionLaunchOptions.Resolve(
            [],
            Env(("REMOTEPC_MODE", "Remote"), ("REMOTEPC_SERVER_URL", "https://relay.example"), ("REMOTEPC_GROUP", "  Summit-Refurb ")));
        Assert.Equal(SessionMode.Remote, fromEnv.Mode);
        Assert.Equal("summit-refurb", fromEnv.Group);

        Assert.Null(SessionLaunchOptions.NormalizeGroup("   "));
        Assert.Null(SessionLaunchOptions.NormalizeGroup(null));

        // Stale RunOnce resume (PC did NOT restart since pending state was saved) drops -u, -i, and -g so the app starts Local.
        var saved = new DateTimeOffset(2026, 11, 12, 10, 0, 0, TimeSpan.Zero);
        var pending = new PendingRebootState(
            saved,
            "Remote user",
            SessionMode.Remote,
            "https://relay.example",
            Guid.Parse("7e57c0de-0000-4000-8000-000000000001"),
            PreUptimeSeconds: 100_000,
            PreUsedMemoryBytes: 4L << 30,
            PreProcessCount: 120,
            PreTopProcesses: "chrome.exe (2 GB)",
            Unattended: true,
            Voice: false,
            Group: "acme-pc");

        var staleArgs = new[] { "-u=https://relay.example", "-i=7e57c0de-0000-4000-8000-000000000001", "-g=acme-pc", "--unattended", "--post-reboot" };
        var staleResolved = SessionLaunchOptions.Resolve(staleArgs, Env(), pending, nowUtc: saved.AddHours(2), uptime: TimeSpan.FromSeconds(107_200));
        Assert.Equal(SessionMode.Local, staleResolved.Mode);
        Assert.Null(staleResolved.Group);
    }

    [Fact]
    public async Task RebootResumeAndRestartArguments_RoundTripGroupSlugAcrossReboots()
    {
        var server = new Uri("https://relay.example:34544");
        var sessionId = Guid.Parse("7e57c0de-0000-4000-8000-000000000099");

        // 1. Browser disconnect / refresh restart arguments keep -g=acme-pc.
        var restartArgs = SessionLaunchOptions.RestartArguments(server, sessionId, unattended: true, voice: true, group: "Acme-PC");
        Assert.Contains("-g=acme-pc", restartArgs);
        Assert.True(SessionLaunchOptions.IsRestarted(restartArgs));
        var resolvedRestart = SessionLaunchOptions.Parse(restartArgs);
        Assert.Equal(SessionMode.Remote, resolvedRestart.Mode);
        Assert.Equal(sessionId, resolvedRestart.Id);
        Assert.Equal("acme-pc", resolvedRestart.Group);
        Assert.True(resolvedRestart.Unattended);
        Assert.True(resolvedRestart.Voice);

        // 2. BuildResumeCommandLine + PendingRebootState round-trip via RebootResumeCoordinator.
        var tempDir = Path.Combine(Path.GetTempPath(), "rpcd-relay-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            var stateFile = Path.Combine(tempDir, "pending-reboot.json");
            var launcher = new ScriptedLauncher((_, _) => ScriptedLauncher.Ok(""));
            var coordinator = new RebootResumeCoordinator(
                new SystemCommandRunner(launcher),
                stateFilePath: stateFile,
                executablePath: @"C:\Program Files\RemotePCDiagnostics\RemotePCDiagnostics.Host.exe");

            var session = new SessionContext(SessionMode.Remote, server, sessionId, unattended: true, voice: false, group: "Acme-PC");
            var savedState = await coordinator.PrepareForRebootAsync("Remote user", session, "reboot-baseline:up=3600;mem=4294967296;procs=110;top=chrome.exe");

            Assert.Equal("acme-pc", savedState.Group);
            Assert.NotNull(coordinator.LastRegisteredCommandLine);
            Assert.Contains(" -g=acme-pc ", coordinator.LastRegisteredCommandLine);

            var reloaded = RebootResumeCoordinator.TryReadPendingStateFile(stateFile);
            Assert.NotNull(reloaded);
            Assert.Equal("acme-pc", reloaded!.Group);

            var postBoot = SessionLaunchOptions.Resolve(
                [],
                Env(),
                reloaded,
                nowUtc: reloaded.InitiatedAtUtc.AddMinutes(4),
                uptime: TimeSpan.FromMinutes(1));

            Assert.Equal(SessionMode.Remote, postBoot.Mode);
            Assert.Equal(server, postBoot.ServerUri);
            Assert.Equal(sessionId, postBoot.Id);
            Assert.Equal("acme-pc", postBoot.Group);
            Assert.True(postBoot.PostReboot);
            Assert.True(postBoot.Unattended);
        }
        finally
        {
            try { Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }

    [Fact]
    public async Task ShopRelayClient_FetchBrandingAsync_Maps200_FallbackVerifyUrl_404_AndNetworkErrors()
    {
        // 1. 200 OK with blank verificationBaseUrl falls back to {relayBase}/r and maps all ShopBrandingDto fields.
        var dtoJson = JsonSerializer.Serialize(new
        {
            group = "acme-pc",
            active = true,
            shopName = "Acme PC Repair",
            logoDataUri = SamplePngDataUri,
            phone = "(555) 010-2000",
            email = "service@acmepc.example",
            website = "https://acmepc.example",
            address = "123 Main St",
            technicianName = "Alex",
            warrantyFooter = "90-day hardware warranty",
            verificationBaseUrl = "",
        });

        var okHandler = new StubHttpHandler((req, _) =>
        {
            Assert.Equal(HttpMethod.Get, req.Method);
            Assert.Equal("https://relay.example/api/shops/acme-pc/branding", req.RequestUri!.ToString());
            return Task.FromResult(JsonResponse(HttpStatusCode.OK, dtoJson));
        });
        var okClient = new ShopRelayClient(new HttpClient(okHandler));
        var found = Assert.IsType<ShopRelayBrandingResult.Found>(
            await okClient.FetchBrandingAsync(new Uri("https://relay.example/"), "  Acme-PC "));

        Assert.Equal("acme-pc", found.GroupSlug);
        Assert.Equal("Acme PC Repair", found.Branding.ShopName);
        Assert.Equal(SamplePngDataUri, found.Branding.SafeLogoDataUri);
        Assert.Equal("(555) 010-2000", found.Branding.Phone);
        Assert.Equal("service@acmepc.example", found.Branding.Email);
        Assert.Equal("https://acmepc.example/", found.Branding.SafeWebsiteHref);
        Assert.Equal("123 Main St", found.Branding.Address);
        Assert.Equal("Alex", found.Branding.TechnicianName);
        Assert.Equal("90-day hardware warranty", found.Branding.WarrantyFooter);
        Assert.Equal("https://relay.example/r", found.Branding.SafeVerificationBaseUrl);

        // 2. 404 Not Found -> NotFoundOrInactive.
        var notFoundHandler = new StubHttpHandler((_, _) =>
            Task.FromResult(JsonResponse(HttpStatusCode.NotFound, """{"error":"not_found"}""")));
        var notFoundClient = new ShopRelayClient(new HttpClient(notFoundHandler));
        var nf = Assert.IsType<ShopRelayBrandingResult.NotFoundOrInactive>(
            await notFoundClient.FetchBrandingAsync(new Uri("https://relay.example"), "expired-shop"));
        Assert.Equal("expired-shop", nf.GroupSlug);

        // 3. Network failure -> NetworkError.
        var netErrHandler = new StubHttpHandler((_, _) =>
            throw new HttpRequestException("DNS name does not exist"));
        var netErrClient = new ShopRelayClient(new HttpClient(netErrHandler));
        var netErr = Assert.IsType<ShopRelayBrandingResult.NetworkError>(
            await netErrClient.FetchBrandingAsync(new Uri("https://offline.relay.example"), "acme-pc"));
        Assert.Contains("DNS name does not exist", netErr.Message);
    }

    [Fact]
    public async Task ShopRelayClient_PublishReportAsync_ValidatesBearerKey_Payloads_AndErrorCodes_WithoutLeakingApiKey()
    {
        const string secretApiKey = "rpd_live_secret_bench_key_987654321";
        var relayUri = new Uri("https://relay.example");

        var branding = new ShopBranding
        {
            ShopName = "Acme PC Repair",
            Phone = "(555) 010-2000",
            WarrantyFooter = "90-day hardware warranty",
            VerificationBaseUrl = "https://relay.example/r",
        }.Normalized();

        var store = new ResultStore();
        var generated = new DateTimeOffset(2026, 11, 12, 16, 0, 0, TimeSpan.Zero);
        var snap = HardwareQaCertificate.Capture(store, "WORKBENCH-01", generated, branding, "Windows 11 Pro");
        var certHtml = HardwareQaCertificate.BuildHtml(snap);

        // QR payload in certificate points to live hosted /r/{id}?h={shortHash} and HTML NEVER contains ShopApiKey!
        Assert.StartsWith($"https://relay.example/r/{snap.CertificateId}?h=", snap.QrPayload);
        Assert.DoesNotContain(secretApiKey, certHtml, StringComparison.OrdinalIgnoreCase);

        var wfReportHtml = ClientReport.Build(new WorkflowState { Branding = branding }, null, null, new BenchmarkComparison([], null, []), generated, branding);
        Assert.DoesNotContain(secretApiKey, wfReportHtml, StringComparison.OrdinalIgnoreCase);

        // 1. Client-side rejection when API key does not start with rpd_live_ (0 network calls).
        var rejectHandler = new StubHttpHandler((_, _) =>
            Task.FromResult(JsonResponse(HttpStatusCode.Created, "{}")));
        var rejectClient = new ShopRelayClient(new HttpClient(rejectHandler));
        var uploadReq = ShopRelayClient.CreateQaCertificateRequest(snap, certHtml);
        var rejected = Assert.IsType<ShopReportPublishResult.InvalidRequest>(
            await rejectClient.PublishReportAsync(relayUri, "sk_wrong_prefix_123", uploadReq));
        Assert.Contains("rpd_live_", rejected.Error);
        Assert.Equal(0, rejectHandler.CallCount);

        // 2. 201 Created sends Bearer header + camelCase JSON payload and parses ReportCreatedDto.
        var createdHandler = new StubHttpHandler((req, _) =>
        {
            Assert.Equal(HttpMethod.Post, req.Method);
            Assert.Equal("https://relay.example/api/reports", req.RequestUri!.ToString());
            Assert.NotNull(req.Headers.Authorization);
            Assert.Equal("Bearer", req.Headers.Authorization!.Scheme);
            Assert.Equal(secretApiKey, req.Headers.Authorization.Parameter);
            var responseJson = JsonSerializer.Serialize(new
            {
                id = snap.CertificateId,
                url = $"https://relay.example/r/{snap.CertificateId}",
                shortHash = snap.VerificationHash[..12],
            });
            return Task.FromResult(JsonResponse(HttpStatusCode.Created, responseJson));
        });

        var publishClient = new ShopRelayClient(new HttpClient(createdHandler));
        var published = Assert.IsType<ShopReportPublishResult.Published>(
            await publishClient.PublishReportAsync(relayUri, "  " + secretApiKey + " ", uploadReq));

        Assert.Equal(snap.CertificateId, published.Id);
        Assert.Equal($"https://relay.example/r/{snap.CertificateId}", published.Url);
        Assert.Equal(snap.VerificationHash[..12], published.ShortHash);

        Assert.NotNull(createdHandler.LastRequestBody);
        using (var doc = JsonDocument.Parse(createdHandler.LastRequestBody!))
        {
            var root = doc.RootElement;
            Assert.Equal(snap.CertificateId, root.GetProperty("id").GetString());
            Assert.Equal("qa_certificate", root.GetProperty("kind").GetString());
            Assert.Contains("Hardware QA Certificate", root.GetProperty("title").GetString());
            Assert.Equal("WORKBENCH-01", root.GetProperty("machineName").GetString());
            Assert.Equal(snap.VerificationHash, root.GetProperty("verificationHash").GetString());
            Assert.Equal(certHtml, root.GetProperty("html").GetString());
        }

        // 3. 401 Unauthorized -> Unauthorized.
        var unauthClient = new ShopRelayClient(new HttpClient(new StubHttpHandler((_, _) =>
            Task.FromResult(JsonResponse(HttpStatusCode.Unauthorized, """{"error":"unauthorized"}""")))));
        Assert.IsType<ShopReportPublishResult.Unauthorized>(
            await unauthClient.PublishReportAsync(relayUri, secretApiKey, uploadReq));

        // 4. 402 PaymentRequired -> PaymentRequired.
        var paymentClient = new ShopRelayClient(new HttpClient(new StubHttpHandler((_, _) =>
            Task.FromResult(JsonResponse(HttpStatusCode.PaymentRequired, """{"error":"payment_required"}""")))));
        Assert.IsType<ShopReportPublishResult.PaymentRequired>(
            await paymentClient.PublishReportAsync(relayUri, secretApiKey, uploadReq));

        // 5. Service report helper builds valid SR-* id and 64-char lowercase SHA-256 hex.
        var srReq = ShopRelayClient.CreateServiceReportRequest("CLIENT-LAPTOP", wfReportHtml, generated);
        Assert.StartsWith("SR-20261112-", srReq.Id);
        Assert.Equal("service_report", srReq.Kind);
        Assert.Equal(64, srReq.VerificationHash!.Length);
        Assert.Equal(srReq.VerificationHash.ToLowerInvariant(), srReq.VerificationHash);
    }

    [Fact]
    public void UserPreferences_PersistsRelayFields_AndRemoteSessionHealthClassifiesRelayErrors()
    {
        var tempFile = Path.Combine(Path.GetTempPath(), "rpcd-prefs-relay-" + Guid.NewGuid().ToString("N") + ".json");
        try
        {
            var store = new FilePreferencesStore(tempFile);
            var svc = new PreferencesService(store);
            svc.Update(p => p with
            {
                RelayServerUrl = "https://relay.example",
                ShopGroupSlug = "acme-pc",
                ShopApiKey = "rpd_live_persisted_key",
            });

            var reloaded = new FilePreferencesStore(tempFile).Load();
            Assert.Equal("https://relay.example", reloaded.RelayServerUrl);
            Assert.Equal("acme-pc", reloaded.ShopGroupSlug);
            Assert.Equal("rpd_live_persisted_key", reloaded.ShopApiKey);
        }
        finally
        {
            try { File.Delete(tempFile); } catch { }
        }

        Assert.Equal(RemoteRelayIssueKind.GroupInactive, RemoteSessionHealth.ClassifyError("createFailed:group_inactive"));
        Assert.Equal(RemoteRelayIssueKind.SessionLimitReached, RemoteSessionHealth.ClassifyError("createFailed:session_limit_reached"));
        Assert.Equal(RemoteRelayIssueKind.CreateFailedOrDenied, RemoteSessionHealth.ClassifyError("WebView Create failed - Id must be unique"));

        var relauncher = new DesktopSessionRelauncher(new SessionContext(SessionMode.Local));
        Assert.False(relauncher.CanRelaunchDesktopProcess);
        var preview = relauncher.RequestRemoteSession(new Uri("https://relay.example/"), "Acme-PC");
        Assert.False(preview.RelaunchedDesktopProcess);
        Assert.Contains("-u=\"https://relay.example\"", preview.CommandLinePreview);
        Assert.Contains("-g=\"acme-pc\"", preview.CommandLinePreview);
    }
}
