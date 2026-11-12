using System.Security.Cryptography;
using System.Text;
using System.Threading.Channels;
using Grpc.Core;
using PeakSWC.RemoteWebView.Agent;
using RemotePCDiagnostics.Agent;

namespace RemotePCDiagnostics.Agent.Core.Tests;

public class AppCacheVersionTests
{
    [Theory]
    [InlineData("1.10.0", "1.9.0", 1)]
    [InlineData("1.2.0", "1.2.0-beta", 1)]
    [InlineData("1.2.0-beta", "1.2.0", -1)]
    [InlineData("1.2", "1.2.0", 0)]
    [InlineData("2.0.0", "10.0.0", -1)]
    [InlineData("1.2.0-alpha", "1.2.0-beta", -1)]
    [InlineData("1.2.0+build1", "1.2.0", 0)]
    [InlineData("1.2.0+build1", "1.2.0-beta", 1)]
    [InlineData("1.2.0-beta+build1", "1.2.0", -1)]
    [InlineData("1.2.0-beta.10", "1.2.0-beta.2", 1)]
    public void Versions_compare_by_number_then_suffix(string a, string b, int sign) =>
        Assert.Equal(sign, Math.Sign(AppCache.CompareVersions(a, b)));

    [Fact]
    public void The_reported_cached_version_is_the_highest_complete_one()
    {
        var validZip = AppCache.FormatRecord(new string('a', 64), "RemotePCDiagnostics-1.0.zip");
        var validEntry = AppCache.FormatRecord(new string('b', 64), "RemotePCDiagnostics.Host.exe");
        var folders = new[]
        {
            new CachedFolder("1.9.0", true, validZip, validEntry),
            new CachedFolder("1.10.0", true, validZip, validEntry),
            new CachedFolder("2.0.0", false, validZip, validEntry),       // program missing
            new CachedFolder("3.0.0.partial", true, validZip, validEntry),// staging folder, not a version
            new CachedFolder("1.11.0", true, null, validEntry),           // no zip record
            new CachedFolder("1.12.0", true, "corrupt", validEntry),      // malformed zip sha256 record
            new CachedFolder("1.13.0", true, validZip, "corrupt"),        // malformed entry sha256 record
        };
        Assert.Equal("1.10.0", AppCache.PickCachedVersion(folders));
        Assert.Equal("", AppCache.PickCachedVersion([]));
    }

    [Fact]
    public void Records_round_trip_and_reject_other_files()
    {
        var hash = new string('A', 64);
        var record = AppCache.FormatRecord(hash, "app.zip");
        Assert.Equal(new string('a', 64) + " *app.zip\n", record);
        Assert.Equal(new string('a', 64), AppCache.ParseRecord(record, "APP.zip"));
        Assert.Null(AppCache.ParseRecord(record, "other.zip"));
        Assert.Null(AppCache.ParseRecord(record + "extra line", "app.zip"));
        Assert.Null(AppCache.ParseRecord("abc *app.zip", "app.zip"));
        Assert.Null(AppCache.ParseRecord(null, "app.zip"));
    }

    [Fact]
    public void A_cached_folder_is_used_only_for_the_manifest_release()
    {
        var m = Manifests.Valid();
        var zip = AppCache.FormatRecord(m.Sha256, m.File);
        var entry = AppCache.FormatRecord(new string('b', 64), m.Entry);
        Assert.True(AppCache.IsUsable(m, new CachedFolder(m.Version, true, zip, entry)));
        Assert.False(AppCache.IsUsable(m, new CachedFolder("1.0.0", true, zip, entry)));
        Assert.False(AppCache.IsUsable(m, new CachedFolder(m.Version, false, zip, entry)));
        Assert.False(AppCache.IsUsable(m, new CachedFolder(m.Version, true, AppCache.FormatRecord(new string('c', 64), m.File), entry)));
        Assert.False(AppCache.IsUsable(m, null));
        Assert.Equal(["1.0.0", "1.2.3.partial"], AppCache.FoldersToDelete(["1.0.0", m.Version, "1.2.3.partial"], m.Version));
    }
}

public class ReleaseUrlsTests
{
    private static readonly Uri Request = new(ReleaseUrls.ManifestUrl);

    [Theory]
    [InlineData("/budcribar/RemotePCDiagnostics/releases/download/v1.2.3/manifest.json")]
    [InlineData("https://objects.githubusercontent.com/github-production-release-asset/123?X-Amz-Algorithm=AWS4")]
    [InlineData("https://release-assets.githubusercontent.com/github-production-release-asset/456?sp=r")]
    public void Valid_redirects_resolve(string location)
    {
        var resolved = ReleaseUrls.ResolveRedirect(Request, new Uri(location, UriKind.RelativeOrAbsolute));
        Assert.NotNull(resolved);
    }

    [Theory]
    [InlineData("../download/v1.0.0/manifest.json")]
    [InlineData("./manifest.json")]
    [InlineData("/budcribar/RemotePCDiagnostics/releases/download/../latest/manifest.json")]
    [InlineData("/budcribar/RemotePCDiagnostics/releases/%2e%2e/other")]
    [InlineData("https://objects.githubusercontent.com/github-production-release-asset/%2e%2e/secret")]
    [InlineData("//evil.example/manifest.json")]
    [InlineData("http://objects.githubusercontent.com/asset")]
    [InlineData("https://evil.example/manifest.json")]
    [InlineData("https://github.com/other/repo/releases/download/v1/x.zip")]
    [InlineData("/budcribar\\RemotePCDiagnostics/releases/download/v1/x.zip")]
    public void Unsafe_redirects_are_rejected(string location)
    {
        Assert.Null(ReleaseUrls.ResolveRedirect(Request, new Uri(location, UriKind.RelativeOrAbsolute)));
    }
}

internal static class Manifests
{
    public static ReleaseManifest Valid() => new()
    {
        Product = ReleaseManifest.ProductName, Version = "1.2.3", File = "RemotePCDiagnostics-1.2.3.zip",
        Url = ReleaseUrls.DownloadPrefix + "v1.2.3/RemotePCDiagnostics-1.2.3.zip", Size = 1234, Sha256 = new string('d', 64),
        Entry = "RemotePCDiagnostics.Host.exe",
    };

    public static string Json(ReleaseManifest m) =>
        "{\"product\":\"" + m.Product + "\",\"version\":\"" + m.Version + "\",\"file\":\"" + m.File + "\",\"url\":\"" + m.Url
        + "\",\"size\":" + m.Size + ",\"sha256\":\"" + m.Sha256 + "\",\"entry\":\"" + m.Entry + "\"}";
}

public class ReleaseManifestTests
{
    [Fact]
    public void A_valid_manifest_parses_and_lowercases_its_hash()
    {
        var m = Manifests.Valid();
        m.Sha256 = new string('D', 64);
        var parsed = ReleaseManifest.Parse(Encoding.UTF8.GetBytes(Manifests.Json(m)), out var error);
        Assert.True(parsed is not null, error);
        Assert.Equal("", error);
        Assert.Equal(new string('d', 64), parsed!.Sha256);
        Assert.Equal("1.2.3", parsed.Version);
    }

    [Theory]
    [InlineData("{\"product\":\"Other\"}", "is for 'Other'")]
    [InlineData("not json", "isn't valid JSON")]
    public void Bad_json_or_product_is_refused_in_plain_words(string json, string expected)
    {
        Assert.Null(ReleaseManifest.Parse(Encoding.UTF8.GetBytes(json), out var error));
        Assert.Contains(expected, error);
    }

    [Theory]
    [InlineData("version", "../1.0", "invalid version")]
    [InlineData("file", "..\\evil.zip", "invalid download file")]
    [InlineData("entry", "run.bat", "invalid program file")]
    [InlineData("size", "0", "invalid size")]
    [InlineData("sha256", "xyz", "invalid SHA-256")]
    [InlineData("url", "https://example.com/RemotePCDiagnostics-1.2.3.zip", "outside the RemotePCDiagnostics GitHub releases")]
    public void Each_field_is_checked(string field, string value, string expected)
    {
        var m = Manifests.Valid();
        switch (field)
        {
            case "version": m.Version = value; break;
            case "file": m.File = value; break;
            case "entry": m.Entry = value; break;
            case "size": m.Size = long.Parse(value); break;
            case "sha256": m.Sha256 = value; break;
            case "url": m.Url = value; break;
        }
        Assert.Contains(expected, ReleaseManifest.Validate(m));
    }

    [Fact]
    public void The_url_must_end_with_the_file_name()
    {
        var m = Manifests.Valid();
        m.Url = ReleaseUrls.DownloadPrefix + "v1.2.3/Other.zip";
        Assert.Contains("doesn't match its file name", ReleaseManifest.Validate(m));
    }

    [Theory]
    [InlineData("1.2", true)]
    [InlineData("1.2.3.4", true)]
    [InlineData("1.2.3-beta.1", true)]
    [InlineData("1", false)]
    [InlineData("1.2.3.4.5", false)]
    [InlineData("1.2.3-", false)]
    [InlineData("1.2.3-a..b", false)]
    [InlineData("1.2/3", false)]
    public void Versions_must_be_safe_folder_names(string v, bool ok) => Assert.Equal(ok, ReleaseManifest.IsSafeVersion(v));
}

public class ManifestSignatureTests
{
    [Fact]
    public void A_signature_verifies_only_over_the_exact_bytes_with_the_right_key()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pem = key.ExportSubjectPublicKeyInfoPem();
        var bytes = Encoding.UTF8.GetBytes(Manifests.Json(Manifests.Valid()));
        var sig = Convert.ToBase64String(key.SignData(bytes, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));

        Assert.True(ManifestSignature.Verify(bytes, "  " + sig + "\n", pem));
        var changed = (byte[])bytes.Clone();
        changed[^2] ^= 1;
        Assert.False(ManifestSignature.Verify(changed, sig, pem));
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Assert.False(ManifestSignature.Verify(bytes, sig, other.ExportSubjectPublicKeyInfoPem()));
        Assert.False(ManifestSignature.Verify(bytes, "not base64!", pem));
        Assert.False(ManifestSignature.Verify(bytes, Convert.ToBase64String(new byte[10]), pem));
        Assert.False(ManifestSignature.Verify(bytes, sig, ""));      // no key configured yet
    }

    [Fact]
    public void A_key_on_another_curve_is_refused()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var bytes = Encoding.UTF8.GetBytes("x");
        var sig = Convert.ToBase64String(key.SignData(bytes, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        Assert.False(ManifestSignature.Verify(bytes, sig, key.ExportSubjectPublicKeyInfoPem()));
    }
}

public class BackoffTests
{
    [Fact]
    public void Delays_double_up_to_a_minute_and_reset_after_a_healthy_connection()
    {
        var b = new Backoff();
        var seen = Enumerable.Range(0, 7).Select(_ => b.Next().TotalSeconds).ToList();
        Assert.Equal([2, 4, 8, 16, 32, 60, 60], seen);
        b.ConnectionEnded(TimeSpan.FromSeconds(5));
        Assert.Equal(60, b.Next().TotalSeconds);                    // a short connection doesn't count
        b.ConnectionEnded(Backoff.HealthyConnection);
        Assert.Equal(2, b.Next().TotalSeconds);
    }
}

public class LaunchRulesTests
{
    [Fact]
    public void The_app_is_started_on_the_requested_session_with_control_going_to_the_requester()
    {
        var session = Guid.Parse("7e57c0de-0000-4000-8000-000000000001");
        var line = LaunchRules.AppCommandLine(@"C:\Cache\1.2.3\RemotePCDiagnostics.Host.exe", "https://relay.example:34544", session);

        Assert.Contains("-u=https://relay.example:34544", line);
        Assert.Contains("-i=7e57c0de-0000-4000-8000-000000000001", line);
        Assert.DoesNotContain("-g=", line);
        // Nobody may be at the PC to hand control over: the requester gets it on joining the session's link.
        Assert.EndsWith(" --unattended", line);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Blank_or_null_group_omits_group_flag(string? group)
    {
        var session = Guid.Parse("7e57c0de-0000-4000-8000-000000000002");
        var line = LaunchRules.AppCommandLine(@"C:\Program Files\Remote PC Diagnostics\RemotePCDiagnostics.Host.exe", "https://relay.example:34544", session, group);

        Assert.StartsWith("\"C:\\Program Files\\Remote PC Diagnostics\\RemotePCDiagnostics.Host.exe\" ", line);
        Assert.DoesNotContain("-g=", line);
        Assert.EndsWith("-i=7e57c0de-0000-4000-8000-000000000002 --unattended", line);
    }

    [Fact]
    public void Group_slug_is_trimmed_lowercased_and_placed_right_before_unattended()
    {
        var session = Guid.Parse("7e57c0de-0000-4000-8000-000000000003");
        var line = LaunchRules.AppCommandLine(@"C:\Program Files\Remote PC Diagnostics\RemotePCDiagnostics.Host.exe", "https://relay.example:34544", session, "  Acme-MSP  ");

        Assert.StartsWith("\"C:\\Program Files\\Remote PC Diagnostics\\RemotePCDiagnostics.Host.exe\" ", line);
        Assert.Contains("-u=https://relay.example:34544", line);
        Assert.Contains("-i=7e57c0de-0000-4000-8000-000000000003", line);
        Assert.EndsWith(" -g=acme-msp --unattended", line);
    }
}

public class AgentCommandLineTests
{
    [Fact]
    public void Self_check_flag_parses_in_top_level_and_run_subcommand()
    {
        var topLevel = AgentCommandLine.Parse(["--self-check"]);
        Assert.Null(topLevel.Error);
        Assert.Equal(AgentCommand.Run, topLevel.Command);
        Assert.True(topLevel.SelfCheck);

        var runSub = AgentCommandLine.Parse(["run", "--self-check"]);
        Assert.Null(runSub.Error);
        Assert.Equal(AgentCommand.Run, runSub.Command);
        Assert.True(runSub.SelfCheck);
    }
}

public class AgentHubWorkerTests
{
    [Fact]
    public async Task Fleet_launch_with_group_passes_group_flag_and_reports_progress_stages()
    {
        var machineGuid = Guid.Parse("7e57c0de-0000-4000-8000-000000000010");
        var sessionGuid = Guid.Parse("7e57c0de-0000-4000-8000-000000000011");
        var config = AgentConfig.ForInstall(
            existing: null,
            new AgentArgs(AgentCommand.Install, Server: "https://relay.example:34544", Key: "rpd_live_fleet_key", Consent: ConsentCeiling.Unattended),
            machineGuid);

        var proc = new FakeLaunchedProcess();
        var platform = new FakeAgentPlatform
        {
            HostExePath = @"C:\Program Files\Remote PC Diagnostics\RemotePCDiagnostics.Host.exe",
            RelayConnectedResult = true,
            ProcessFactory = (_, cmdLine) =>
            {
                proc.StartedCommandLine = cmdLine;
                return (proc, null);
            },
        };

        var hub = new FakeAgentHubClient();
        var worker = new AgentHubWorker(config, platform, new AgentSessionOptions
        {
            HeartbeatInterval = TimeSpan.FromMinutes(5),
            StatusPollInterval = TimeSpan.FromMilliseconds(10),
        });

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var runTask = worker.RunSingleConnectionAsync(hub, cts.Token);

        var first = await hub.ReadAgentMessageAsync(cts.Token);
        Assert.Equal(AgentMessage.BodyOneofCase.Hello, first.BodyCase);
        Assert.Equal(machineGuid.ToString("D"), first.Hello.MachineId);
        Assert.Equal("rpd_live_fleet_key", first.Hello.EnrollmentKey);
        Assert.Equal(ConsentMode.ConsentUnattendedAllowed, first.Hello.ConsentCeiling);
        Assert.Equal(Lifetime.Persistent, first.Hello.Lifetime);

        var cmd = new LaunchCommand
        {
            RequestId = "req-1",
            SessionId = sessionGuid.ToString("D"),
            ServerUrl = "https://relay.example:34544",
            Requester = "Alice Tech",
            RequireConsent = false,
            Group = "Acme-MSP",
        };
        Assert.Equal("Acme-MSP", cmd.Group);
        await hub.SendHubCommandAsync(new HubCommand { Launch = cmd }, cts.Token);

        var stages = new List<LaunchStage>();
        while (true)
        {
            var msg = await hub.ReadAgentMessageAsync(cts.Token);
            if (msg.BodyCase != AgentMessage.BodyOneofCase.Progress)
                continue;
            stages.Add(msg.Progress.Stage);
            if (msg.Progress.Stage == LaunchStage.StageReady)
            {
                proc.CompleteExit(0);
            }
            if (msg.Progress.Stage == LaunchStage.StageEnded)
                break;
        }

        hub.CompleteServerStream();
        await runTask;

        Assert.Equal(
            [LaunchStage.StageQueued, LaunchStage.StageStarting, LaunchStage.StageReady, LaunchStage.StageEnded],
            stages);
        Assert.NotNull(proc.StartedCommandLine);
        Assert.Contains("-g=acme-msp --unattended", proc.StartedCommandLine);
    }

    [Fact]
    public async Task Declined_consent_reports_StageDeclined_and_never_starts_host()
    {
        var machineGuid = Guid.Parse("7e57c0de-0000-4000-8000-000000000020");
        var sessionGuid = Guid.Parse("7e57c0de-0000-4000-8000-000000000021");
        var config = AgentConfig.ForInstall(
            existing: null,
            new AgentArgs(AgentCommand.Install, Server: "https://relay.example:34544", Consent: ConsentCeiling.Ask),
            machineGuid);

        var hostStarted = false;
        var platform = new FakeAgentPlatform
        {
            ConsentResult = ConsentOutcome.Declined,
            ProcessFactory = (_, _) =>
            {
                hostStarted = true;
                return (new FakeLaunchedProcess(), null);
            },
        };

        var hub = new FakeAgentHubClient();
        var worker = new AgentHubWorker(config, platform, new AgentSessionOptions
        {
            HeartbeatInterval = TimeSpan.FromMinutes(5),
        });

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var runTask = worker.RunSingleConnectionAsync(hub, cts.Token);

        var hello = await hub.ReadAgentMessageAsync(cts.Token);
        Assert.Equal(AgentMessage.BodyOneofCase.Hello, hello.BodyCase);

        await hub.SendHubCommandAsync(new HubCommand
        {
            Launch = new LaunchCommand
            {
                RequestId = "req-decline",
                SessionId = sessionGuid.ToString("D"),
                ServerUrl = "https://relay.example:34544",
                Requester = "Bob Tech",
                RequireConsent = true,
                Group = "shop-west",
            },
        }, cts.Token);

        var stages = new List<LaunchStage>();
        while (true)
        {
            var msg = await hub.ReadAgentMessageAsync(cts.Token);
            if (msg.BodyCase != AgentMessage.BodyOneofCase.Progress)
                continue;
            stages.Add(msg.Progress.Stage);
            if (msg.Progress.Stage == LaunchStage.StageDeclined)
                break;
        }

        hub.CompleteServerStream();
        await runTask;

        Assert.Equal([LaunchStage.StageQueued, LaunchStage.StageWaitingForConsent, LaunchStage.StageDeclined], stages);
        Assert.False(hostStarted);
    }

    [Fact]
    public async Task Cancel_command_aborts_pending_consent_and_reports_StageFailed()
    {
        var machineGuid = Guid.Parse("7e57c0de-0000-4000-8000-000000000030");
        var sessionGuid = Guid.Parse("7e57c0de-0000-4000-8000-000000000031");
        var config = AgentConfig.ForInstall(
            existing: null,
            new AgentArgs(AgentCommand.Install, Server: "https://relay.example:34544", Consent: ConsentCeiling.Ask),
            machineGuid);

        var consentEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var platform = new FakeAgentPlatform
        {
            ConsentHandler = async (_, _, ct) =>
            {
                consentEntered.TrySetResult();
                await Task.Delay(Timeout.InfiniteTimeSpan, ct);
                return ConsentOutcome.Allowed;
            },
        };

        var hub = new FakeAgentHubClient();
        var worker = new AgentHubWorker(config, platform, new AgentSessionOptions
        {
            HeartbeatInterval = TimeSpan.FromMinutes(5),
        });

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var runTask = worker.RunSingleConnectionAsync(hub, cts.Token);

        _ = await hub.ReadAgentMessageAsync(cts.Token); // Hello

        await hub.SendHubCommandAsync(new HubCommand
        {
            Launch = new LaunchCommand
            {
                RequestId = "req-cancel",
                SessionId = sessionGuid.ToString("D"),
                ServerUrl = "https://relay.example:34544",
                Requester = "Bob Tech",
                RequireConsent = true,
            },
        }, cts.Token);

        await consentEntered.Task.WaitAsync(cts.Token);
        await hub.SendHubCommandAsync(new HubCommand
        {
            Cancel = new CancelCommand { RequestId = "req-cancel" },
        }, cts.Token);

        LaunchProgress? terminal = null;
        while (terminal is null)
        {
            var msg = await hub.ReadAgentMessageAsync(cts.Token);
            if (msg.BodyCase == AgentMessage.BodyOneofCase.Progress && msg.Progress.Stage == LaunchStage.StageFailed)
                terminal = msg.Progress;
        }

        hub.CompleteServerStream();
        await runTask;

        Assert.Equal("Launch cancelled", terminal.Detail);
    }

    private sealed class FakeLaunchedProcess : IAgentLaunchedProcess
    {
        private readonly TaskCompletionSource<uint> _exitTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public string? StartedCommandLine { get; set; }
        public bool HasExited => _exitTcs.Task.IsCompleted;
        public uint ExitCode => _exitTcs.Task.IsCompletedSuccessfully ? _exitTcs.Task.Result : 0;

        public void CompleteExit(uint code) => _exitTcs.TrySetResult(code);

        public async Task WaitForExitAsync(CancellationToken ct) =>
            await _exitTcs.Task.WaitAsync(ct);

        public void Kill() => _exitTcs.TrySetResult(1);
        public void Dispose() { }
    }

    private sealed class FakeAgentPlatform : IAgentPlatform
    {
        public string MachineName { get; init; } = "BENCH-PC-01";
        public string SignedInUser { get; init; } = @"CONTOSO\tech";
        public string HostExePath { get; init; } = @"C:\RemotePCDiagnostics\RemotePCDiagnostics.Host.exe";
        public ConsentOutcome ConsentResult { get; init; } = ConsentOutcome.Allowed;
        public Func<string, int, CancellationToken, Task<ConsentOutcome>>? ConsentHandler { get; init; }
        public bool? RelayConnectedResult { get; init; } = true;
        public Func<string, string, (IAgentLaunchedProcess?, string?)>? ProcessFactory { get; init; }

        public string GetOsVersion() => "Windows 11 Pro 24H2 (build 26100)";
        public string GetActiveSignedInUser() => SignedInUser;
        public string GetAgentVersion() => "1.2.0-test";
        public string GetCachedOrInstalledAppVersion() => "1.2.0";

        public Task<ConsentOutcome> RequestConsentAsync(string requester, int timeoutSeconds, CancellationToken ct) =>
            ConsentHandler is not null ? ConsentHandler(requester, timeoutSeconds, ct) : Task.FromResult(ConsentResult);

        public Task<(string? ExePath, string? Error)> ResolveHostExecutableAsync(
            Func<LaunchStage, string, int, Task> reportStageAsync,
            CancellationToken ct) =>
            Task.FromResult<(string?, string?)>((HostExePath, null));

        public (IAgentLaunchedProcess? Process, string? Error) StartHostProcess(string hostExePath, string fullCommandLine) =>
            ProcessFactory is not null ? ProcessFactory(hostExePath, fullCommandLine) : (new FakeLaunchedProcess(), null);

        public Task<bool?> CheckRelaySessionConnectedAsync(string statusUrl, CancellationToken ct) =>
            Task.FromResult(RelayConnectedResult);

        public Task RemoveSelfAfterSessionAsync() => Task.CompletedTask;
    }

    private sealed class FakeAgentHubClient : AgentHub.AgentHubClient
    {
        private readonly Channel<AgentMessage> _toServer = Channel.CreateUnbounded<AgentMessage>();
        private readonly Channel<HubCommand> _toAgent = Channel.CreateUnbounded<HubCommand>();

        public ValueTask SendHubCommandAsync(HubCommand command, CancellationToken ct) =>
            _toAgent.Writer.WriteAsync(command, ct);

        public ValueTask<AgentMessage> ReadAgentMessageAsync(CancellationToken ct) =>
            _toServer.Reader.ReadAsync(ct);

        public void CompleteServerStream() => _toAgent.Writer.TryComplete();

        public override AsyncDuplexStreamingCall<AgentMessage, HubCommand> Connect(
            Metadata? headers = null,
            DateTime? deadline = null,
            CancellationToken cancellationToken = default) =>
            Connect(new CallOptions(headers, deadline, cancellationToken));

        public override AsyncDuplexStreamingCall<AgentMessage, HubCommand> Connect(CallOptions options)
        {
            var reqWriter = new ChannelClientStreamWriter<AgentMessage>(_toServer.Writer);
            var respReader = new ChannelAsyncStreamReader<HubCommand>(_toAgent.Reader, options.CancellationToken);
            return new AsyncDuplexStreamingCall<AgentMessage, HubCommand>(
                reqWriter,
                respReader,
                Task.FromResult(new Metadata()),
                () => Status.DefaultSuccess,
                () => new Metadata(),
                () => { });
        }

        private sealed class ChannelClientStreamWriter<T>(ChannelWriter<T> writer) : IClientStreamWriter<T>
        {
            public WriteOptions? WriteOptions { get; set; }
            public Task WriteAsync(T message) => writer.WriteAsync(message).AsTask();
            public Task CompleteAsync()
            {
                writer.TryComplete();
                return Task.CompletedTask;
            }
        }

        private sealed class ChannelAsyncStreamReader<T>(ChannelReader<T> reader, CancellationToken callCt) : IAsyncStreamReader<T>
        {
            private T? _current;
            public T Current => _current!;

            public async Task<bool> MoveNext(CancellationToken cancellationToken)
            {
                using var linked = CancellationTokenSource.CreateLinkedTokenSource(callCt, cancellationToken);
                if (!await reader.WaitToReadAsync(linked.Token).ConfigureAwait(false))
                    return false;
                return reader.TryRead(out _current);
            }
        }
    }
}
