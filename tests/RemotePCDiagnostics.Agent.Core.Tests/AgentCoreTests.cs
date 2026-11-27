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
    // The app normally registers with the relay a second or two after it starts: ask often then, and less often for a launch
    // that is taking long.
    [Theory]
    [InlineData(0, 250)]
    [InlineData(1500, 250)]
    [InlineData(4999, 250)]
    [InlineData(5000, 1000)]
    [InlineData(19999, 1000)]
    [InlineData(20000, 2000)]
    [InlineData(89000, 2000)]
    public void Status_is_polled_often_at_first_and_then_less_so(int elapsedMs, int expectedMs) =>
        Assert.Equal(TimeSpan.FromMilliseconds(expectedMs), LaunchRules.PollInterval(TimeSpan.FromMilliseconds(elapsedMs)));

    [Fact]
    public void A_launch_that_never_registers_is_not_polled_hundreds_of_times()
    {
        var polls = 0;
        for (var elapsed = TimeSpan.Zero; elapsed < LaunchRules.StatusPollLimit; elapsed += LaunchRules.PollInterval(elapsed))
            polls++;
        Assert.InRange(polls, 60, 80);
    }

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
    [InlineData(null, " -i=7e57c0de-0000-4000-8000-000000000004 --unattended --no-window")]
    [InlineData("acme", " -g=acme --unattended --no-window")]
    public void A_hidden_launch_adds_the_no_window_switch_last(string? group, string expectedEnd)
    {
        var session = Guid.Parse("7e57c0de-0000-4000-8000-000000000004");
        var line = LaunchRules.AppCommandLine(@"C:\Cache\1.2.3\RemotePCDiagnostics.Host.exe", "https://relay.example:34544", session, group, hidden: true);

        Assert.EndsWith(expectedEnd, line);
        Assert.DoesNotContain("--no-window", LaunchRules.AppCommandLine(@"C:\Cache\1.2.3\RemotePCDiagnostics.Host.exe", "https://relay.example:34544", session, group));
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

    [Theory]
    [InlineData(@"C:\Users\Jane\Downloads\RemotePCDiagnostics-Agent.as.rpd_inv_Abc123_-XYZ.pkg.msi", "rpd_inv_Abc123_-XYZ", ConsentCeiling.Ask, AgentLifetime.Session)]
    [InlineData(@"C:\Users\Jane\Downloads\RemotePCDiagnostics-Agent.as.rpd_inv_Abc123_-XYZ.pkg (1).msi", "rpd_inv_Abc123_-XYZ", ConsentCeiling.Ask, AgentLifetime.Session)]
    [InlineData(@"C:\Users\Jane\Downloads\RemotePCDiagnostics-Agent.ap.rpd_live_9876543210abcdef.pkg(2).msi", "rpd_live_9876543210abcdef", ConsentCeiling.Ask, AgentLifetime.Persistent)]
    [InlineData(@"/tmp/RemotePCDiagnostics-Agent.up.rpd_live_fleet_key.pkg-1.msi", "rpd_live_fleet_key", ConsentCeiling.Unattended, AgentLifetime.Persistent)]
    [InlineData(@"RemotePCDiagnostics-Agent.us.rpd_inv_onetimetoken.pkg - Copy.msi", "rpd_inv_onetimetoken", ConsentCeiling.Unattended, AgentLifetime.Session)]
    public void From_msi_extracts_tokenized_filename_and_ignores_empty_msi_properties(
        string msiPath,
        string expectedKey,
        ConsentCeiling expectedConsent,
        AgentLifetime expectedLifetime)
    {
        var parsed = AgentCommandLine.Parse([
            "install",
            $"--from-msi={msiPath}",
            "--server=",
            "--key=",
            "--consent=",
            "--lifetime=",
        ]);

        Assert.Null(parsed.Error);
        Assert.Equal(AgentCommand.Install, parsed.Command);
        Assert.True(parsed.FromMsi);
        Assert.Equal(AgentCommandLine.DefaultServer, parsed.Server);
        Assert.Equal(expectedKey, parsed.Key);
        Assert.Equal(expectedConsent, parsed.Consent);
        Assert.Equal(expectedLifetime, parsed.Lifetime);
    }

    [Fact]
    public void Custom_relay_server_round_trips_through_msi_filename_and_explicit_msi_properties_override()
    {
        var fileName = AgentMsiParameters.FormatFileName(
            "https://relay.example.com:34544/",
            "rpd_live_shop_token_01",
            ConsentCeiling.Ask,
            AgentLifetime.Persistent);

        Assert.StartsWith("RemotePCDiagnostics-Agent.ap.rpd_live_shop_token_01.h.", fileName);
        Assert.EndsWith(".pkg.msi", fileName);

        var parsed = AgentCommandLine.Parse([
            "install",
            $"--from-msi=C:\\Downloads\\{fileName.Replace(".pkg.msi", ".pkg (3).msi")}",
            "--server=",
            "--key=",
            "--consent=",
            "--lifetime=",
        ]);

        Assert.Null(parsed.Error);
        Assert.Equal("https://relay.example.com:34544", parsed.Server);
        Assert.Equal("rpd_live_shop_token_01", parsed.Key);
        Assert.Equal(ConsentCeiling.Ask, parsed.Consent);
        Assert.Equal(AgentLifetime.Persistent, parsed.Lifetime);

        var overridden = AgentCommandLine.Parse([
            "install",
            @"--from-msi=C:\Cache\RemotePCDiagnostics.Agent-1.2.0-win-x64.msi",
            "--server=https://custom.relay.example:34544",
            "--key=rpd_live_override",
            "--consent=unattended",
            "--lifetime=persistent",
        ]);

        Assert.Null(overridden.Error);
        Assert.True(overridden.FromMsi);
        Assert.Equal("https://custom.relay.example:34544", overridden.Server);
        Assert.Equal("rpd_live_override", overridden.Key);
        Assert.Equal(ConsentCeiling.Unattended, overridden.Consent);
        Assert.Equal(AgentLifetime.Persistent, overridden.Lifetime);
    }

    [Theory]
    [InlineData(@"C:\Downloads\RemotePCDiagnostics-Agent.xx.rpd_live_key.pkg.msi")]
    [InlineData(@"C:\Downloads\RemotePCDiagnostics-Agent.as.rpd_live_key.msi")]
    [InlineData(@"C:\Downloads\RemotePCDiagnostics-Agent.as..pkg.msi")]
    [InlineData(@"C:\Downloads\RemotePCDiagnostics-Agent.as.rpd_live_key.h.not!!valid.pkg.msi")]
    public void Malformed_tokenized_msi_filename_is_rejected(string msiPath)
    {
        var parsed = AgentCommandLine.Parse(["install", $"--from-msi={msiPath}"]);
        Assert.NotNull(parsed.Error);
        Assert.Equal(AgentCommand.Help, parsed.Command);
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
        var links = new List<(bool Connected, string? Group)>();
        var worker = new AgentHubWorker(config, platform, new AgentSessionOptions
        {
            HeartbeatInterval = TimeSpan.FromMinutes(5),
            StatusPollInterval = TimeSpan.FromMilliseconds(10),
            LinkChanged = (connected, group) =>
            {
                lock (links) links.Add((connected, group));
            },
        });

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var runTask = worker.RunSingleConnectionAsync(hub, cts.Token);

        var first = await hub.ReadAgentMessageAsync(cts.Token);
        Assert.Equal(AgentMessage.BodyOneofCase.Hello, first.BodyCase);
        Assert.Equal(machineGuid.ToString("D"), first.Hello.MachineId);
        Assert.Equal("rpd_live_fleet_key", first.Hello.EnrollmentKey);
        Assert.Equal(ConsentMode.ConsentUnattendedAllowed, first.Hello.ConsentCeiling);
        Assert.Equal(Lifetime.Persistent, first.Hello.Lifetime);
        Assert.Equal(new DateTimeOffset(2026, 11, 19, 8, 0, 0, TimeSpan.Zero), first.Hello.BootTime.ToDateTimeOffset());

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
        lock (links)
        {
            Assert.Contains(links, x => x.Connected && x.Group == "acme-msp");
            Assert.False(links[^1].Connected);
        }
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

    [Theory]
    [InlineData(PowerReading.Battery, 3600, false, "on battery")]
    [InlineData(PowerReading.Ac, 60, false, "Someone used this computer")]
    [InlineData(PowerReading.Ac, 3600, true, null)]
    public async Task A_hidden_launch_with_conditions_starts_only_when_they_hold(PowerReading power, int idleSeconds, bool expectStart, string? reason)
    {
        var config = AgentConfig.ForInstall(
            existing: null,
            new AgentArgs(AgentCommand.Install, Server: "https://relay.example:34544", Consent: ConsentCeiling.Unattended),
            Guid.Parse("7e57c0de-0000-4000-8000-000000000060"));
        var hostStarted = false;
        var platform = new FakeAgentPlatform
        {
            Power = power,
            IdleSeconds = idleSeconds,
            ProcessFactory = (_, _) =>
            {
                hostStarted = true;
                return (new FakeLaunchedProcess(), null);
            },
        };
        var hub = new FakeAgentHubClient();
        var worker = new AgentHubWorker(config, platform, new AgentSessionOptions { HeartbeatInterval = TimeSpan.FromMinutes(5), StatusPollInterval = TimeSpan.FromMilliseconds(10) });
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var runTask = worker.RunSingleConnectionAsync(hub, cts.Token);

        var hello = await hub.ReadAgentMessageAsync(cts.Token);
        Assert.Equal(-420, hello.Hello.UtcOffsetMinutes);
        Assert.Equal(power == PowerReading.Ac ? PowerSource.PowerAc : PowerSource.PowerBattery, hello.Hello.PowerSource);

        await hub.SendHubCommandAsync(new HubCommand
        {
            Launch = new LaunchCommand
            {
                RequestId = "req-cond",
                SessionId = Guid.Parse("7e57c0de-0000-4000-8000-000000000061").ToString("D"),
                ServerUrl = "https://relay.example:34544",
                Requester = "AI",
                Hidden = true,
                // 10 PM to 6 AM; the fake PC's clock says 11:30 PM.
                Conditions = new LaunchConditions { RequireAcPower = true, MinIdleMinutes = 15, WindowStartMinute = 1320, WindowEndMinute = 360 },
            },
        }, cts.Token);

        LaunchProgress last;
        while (true)
        {
            var msg = await hub.ReadAgentMessageAsync(cts.Token);
            if (msg.BodyCase != AgentMessage.BodyOneofCase.Progress)
                continue;
            last = msg.Progress;
            if (last.Stage is LaunchStage.StageConditionsNotMet or LaunchStage.StageStarting or LaunchStage.StageFailed)
                break;
        }
        hub.CompleteServerStream();
        try { await runTask; } catch (OperationCanceledException) { }

        if (expectStart)
        {
            Assert.Equal(LaunchStage.StageStarting, last.Stage);
        }
        else
        {
            Assert.Equal(LaunchStage.StageConditionsNotMet, last.Stage);
            Assert.Contains(reason!, last.Detail);
            Assert.False(hostStarted);
        }
    }

    [Fact]
    public async Task Unanswered_consent_reports_StageConsentTimedOut_and_never_starts_host()
    {
        var machineGuid = Guid.Parse("7e57c0de-0000-4000-8000-000000000022");
        var sessionGuid = Guid.Parse("7e57c0de-0000-4000-8000-000000000023");
        var config = AgentConfig.ForInstall(
            existing: null,
            new AgentArgs(AgentCommand.Install, Server: "https://relay.example:34544", Consent: ConsentCeiling.Ask),
            machineGuid);

        var hostStarted = false;
        var platform = new FakeAgentPlatform
        {
            ConsentResult = ConsentOutcome.TimedOut,
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
                RequestId = "req-no-answer",
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
            if (msg.Progress.Stage == LaunchStage.StageConsentTimedOut)
                break;
        }

        hub.CompleteServerStream();
        await runTask;

        Assert.Equal([LaunchStage.StageQueued, LaunchStage.StageWaitingForConsent, LaunchStage.StageConsentTimedOut], stages);
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

    [Fact]
    public async Task Launch_is_refused_as_already_open_when_an_untracked_app_copy_is_running()
    {
        // The copy the agent starts again after an update isn't one of its sessions; a new copy would only exit "already open".
        var config = AgentConfig.ForInstall(
            existing: null,
            new AgentArgs(AgentCommand.Install, Server: "https://relay.example:34544", Consent: ConsentCeiling.Unattended),
            Guid.Parse("7e57c0de-0000-4000-8000-000000000040"));
        var hostStarted = false;
        var platform = new FakeAgentPlatform
        {
            AppRunning = true,
            ProcessFactory = (_, _) => { hostStarted = true; return (new FakeLaunchedProcess(), null); },
        };
        var hub = new FakeAgentHubClient();
        var worker = new AgentHubWorker(config, platform, new AgentSessionOptions { HeartbeatInterval = TimeSpan.FromMinutes(5) });

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var runTask = worker.RunSingleConnectionAsync(hub, cts.Token);
        _ = await hub.ReadAgentMessageAsync(cts.Token); // Hello
        await hub.SendHubCommandAsync(new HubCommand
        {
            Launch = new LaunchCommand
            {
                RequestId = "req-open",
                SessionId = Guid.Parse("7e57c0de-0000-4000-8000-000000000041").ToString("D"),
                ServerUrl = "https://relay.example:34544",
                Requester = "Bob Tech",
            },
        }, cts.Token);

        LaunchProgress? failed = null;
        while (failed is null)
        {
            var msg = await hub.ReadAgentMessageAsync(cts.Token);
            if (msg.BodyCase == AgentMessage.BodyOneofCase.Progress && msg.Progress.Stage == LaunchStage.StageFailed)
                failed = msg.Progress;
        }
        hub.CompleteServerStream();
        await runTask;

        Assert.Equal(LaunchRules.AlreadyOpenText, failed.Detail);
        Assert.Equal("req-open", failed.RequestId);
        Assert.False(hostStarted);
    }

    private static async Task<AgentHubWorker> LaunchToReadyAsync(
        FakeAgentHubClient hub, FakeLaunchedProcess proc, string requestId, Guid machineGuid, Guid sessionGuid,
        CancellationToken ct, Action<Task> keepRunTask)
    {
        var config = AgentConfig.ForInstall(
            existing: null,
            new AgentArgs(AgentCommand.Install, Server: "https://relay.example:34544", Consent: ConsentCeiling.Unattended),
            machineGuid);
        var platform = new FakeAgentPlatform { ProcessFactory = (_, _) => (proc, null) };
        var worker = new AgentHubWorker(config, platform, new AgentSessionOptions
        {
            HeartbeatInterval = TimeSpan.FromMinutes(5),
            StatusPollInterval = TimeSpan.FromMilliseconds(10),
        });
        keepRunTask(worker.RunSingleConnectionAsync(hub, ct));
        _ = await hub.ReadAgentMessageAsync(ct); // Hello
        await hub.SendHubCommandAsync(new HubCommand
        {
            Launch = new LaunchCommand
            {
                RequestId = requestId,
                SessionId = sessionGuid.ToString("D"),
                ServerUrl = "https://relay.example:34544",
                Requester = "Alice Tech",
            },
        }, ct);
        while (true)
        {
            var msg = await hub.ReadAgentMessageAsync(ct);
            if (msg.BodyCase == AgentMessage.BodyOneofCase.Progress && msg.Progress.Stage == LaunchStage.StageReady)
                return worker;
        }
    }

    private static async Task<LaunchProgress> ReadProgressAsync(FakeAgentHubClient hub, CancellationToken ct)
    {
        while (true)
        {
            var msg = await hub.ReadAgentMessageAsync(ct);
            if (msg.BodyCase == AgentMessage.BodyOneofCase.Progress)
                return msg.Progress;
        }
    }

    [Fact]
    public async Task End_request_after_a_reconnect_still_closes_a_ready_session()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var proc = new FakeLaunchedProcess();
        var firstHub = new FakeAgentHubClient();
        Task firstRun = Task.CompletedTask;
        var worker = await LaunchToReadyAsync(firstHub, proc, "req-keep", Guid.Parse("7e57c0de-0000-4000-8000-000000000050"),
            Guid.Parse("7e57c0de-0000-4000-8000-000000000051"), cts.Token, t => firstRun = t);

        // The stream drops (relay redeploy, network blip) while the app keeps running.
        firstHub.CompleteServerStream();
        await firstRun.WaitAsync(cts.Token);
        Assert.False(proc.HasExited);

        var secondHub = new FakeAgentHubClient();
        var secondRun = worker.RunSingleConnectionAsync(secondHub, cts.Token);
        _ = await secondHub.ReadAgentMessageAsync(cts.Token); // Hello
        var again = await ReadProgressAsync(secondHub, cts.Token);
        Assert.Equal(LaunchStage.StageReady, again.Stage); // the running session is reported again on the new stream

        // The relay kept the READY launch, so Admin's end request names the old request ID.
        await secondHub.SendHubCommandAsync(new HubCommand { Cancel = new CancelCommand { RequestId = "req-keep" } }, cts.Token);

        var ended = await ReadProgressAsync(secondHub, cts.Token);
        Assert.Equal(LaunchStage.StageEnded, ended.Stage);
        Assert.Equal("req-keep", ended.RequestId);
        Assert.True(proc.HasExited);

        secondHub.CompleteServerStream();
        await secondRun;
    }

    [Fact]
    public async Task Ready_session_is_reported_again_after_a_reconnect_so_a_restarted_relay_knows_it()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var proc = new FakeLaunchedProcess();
        var firstHub = new FakeAgentHubClient();
        Task firstRun = Task.CompletedTask;
        var sessionId = Guid.Parse("7e57c0de-0000-4000-8000-000000000055");
        var worker = await LaunchToReadyAsync(firstHub, proc, "req-relay-restart", Guid.Parse("7e57c0de-0000-4000-8000-000000000054"),
            sessionId, cts.Token, t => firstRun = t);

        // The relay is redeployed: the stream drops and the new relay has no record of the launch.
        firstHub.CompleteServerStream();
        await firstRun.WaitAsync(cts.Token);

        var secondHub = new FakeAgentHubClient();
        var secondRun = worker.RunSingleConnectionAsync(secondHub, cts.Token);
        _ = await secondHub.ReadAgentMessageAsync(cts.Token); // Hello

        var again = await ReadProgressAsync(secondHub, cts.Token);
        Assert.Equal(LaunchStage.StageReady, again.Stage);
        Assert.Equal("req-relay-restart", again.RequestId);
        Assert.Equal(sessionId.ToString(), again.SessionId, ignoreCase: true);

        // With the launch known again, the end request closes the app.
        await secondHub.SendHubCommandAsync(new HubCommand { Cancel = new CancelCommand { RequestId = "req-relay-restart" } }, cts.Token);
        var ended = await ReadProgressAsync(secondHub, cts.Token);
        Assert.Equal(LaunchStage.StageEnded, ended.Stage);
        Assert.True(proc.HasExited);

        secondHub.CompleteServerStream();
        await secondRun;
    }

    [Fact]
    public async Task Ready_session_that_closes_while_disconnected_reports_ended_on_the_next_stream()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var proc = new FakeLaunchedProcess();
        var firstHub = new FakeAgentHubClient();
        Task firstRun = Task.CompletedTask;
        var worker = await LaunchToReadyAsync(firstHub, proc, "req-offline-close", Guid.Parse("7e57c0de-0000-4000-8000-000000000052"),
            Guid.Parse("7e57c0de-0000-4000-8000-000000000053"), cts.Token, t => firstRun = t);

        firstHub.CompleteServerStream();
        await firstRun.WaitAsync(cts.Token);

        // The person closes the app while the agent is offline.
        proc.CompleteExit(0);
        await Task.Delay(200, cts.Token);

        var secondHub = new FakeAgentHubClient();
        var secondRun = worker.RunSingleConnectionAsync(secondHub, cts.Token);
        _ = await secondHub.ReadAgentMessageAsync(cts.Token); // Hello

        var ended = await ReadProgressAsync(secondHub, cts.Token);
        Assert.Equal(LaunchStage.StageEnded, ended.Stage);
        Assert.Equal("req-offline-close", ended.RequestId);

        secondHub.CompleteServerStream();
        await secondRun;
    }

    [Fact]
    public async Task The_app_started_again_after_an_update_is_reported_ready_then_ended_when_it_closes()
    {
        var config = AgentConfig.ForInstall(
            existing: null,
            new AgentArgs(AgentCommand.Install, Server: "https://relay.example:34544", Consent: ConsentCeiling.Unattended),
            Guid.Parse("7e57c0de-0000-4000-8000-000000000060"));
        var sessionId = Guid.Parse("7e57c0de-0000-4000-8000-000000000061").ToString("D");
        var proc = new FakeLaunchedProcess();
        var platform = new FakeAgentPlatform { Relaunched = (proc, sessionId) };
        var hub = new FakeAgentHubClient();
        var worker = new AgentHubWorker(config, platform, new AgentSessionOptions { HeartbeatInterval = TimeSpan.FromMinutes(5) });

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var run = worker.RunSingleConnectionAsync(hub, cts.Token);
        _ = await hub.ReadAgentMessageAsync(cts.Token); // Hello

        var ready = await ReadProgressAsync(hub, cts.Token);
        Assert.Equal(LaunchStage.StageReady, ready.Stage);
        Assert.Equal(sessionId, ready.SessionId);
        Assert.StartsWith("relaunch-", ready.RequestId);

        // An end request for it closes the app, and the end is reported under the same request.
        await hub.SendHubCommandAsync(new HubCommand { Cancel = new CancelCommand { RequestId = ready.RequestId } }, cts.Token);
        var ended = await ReadProgressAsync(hub, cts.Token);
        Assert.Equal(LaunchStage.StageEnded, ended.Stage);
        Assert.Equal(ready.RequestId, ended.RequestId);
        Assert.True(proc.HasExited);

        hub.CompleteServerStream();
        await run;
    }

    [Fact]
    public async Task Update_without_approval_is_refused_and_a_status_poll_returns_it()
    {
        var config = AgentConfig.ForInstall(
            existing: null,
            new AgentArgs(AgentCommand.Install, Server: "https://relay.example:34544", Consent: ConsentCeiling.Unattended),
            Guid.Parse("7e57c0de-0000-4000-8000-000000000041"));
        UpdateRpcdCommand? seen = null;
        UpdateRpcdProgress? latest = null;
        var hub = new FakeAgentHubClient();
        var worker = new AgentHubWorker(config, new FakeAgentPlatform(), new AgentSessionOptions
        {
            HeartbeatInterval = TimeSpan.FromMinutes(5),
            UpdateRpcd = async (command, report, ct) =>
            {
                seen = command;
                latest = new UpdateRpcdProgress
                {
                    RequestId = "upd-1",
                    Stage = "refused",
                    Terminal = true,
                    Error = "Technician approval is required before Remote PC Diagnostics can be updated on this PC.",
                    Detail = "Technician approval is required before Remote PC Diagnostics can be updated on this PC.",
                    Channel = command.Channel,
                };
                await report(latest, ct);
            },
            ReadUpdateRpcd = _ => latest,
        });

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var runTask = worker.RunSingleConnectionAsync(hub, cts.Token);
        _ = await hub.ReadAgentMessageAsync(cts.Token);

        await hub.SendHubCommandAsync(new HubCommand
        {
            UpdateRpcd = new UpdateRpcdCommand
            {
                RequestId = "upd-1",
                Channel = "prerelease",
                Version = "1.2.0-ci.996.1",
                Approved = false,
                ApprovedBy = "shop owner",
            },
        }, cts.Token);

        UpdateRpcdProgress? progress = null;
        while (progress is null)
        {
            var msg = await hub.ReadAgentMessageAsync(cts.Token);
            if (msg.BodyCase == AgentMessage.BodyOneofCase.UpdateRpcd)
                progress = msg.UpdateRpcd;
        }

        Assert.NotNull(seen);
        Assert.False(seen.Approved);
        Assert.Equal("prerelease", seen.Channel);
        Assert.Equal("1.2.0-ci.996.1", seen.Version);
        Assert.Equal("refused", progress.Stage);
        Assert.True(progress.Terminal);
        Assert.Contains("approval", progress.Error);

        await hub.SendHubCommandAsync(new HubCommand
        {
            UpdateRpcdStatus = new UpdateRpcdStatusCommand { RequestId = "upd-1" },
        }, cts.Token);
        UpdateRpcdProgress? polled = null;
        while (polled is null)
        {
            var msg = await hub.ReadAgentMessageAsync(cts.Token);
            if (msg.BodyCase == AgentMessage.BodyOneofCase.UpdateRpcd && msg.UpdateRpcd.RequestId == "upd-1" && msg.UpdateRpcd.Stage == "refused")
                polled = msg.UpdateRpcd;
        }
        Assert.True(polled.Terminal);

        hub.CompleteServerStream();
        await runTask;
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

    [Fact]
    public void Boot_time_is_now_minus_the_tick_count_rounded_to_the_second()
    {
        var now = new DateTimeOffset(2026, 11, 19, 17, 30, 15, 400, TimeSpan.FromHours(-7));

        Assert.Equal(new DateTimeOffset(2026, 11, 20, 0, 0, 15, TimeSpan.Zero), BootTime.From(now, (long)TimeSpan.FromMinutes(30).TotalMilliseconds));
        // The same boot read a moment later gives the same value.
        Assert.Equal(BootTime.From(now, 1_000), BootTime.From(now.AddMilliseconds(300), 1_300));
        Assert.Null(BootTime.From(now, -1));
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
        public DateTimeOffset? Booted { get; init; } = new DateTimeOffset(2026, 11, 19, 8, 0, 0, TimeSpan.Zero);
        public DateTimeOffset? GetBootTime() => Booted;
        public PowerReading Power { get; init; } = PowerReading.Ac;
        public PowerReading GetPowerSource() => Power;
        public DateTimeOffset LocalNow { get; init; } = new DateTimeOffset(2026, 11, 25, 23, 30, 0, TimeSpan.FromHours(-7));
        public DateTimeOffset GetLocalNow() => LocalNow;
        public bool Locked { get; init; }
        public bool IsSessionLocked() => Locked;
        public int? IdleSeconds { get; init; } = 3600;
        public int IdleReads { get; private set; }
        public Task<int?> GetUserIdleSecondsAsync(CancellationToken ct)
        {
            IdleReads++;
            return Task.FromResult(IdleSeconds);
        }

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

        public bool AppRunning { get; init; }
        public bool IsAppRunning() => AppRunning;

        public (IAgentLaunchedProcess Process, string SessionId)? Relaunched { get; set; }
        public (IAgentLaunchedProcess Process, string SessionId)? TakeRelaunchedApp()
        {
            var taken = Relaunched;
            Relaunched = null;
            return taken;
        }
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

    [Fact]
    public void AgentConfig_AgentToken_RoundTrips_And_Clears_When_Key_Or_Server_Changes()
    {
        var original = new AgentConfig
        {
            MachineId = Guid.NewGuid().ToString("D"),
            Server = "https://relay.example:34544",
            Key = "rpd_live_key1",
            AgentToken = "rpd_agt_secret_1",
        };
        var parsed = AgentConfig.Parse(original.ToJson());
        Assert.NotNull(parsed);
        Assert.Equal("rpd_agt_secret_1", parsed!.AgentToken);

        // In-place upgrade keeps the token when server & key stay the same.
        var upgraded = AgentConfig.ForInstall(parsed, new AgentArgs(AgentCommand.Install));
        Assert.Equal("rpd_agt_secret_1", upgraded.AgentToken);

        // Re-enrolling with a different key clears the old token.
        var rekeyed = AgentConfig.ForInstall(parsed, new AgentArgs(AgentCommand.Install, Key: "rpd_live_key2"));
        Assert.Equal("", rekeyed.AgentToken);
    }

    [Fact]
    public async Task Hub_Sends_And_Persists_Assigned_AgentToken()
    {
        var cfg = new AgentConfig
        {
            MachineId = Guid.NewGuid().ToString("D"),
            Server = "https://relay.example:34544",
            Key = "rpd_live_key1",
            AgentToken = "rpd_agt_initial",
        };
        var fakeClient = new FakeAgentHubClient();
        var platform = new FakeAgentPlatform();
        string? savedToken = null;
        var worker = new AgentHubWorker(cfg, platform, new AgentSessionOptions
        {
            HeartbeatInterval = TimeSpan.FromMinutes(10),
            SaveAgentToken = t => savedToken = t,
        });

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var runTask = worker.RunSingleConnectionAsync(fakeClient, cts.Token);

        var helloMsg = await fakeClient.ReadAgentMessageAsync(cts.Token);
        Assert.Equal(AgentMessage.BodyOneofCase.Hello, helloMsg.BodyCase);
        Assert.Equal("rpd_agt_initial", helloMsg.Hello.AgentToken);

        await fakeClient.SendHubCommandAsync(new HubCommand
        {
            AssignAgentToken = new AssignAgentTokenCommand { AgentToken = "rpd_agt_rotated_2" },
        }, cts.Token);
        fakeClient.CompleteServerStream();
        await runTask;

        Assert.Equal("rpd_agt_rotated_2", cfg.AgentToken);
        Assert.Equal("rpd_agt_rotated_2", savedToken);
    }
}

public class RestartedCopyTests
{
    private const string Id = "205523f9-df7d-4f0b-8c7d-31caf7328962";

    [Fact]
    public void Reads_the_session_id_from_the_agent_command_line() =>
        Assert.Equal(Id, RestartedCopy.SessionIdFrom($"-u=https://relay.example:34544 -i={Id} -g=test-shop --unattended"));

    [Fact]
    public void No_session_id_is_null() => Assert.Null(RestartedCopy.SessionIdFrom("--unattended"));

    [Fact]
    public void A_restarted_copy_of_the_same_session_matches() =>
        Assert.True(RestartedCopy.IsRestartOf(
            $"\"C:\\Program Files\\RemotePCDiagnostics\\RemotePCDiagnostics.Host.exe\" -u=https://relay.example:34544 -i={Id} -g=test-shop --unattended --admin --restarted", Id));

    [Theory]
    [InlineData("-u=https://relay.example:34544 -i=" + Id + " --unattended")] // not marked --restarted
    [InlineData("-u=https://relay.example:34544 -i=11111111-2222-4333-8444-555555555555 --restarted")] // another session
    [InlineData("--restarted")] // Local Mode copy
    [InlineData("")]
    public void Other_copies_do_not_match(string commandLine) =>
        Assert.False(RestartedCopy.IsRestartOf(commandLine, Id));

    [Fact]
    public void No_session_never_matches() => Assert.False(RestartedCopy.IsRestartOf($"-i={Id} --restarted", null));
}

public class LaunchConditionRulesTests
{
    private static readonly DateTimeOffset At2330 = new(2026, 11, 25, 23, 30, 0, TimeSpan.FromHours(-7));

    [Theory]
    [InlineData(1320, 360, 23 * 60, true)]
    [InlineData(1320, 360, 2 * 60, true)]
    [InlineData(1320, 360, 6 * 60, false)] // the end minute is outside
    [InlineData(1320, 360, 12 * 60, false)]
    [InlineData(60, 300, 120, true)]
    [InlineData(60, 300, 400, false)]
    [InlineData(0, 0, 777, true)] // start == end: any time
    public void The_window_may_cross_midnight(int start, int end, int minute, bool inside) =>
        Assert.Equal(inside, LaunchConditionRules.InWindow(start, end, minute));

    [Fact]
    public void Each_rule_says_why_it_failed()
    {
        Assert.Contains("allowed hours (1:00 AM to 5:00 AM)", LaunchConditionRules.Check(false, 0, 60, 300, At2330, PowerReading.Ac, false, null));
        Assert.Contains("on battery", LaunchConditionRules.Check(true, 0, 0, 0, At2330, PowerReading.Battery, false, null));
        Assert.Contains("plugged in", LaunchConditionRules.Check(true, 0, 0, 0, At2330, PowerReading.Unknown, false, null));
        Assert.Contains("Couldn't tell whether someone", LaunchConditionRules.Check(false, 15, 0, 0, At2330, PowerReading.Ac, false, null));
        Assert.Contains("4 minutes ago", LaunchConditionRules.Check(false, 15, 0, 0, At2330, PowerReading.Ac, false, 250));
        Assert.Null(LaunchConditionRules.Check(true, 15, 1320, 360, At2330, PowerReading.Ac, false, 15 * 60));
    }

    [Fact]
    public void A_locked_session_counts_as_idle_and_needs_no_idle_read()
    {
        Assert.False(LaunchConditionRules.NeedsIdle(15, sessionLocked: true));
        Assert.True(LaunchConditionRules.NeedsIdle(15, sessionLocked: false));
        Assert.False(LaunchConditionRules.NeedsIdle(0, sessionLocked: false));
        Assert.Null(LaunchConditionRules.Check(false, 15, 0, 0, At2330, PowerReading.Ac, true, null));
    }
}
