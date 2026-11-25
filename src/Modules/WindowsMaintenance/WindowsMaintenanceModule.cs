using System.Globalization;
using System.Net.Http.Headers;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Workflow;

namespace RemotePCDiagnostics.Modules.WindowsMaintenance;

public enum ClockProbeStatus { Ok, CertificateTimeInvalid, NetworkOrTlsError }

/// <summary>One bracketed HTTPS HEAD/GET response used for clock comparison.</summary>
public sealed record ClockHttpsSample(
    ClockProbeStatus Status,
    DateTimeOffset BeforeUtc,
    DateTimeOffset AfterUtc,
    DateTimeOffset? ServerDateUtc,
    TimeSpan? AgeHeader = null,
    string? Error = null)
{
    public TimeSpan Rtt => AfterUtc - BeforeUtc;
    public DateTimeOffset LocalMidpointUtc => BeforeUtc + TimeSpan.FromTicks(Rtt.Ticks / 2);
    public TimeSpan? Offset => ServerDateUtc is { } srv ? LocalMidpointUtc - srv : null;
}

public interface IClockHttpsProber
{
    Task<ClockHttpsSample> ProbeOnceAsync(Uri uri, CancellationToken ct);
}

/// <summary>
/// Probes the Admin server over HTTPS with full TLS certificate validation enabled.
/// Never bypasses certificate validation: the callback only observes <see cref="X509ChainStatusFlags.NotTimeValid"/> and returns <c>false</c> on any TLS error.
/// </summary>
public sealed class StrictHttpsClockProber(Func<DateTimeOffset>? utcNow = null) : IClockHttpsProber
{
    private readonly Func<DateTimeOffset> _utcNow = utcNow ?? (() => DateTimeOffset.UtcNow);
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(4);

    public async Task<ClockHttpsSample> ProbeOnceAsync(Uri uri, CancellationToken ct)
    {
        var sawNotTimeValid = false;
        using var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            UseDefaultCredentials = false,
            ServerCertificateCustomValidationCallback = (_, _, chain, errors) =>
            {
                if (errors == SslPolicyErrors.None) return true;
                if (chain?.ChainStatus.Any(s => s.Status == X509ChainStatusFlags.NotTimeValid) == true)
                    sawNotTimeValid = true;
                return false;
            },
        };
        using var http = new HttpClient(handler) { Timeout = RequestTimeout };
        using var req = new HttpRequestMessage(HttpMethod.Head, uri);
        req.Headers.CacheControl = new CacheControlHeaderValue { NoCache = true, NoStore = true };

        var before = _utcNow();
        try
        {
            using var resp = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            var after = _utcNow();
            return new ClockHttpsSample(ClockProbeStatus.Ok, before, after, resp.Headers.Date, resp.Headers.Age);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) when (sawNotTimeValid || IsNotTimeValidException(ex))
        {
            var after = _utcNow();
            return new ClockHttpsSample(ClockProbeStatus.CertificateTimeInvalid, before, after, null, Error: ex.Message);
        }
        catch (Exception ex)
        {
            var after = _utcNow();
            return new ClockHttpsSample(ClockProbeStatus.NetworkOrTlsError, before, after, null, Error: ex.Message);
        }
    }

    internal static bool IsNotTimeValidException(Exception ex)
    {
        for (var cur = ex; cur is not null; cur = cur.InnerException)
        {
            if (cur is AuthenticationException && cur.Message.Contains("NotTimeValid", StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }
}

public sealed record W32tmStatus(string? Source, DateTimeOffset? LastSuccessfulSyncUtc, string? RawLastSync, bool Unsynchronized);

public sealed record ClockAssessment(
    bool Offline,
    bool CertificateTimeInvalid,
    double? CorroboratedOffsetSeconds,
    bool OffsetWarning,
    string OffsetSummary,
    W32tmStatus? TimeService,
    TimeSpan? SyncAge,
    bool StaleSyncWarning);

public sealed record HostsEntry(string Ip, string Hostname);
public sealed record HostsFileStatus(bool Readable, int NonCommentLineCount, IReadOnlyList<HostsEntry> NonLocalhostEntries, string? Error = null);

public sealed record RestorePointInfo(int SequenceNumber, string Description, DateTimeOffset? CreatedUtc);
public sealed record RestorePointsStatus(bool? SystemProtectionEnabled, IReadOnlyList<RestorePointInfo>? RestorePoints, bool AgentRequired, string? Note = null);

public sealed record DeliveryOptimizationStatus(int? EffectiveMode, string Source, string Description);

/// <summary>
/// Read-only Windows maintenance check (<see cref="ModuleKind.Check"/>, <see cref="ModuleGroups.Windows"/>):
/// Clock &amp; time sync, hosts file, Restore points (Agent), and Delivery Optimization.
/// </summary>
public sealed class WindowsMaintenanceModule(
    SystemCommandRunner? commands = null,
    IRegistrySource? registry = null,
    IWmiSource? wmi = null,
    IElevatedCommandBridge? bridge = null,
    IClockHttpsProber? clockProber = null,
    Func<bool>? isNetworkAvailable = null,
    Func<DateTimeOffset>? utcNow = null,
    Uri? clockUri = null)
    : AreaModuleBase(commands?.Log)
{
    public const string ModuleName = ModuleSlugs.WindowsMaintenance;
    public const double ClockOffsetWarningSeconds = 60.0;
    public const double MaxSampleDisagreementSeconds = 15.0;
    public static readonly TimeSpan MaxAcceptableRtt = TimeSpan.FromMilliseconds(2500);
    public static readonly TimeSpan MaxAcceptableAgeHeader = TimeSpan.FromSeconds(5);
    public static readonly TimeSpan StaleSyncThreshold = TimeSpan.FromDays(7);
    public const string CertTimeFailedMessage = "Certificate time validation failed. The PC clock or server certificate may be out of date.";
    public const string ClockUnavailableMessage = "Clock offset unavailable";

    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.WindowsMaintenance;
    public override string DisplayName => "Windows maintenance";
    protected override string FailedMessage => "Couldn't read Windows maintenance details on this PC.";

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        var nowFn = utcNow ?? (() => DateTimeOffset.UtcNow);
        var netAvailFn = isNetworkAvailable ?? NetworkInterface.GetIsNetworkAvailable;
        var prober = clockProber ?? new StrictHttpsClockProber(nowFn);
        var uri = clockUri ?? new Uri(ShopRelayClient.DefaultShopPortalUrl);

        progress.ReportStep(1, 4, "Checking PC clock and Windows Time service…");
        var w32tm = await ReadW32tmAsync(ct).ConfigureAwait(false);
        var clock = await AssessClockAsync(prober, uri, netAvailFn, nowFn, w32tm, ct).ConfigureAwait(false);

        progress.ReportStep(2, 4, "Reading Windows hosts file…");
        var hosts = ReadHostsFile();

        progress.ReportStep(3, 4, "Checking System Restore points…");
        var restore = await ReadRestorePointsAsync(ct).ConfigureAwait(false);

        progress.ReportStep(4, 4, "Checking Delivery Optimization settings…");
        var deliveryOpt = await ReadDeliveryOptimizationAsync(ct).ConfigureAwait(false);

        return Build(clock, hosts, restore, deliveryOpt);
    }

    public static async Task<ClockAssessment> AssessClockAsync(
        IClockHttpsProber prober,
        Uri uri,
        Func<bool> isNetworkAvailable,
        Func<DateTimeOffset> utcNow,
        W32tmStatus? w32tm,
        CancellationToken ct)
    {
        var now = utcNow();
        TimeSpan? syncAge = w32tm?.LastSuccessfulSyncUtc is { } lastSync ? now - lastSync : null;
        var staleSync = syncAge is { } age && age >= StaleSyncThreshold;

        if (!isNetworkAvailable())
        {
            return new ClockAssessment(
                Offline: true,
                CertificateTimeInvalid: false,
                CorroboratedOffsetSeconds: null,
                OffsetWarning: false,
                OffsetSummary: "Offline — network is unavailable",
                TimeService: w32tm,
                SyncAge: syncAge,
                StaleSyncWarning: staleSync);
        }

        var s1 = await prober.ProbeOnceAsync(uri, ct).ConfigureAwait(false);
        if (s1.Status == ClockProbeStatus.CertificateTimeInvalid)
        {
            return new ClockAssessment(false, true, null, false, CertTimeFailedMessage, w32tm, syncAge, staleSync);
        }

        var s2 = await prober.ProbeOnceAsync(uri, ct).ConfigureAwait(false);
        if (s2.Status == ClockProbeStatus.CertificateTimeInvalid)
        {
            return new ClockAssessment(false, true, null, false, CertTimeFailedMessage, w32tm, syncAge, staleSync);
        }

        return EvaluateClockSamples(s1, s2, w32tm, syncAge, staleSync);
    }

    public static ClockAssessment EvaluateClockSamples(
        ClockHttpsSample? s1,
        ClockHttpsSample? s2,
        W32tmStatus? w32tm,
        TimeSpan? syncAge,
        bool staleSync)
    {
        if (s1?.Status == ClockProbeStatus.CertificateTimeInvalid || s2?.Status == ClockProbeStatus.CertificateTimeInvalid)
            return new ClockAssessment(false, true, null, false, CertTimeFailedMessage, w32tm, syncAge, staleSync);

        if (!IsUsableSample(s1) || !IsUsableSample(s2))
            return new ClockAssessment(false, false, null, false, ClockUnavailableMessage, w32tm, syncAge, staleSync);

        var o1 = s1!.Offset!.Value.TotalSeconds;
        var o2 = s2!.Offset!.Value.TotalSeconds;

        // Conflicting samples (opposite directions beyond noise or disagreeing by > 15s) -> unavailable, never warn.
        if (Math.Abs(o1 - o2) > MaxSampleDisagreementSeconds)
            return new ClockAssessment(false, false, null, false, ClockUnavailableMessage, w32tm, syncAge, staleSync);

        var bothOverThreshold = Math.Abs(o1) > ClockOffsetWarningSeconds
            && Math.Abs(o2) > ClockOffsetWarningSeconds
            && Math.Sign(o1) == Math.Sign(o2);

        var avgOffset = (o1 + o2) / 2.0;
        var summary = bothOverThreshold
            ? $"PC clock is {(avgOffset > 0 ? "ahead" : "behind")} by about {Math.Abs(avgOffset):0} seconds"
            : Math.Abs(avgOffset) <= 5
                ? "Within a few seconds of HTTPS server time"
                : $"Within {Math.Abs(avgOffset):0} seconds of HTTPS server time";

        return new ClockAssessment(false, false, avgOffset, bothOverThreshold, summary, w32tm, syncAge, staleSync);
    }

    private static bool IsUsableSample(ClockHttpsSample? s) =>
        s is { Status: ClockProbeStatus.Ok, ServerDateUtc: not null }
        && s.Rtt >= TimeSpan.Zero
        && s.Rtt <= MaxAcceptableRtt
        && (s.AgeHeader is null || s.AgeHeader.Value <= MaxAcceptableAgeHeader);

    public static AreaReport Build(
        ClockAssessment clock,
        HostsFileStatus hosts,
        RestorePointsStatus restore,
        DeliveryOptimizationStatus deliveryOpt)
    {
        var cards = new List<AreaCard>
        {
            BuildClockCard(clock),
            BuildHostsCard(hosts),
            BuildRestorePointsCard(restore),
            BuildDeliveryOptimizationCard(deliveryOpt),
        };

        var summaryParts = new List<string>();
        if (clock.CertificateTimeInvalid) summaryParts.Add("certificate time validation failed");
        else if (clock.OffsetWarning) summaryParts.Add("clock offset warning");
        else if (clock.StaleSyncWarning) summaryParts.Add("time sync older than 7 days");
        else if (clock.Offline) summaryParts.Add("offline");
        else summaryParts.Add("clock checked");

        if (hosts.Readable && hosts.NonLocalhostEntries.Count > 0)
            summaryParts.Add($"{hosts.NonLocalhostEntries.Count} custom hosts {(hosts.NonLocalhostEntries.Count == 1 ? "entry" : "entries")}");

        if (restore.SystemProtectionEnabled == false)
            summaryParts.Add("System Protection off");

        var status = AreaReport.Worst(cards.Select(c => c.ErrorText is not null ? AreaLevel.Warning : c.Level));
        return new AreaReport(cards, string.Join(" · ", summaryParts), status);
    }

    private static AreaCard BuildClockCard(ClockAssessment clock)
    {
        var level = clock.CertificateTimeInvalid || clock.OffsetWarning || clock.StaleSyncWarning
            ? AreaLevel.Warning
            : clock.CorroboratedOffsetSeconds is not null
                ? AreaLevel.Ok
                : AreaLevel.Neutral;

        var headline = clock.CertificateTimeInvalid
            ? CertTimeFailedMessage
            : clock.OffsetWarning
                ? clock.OffsetSummary
                : clock.Offline
                    ? "Offline — network unavailable"
                    : clock.CorroboratedOffsetSeconds is not null
                        ? clock.OffsetSummary
                        : ClockUnavailableMessage;

        var rows = new List<AreaRow>
        {
            new(clock.CertificateTimeInvalid || clock.OffsetWarning ? AreaLevel.Warning : clock.CorroboratedOffsetSeconds is not null ? AreaLevel.Ok : AreaLevel.Neutral,
                ["HTTPS clock check", clock.OffsetSummary]),
        };

        if (clock.TimeService is { } ts)
        {
            var ageText = clock.SyncAge is { } age
                ? FormatAge(age)
                : !string.IsNullOrWhiteSpace(ts.RawLastSync) ? ts.RawLastSync : "Unavailable";
            rows.Add(new(clock.StaleSyncWarning ? AreaLevel.Warning : AreaLevel.Neutral, ["Last time sync", ageText]));
            rows.Add(new(AreaLevel.Neutral, ["Time source", string.IsNullOrWhiteSpace(ts.Source) ? "Unavailable" : ts.Source]));
        }
        else
        {
            rows.Add(new(AreaLevel.Neutral, ["Windows Time service", "Unavailable"]));
        }

        var notes = new List<string>();
        if (clock.CertificateTimeInvalid)
            notes.Add(CertTimeFailedMessage);
        if (clock.StaleSyncWarning)
            notes.Add("Windows Time has not synced successfully in at least 7 days.");
        notes.Add("Read-only check using strict TLS certificate validation against the Admin HTTPS server.");

        // Read-only in Batch 4: no resync action.
        return new("clock", "Clock & time sync", level, headline,
            clock.TimeService?.Source is { Length: > 0 } src ? $"Time source: {src}" : "HTTPS time check",
            ["Detail", "Value"], rows, Note: string.Join(" ", notes));
    }

    private static AreaCard BuildHostsCard(HostsFileStatus hosts)
    {
        if (!hosts.Readable)
        {
            return new("hosts", "Windows hosts file", AreaLevel.Neutral, "Hosts file unreadable",
                hosts.Error ?? "Couldn't read hosts file", ["Host", "IP address"], []);
        }

        var custom = hosts.NonLocalhostEntries;
        var level = custom.Count > 0 ? AreaLevel.Neutral : AreaLevel.Ok;
        var headline = custom.Count == 0
            ? "No custom entries"
            : $"{custom.Count} custom {(custom.Count == 1 ? "entry" : "entries")}";
        var meta = $"{hosts.NonCommentLineCount} active {(hosts.NonCommentLineCount == 1 ? "line" : "lines")} in drivers\\etc\\hosts";
        var rows = custom.Take(50).Select(e => new AreaRow(AreaLevel.Neutral, [e.Hostname, e.Ip])).ToList();
        return new("hosts", "Windows hosts file", level, headline, meta, ["Hostname", "IP address"], rows,
            EmptyText: custom.Count == 0 ? "Only default localhost entries (or comments) were found." : null,
            Note: "Read-only check of %SystemRoot%\\System32\\drivers\\etc\\hosts.");
    }

    private static AreaCard BuildRestorePointsCard(RestorePointsStatus restore)
    {
        var protText = restore.SystemProtectionEnabled switch
        {
            true => "On",
            false => "Off",
            null => "Unknown",
        };
        var latest = restore.RestorePoints?.OrderByDescending(p => p.CreatedUtc).FirstOrDefault();
        var level = restore.SystemProtectionEnabled == false ? AreaLevel.Warning
            : restore.SystemProtectionEnabled == true && latest is not null ? AreaLevel.Ok
            : AreaLevel.Neutral;

        var headline = restore.AgentRequired
            ? "Restore points require the Agent"
            : restore.SystemProtectionEnabled == false
                ? "System Protection is off"
                : latest is not null
                    ? $"Last restore point: {latest.Description}"
                    : "No restore points found";

        var rows = new List<AreaRow>
        {
            new(restore.SystemProtectionEnabled == false ? AreaLevel.Warning : AreaLevel.Neutral, ["System Protection", protText]),
            new(AreaLevel.Neutral, ["Restore points found", restore.RestorePoints is null ? "Unavailable" : restore.RestorePoints.Count.ToString(CultureInfo.InvariantCulture)]),
        };
        if (latest is not null)
        {
            rows.Add(new(AreaLevel.Neutral, ["Most recent", latest.CreatedUtc is { } dt ? $"{latest.Description} ({dt:yyyy-MM-dd HH:mm} UTC)" : latest.Description]));
        }

        return new("restore-points", "System Restore points", level, headline,
            restore.AgentRequired ? ElevationService.AdminRepairHint : $"System Protection: {protText}",
            ["Detail", "Value"], rows, Note: restore.Note);
    }

    private static AreaCard BuildDeliveryOptimizationCard(DeliveryOptimizationStatus dopt)
    {
        var headline = dopt.EffectiveMode is { } m ? $"{dopt.Description} (mode {m})" : dopt.Description;
        var rows = new List<AreaRow>
        {
            new(AreaLevel.Neutral, ["Effective upload mode", headline]),
            new(AreaLevel.Neutral, ["Source", dopt.Source]),
        };
        return new("delivery-optimization", "Delivery Optimization", AreaLevel.Neutral, headline,
            "Read-only check of Windows Update peer-to-peer upload mode",
            ["Detail", "Value"], rows);
    }

    // -------------------------------------------------------------------------
    // Parsers & Readers
    // -------------------------------------------------------------------------

    public static W32tmStatus? ParseW32tmOutput(string? stdout)
    {
        if (string.IsNullOrWhiteSpace(stdout)) return null;
        string? source = null;
        string? rawLastSync = null;
        var unsynced = false;

        foreach (var raw in stdout.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var colon = raw.IndexOf(':');
            if (colon <= 0) continue;
            var key = raw[..colon].Trim();
            var val = raw[(colon + 1)..].Trim();
            if (string.Equals(key, "Leap Indicator", StringComparison.OrdinalIgnoreCase))
            {
                if (val.StartsWith("3", StringComparison.Ordinal) || val.Contains("not synchronized", StringComparison.OrdinalIgnoreCase))
                    unsynced = true;
            }
            else if (string.Equals(key, "Source", StringComparison.OrdinalIgnoreCase))
            {
                source = val;
            }
            else if (string.Equals(key, "Last Successful Sync Time", StringComparison.OrdinalIgnoreCase))
            {
                rawLastSync = val;
            }
        }

        DateTimeOffset? parsedSync = null;
        if (!string.IsNullOrWhiteSpace(rawLastSync)
            && !rawLastSync.Equals("unspecified", StringComparison.OrdinalIgnoreCase)
            && DateTimeOffset.TryParse(rawLastSync, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out var dto))
        {
            parsedSync = dto.ToUniversalTime();
        }
        else if (!string.IsNullOrWhiteSpace(rawLastSync)
            && !rawLastSync.Equals("unspecified", StringComparison.OrdinalIgnoreCase)
            && DateTimeOffset.TryParse(rawLastSync, CultureInfo.CurrentCulture, DateTimeStyles.AssumeLocal, out var dtoLocal))
        {
            parsedSync = dtoLocal.ToUniversalTime();
        }

        return new W32tmStatus(source, parsedSync, rawLastSync, unsynced);
    }

    public static HostsFileStatus ParseHostsContent(string? content)
    {
        if (content is null) return new(false, 0, [], "Hosts file not found.");
        var nonCommentLines = 0;
        var custom = new List<HostsEntry>();

        foreach (var raw in content.Split(['\r', '\n']))
        {
            var line = raw;
            var hash = line.IndexOf('#');
            if (hash >= 0) line = line[..hash];
            line = line.Trim();
            if (line.Length == 0) continue;
            nonCommentLines++;

            var parts = line.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) continue;
            var ip = parts[0];
            for (var i = 1; i < parts.Length; i++)
            {
                var host = parts[i];
                if (IsLocalhostEntry(ip, host)) continue;
                custom.Add(new HostsEntry(ip, host));
            }
        }

        return new(true, nonCommentLines, custom);
    }

    private static bool IsLocalhostEntry(string ip, string host) =>
        (ip == "127.0.0.1" || ip == "::1")
        && (string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase)
            || string.Equals(host, "localhost.localdomain", StringComparison.OrdinalIgnoreCase));

    public static string DescribeDeliveryOptimizationMode(int? mode) => mode switch
    {
        0 => "HTTP only (no peering)",
        1 => "PCs on my local network",
        2 => "PCs on my local network / private group",
        3 => "PCs on my local network and PCs on the internet",
        99 => "Simple download mode (no peering)",
        100 => "Bypass mode (BITS)",
        null => "Default (Windows managed)",
        _ => $"Custom mode ({mode})",
    };

    private async Task<W32tmStatus?> ReadW32tmAsync(CancellationToken ct)
    {
        try
        {
            if (bridge is { IsConnected: true })
            {
                var elevated = await bridge.RunElevatedAsync("w32tm.exe", ["/query", "/status", "/verbose"], TimeSpan.FromSeconds(5), ct).ConfigureAwait(false);
                if (elevated is { ExitCode: 0 })
                    return ParseW32tmOutput(elevated.StdOut);
            }
            if (commands is not null)
            {
                var res = await commands.RunAsync(SystemCommandRunner.SystemTool("w32tm.exe"), ["/query", "/status", "/verbose"], ct).ConfigureAwait(false);
                if (res is { ExitCode: 0 })
                    return ParseW32tmOutput(res.StdOut);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { }
        return null;
    }

    private static HostsFileStatus ReadHostsFile()
    {
        try
        {
            var path = Path.Combine(Environment.SystemDirectory, "drivers", "etc", "hosts");
            if (!File.Exists(path)) return new(false, 0, [], "Hosts file not found.");
            return ParseHostsContent(File.ReadAllText(path));
        }
        catch (Exception ex)
        {
            return new(false, 0, [], ex.Message);
        }
    }

    private async Task<RestorePointsStatus> ReadRestorePointsAsync(CancellationToken ct)
    {
        bool? enabled = null;
        if (registry is not null)
        {
            var sr = await registry.ReadAsync(new RegistryRead(
                RegistryRoot.LocalMachine,
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore",
                ["RPSessionInterval", "DisableSR"]), ct).ConfigureAwait(false);
            var row = sr.Rows?.FirstOrDefault();
            var disableSr = row?.Long("DisableSR");
            var rpInterval = row?.Long("RPSessionInterval");
            if (disableSr == 1) enabled = false;
            else if (rpInterval is > 0) enabled = true;
            else if (rpInterval == 0) enabled = false;
        }

        if (wmi is null)
            return new RestorePointsStatus(enabled, null, AgentRequired: true, Note: "Reading restore point history requires the Agent.");

        var q = await wmi.QueryAsync(@"root\default", "SELECT SequenceNumber, Description, CreationTime FROM SystemRestore", ct).ConfigureAwait(false);
        if (!q.Success || q.Rows is null)
            return new RestorePointsStatus(enabled, null, AgentRequired: bridge is not { IsConnected: true }, Note: q.Error ?? "Couldn't read System Restore points.");

        var points = new List<RestorePointInfo>();
        foreach (var r in q.Rows)
        {
            var seq = (int)(r.Long("SequenceNumber") ?? 0);
            var desc = r.Str("Description");
            var created = ParseWmiDateTime(r.Str("CreationTime"));
            points.Add(new RestorePointInfo(seq, string.IsNullOrWhiteSpace(desc) ? $"Restore point #{seq}" : desc, created));
        }
        return new RestorePointsStatus(enabled ?? (points.Count > 0 ? true : null), points, AgentRequired: false);
    }

    public static DateTimeOffset? ParseWmiDateTime(string? dmtf)
    {
        if (string.IsNullOrWhiteSpace(dmtf) || dmtf.Length < 14) return null;
        if (!DateTime.TryParseExact(dmtf[..14], "yyyyMMddHHmmss", CultureInfo.InvariantCulture, DateTimeStyles.None, out var dt))
            return null;
        return new DateTimeOffset(dt, TimeSpan.Zero);
    }

    private async Task<DeliveryOptimizationStatus> ReadDeliveryOptimizationAsync(CancellationToken ct)
    {
        if (registry is null)
            return new DeliveryOptimizationStatus(null, "Default", DescribeDeliveryOptimizationMode(null));

        var policy = await registry.ReadAsync(new RegistryRead(
            RegistryRoot.LocalMachine,
            @"SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization",
            ["DODownloadMode"]), ct).ConfigureAwait(false);
        if (policy.Success && policy.Rows?.FirstOrDefault()?.Long("DODownloadMode") is { } pMode)
            return new DeliveryOptimizationStatus((int)pMode, "Group Policy", DescribeDeliveryOptimizationMode((int)pMode));

        var config = await registry.ReadAsync(new RegistryRead(
            RegistryRoot.LocalMachine,
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config",
            ["DODownloadMode"]), ct).ConfigureAwait(false);
        if (config.Success && config.Rows?.FirstOrDefault()?.Long("DODownloadMode") is { } cMode)
            return new DeliveryOptimizationStatus((int)cMode, "Windows configuration", DescribeDeliveryOptimizationMode((int)cMode));

        return new DeliveryOptimizationStatus(null, "Windows default", DescribeDeliveryOptimizationMode(null));
    }

    private static string FormatAge(TimeSpan age)
    {
        if (age < TimeSpan.Zero) return "Just now";
        if (age.TotalDays >= 1) return $"{(int)age.TotalDays} day{((int)age.TotalDays == 1 ? "" : "s")} ago";
        if (age.TotalHours >= 1) return $"{(int)age.TotalHours} hour{((int)age.TotalHours == 1 ? "" : "s")} ago";
        return $"{Math.Max(1, (int)age.TotalMinutes)} min ago";
    }
}
