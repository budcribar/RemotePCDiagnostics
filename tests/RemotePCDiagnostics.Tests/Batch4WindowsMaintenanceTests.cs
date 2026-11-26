using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Modules.WindowsMaintenance;
using Xunit;

namespace RemotePCDiagnostics.Tests;

public sealed class Batch4WindowsMaintenanceTests
{
    private static readonly Uri AdminUri = new("https://admin.remoteblazorwebview.com");
    private static readonly DateTimeOffset Now = new(2026, 11, 25, 18, 0, 0, TimeSpan.Zero);

    // -------------------------------------------------------------------------
    // Pending restart on existing PendingUpdates card
    // -------------------------------------------------------------------------

    [Fact]
    public void PendingUpdates_ReadRegistryRebootReasons_DetectsCbsWuAndPendingFileRename()
    {
        var reasons = PendingUpdates.ReadRegistryRebootReasons(
            hklmKeyExists: path => path == PendingUpdates.CbsRebootPendingKey || path == PendingUpdates.WuRebootRequiredKey,
            hklmNonEmptyMultiString: (path, val) => path == PendingUpdates.SessionManagerKey && val == PendingUpdates.PendingFileRenameValue);

        Assert.Equal(3, reasons.Count);
        Assert.Contains(reasons, r => r.Contains("CBS", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(reasons, r => r.Contains("Windows Update", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(reasons, r => r.Contains("file rename", StringComparison.OrdinalIgnoreCase));

        var list = new PendingUpdateList([], RebootRequired: true, RebootReasons: reasons);
        var card = PendingUpdates.Card(list, drivers: false);
        Assert.Equal(PendingUpdates.SoftwareCardId, card.Id);
        Assert.Contains("CBS", card.Meta, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(card.Actions ?? [], a => a.Kind == RemediationKind.ScheduleCleanRestart);
    }

    // -------------------------------------------------------------------------
    // Clock card tests (all v8 Batch 4 requirements)
    // -------------------------------------------------------------------------

    [Fact]
    public async Task Clock_Corroborated90sOffset_WarnsAndExposesNoResyncAction()
    {
        // PC clock is 90s ahead of HTTPS server Date across two fresh, low-latency responses.
        var prober = new SequenceClockProber(
            new ClockHttpsSample(ClockProbeStatus.Ok, Now, Now.AddMilliseconds(120), Now.AddSeconds(-90)),
            new ClockHttpsSample(ClockProbeStatus.Ok, Now.AddSeconds(1), Now.AddSeconds(1).AddMilliseconds(140), Now.AddSeconds(-89)));

        var w32tm = new W32tmStatus("time.windows.com", Now.AddHours(-2), null, false);
        var clock = await WindowsMaintenanceModule.AssessClockAsync(prober, AdminUri, () => true, () => Now, w32tm, CancellationToken.None);

        Assert.True(clock.OffsetWarning);
        Assert.False(clock.Offline);
        Assert.False(clock.CertificateTimeInvalid);
        Assert.NotNull(clock.CorroboratedOffsetSeconds);
        Assert.InRange(clock.CorroboratedOffsetSeconds!.Value, 88, 92);

        var report = WindowsMaintenanceModule.Build(clock, new(true, 0, []), new(true, [], false), new(1, "Windows", "LAN"));
        var card = Assert.Single(report.Cards, c => c.Id == "clock");
        Assert.Equal(AreaLevel.Warning, card.Level);
        Assert.Null(card.Actions); // Batch 4 exposes no resync action.
    }

    [Fact]
    public async Task Clock_ExpiredServerOrIntermediateCert_ShowsExactCertTimeMessageWithoutBlamingClockAlone()
    {
        var prober = new SequenceClockProber(
            new ClockHttpsSample(ClockProbeStatus.CertificateTimeInvalid, Now, Now.AddMilliseconds(80), null, Error: "NotTimeValid"));

        var clock = await WindowsMaintenanceModule.AssessClockAsync(prober, AdminUri, () => true, () => Now, null, CancellationToken.None);

        Assert.True(clock.CertificateTimeInvalid);
        Assert.False(clock.OffsetWarning);
        Assert.Equal(WindowsMaintenanceModule.CertTimeFailedMessage, clock.OffsetSummary);

        var report = WindowsMaintenanceModule.Build(clock, new(true, 0, []), new(true, [], false), new(1, "Windows", "LAN"));
        var card = Assert.Single(report.Cards, c => c.Id == "clock");
        Assert.Equal(AreaLevel.Warning, card.Level);
        Assert.Equal(WindowsMaintenanceModule.CertTimeFailedMessage, card.Headline);
        Assert.Null(card.Actions);
    }

    [Fact]
    public async Task Clock_PossibleSkewWithoutCorroboration_TreatsAsUnavailableAndDoesNotWarn()
    {
        // Sample 1 shows +90s, Sample 2 shows +10s -> conflicting samples -> unavailable.
        var conflicting = new SequenceClockProber(
            new ClockHttpsSample(ClockProbeStatus.Ok, Now, Now.AddMilliseconds(100), Now.AddSeconds(-90)),
            new ClockHttpsSample(ClockProbeStatus.Ok, Now.AddSeconds(1), Now.AddSeconds(1).AddMilliseconds(100), Now.AddSeconds(-9)));

        var c1 = await WindowsMaintenanceModule.AssessClockAsync(conflicting, AdminUri, () => true, () => Now, null, CancellationToken.None);
        Assert.False(c1.OffsetWarning);
        Assert.Null(c1.CorroboratedOffsetSeconds);
        Assert.Equal(WindowsMaintenanceModule.ClockUnavailableMessage, c1.OffsetSummary);

        // Only one valid sample, second fails -> uncorroborated -> unavailable.
        var singleOnly = new SequenceClockProber(
            new ClockHttpsSample(ClockProbeStatus.Ok, Now, Now.AddMilliseconds(100), Now.AddSeconds(-90)),
            new ClockHttpsSample(ClockProbeStatus.NetworkOrTlsError, Now.AddSeconds(1), Now.AddSeconds(2), null, Error: "timeout"));

        var c2 = await WindowsMaintenanceModule.AssessClockAsync(singleOnly, AdminUri, () => true, () => Now, null, CancellationToken.None);
        Assert.False(c2.OffsetWarning);
        Assert.False(c2.Offline); // Network is available, so must NOT say offline!
        Assert.Equal(WindowsMaintenanceModule.ClockUnavailableMessage, c2.OffsetSummary);
    }

    [Fact]
    public async Task Clock_StaleLocalSync_WarnsAndShowsSyncAgeAndSourceSeparately()
    {
        var w32tmOut = """
            Leap Indicator: 0(no warning)
            Stratum: 3 (secondary reference - syncd by (S)NTP)
            Last Successful Sync Time: 2026-11-10 12:00:00
            Source: time.windows.com,0x9
            """;
        var parsed = WindowsMaintenanceModule.ParseW32tmOutput(w32tmOut);
        Assert.NotNull(parsed);
        Assert.Equal("time.windows.com,0x9", parsed!.Source);
        Assert.NotNull(parsed.LastSuccessfulSyncUtc);

        var healthyHttps = new SequenceClockProber(
            new ClockHttpsSample(ClockProbeStatus.Ok, Now, Now.AddMilliseconds(80), Now),
            new ClockHttpsSample(ClockProbeStatus.Ok, Now.AddSeconds(1), Now.AddSeconds(1).AddMilliseconds(90), Now.AddSeconds(1)));

        var clock = await WindowsMaintenanceModule.AssessClockAsync(healthyHttps, AdminUri, () => true, () => Now, parsed, CancellationToken.None);
        Assert.False(clock.OffsetWarning);
        Assert.True(clock.StaleSyncWarning);

        var report = WindowsMaintenanceModule.Build(clock, new(true, 0, []), new(true, [], false), new(1, "Windows", "LAN"));
        var card = Assert.Single(report.Cards, c => c.Id == "clock");
        Assert.Equal(AreaLevel.Warning, card.Level);
        Assert.Contains(card.Rows, r => r.Values[0] == "Last time sync" && r.Values[1].Contains("days ago"));
        Assert.Contains(card.Rows, r => r.Values[0] == "Time source" && r.Values[1] == "time.windows.com");
        Assert.Null(card.Actions);
    }

    [Fact]
    public async Task Clock_MissingOrStaleDateHeaderOrHighRtt_IsUnavailable()
    {
        // Missing Date header
        var missingDate = new SequenceClockProber(
            new ClockHttpsSample(ClockProbeStatus.Ok, Now, Now.AddMilliseconds(100), null),
            new ClockHttpsSample(ClockProbeStatus.Ok, Now, Now.AddMilliseconds(100), null));
        var c1 = await WindowsMaintenanceModule.AssessClockAsync(missingDate, AdminUri, () => true, () => Now, null, CancellationToken.None);
        Assert.Equal(WindowsMaintenanceModule.ClockUnavailableMessage, c1.OffsetSummary);
        Assert.False(c1.OffsetWarning);

        // Stale cached response (Age > 5s)
        var staleAge = new SequenceClockProber(
            new ClockHttpsSample(ClockProbeStatus.Ok, Now, Now.AddMilliseconds(100), Now.AddSeconds(-120), AgeHeader: TimeSpan.FromSeconds(30)),
            new ClockHttpsSample(ClockProbeStatus.Ok, Now, Now.AddMilliseconds(100), Now.AddSeconds(-120), AgeHeader: TimeSpan.FromSeconds(30)));
        var c2 = await WindowsMaintenanceModule.AssessClockAsync(staleAge, AdminUri, () => true, () => Now, null, CancellationToken.None);
        Assert.Equal(WindowsMaintenanceModule.ClockUnavailableMessage, c2.OffsetSummary);
        Assert.False(c2.OffsetWarning);

        // Excessive RTT (> 2.5s timing uncertainty)
        var slowRtt = new SequenceClockProber(
            new ClockHttpsSample(ClockProbeStatus.Ok, Now, Now.AddSeconds(4), Now.AddSeconds(-120)),
            new ClockHttpsSample(ClockProbeStatus.Ok, Now, Now.AddSeconds(4), Now.AddSeconds(-120)));
        var c3 = await WindowsMaintenanceModule.AssessClockAsync(slowRtt, AdminUri, () => true, () => Now, null, CancellationToken.None);
        Assert.Equal(WindowsMaintenanceModule.ClockUnavailableMessage, c3.OffsetSummary);
        Assert.False(c3.OffsetWarning);
    }

    [Fact]
    public async Task Clock_TrueOfflineOperation_ReportsOfflineWithoutProbing()
    {
        var prober = new SequenceClockProber();
        var clock = await WindowsMaintenanceModule.AssessClockAsync(prober, AdminUri, () => false, () => Now, null, CancellationToken.None);

        Assert.True(clock.Offline);
        Assert.False(clock.OffsetWarning);
        Assert.Equal(0, prober.Calls);
        Assert.Contains("Offline", clock.OffsetSummary, StringComparison.OrdinalIgnoreCase);
    }

    // -------------------------------------------------------------------------
    // hosts file, Restore points, Delivery Optimization
    // -------------------------------------------------------------------------

    [Fact]
    public void HostsFile_CountsNonCommentLinesAndListsNonLocalhostEntries()
    {
        var content = """
            # Copyright Microsoft Corp.
            127.0.0.1       localhost
            ::1             localhost
            10.0.0.5        intranet.local  app.local # custom
            0.0.0.0         ads.example.test
            """;

        var parsed = WindowsMaintenanceModule.ParseHostsContent(content);
        Assert.True(parsed.Readable);
        Assert.Equal(4, parsed.NonCommentLineCount);
        Assert.Equal(3, parsed.NonLocalhostEntries.Count);
        Assert.Contains(parsed.NonLocalhostEntries, e => e.Ip == "10.0.0.5" && e.Hostname == "intranet.local");
        Assert.Contains(parsed.NonLocalhostEntries, e => e.Ip == "10.0.0.5" && e.Hostname == "app.local");
        Assert.Contains(parsed.NonLocalhostEntries, e => e.Ip == "0.0.0.0" && e.Hostname == "ads.example.test");
    }

    [Fact]
    public void WmiQueryPolicy_AllowsRootDefaultSystemRestore_AndDeliveryOptimizationDescriptions()
    {
        Assert.Null(WmiQueryPolicy.Problem(@"root\default", "SELECT SequenceNumber, Description, CreationTime FROM SystemRestore"));
        Assert.Contains("no peering", WindowsMaintenanceModule.DescribeDeliveryOptimizationMode(0), StringComparison.OrdinalIgnoreCase);
        Assert.Contains("local network", WindowsMaintenanceModule.DescribeDeliveryOptimizationMode(1), StringComparison.OrdinalIgnoreCase);
        Assert.Contains("internet", WindowsMaintenanceModule.DescribeDeliveryOptimizationMode(3), StringComparison.OrdinalIgnoreCase);
        Assert.Equal("time.windows.com", WindowsMaintenanceModule.CleanTimeSource("time.windows.com,0x9"));
        Assert.Equal("Local CMOS Clock", WindowsMaintenanceModule.CleanTimeSource("Local CMOS Clock"));
    }

    private sealed class SequenceClockProber(params ClockHttpsSample[] samples) : IClockHttpsProber
    {
        private int _i;
        public int Calls => _i;
        public Task<ClockHttpsSample> ProbeOnceAsync(Uri uri, CancellationToken ct)
        {
            var idx = _i++;
            return Task.FromResult(idx < samples.Length
                ? samples[idx]
                : new ClockHttpsSample(ClockProbeStatus.NetworkOrTlsError, Now, Now.AddMilliseconds(50), null, Error: "exhausted"));
        }
    }
}
